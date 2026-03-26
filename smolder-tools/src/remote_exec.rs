//! Windows remote execution support built on top of SMB2/3 and SCMR over `IPC$`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rand::random;
use tokio::fs;
use tokio::time::{sleep, timeout, Instant};

use smolder_proto::rpc::{SyntaxId, Uuid};
use smolder_proto::smb::smb2::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect, DispositionInformation,
    FileAttributes, FileId, FileInfoClass, FlushRequest, GlobalCapabilities, ReadRequest,
    SetInfoRequest, ShareAccess, SigningMode, WriteRequest,
};
use smolder_proto::smb::status::NtStatus;

use smolder_core::auth::NtlmCredentials;
use smolder_core::client::{Connection, TreeConnected};
use smolder_core::error::CoreError;
use smolder_core::pipe::{connect_tree, NamedPipe, PipeAccess, SmbSessionConfig};
use smolder_core::rpc::PipeRpcClient;
use smolder_core::transport::TokioTcpTransport;

const DEFAULT_PORT: u16 = 445;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const OUTPUT_SETTLE_TIMEOUT: Duration = Duration::from_secs(3);
const OUTPUT_SETTLE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const PIPE_CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const ADMIN_SHARE_ROOT: &str = r"C:\Windows";
const DEFAULT_STAGING_DIR: &str = r"Temp";
const DEFAULT_PSEXEC_BINARY_NAME: &str = "smolder-psexecsvc.exe";
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_ALL_ACCESS: u32 = 0x000f_01ff;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
const SERVICE_DEMAND_START: u32 = 0x0000_0003;
const SERVICE_STOPPED: u32 = 0x0000_0001;
const ERROR_SERVICE_REQUEST_TIMEOUT: u32 = 1053;
const SVCCTL_CONTEXT_ID: u16 = 0;
const SVCCTL_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x367a_bb81,
        0x9844,
        0x35f1,
        [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
    ),
    2,
    0,
);

/// Remote execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Inline `cmd.exe` service command with combined output capture.
    SmbExec,
    /// Staged `.cmd` runner with separate stdout/stderr capture.
    PsExec,
}

/// One remote execution request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    command: String,
    working_directory: Option<String>,
    timeout: Option<Duration>,
}

impl ExecRequest {
    /// Builds a request for the provided shell command line.
    #[must_use]
    pub fn command(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            working_directory: None,
            timeout: None,
        }
    }

    /// Sets the remote working directory for the command.
    #[must_use]
    pub fn with_working_directory(mut self, working_directory: impl Into<String>) -> Self {
        self.working_directory = Some(working_directory.into());
        self
    }

    /// Overrides the per-request timeout budget.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    fn command_text(&self) -> Option<&str> {
        let command = self.command.trim();
        if command.is_empty() {
            None
        } else {
            Some(command)
        }
    }
}

/// Result of one remote execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Execution mode used.
    pub mode: ExecMode,
    /// Temporary service name used for the command.
    pub service_name: String,
    /// Exit code reported by the remote command.
    pub exit_code: i32,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// Total wall time spent from service creation through output collection.
    pub duration: Duration,
}

/// One interactive psexec session split into stdin/stdout/stderr/control parts.
pub struct InteractiveSession {
    stdin: InteractiveStdin,
    stdout: InteractiveReader,
    stderr: InteractiveReader,
    waiter: InteractiveWaiter,
}

impl InteractiveSession {
    /// Splits the session into independent stdin/stdout/stderr handles plus a completion waiter.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        InteractiveStdin,
        InteractiveReader,
        InteractiveReader,
        InteractiveWaiter,
    ) {
        (self.stdin, self.stdout, self.stderr, self.waiter)
    }
}

/// Writable stdin handle for an interactive remote process.
pub struct InteractiveStdin {
    pipe: Option<NamedPipe>,
}

impl InteractiveStdin {
    /// Writes one chunk to the remote stdin stream.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        let pipe = self.pipe.as_mut().ok_or(CoreError::InvalidInput(
            "interactive stdin is already closed",
        ))?;
        pipe.write_all(bytes).await
    }

    /// Closes the remote stdin stream and signals EOF to the child process.
    pub async fn close(&mut self) -> Result<(), CoreError> {
        let _ = self.pipe.take();
        Ok(())
    }
}

/// Readable stdout/stderr handle for an interactive remote process.
pub struct InteractiveReader {
    pipe: NamedPipe,
}

impl InteractiveReader {
    /// Reads the next chunk from the remote stream. `None` indicates EOF.
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, CoreError> {
        self.pipe.read_chunk().await
    }
}

/// Completion handle for an interactive remote process.
pub struct InteractiveWaiter {
    control: NamedPipe,
    cleanup: Option<InteractiveCleanup>,
    timeout: Duration,
    start: Instant,
    buffer: Vec<u8>,
}

impl InteractiveWaiter {
    /// Waits for the remote process to exit, then performs best-effort cleanup.
    pub async fn wait(mut self) -> Result<i32, CoreError> {
        let exit_code = loop {
            let line = timeout(
                self.remaining_time(),
                self.control.read_line(&mut self.buffer),
            )
            .await
            .map_err(|_| {
                CoreError::Timeout("waiting for interactive remote command completion")
            })??;
            let Some(line) = line else {
                return Err(CoreError::InvalidResponse(
                    "interactive control pipe closed before reporting exit code",
                ));
            };
            if let Some(exit_code) = parse_exit_control_line(&line)? {
                break exit_code;
            }
        };

        if let Some(cleanup) = self.cleanup.take() {
            cleanup.run().await;
        }
        Ok(exit_code)
    }

    fn remaining_time(&self) -> Duration {
        let elapsed = self.start.elapsed();
        self.timeout.saturating_sub(elapsed)
    }
}

/// Builder for a Windows remote execution client.
#[derive(Debug, Clone)]
pub struct RemoteExecBuilder {
    server: Option<String>,
    port: u16,
    credentials: Option<NtlmCredentials>,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
    admin_share: String,
    ipc_share: String,
    staging_directory: String,
    psexec_service_binary: Option<PathBuf>,
    psexec_remote_binary_name: String,
    mode: ExecMode,
    timeout: Duration,
    poll_interval: Duration,
}

impl Default for RemoteExecBuilder {
    fn default() -> Self {
        Self {
            server: None,
            port: DEFAULT_PORT,
            credentials: None,
            signing_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::LEASING,
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            client_guid: random(),
            admin_share: "ADMIN$".to_string(),
            ipc_share: "IPC$".to_string(),
            staging_directory: DEFAULT_STAGING_DIR.to_string(),
            psexec_service_binary: None,
            psexec_remote_binary_name: DEFAULT_PSEXEC_BINARY_NAME.to_string(),
            mode: ExecMode::SmbExec,
            timeout: DEFAULT_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl RemoteExecBuilder {
    /// Creates a new remote-exec builder with SMB2/3 defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the target server host name or IP address.
    #[must_use]
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    /// Sets the target SMB TCP port.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the NTLM credentials used for each execution session.
    #[must_use]
    pub fn credentials(mut self, credentials: NtlmCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Overrides the default execution mode.
    #[must_use]
    pub fn mode(mut self, mode: ExecMode) -> Self {
        self.mode = mode;
        self
    }

    /// Overrides the SMB signing mode used during negotiate.
    #[must_use]
    pub fn signing_mode(mut self, signing_mode: SigningMode) -> Self {
        self.signing_mode = signing_mode;
        self
    }

    /// Overrides the dialect list used during negotiate.
    #[must_use]
    pub fn dialects(mut self, dialects: Vec<Dialect>) -> Self {
        self.dialects = dialects;
        self
    }

    /// Overrides the staging directory relative to `ADMIN$`.
    #[must_use]
    pub fn staging_directory(mut self, staging_directory: impl Into<String>) -> Self {
        self.staging_directory = staging_directory.into();
        self
    }

    /// Sets the local Windows service executable staged for `psexec` mode.
    #[must_use]
    pub fn psexec_service_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.psexec_service_binary = Some(path.into());
        self
    }

    /// Overrides the remote executable filename used under `ADMIN$` for `psexec`.
    #[must_use]
    pub fn psexec_remote_binary_name(mut self, name: impl Into<String>) -> Self {
        self.psexec_remote_binary_name = name.into();
        self
    }

    /// Overrides the default execution timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the output-poll interval.
    #[must_use]
    pub fn poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    /// Connects the builder into a reusable remote-exec client.
    pub async fn connect(self) -> Result<RemoteExecClient, CoreError> {
        let server = self
            .server
            .ok_or(CoreError::InvalidInput("server must be configured"))?;
        let credentials = self
            .credentials
            .ok_or(CoreError::InvalidInput("credentials must be configured"))?;
        let admin_share = normalize_share_name(&self.admin_share)?;
        let ipc_share = normalize_share_name(&self.ipc_share)?;
        let staging_directory = normalize_share_path(&self.staging_directory)?;

        Ok(RemoteExecClient {
            config: SmbSessionConfig::new(server, credentials)
                .with_port(self.port)
                .with_signing_mode(self.signing_mode)
                .with_capabilities(self.capabilities)
                .with_dialects(self.dialects)
                .with_client_guid(self.client_guid),
            admin_share,
            ipc_share,
            staging_directory,
            psexec_service_binary: self.psexec_service_binary,
            psexec_remote_binary_name: normalize_remote_file_name(&self.psexec_remote_binary_name)?,
            mode: self.mode,
            timeout: self.timeout,
            poll_interval: self.poll_interval,
        })
    }
}

/// Reusable remote-exec client that creates fresh SMB sessions per command.
#[derive(Debug, Clone)]
pub struct RemoteExecClient {
    config: SmbSessionConfig,
    admin_share: String,
    ipc_share: String,
    staging_directory: String,
    psexec_service_binary: Option<PathBuf>,
    psexec_remote_binary_name: String,
    mode: ExecMode,
    timeout: Duration,
    poll_interval: Duration,
}

impl RemoteExecClient {
    /// Creates a builder for a new remote-exec client.
    #[must_use]
    pub fn builder() -> RemoteExecBuilder {
        RemoteExecBuilder::new()
    }

    /// Runs one request using the client's configured default mode.
    pub async fn run(&self, request: ExecRequest) -> Result<ExecResult, CoreError> {
        self.run_with_mode(self.mode, request).await
    }

    /// Starts one interactive `psexec` session and returns stream handles plus a completion waiter.
    pub async fn spawn(&self, request: ExecRequest) -> Result<InteractiveSession, CoreError> {
        if !matches!(self.mode, ExecMode::PsExec) {
            return Err(CoreError::Unsupported(
                "interactive sessions require psexec mode",
            ));
        }
        if self.psexec_service_binary.is_some() {
            return Err(CoreError::Unsupported(
                "interactive psexec with the staged service payload is not supported yet",
            ));
        }
        let service_binary =
            self.psexec_service_binary
                .as_deref()
                .ok_or(CoreError::Unsupported(
                    "interactive psexec is not supported yet",
                ))?;
        let timeout_budget = request.timeout.unwrap_or(self.timeout);
        let command_paths =
            CommandPaths::new(&self.staging_directory, &self.psexec_remote_binary_name);
        let mut admin = AdminShare::connect(&self.config, &self.admin_share).await?;
        let mut scm = ScmClient::connect(&self.config, &self.ipc_share).await?;

        let payload = fs::read(service_binary).await.map_err(CoreError::LocalIo)?;
        admin
            .write_all(&command_paths.service_binary_relative, &payload)
            .await?;

        let scm_handle = scm.open_sc_manager().await?;
        let service_command = build_psexec_interactive_service_command(&request, &command_paths);
        let service_handle = match scm
            .create_service(&scm_handle, &command_paths.service_name, &service_command)
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                let _ = scm.close_handle(&scm_handle).await;
                let _ = admin
                    .try_remove(&command_paths.service_binary_relative)
                    .await;
                return Err(error);
            }
        };

        if let Err(error) = scm.start_service(&service_handle).await {
            let _ = scm.delete_service(&service_handle).await;
            let _ = scm.close_handle(&service_handle).await;
            let _ = scm.close_handle(&scm_handle).await;
            let _ = admin
                .try_remove(&command_paths.service_binary_relative)
                .await;
            return Err(error);
        }

        let stdin_pipe_name = command_paths.stdin_pipe_name();
        let stdout_pipe_name = command_paths.stdout_pipe_name();
        let stderr_pipe_name = command_paths.stderr_pipe_name();
        let control_pipe_name = command_paths.control_pipe_name();
        let pipes = tokio::try_join!(
            connect_pipe_with_retry(
                &self.config,
                &self.ipc_share,
                &stdin_pipe_name,
                PipeAccess::WriteOnly,
                timeout_budget,
            ),
            connect_pipe_with_retry(
                &self.config,
                &self.ipc_share,
                &stdout_pipe_name,
                PipeAccess::ReadOnly,
                timeout_budget,
            ),
            connect_pipe_with_retry(
                &self.config,
                &self.ipc_share,
                &stderr_pipe_name,
                PipeAccess::ReadOnly,
                timeout_budget,
            ),
            connect_pipe_with_retry(
                &self.config,
                &self.ipc_share,
                &control_pipe_name,
                PipeAccess::ReadOnly,
                timeout_budget,
            ),
        );

        let (stdin_pipe, stdout_pipe, stderr_pipe, mut control_pipe) = match pipes {
            Ok(pipes) => pipes,
            Err(error) => {
                cleanup_interactive_startup(
                    &mut admin,
                    &mut scm,
                    &service_handle,
                    &scm_handle,
                    &command_paths,
                )
                .await;
                return Err(error);
            }
        };

        let mut control_buffer = Vec::new();
        let ready_line = timeout(timeout_budget, control_pipe.read_line(&mut control_buffer))
            .await
            .map_err(|_| CoreError::Timeout("waiting for interactive psexec service readiness"))??;
        match ready_line.as_deref() {
            Some("READY") => {}
            Some(_) => {
                cleanup_interactive_startup(
                    &mut admin,
                    &mut scm,
                    &service_handle,
                    &scm_handle,
                    &command_paths,
                )
                .await;
                return Err(CoreError::InvalidResponse(
                    "interactive control pipe returned an unexpected banner",
                ));
            }
            None => {
                cleanup_interactive_startup(
                    &mut admin,
                    &mut scm,
                    &service_handle,
                    &scm_handle,
                    &command_paths,
                )
                .await;
                return Err(CoreError::InvalidResponse(
                    "interactive control pipe closed before readiness",
                ));
            }
        }

        Ok(InteractiveSession {
            stdin: InteractiveStdin {
                pipe: Some(stdin_pipe),
            },
            stdout: InteractiveReader { pipe: stdout_pipe },
            stderr: InteractiveReader { pipe: stderr_pipe },
            waiter: InteractiveWaiter {
                control: control_pipe,
                cleanup: Some(InteractiveCleanup {
                    admin,
                    scm,
                    service_handle,
                    scm_handle,
                    command_paths,
                    staged_service_binary: true,
                }),
                timeout: timeout_budget,
                start: Instant::now(),
                buffer: control_buffer,
            },
        })
    }

    /// Runs one request using the provided mode.
    pub async fn run_with_mode(
        &self,
        mode: ExecMode,
        request: ExecRequest,
    ) -> Result<ExecResult, CoreError> {
        if request.command_text().is_none() {
            return Err(CoreError::InvalidInput(
                "remote command must not be empty for one-shot execution",
            ));
        }
        let start = Instant::now();
        let timeout_budget = request.timeout.unwrap_or(self.timeout);
        let command_paths =
            CommandPaths::new(&self.staging_directory, &self.psexec_remote_binary_name);
        let mut admin = AdminShare::connect(&self.config, &self.admin_share).await?;
        let mut scm = ScmClient::connect(&self.config, &self.ipc_share).await?;

        let service_name = command_paths.service_name.clone();
        let execution = async {
            match mode {
                ExecMode::SmbExec => {
                    let script = build_smbexec_script(&request, &command_paths);
                    admin
                        .write_all(&command_paths.script_relative, script.as_bytes())
                        .await?;
                }
                ExecMode::PsExec => {
                    let script = if self.psexec_service_binary.is_some() {
                        build_psexec_script(&request)
                    } else {
                        build_psexec_wrapper_script(&command_paths)
                    };
                    admin
                        .write_all(&command_paths.script_relative, script.as_bytes())
                        .await?;
                    if self.psexec_service_binary.is_none() {
                        let runner = build_psexec_runner_script(&request, &command_paths);
                        admin
                            .write_all(&command_paths.runner_relative, runner.as_bytes())
                            .await?;
                    }
                }
            }
            if matches!(mode, ExecMode::PsExec) {
                if let Some(service_binary) = &self.psexec_service_binary {
                    let payload = fs::read(service_binary).await.map_err(CoreError::LocalIo)?;
                    admin
                        .write_all(&command_paths.service_binary_relative, &payload)
                        .await?;
                }
            }

            let service_command = match mode {
                ExecMode::SmbExec => build_smbexec_service_command(&command_paths),
                ExecMode::PsExec => build_psexec_service_command(
                    self.psexec_service_binary.as_deref(),
                    &command_paths,
                ),
            };
            if std::env::var_os("SMOLDER_NTLM_DEBUG").is_some() {
                eprintln!(
                    "remote exec mode={:?} service={} script={} runner={} stdout={} stderr={} exit={} command={}",
                    mode,
                    service_name,
                    command_paths.script_relative,
                    command_paths.runner_relative,
                    command_paths.stdout_relative,
                    command_paths.stderr_relative,
                    command_paths.exit_relative,
                    service_command
                );
            }

            let scm_handle = scm.open_sc_manager().await?;
            let service_handle = scm
                .create_service(&scm_handle, &service_name, &service_command)
                .await?;
            let start_result = scm.start_service(&service_handle).await;
            if let Err(error) = start_result {
                let _ = scm.delete_service(&service_handle).await;
                let _ = scm.close_handle(&service_handle).await;
                let _ = scm.close_handle(&scm_handle).await;
                return Err(error);
            }
            if matches!(mode, ExecMode::SmbExec) {
                scm.wait_for_service_stop(&service_handle, timeout_budget, self.poll_interval)
                    .await?;
            }

            let exec_result = wait_for_result(
                mode,
                &mut admin,
                &command_paths,
                timeout_budget,
                self.poll_interval,
            )
            .await;

            let _ = scm.delete_service(&service_handle).await;
            let _ = scm.close_handle(&service_handle).await;
            let _ = scm.close_handle(&scm_handle).await;

            exec_result
        }
        .await;

        if std::env::var_os("SMOLDER_KEEP_REMOTE_ARTIFACTS").is_none() {
            let _ = admin.try_remove(&command_paths.stdout_relative).await;
            let _ = admin.try_remove(&command_paths.stderr_relative).await;
            let _ = admin.try_remove(&command_paths.exit_relative).await;
            let _ = admin.try_remove(&command_paths.debug_relative).await;
            let _ = admin.try_remove(&command_paths.runner_relative).await;
            let _ = admin.try_remove(&command_paths.script_relative).await;
            if matches!(mode, ExecMode::PsExec) {
                if self.psexec_service_binary.is_some() {
                    let _ = admin
                        .try_remove(&command_paths.service_binary_relative)
                        .await;
                }
            }
        }

        let mut result = execution?;
        result.duration = start.elapsed();
        Ok(result)
    }
}

struct InteractiveCleanup {
    admin: AdminShare,
    scm: ScmClient,
    service_handle: ScHandle,
    scm_handle: ScHandle,
    command_paths: CommandPaths,
    staged_service_binary: bool,
}

impl InteractiveCleanup {
    async fn run(mut self) {
        let _ = self.scm.delete_service(&self.service_handle).await;
        let _ = self.scm.close_handle(&self.service_handle).await;
        let _ = self.scm.close_handle(&self.scm_handle).await;
        if self.staged_service_binary {
            let _ = self
                .admin
                .try_remove(&self.command_paths.service_binary_relative)
                .await;
        }
    }
}

#[derive(Debug, Clone)]
struct CommandPaths {
    service_name: String,
    pipe_prefix: String,
    stdout_relative: String,
    stderr_relative: String,
    exit_relative: String,
    debug_relative: String,
    script_relative: String,
    runner_relative: String,
    service_binary_relative: String,
    stdout_absolute: String,
    stderr_absolute: String,
    exit_absolute: String,
    debug_absolute: String,
    script_absolute: String,
    runner_absolute: String,
    service_binary_absolute: String,
}

impl CommandPaths {
    fn new(staging_directory: &str, psexec_binary_name: &str) -> Self {
        let token = random::<u64>();
        let prefix = format!("SMOLDER-{token:016x}");
        let stdout_relative = join_share_path(staging_directory, &format!("{prefix}.out"));
        let stderr_relative = join_share_path(staging_directory, &format!("{prefix}.err"));
        let exit_relative = join_share_path(staging_directory, &format!("{prefix}.exit"));
        let debug_relative = join_share_path(staging_directory, &format!("{prefix}.dbg"));
        let script_relative = join_share_path(staging_directory, &format!("{prefix}.cmd"));
        let runner_relative = join_share_path(staging_directory, &format!("{prefix}.bat"));
        let service_binary_relative =
            join_share_path(staging_directory, &format!("{prefix}-{psexec_binary_name}"));
        let service_name = format!("SMOLDER{token:016X}");
        Self {
            service_name,
            pipe_prefix: prefix.clone(),
            stdout_absolute: admin_absolute_path(&stdout_relative),
            stderr_absolute: admin_absolute_path(&stderr_relative),
            exit_absolute: admin_absolute_path(&exit_relative),
            debug_absolute: admin_absolute_path(&debug_relative),
            script_absolute: admin_absolute_path(&script_relative),
            runner_absolute: admin_absolute_path(&runner_relative),
            service_binary_absolute: admin_absolute_path(&service_binary_relative),
            stdout_relative,
            stderr_relative,
            exit_relative,
            debug_relative,
            script_relative,
            runner_relative,
            service_binary_relative,
        }
    }

    fn stdin_pipe_name(&self) -> String {
        format!("{}.stdin", self.pipe_prefix)
    }

    fn stdout_pipe_name(&self) -> String {
        format!("{}.stdout", self.pipe_prefix)
    }

    fn stderr_pipe_name(&self) -> String {
        format!("{}.stderr", self.pipe_prefix)
    }

    fn control_pipe_name(&self) -> String {
        format!("{}.control", self.pipe_prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScHandle([u8; 20]);

struct ScmClient {
    rpc: PipeRpcClient,
}

impl ScmClient {
    async fn connect(config: &SmbSessionConfig, ipc_share: &str) -> Result<Self, CoreError> {
        let pipe = NamedPipe::connect(config, ipc_share, "svcctl", PipeAccess::ReadWrite).await?;
        let mut rpc = PipeRpcClient::new(pipe);
        // `svcctl` over `ncacn_np` already rides an authenticated SMB session.
        // Forcing WinNT secure bind here reproduces Windows `rpc_s_cannot_support (0x6e4)`,
        // and Impacket's working service-control paths use a plain bind on this transport.
        rpc.bind_context(SVCCTL_CONTEXT_ID, SVCCTL_SYNTAX).await?;
        Ok(Self { rpc })
    }

    async fn open_sc_manager(&mut self) -> Result<ScHandle, CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_unique_wide_string(None);
        stub.write_unique_wide_string(Some("ServicesActive"));
        stub.write_u32(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 15, stub.into_bytes())
            .await?;
        parse_open_handle_response(&response, "open_sc_manager")
    }

    async fn create_service(
        &mut self,
        scm_handle: &ScHandle,
        service_name: &str,
        binary_path: &str,
    ) -> Result<ScHandle, CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(scm_handle);
        stub.write_wide_string(service_name);
        stub.write_unique_wide_string(Some(service_name));
        stub.write_u32(SERVICE_ALL_ACCESS);
        stub.write_u32(SERVICE_WIN32_OWN_PROCESS);
        stub.write_u32(SERVICE_DEMAND_START);
        stub.write_u32(0);
        stub.write_wide_string(binary_path);
        stub.write_unique_wide_string(None);
        stub.write_u32(0);
        stub.write_unique_bytes(None);
        stub.write_u32(0);
        stub.write_unique_wide_string(None);
        stub.write_u32(0);
        stub.write_unique_bytes(None);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 12, stub.into_bytes())
            .await?;
        parse_create_service_response(&response)
    }

    async fn start_service(&mut self, service_handle: &ScHandle) -> Result<(), CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(service_handle);
        stub.write_u32(0);
        stub.write_u32(0);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 19, stub.into_bytes())
            .await?;
        let status = read_u32_status(&response)?;
        if status == 0 || status == ERROR_SERVICE_REQUEST_TIMEOUT {
            return Ok(());
        }
        Err(CoreError::RemoteOperation {
            operation: "start_service",
            code: status,
        })
    }

    async fn delete_service(&mut self, service_handle: &ScHandle) -> Result<(), CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(service_handle);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 2, stub.into_bytes())
            .await?;
        let status = read_u32_status(&response)?;
        if status == 0 {
            return Ok(());
        }
        Err(CoreError::RemoteOperation {
            operation: "delete_service",
            code: status,
        })
    }

    async fn wait_for_service_stop(
        &mut self,
        service_handle: &ScHandle,
        timeout_budget: Duration,
        poll_interval: Duration,
    ) -> Result<(), CoreError> {
        let deadline = Instant::now() + timeout_budget;
        loop {
            let current_state = self.query_service_status(service_handle).await?;
            if current_state == SERVICE_STOPPED {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(CoreError::Timeout("waiting for service to stop"));
            }
            sleep(poll_interval).await;
        }
    }

    async fn query_service_status(&mut self, service_handle: &ScHandle) -> Result<u32, CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(service_handle);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 6, stub.into_bytes())
            .await?;
        parse_query_service_status_response(&response)
    }

    async fn close_handle(&mut self, handle: &ScHandle) -> Result<(), CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(handle);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 0, stub.into_bytes())
            .await?;
        let status = parse_close_handle_response(&response)?;
        if status == 0 {
            return Ok(());
        }
        Err(CoreError::RemoteOperation {
            operation: "close_service_handle",
            code: status,
        })
    }
}

async fn connect_pipe_with_retry(
    config: &SmbSessionConfig,
    ipc_share: &str,
    pipe_name: &str,
    access: PipeAccess,
    timeout_budget: Duration,
) -> Result<NamedPipe, CoreError> {
    let deadline = Instant::now() + timeout_budget;
    loop {
        match NamedPipe::connect(config, ipc_share, pipe_name, access).await {
            Ok(pipe) => return Ok(pipe),
            Err(error) if is_pipe_not_ready(&error) && Instant::now() < deadline => {
                sleep(PIPE_CONNECT_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(error),
        }
    }
}

struct AdminShare {
    connection: Connection<TokioTcpTransport, TreeConnected>,
    max_read_size: u32,
    max_write_size: u32,
}

impl AdminShare {
    async fn connect(config: &SmbSessionConfig, share: &str) -> Result<Self, CoreError> {
        let connection = connect_tree(config, share).await?;
        let max_read_size = connection
            .state()
            .negotiated
            .max_read_size
            .min(u32::from(u16::MAX))
            .max(1);
        let max_write_size = connection
            .state()
            .negotiated
            .max_write_size
            .min(u32::from(u16::MAX))
            .max(1);
        Ok(Self {
            connection,
            max_read_size,
            max_write_size,
        })
    }

    async fn read_if_exists(&mut self, path: &str) -> Result<Option<Vec<u8>>, CoreError> {
        let file_id = match self
            .open_file(path, FILE_READ_DATA | FILE_READ_ATTRIBUTES)
            .await
        {
            Ok(file_id) => file_id,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };

        let mut offset = 0_u64;
        let mut output = Vec::new();
        let read_result = async {
            loop {
                let response = match self
                    .connection
                    .read(&ReadRequest::for_file(file_id, offset, self.max_read_size))
                    .await
                {
                    Ok(response) => response,
                    Err(error) if is_end_of_file(&error) => break,
                    Err(error) => return Err(error),
                };
                if response.data.is_empty() {
                    break;
                }
                offset += response.data.len() as u64;
                let reached_end = response.data.len() < self.max_read_size as usize;
                output.extend_from_slice(&response.data);
                if reached_end {
                    break;
                }
            }
            Ok::<(), CoreError>(())
        }
        .await;
        let close_result = self.close(file_id).await;
        match read_result {
            Ok(()) => {
                close_result?;
                Ok(Some(output))
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    async fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), CoreError> {
        let file_id = self
            .create_file(path, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES)
            .await?;
        let mut offset = 0_u64;
        let write_result = async {
            while (offset as usize) < data.len() {
                let chunk_end = ((offset as usize) + self.max_write_size as usize).min(data.len());
                let request = WriteRequest::for_file(
                    file_id,
                    offset,
                    data[offset as usize..chunk_end].to_vec(),
                );
                let response = self.connection.write(&request).await?;
                if response.count == 0 {
                    return Err(CoreError::InvalidResponse(
                        "admin share write returned zero bytes",
                    ));
                }
                offset += response.count as u64;
            }
            let _ = self
                .connection
                .flush(&FlushRequest::for_file(file_id))
                .await;
            Ok::<(), CoreError>(())
        }
        .await;
        let close_result = self.close(file_id).await;
        match write_result {
            Ok(()) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    async fn try_remove(&mut self, path: &str) -> Result<(), CoreError> {
        let file_id = match self
            .open_file(path, DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .await
        {
            Ok(file_id) => file_id,
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let delete_result = self
            .connection
            .set_info(&SetInfoRequest::for_file_info(
                file_id,
                FileInfoClass::DispositionInformation,
                DispositionInformation {
                    delete_pending: true,
                }
                .encode(),
            ))
            .await;
        let close_result = self.close(file_id).await;
        match delete_result {
            Ok(_) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    async fn open_file(&mut self, path: &str, desired_access: u32) -> Result<FileId, CoreError> {
        let normalized = normalize_share_path(path)?;
        let mut request = CreateRequest::from_path(&normalized);
        request.desired_access = desired_access | READ_CONTROL | SYNCHRONIZE;
        request.create_disposition = CreateDisposition::Open;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        self.connection
            .create(&request)
            .await
            .map(|response| response.file_id)
    }

    async fn create_file(&mut self, path: &str, desired_access: u32) -> Result<FileId, CoreError> {
        let normalized = normalize_share_path(path)?;
        let mut request = CreateRequest::from_path(&normalized);
        request.desired_access = desired_access | READ_CONTROL | SYNCHRONIZE;
        request.create_disposition = CreateDisposition::OverwriteIf;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        self.connection
            .create(&request)
            .await
            .map(|response| response.file_id)
    }

    async fn close(&mut self, file_id: FileId) -> Result<(), CoreError> {
        let _ = self
            .connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(())
    }
}

async fn cleanup_interactive_startup(
    admin: &mut AdminShare,
    scm: &mut ScmClient,
    service_handle: &ScHandle,
    scm_handle: &ScHandle,
    command_paths: &CommandPaths,
) {
    let _ = scm.delete_service(service_handle).await;
    let _ = scm.close_handle(service_handle).await;
    let _ = scm.close_handle(scm_handle).await;
    let _ = admin
        .try_remove(&command_paths.service_binary_relative)
        .await;
}

async fn wait_for_result(
    mode: ExecMode,
    admin: &mut AdminShare,
    paths: &CommandPaths,
    timeout_budget: Duration,
    poll_interval: Duration,
) -> Result<ExecResult, CoreError> {
    let deadline = Instant::now() + timeout_budget;
    loop {
        let exit_contents = timeout(deadline.saturating_duration_since(Instant::now()), async {
            admin.read_if_exists(&paths.exit_relative).await
        })
        .await
        .map_err(|_| CoreError::Timeout("waiting for remote command completion"))??;
        if let Some(exit_contents) = exit_contents {
            let exit_code = parse_exit_code(&exit_contents)?;
            let (stdout, stderr) =
                collect_command_output(mode, admin, paths, deadline, poll_interval).await?;
            return Ok(ExecResult {
                mode,
                service_name: paths.service_name.clone(),
                exit_code,
                stdout,
                stderr,
                duration: Duration::ZERO,
            });
        }
        if Instant::now() >= deadline {
            return Err(CoreError::Timeout("waiting for remote command completion"));
        }
        sleep(poll_interval).await;
    }
}

async fn collect_command_output(
    mode: ExecMode,
    admin: &mut AdminShare,
    paths: &CommandPaths,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let settle_deadline = deadline.min(Instant::now() + OUTPUT_SETTLE_TIMEOUT.max(poll_interval));
    loop {
        let stdout = admin
            .read_if_exists(&paths.stdout_relative)
            .await?
            .unwrap_or_default();
        let stderr = if matches!(mode, ExecMode::PsExec) {
            admin
                .read_if_exists(&paths.stderr_relative)
                .await?
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        if !stdout.is_empty() || !stderr.is_empty() || Instant::now() >= settle_deadline {
            return Ok((stdout, stderr));
        }

        sleep(OUTPUT_SETTLE_RETRY_INTERVAL).await;
    }
}

fn build_smbexec_service_command(command_paths: &CommandPaths) -> String {
    format!(r#"%COMSPEC% /Q /c {}"#, command_paths.script_absolute)
}

fn build_psexec_service_command(
    psexec_service_binary: Option<&Path>,
    command_paths: &CommandPaths,
) -> String {
    match psexec_service_binary {
        Some(_) => format!(
            "{} --service-name {}{} --script {} --stdout {} --stderr {} --exit-code {}",
            quote_windows_arg(&command_paths.service_binary_absolute),
            quote_windows_arg(&command_paths.service_name),
            psexec_debug_log_arg(command_paths),
            quote_windows_arg(&command_paths.script_absolute),
            quote_windows_arg(&command_paths.stdout_absolute),
            quote_windows_arg(&command_paths.stderr_absolute),
            quote_windows_arg(&command_paths.exit_absolute),
        ),
        None => format!(
            r#"%COMSPEC% /Q /c {}"#,
            quote_windows_arg(&command_paths.script_absolute)
        ),
    }
}

fn psexec_debug_log_arg(command_paths: &CommandPaths) -> String {
    if std::env::var_os("SMOLDER_NTLM_DEBUG").is_some() {
        format!(
            " --debug-log {}",
            quote_windows_arg(&command_paths.debug_absolute)
        )
    } else {
        String::new()
    }
}

fn build_psexec_interactive_service_command(
    request: &ExecRequest,
    command_paths: &CommandPaths,
) -> String {
    let mut command = format!(
        "{} --service-name {} --pipe-prefix {}",
        quote_windows_arg(&command_paths.service_binary_absolute),
        quote_windows_arg(&command_paths.service_name),
        quote_windows_arg(&command_paths.pipe_prefix),
    );
    if let Some(command_text) = request.command_text() {
        command.push_str(" --command ");
        command.push_str(&quote_windows_arg(command_text));
    }
    if let Some(working_directory) = &request.working_directory {
        command.push_str(" --workdir ");
        command.push_str(&quote_windows_arg(working_directory));
    }
    command
}

fn build_psexec_script(request: &ExecRequest) -> String {
    let mut script = String::from("@echo off\r\n");
    if let Some(working_directory) = &request.working_directory {
        script.push_str(&format!(r#"cd /d "{}" || exit /b 1"#, working_directory));
        script.push_str("\r\n");
    }
    script.push_str(&request.command);
    script.push_str("\r\n");
    script
}

fn build_psexec_wrapper_script(command_paths: &CommandPaths) -> String {
    let runner_path = quote_windows_arg(&command_paths.runner_absolute);
    let mut script = String::from("@echo off\r\n");
    script.push_str(&format!(r#"%COMSPEC% /Q /c {runner_path}"#));
    script.push_str("\r\n");
    script
}

fn build_psexec_runner_script(request: &ExecRequest, command_paths: &CommandPaths) -> String {
    let stdout_path = quote_windows_arg(&command_paths.stdout_absolute);
    let stderr_path = quote_windows_arg(&command_paths.stderr_absolute);
    let exit_path = quote_windows_arg(&command_paths.exit_absolute);
    let mut script = String::from("@echo off\r\n");
    if let Some(working_directory) = &request.working_directory {
        script.push_str(&format!(r#"cd /d "{working_directory}""#));
        script.push_str("\r\n");
        script.push_str("if errorlevel 1 goto write_exit\r\n");
    }
    script.push_str(request.command_text().expect("validated non-empty command"));
    script.push_str(&format!(r#" 1> {stdout_path} 2> {stderr_path}"#));
    script.push_str("\r\n");
    script.push_str(":write_exit\r\n");
    script.push_str(&format!(r#"echo %ERRORLEVEL% > {exit_path}"#));
    script.push_str("\r\n");
    script
}

fn build_smbexec_script(request: &ExecRequest, command_paths: &CommandPaths) -> String {
    let runner_script = build_smbexec_runner_script(request, command_paths);
    let runner_path = quote_windows_arg(&command_paths.runner_absolute);
    let mut script = String::from("@echo off\r\n");
    for (index, line) in runner_script
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let redirect = if index == 0 { ">" } else { ">>" };
        script.push_str("echo ");
        script.push_str(&escape_cmd_for_echo(line));
        script.push(' ');
        script.push_str(redirect);
        script.push(' ');
        script.push_str(&runner_path);
        script.push_str("\r\n");
    }
    script.push_str(&format!(r#"%COMSPEC% /Q /c {runner_path}"#));
    script.push_str("\r\n");
    script.push_str(&format!(r#"del {runner_path}"#));
    script.push_str("\r\n");
    script
}

fn build_smbexec_runner_script(request: &ExecRequest, command_paths: &CommandPaths) -> String {
    let stdout_path = quote_windows_arg(&command_paths.stdout_absolute);
    let exit_path = quote_windows_arg(&command_paths.exit_absolute);
    let mut script = String::from("@echo off\r\n");
    if let Some(working_directory) = &request.working_directory {
        script.push_str(&format!(r#"cd /d "{working_directory}""#));
        script.push_str("\r\n");
        script.push_str("if errorlevel 1 goto write_exit\r\n");
    }
    script.push_str(request.command_text().expect("validated non-empty command"));
    script.push_str(&format!(r#" > {stdout_path} 2>&1"#));
    script.push_str("\r\n");
    script.push_str(":write_exit\r\n");
    script.push_str(&format!(r#"echo %ERRORLEVEL% > {exit_path}"#));
    script.push_str("\r\n");
    script
}

fn escape_cmd_for_echo(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '^' => escaped.push_str("^^"),
            '&' => escaped.push_str("^&"),
            '|' => escaped.push_str("^|"),
            '<' => escaped.push_str("^<"),
            '>' => escaped.push_str("^>"),
            '(' => escaped.push_str("^("),
            ')' => escaped.push_str("^)"),
            '%' => escaped.push_str("%%"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn parse_exit_control_line(line: &str) -> Result<Option<i32>, CoreError> {
    if line == "READY" {
        return Ok(None);
    }
    if let Some(exit_code) = line.strip_prefix("EXIT ") {
        return exit_code
            .trim()
            .parse::<i32>()
            .map(Some)
            .map_err(|_| CoreError::InvalidResponse("interactive exit line was not numeric"));
    }
    Err(CoreError::InvalidResponse(
        "interactive control pipe returned an unknown control line",
    ))
}

fn parse_open_handle_response(
    response: &[u8],
    operation: &'static str,
) -> Result<ScHandle, CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "scmr open-handle response was too short",
        ));
    }
    let mut handle = [0_u8; 20];
    handle.copy_from_slice(&response[..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("u32 status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation,
            code: status,
        });
    }
    Ok(ScHandle(handle))
}

fn parse_create_service_response(response: &[u8]) -> Result<ScHandle, CoreError> {
    if response.len() < 28 {
        return Err(CoreError::InvalidResponse(
            "scmr create-service response was too short",
        ));
    }
    let _tag_id_referent = u32::from_le_bytes(response[..4].try_into().expect("referent slice"));
    let mut handle = [0_u8; 20];
    handle.copy_from_slice(&response[4..24]);
    let status = u32::from_le_bytes(response[24..28].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "create_service",
            code: status,
        });
    }
    Ok(ScHandle(handle))
}

fn parse_close_handle_response(response: &[u8]) -> Result<u32, CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "scmr close-handle response was too short",
        ));
    }
    Ok(u32::from_le_bytes(
        response[20..24].try_into().expect("close status slice"),
    ))
}

fn parse_query_service_status_response(response: &[u8]) -> Result<u32, CoreError> {
    if response.len() < 32 {
        return Err(CoreError::InvalidResponse(
            "scmr query-service-status response was too short",
        ));
    }
    let current_state = u32::from_le_bytes(response[4..8].try_into().expect("current-state slice"));
    let status = u32::from_le_bytes(response[28..32].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "query_service_status",
            code: status,
        });
    }
    Ok(current_state)
}

fn read_u32_status(response: &[u8]) -> Result<u32, CoreError> {
    if response.len() < 4 {
        return Err(CoreError::InvalidResponse(
            "scmr status response was too short",
        ));
    }
    Ok(u32::from_le_bytes(
        response[..4].try_into().expect("status slice"),
    ))
}

fn parse_exit_code(bytes: &[u8]) -> Result<i32, CoreError> {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    trimmed
        .parse::<i32>()
        .map_err(|_| CoreError::InvalidResponse("remote exit-code file was not numeric"))
}

fn admin_absolute_path(relative: &str) -> String {
    format!(r"{ADMIN_SHARE_ROOT}\{}", relative.replace('/', r"\"))
}

fn join_share_path(base: &str, leaf: &str) -> String {
    if base.is_empty() {
        leaf.to_string()
    } else {
        format!(r"{}\{}", base.trim_matches(['\\', '/']), leaf)
    }
}

fn normalize_remote_file_name(name: &str) -> Result<String, CoreError> {
    let name = name.trim_matches(['\\', '/']);
    if name.is_empty() {
        return Err(CoreError::PathInvalid(
            "remote psexec binary name must not be empty",
        ));
    }
    if name.contains(['\\', '/', '\0']) {
        return Err(CoreError::PathInvalid(
            "remote psexec binary name must not contain separators or NUL bytes",
        ));
    }
    Ok(name.to_string())
}

fn quote_windows_arg(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

fn normalize_share_name(share: &str) -> Result<String, CoreError> {
    let share = share.trim_matches(['\\', '/']);
    if share.is_empty() {
        return Err(CoreError::PathInvalid("share name must not be empty"));
    }
    if share.contains(['\\', '/', '\0']) {
        return Err(CoreError::PathInvalid(
            "share name must not contain separators or NUL bytes",
        ));
    }
    Ok(share.to_string())
}

fn normalize_share_path(path: &str) -> Result<String, CoreError> {
    if path.contains('\0') {
        return Err(CoreError::PathInvalid("path must not contain NUL bytes"));
    }
    let normalized = path
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("\\");
    if normalized.is_empty() {
        return Err(CoreError::PathInvalid("path must not be empty"));
    }
    Ok(normalized)
}

fn is_not_found(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::UnexpectedStatus { status, .. }
            if *status == NtStatus::OBJECT_NAME_NOT_FOUND.to_u32()
                || *status == NtStatus::OBJECT_PATH_NOT_FOUND.to_u32()
    )
}

fn is_end_of_file(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::UnexpectedStatus { status, .. } if *status == NtStatus::END_OF_FILE.to_u32()
    )
}

fn is_pipe_not_ready(error: &CoreError) -> bool {
    is_not_found(error)
}

struct NdrWriter {
    bytes: Vec<u8>,
    referent: u32,
}

impl NdrWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            referent: 1,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn write_context_handle(&mut self, handle: &ScHandle) {
        self.align(4);
        self.bytes.extend_from_slice(&handle.0);
    }

    fn write_u32(&mut self, value: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_unique_wide_string(&mut self, value: Option<&str>) {
        self.align(4);
        match value {
            Some(value) => {
                let referent = self.next_referent();
                self.bytes.extend_from_slice(&referent.to_le_bytes());
                self.write_wide_string_body(value);
            }
            None => self.bytes.extend_from_slice(&0_u32.to_le_bytes()),
        }
    }

    fn write_wide_string(&mut self, value: &str) {
        self.align(4);
        self.write_wide_string_body(value);
    }

    fn write_wide_string_body(&mut self, value: &str) {
        self.align(4);
        let mut encoded = value.encode_utf16().collect::<Vec<_>>();
        encoded.push(0);
        let count = encoded.len() as u32;
        self.bytes.extend_from_slice(&count.to_le_bytes());
        self.bytes.extend_from_slice(&0_u32.to_le_bytes());
        self.bytes.extend_from_slice(&count.to_le_bytes());
        for code_unit in encoded {
            self.bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        self.align(4);
    }

    fn write_unique_bytes(&mut self, value: Option<&[u8]>) {
        self.align(4);
        match value {
            Some(value) => {
                let referent = self.next_referent();
                self.bytes.extend_from_slice(&referent.to_le_bytes());
                self.align(4);
                let count = value.len() as u32;
                self.bytes.extend_from_slice(&count.to_le_bytes());
                self.bytes.extend_from_slice(value);
                self.align(4);
            }
            None => self.bytes.extend_from_slice(&0_u32.to_le_bytes()),
        }
    }

    fn align(&mut self, alignment: usize) {
        let padding = (alignment - (self.bytes.len() % alignment)) % alignment;
        self.bytes.resize(self.bytes.len() + padding, 0);
    }

    fn next_referent(&mut self) -> u32 {
        let current = self.referent;
        self.referent += 1;
        current
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        build_psexec_interactive_service_command, build_psexec_runner_script, build_psexec_script,
        build_psexec_service_command, build_psexec_wrapper_script, build_smbexec_runner_script,
        build_smbexec_script, build_smbexec_service_command, escape_cmd_for_echo,
        normalize_remote_file_name, parse_create_service_response, parse_exit_code,
        parse_exit_control_line, parse_open_handle_response, quote_windows_arg, CommandPaths,
        ExecMode, ExecRequest,
    };

    #[test]
    fn smbexec_command_redirects_output_and_exit_code() {
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let command = build_smbexec_service_command(&paths);
        assert_eq!(
            command,
            format!(r#"%COMSPEC% /Q /c {}"#, paths.script_absolute)
        );
    }

    #[test]
    fn smbexec_script_redirects_command_output_and_exit_code() {
        let request = ExecRequest::command("whoami").with_working_directory(r"C:\");
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let script = build_smbexec_script(&request, &paths);
        assert!(script.starts_with("@echo off\r\n"));
        assert!(script.contains(r#"echo @echo off > "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#"echo cd /d "C:\" >> "C:\Windows\Temp\SMOLDER-"#));
        assert!(
            script.contains(r#"echo if errorlevel 1 goto write_exit >> "C:\Windows\Temp\SMOLDER-"#)
        );
        assert!(script.contains(r#"echo whoami ^> "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#".out" 2^>^&1 >> "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#"%COMSPEC% /Q /c "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#".bat""#));
        assert!(script.contains(r#"del "C:\Windows\Temp\SMOLDER-"#));
    }

    #[test]
    fn smbexec_runner_redirects_command_output_and_exit_code() {
        let request = ExecRequest::command("whoami").with_working_directory(r"C:\");
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let script = build_smbexec_runner_script(&request, &paths);
        assert!(script.starts_with("@echo off\r\n"));
        assert!(script.contains(r#"cd /d "C:\""#));
        assert!(script.contains("if errorlevel 1 goto write_exit\r\n"));
        assert!(script.contains(r#"whoami > "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#".out" 2>&1"#));
        assert!(script.contains(":write_exit\r\n"));
        assert!(script.contains(r#"echo %ERRORLEVEL% > "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(".exit"));
    }

    #[test]
    fn escape_cmd_for_echo_preserves_literal_batch_text() {
        assert_eq!(
            escape_cmd_for_echo(r#"echo %ERRORLEVEL% > "C:\Temp\out.txt" 2>&1 & exit /b 1"#),
            r#"echo %%ERRORLEVEL%% ^> "C:\Temp\out.txt" 2^>^&1 ^& exit /b 1"#
        );
    }

    #[test]
    fn psexec_script_preserves_workdir_and_command() {
        let request = ExecRequest::command("dir").with_working_directory(r"C:\Temp");
        let script = build_psexec_script(&request);
        assert!(script.starts_with("@echo off\r\n"));
        assert!(script.contains(r#"cd /d "C:\Temp" || exit /b 1"#));
        assert!(script.contains("dir\r\n"));
    }

    #[test]
    fn psexec_service_command_without_payload_runs_wrapper_script() {
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let command = build_psexec_service_command(None, &paths);
        assert_eq!(
            command,
            format!(r#"%COMSPEC% /Q /c "{}""#, paths.script_absolute)
        );
    }

    #[test]
    fn psexec_runner_redirects_stdout_stderr_and_exit_code() {
        let request = ExecRequest::command("whoami").with_working_directory(r"C:\");
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let script = build_psexec_runner_script(&request, &paths);
        assert!(script.starts_with("@echo off\r\n"));
        assert!(script.contains(r#"cd /d "C:\""#));
        assert!(script.contains("if errorlevel 1 goto write_exit\r\n"));
        assert!(script.contains(r#"whoami 1> "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#".out" 2> "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(r#".err""#));
        assert!(script.contains(":write_exit\r\n"));
        assert!(script.contains(r#"echo %ERRORLEVEL% > "C:\Windows\Temp\SMOLDER-"#));
        assert!(script.contains(".exit"));
    }

    #[test]
    fn psexec_wrapper_invokes_runner_via_cmd() {
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let script = build_psexec_wrapper_script(&paths);
        assert_eq!(
            script,
            format!(
                "@echo off\r\n%COMSPEC% /Q /c \"{}\"\r\n",
                paths.runner_absolute
            )
        );
    }

    #[test]
    fn psexec_service_binary_command_uses_uploaded_payload() {
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let command = build_psexec_service_command(Some(Path::new("local.exe")), &paths);
        assert!(command.starts_with(r#""C:\Windows\Temp\SMOLDER-"#));
        assert!(command.contains("--service-name"));
        assert!(command.contains("--script"));
        assert!(command.contains("--stdout"));
        assert!(command.contains("--stderr"));
        assert!(command.contains("--exit-code"));
    }

    #[test]
    fn interactive_psexec_command_uses_pipe_prefix_and_optional_workdir() {
        let paths = CommandPaths::new("Temp", "smolder-psexecsvc.exe");
        let request = ExecRequest::command("powershell.exe").with_working_directory(r"C:\Temp");
        let command = build_psexec_interactive_service_command(&request, &paths);
        assert!(command.contains("--pipe-prefix"));
        assert!(command.contains(&paths.pipe_prefix));
        assert!(command.contains("--command"));
        assert!(command.contains("powershell.exe"));
        assert!(command.contains("--workdir"));
        assert!(command.contains(r#""C:\Temp""#));
    }

    #[test]
    fn parses_open_handle_response() {
        let mut response = vec![0x11; 20];
        response.extend_from_slice(&0_u32.to_le_bytes());
        let handle = parse_open_handle_response(&response, "open_sc_manager")
            .expect("response should parse");
        assert_eq!(handle.0, [0x11; 20]);
    }

    #[test]
    fn parses_create_service_response_with_tag_pointer() {
        let mut response = vec![1, 0, 0, 0];
        response.extend_from_slice(&[0x22; 20]);
        response.extend_from_slice(&0_u32.to_le_bytes());
        let handle = parse_create_service_response(&response).expect("response should parse");
        assert_eq!(handle.0, [0x22; 20]);
    }

    #[test]
    fn parses_exit_code_file() {
        let code = parse_exit_code(b"42\r\n").expect("exit code should parse");
        assert_eq!(code, 42);
    }

    #[test]
    fn command_paths_are_mode_agnostic() {
        let paths = CommandPaths::new("Temp", "svc.exe");
        assert!(paths.service_name.starts_with("SMOLDER"));
        assert!(paths.pipe_prefix.starts_with("SMOLDER-"));
        assert!(paths.stdout_relative.starts_with(r"Temp\SMOLDER-"));
        assert!(paths.service_binary_relative.ends_with("-svc.exe"));
        assert!(matches!(ExecMode::SmbExec, ExecMode::SmbExec));
    }

    #[test]
    fn control_line_parser_accepts_ready_and_exit() {
        assert_eq!(
            parse_exit_control_line("READY").expect("ready line should parse"),
            None
        );
        assert_eq!(
            parse_exit_control_line("EXIT 17").expect("exit line should parse"),
            Some(17)
        );
    }

    #[test]
    fn remote_binary_name_rejects_separators() {
        let error =
            normalize_remote_file_name(r"bad\name.exe").expect_err("separator should be rejected");
        assert!(matches!(
            error,
            smolder_core::error::CoreError::PathInvalid(_)
        ));
    }

    #[test]
    fn windows_arg_quoting_doubles_inner_quotes() {
        assert_eq!(
            quote_windows_arg(r#"C:\Temp\say "hi".cmd"#),
            r#""C:\Temp\say ""hi"".cmd""#
        );
    }
}
