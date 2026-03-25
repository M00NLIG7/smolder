//! Windows remote execution support built on top of SMB2/3 and SCMR over `IPC$`.

use std::time::Duration;

use rand::random;
use tokio::time::{sleep, timeout, Instant};

use smolder_proto::rpc::{
    BindAckPdu, BindPdu, Packet, PacketFlags, RequestPdu, ResponsePdu, SyntaxId, Uuid,
};
use smolder_proto::smb::smb2::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect,
    DispositionInformation, FileAttributes, FileId, FileInfoClass, FlushRequest,
    GlobalCapabilities, NegotiateContext, NegotiateRequest, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId, ReadRequest, SetInfoRequest, ShareAccess, SigningMode,
    TreeConnectRequest, WriteRequest,
};
use smolder_proto::smb::status::NtStatus;

use crate::auth::{NtlmAuthenticator, NtlmCredentials};
use crate::client::{Connection, TreeConnected};
use crate::error::CoreError;
use crate::transport::TokioTcpTransport;

const DEFAULT_PORT: u16 = 445;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const ADMIN_SHARE_ROOT: &str = r"C:\Windows";
const DEFAULT_STAGING_DIR: &str = r"Temp";
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
            config: SessionConfig {
                server,
                port: self.port,
                credentials,
                signing_mode: self.signing_mode,
                capabilities: self.capabilities,
                dialects: self.dialects,
                client_guid: self.client_guid,
            },
            admin_share,
            ipc_share,
            staging_directory,
            mode: self.mode,
            timeout: self.timeout,
            poll_interval: self.poll_interval,
        })
    }
}

/// Reusable remote-exec client that creates fresh SMB sessions per command.
#[derive(Debug, Clone)]
pub struct RemoteExecClient {
    config: SessionConfig,
    admin_share: String,
    ipc_share: String,
    staging_directory: String,
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

    /// Runs one request using the provided mode.
    pub async fn run_with_mode(
        &self,
        mode: ExecMode,
        request: ExecRequest,
    ) -> Result<ExecResult, CoreError> {
        let start = Instant::now();
        let timeout_budget = request.timeout.unwrap_or(self.timeout);
        let command_paths = CommandPaths::new(&self.staging_directory);
        let mut admin = AdminShare::connect(&self.config, &self.admin_share).await?;
        let mut scm = ScmClient::connect(&self.config, &self.ipc_share).await?;

        let service_name = command_paths.service_name.clone();
        let execution = async {
            if matches!(mode, ExecMode::PsExec) {
                let script = build_psexec_script(&request);
                admin.write_all(&command_paths.script_relative, script.as_bytes()).await?;
            }

            let service_command = match mode {
                ExecMode::SmbExec => build_smbexec_service_command(
                    &request,
                    &command_paths.stdout_absolute,
                    &command_paths.exit_absolute,
                ),
                ExecMode::PsExec => build_psexec_service_command(
                    &command_paths.script_absolute,
                    &command_paths.stdout_absolute,
                    &command_paths.stderr_absolute,
                    &command_paths.exit_absolute,
                ),
            };

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

        let _ = admin.try_remove(&command_paths.stdout_relative).await;
        let _ = admin.try_remove(&command_paths.stderr_relative).await;
        let _ = admin.try_remove(&command_paths.exit_relative).await;
        if matches!(mode, ExecMode::PsExec) {
            let _ = admin.try_remove(&command_paths.script_relative).await;
        }

        let mut result = execution?;
        result.duration = start.elapsed();
        Ok(result)
    }
}

#[derive(Debug, Clone)]
struct SessionConfig {
    server: String,
    port: u16,
    credentials: NtlmCredentials,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
}

#[derive(Debug, Clone)]
struct CommandPaths {
    service_name: String,
    stdout_relative: String,
    stderr_relative: String,
    exit_relative: String,
    script_relative: String,
    stdout_absolute: String,
    stderr_absolute: String,
    exit_absolute: String,
    script_absolute: String,
}

impl CommandPaths {
    fn new(staging_directory: &str) -> Self {
        let token = random::<u64>();
        let prefix = format!("SMOLDER-{token:016x}");
        let stdout_relative = join_share_path(staging_directory, &format!("{prefix}.out"));
        let stderr_relative = join_share_path(staging_directory, &format!("{prefix}.err"));
        let exit_relative = join_share_path(staging_directory, &format!("{prefix}.exit"));
        let script_relative = join_share_path(staging_directory, &format!("{prefix}.cmd"));
        let service_name = format!("SMOLDER{token:016X}");
        Self {
            service_name,
            stdout_absolute: admin_absolute_path(&stdout_relative),
            stderr_absolute: admin_absolute_path(&stderr_relative),
            exit_absolute: admin_absolute_path(&exit_relative),
            script_absolute: admin_absolute_path(&script_relative),
            stdout_relative,
            stderr_relative,
            exit_relative,
            script_relative,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScHandle([u8; 20]);

struct ScmClient {
    rpc: RpcPipeClient,
}

impl ScmClient {
    async fn connect(config: &SessionConfig, ipc_share: &str) -> Result<Self, CoreError> {
        let pipe = NamedPipeClient::connect(config, ipc_share, "svcctl").await?;
        let mut rpc = RpcPipeClient::new(pipe);
        rpc.bind(SVCCTL_SYNTAX).await?;
        Ok(Self { rpc })
    }

    async fn open_sc_manager(&mut self) -> Result<ScHandle, CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_unique_wide_string(None);
        stub.write_unique_wide_string(Some("ServicesActive"));
        stub.write_u32(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
        let response = self.rpc.call(15, stub.into_bytes()).await?;
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
        stub.write_unique_wide_string(Some(service_name));
        stub.write_unique_wide_string(Some(service_name));
        stub.write_u32(SERVICE_ALL_ACCESS);
        stub.write_u32(SERVICE_WIN32_OWN_PROCESS);
        stub.write_u32(SERVICE_DEMAND_START);
        stub.write_u32(0);
        stub.write_unique_wide_string(Some(binary_path));
        stub.write_unique_wide_string(None);
        stub.write_non_null_pointer();
        stub.write_u32(0);
        stub.write_u32(0);
        stub.write_unique_bytes(None);
        stub.write_unique_wide_string(None);
        stub.write_u32(0);
        stub.write_unique_bytes(None);
        let response = self.rpc.call(12, stub.into_bytes()).await?;
        parse_create_service_response(&response)
    }

    async fn start_service(&mut self, service_handle: &ScHandle) -> Result<(), CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(service_handle);
        stub.write_u32(0);
        stub.write_u32(0);
        let response = self.rpc.call(19, stub.into_bytes()).await?;
        let status = parse_u32_status(&response, "start_service")?;
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
        let response = self.rpc.call(2, stub.into_bytes()).await?;
        let status = parse_u32_status(&response, "delete_service")?;
        if status == 0 {
            return Ok(());
        }
        Err(CoreError::RemoteOperation {
            operation: "delete_service",
            code: status,
        })
    }

    async fn close_handle(&mut self, handle: &ScHandle) -> Result<(), CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(handle);
        let response = self.rpc.call(0, stub.into_bytes()).await?;
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

struct RpcPipeClient {
    pipe: NamedPipeClient,
    call_id: u32,
}

impl RpcPipeClient {
    fn new(pipe: NamedPipeClient) -> Self {
        Self { pipe, call_id: 1 }
    }

    async fn bind(&mut self, abstract_syntax: SyntaxId) -> Result<(), CoreError> {
        let bind = Packet::Bind(BindPdu {
            call_id: self.next_call_id(),
            max_xmit_frag: self.pipe.fragment_size as u16,
            max_recv_frag: self.pipe.fragment_size as u16,
            assoc_group_id: 0,
            context_id: SVCCTL_CONTEXT_ID,
            abstract_syntax,
            transfer_syntax: SyntaxId::NDR32,
        });
        let response = self.pipe.call(bind.encode()).await?;
        let packet = Packet::decode(&response)?;
        let Packet::BindAck(BindAckPdu { result, .. }) = packet else {
            return Err(CoreError::InvalidResponse("expected rpc bind ack"));
        };
        if result.result == 0 {
            return Ok(());
        }
        Err(CoreError::RemoteOperation {
            operation: "rpc_bind",
            code: u32::from(result.reason),
        })
    }

    async fn call(&mut self, opnum: u16, stub_data: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let request = Packet::Request(RequestPdu {
            call_id: self.next_call_id(),
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: stub_data.len() as u32,
            context_id: SVCCTL_CONTEXT_ID,
            opnum,
            object_uuid: None,
            stub_data,
        });
        let response = self.pipe.call(request.encode()).await?;
        match Packet::decode(&response)? {
            Packet::Response(ResponsePdu { stub_data, .. }) => Ok(stub_data),
            Packet::Fault(fault) => Err(CoreError::RemoteOperation {
                operation: "rpc_fault",
                code: fault.status,
            }),
            _ => Err(CoreError::InvalidResponse("unexpected rpc packet type")),
        }
    }

    fn next_call_id(&mut self) -> u32 {
        let current = self.call_id;
        self.call_id += 1;
        current
    }
}

struct NamedPipeClient {
    connection: Connection<TokioTcpTransport, TreeConnected>,
    file_id: FileId,
    fragment_size: u32,
}

impl NamedPipeClient {
    async fn connect(
        config: &SessionConfig,
        ipc_share: &str,
        pipe_name: &str,
    ) -> Result<Self, CoreError> {
        let mut connection = connect_tree(config, ipc_share).await?;
        let mut request = CreateRequest::from_path(pipe_name);
        request.desired_access = FILE_READ_DATA
            | FILE_WRITE_DATA
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL
            | SYNCHRONIZE;
        request.create_disposition = CreateDisposition::Open;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        let response = connection.create(&request).await?;
        let fragment_size = connection
            .state()
            .negotiated
            .max_transact_size
            .min(connection.state().negotiated.max_read_size)
            .min(connection.state().negotiated.max_write_size)
            .max(1024);

        Ok(Self {
            connection,
            file_id: response.file_id,
            fragment_size,
        })
    }

    async fn call(&mut self, request: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        self.write_all(&request).await?;
        self.read_one_pdu().await
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let chunk_end = (offset + self.fragment_size as usize).min(bytes.len());
            let request = WriteRequest::for_file(self.file_id, 0, bytes[offset..chunk_end].to_vec());
            let response = self.connection.write(&request).await?;
            if response.count == 0 {
                return Err(CoreError::InvalidResponse("named pipe write returned zero bytes"));
            }
            offset = chunk_end;
        }
        let _ = self
            .connection
            .flush(&FlushRequest::for_file(self.file_id))
            .await;
        Ok(())
    }

    async fn read_one_pdu(&mut self) -> Result<Vec<u8>, CoreError> {
        let mut buffer = Vec::new();
        let expected_len = loop {
            let response = self
                .connection
                .read(&ReadRequest::for_file(self.file_id, 0, self.fragment_size))
                .await?;
            if response.data.is_empty() {
                return Err(CoreError::InvalidResponse("named pipe read returned no data"));
            }
            buffer.extend_from_slice(&response.data);
            if buffer.len() >= 10 {
                let frag_len = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
                break frag_len;
            }
        };

        while buffer.len() < expected_len {
            let response = self
                .connection
                .read(&ReadRequest::for_file(self.file_id, 0, self.fragment_size))
                .await?;
            if response.data.is_empty() {
                return Err(CoreError::InvalidResponse(
                    "named pipe response ended before rpc fragment was complete",
                ));
            }
            buffer.extend_from_slice(&response.data);
        }
        buffer.truncate(expected_len);
        Ok(buffer)
    }
}

struct AdminShare {
    connection: Connection<TokioTcpTransport, TreeConnected>,
    max_read_size: u32,
    max_write_size: u32,
}

impl AdminShare {
    async fn connect(config: &SessionConfig, share: &str) -> Result<Self, CoreError> {
        let connection = connect_tree(config, share).await?;
        let max_read_size = connection.state().negotiated.max_read_size.max(1);
        let max_write_size = connection.state().negotiated.max_write_size.max(1);
        Ok(Self {
            connection,
            max_read_size,
            max_write_size,
        })
    }

    async fn read_if_exists(&mut self, path: &str) -> Result<Option<Vec<u8>>, CoreError> {
        let file_id = match self.open_file(path, FILE_READ_DATA | FILE_READ_ATTRIBUTES).await {
            Ok(file_id) => file_id,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };

        let mut offset = 0_u64;
        let mut output = Vec::new();
        let read_result = async {
            loop {
                let response = self
                    .connection
                    .read(&ReadRequest::for_file(file_id, offset, self.max_read_size))
                    .await?;
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
                let request =
                    WriteRequest::for_file(file_id, offset, data[offset as usize..chunk_end].to_vec());
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
        self.connection.create(&request).await.map(|response| response.file_id)
    }

    async fn create_file(&mut self, path: &str, desired_access: u32) -> Result<FileId, CoreError> {
        let normalized = normalize_share_path(path)?;
        let mut request = CreateRequest::from_path(&normalized);
        request.desired_access = desired_access | READ_CONTROL | SYNCHRONIZE;
        request.create_disposition = CreateDisposition::OverwriteIf;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        self.connection.create(&request).await.map(|response| response.file_id)
    }

    async fn close(&mut self, file_id: FileId) -> Result<(), CoreError> {
        let _ = self
            .connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(())
    }
}

async fn connect_tree(
    config: &SessionConfig,
    share: &str,
) -> Result<Connection<TokioTcpTransport, TreeConnected>, CoreError> {
    let mut auth = NtlmAuthenticator::new(config.credentials.clone());
    let transport = TokioTcpTransport::connect((config.server.as_str(), config.port)).await?;
    let request = NegotiateRequest {
        security_mode: config.signing_mode,
        capabilities: config.capabilities,
        client_guid: config.client_guid,
        negotiate_contexts: default_negotiate_contexts(&config.dialects),
        dialects: config.dialects.clone(),
    };
    let connection = Connection::new(transport).negotiate(&request).await?;
    let connection = connection.authenticate(&mut auth).await?;
    let unc = format!(r"\\{}\{}", config.server, normalize_share_name(share)?);
    connection.tree_connect(&TreeConnectRequest::from_unc(&unc)).await
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

fn default_negotiate_contexts(dialects: &[Dialect]) -> Vec<NegotiateContext> {
    if !dialects.contains(&Dialect::Smb311) {
        return Vec::new();
    }

    vec![NegotiateContext::preauth_integrity(
        PreauthIntegrityCapabilities {
            hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
            salt: random::<[u8; 32]>().to_vec(),
        },
    )]
}

fn build_smbexec_service_command(
    request: &ExecRequest,
    stdout_absolute: &str,
    exit_absolute: &str,
) -> String {
    let command = request_command_fragment(request);
    format!(
        r#"%COMSPEC% /Q /V:ON /c "({command}) > "{stdout_absolute}" 2>&1 & echo !ERRORLEVEL! > "{exit_absolute}"""#
    )
}

fn build_psexec_service_command(
    script_absolute: &str,
    stdout_absolute: &str,
    stderr_absolute: &str,
    exit_absolute: &str,
) -> String {
    format!(
        r#"%COMSPEC% /Q /V:ON /c ""{script_absolute}" 1> "{stdout_absolute}" 2> "{stderr_absolute}" & echo !ERRORLEVEL! > "{exit_absolute}"""#
    )
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

fn request_command_fragment(request: &ExecRequest) -> String {
    match &request.working_directory {
        Some(working_directory) => {
            format!(r#"cd /d "{working_directory}" && {}"#, request.command)
        }
        None => request.command.clone(),
    }
}

fn parse_open_handle_response(response: &[u8], operation: &'static str) -> Result<ScHandle, CoreError> {
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
    let mut handle = [0_u8; 20];
    handle.copy_from_slice(&response[..20]);
    let referent = u32::from_le_bytes(response[20..24].try_into().expect("referent slice"));
    let status_offset = if referent == 0 { 24 } else { 28 };
    if response.len() < status_offset + 4 {
        return Err(CoreError::InvalidResponse(
            "scmr create-service status field was truncated",
        ));
    }
    let status = u32::from_le_bytes(
        response[status_offset..status_offset + 4]
            .try_into()
            .expect("status slice"),
    );
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

fn parse_u32_status(response: &[u8], operation: &'static str) -> Result<u32, CoreError> {
    if response.len() < 4 {
        return Err(CoreError::InvalidResponse("scmr status response was too short"));
    }
    let status = u32::from_le_bytes(response[..4].try_into().expect("status slice"));
    if status == 0 {
        return Ok(status);
    }
    Err(CoreError::RemoteOperation { operation, code: status })
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

    fn write_non_null_pointer(&mut self) {
        self.align(4);
        let referent = self.next_referent();
        self.bytes.extend_from_slice(&referent.to_le_bytes());
    }

    fn write_unique_wide_string(&mut self, value: Option<&str>) {
        self.align(4);
        match value {
            Some(value) => {
                let referent = self.next_referent();
                self.bytes.extend_from_slice(&referent.to_le_bytes());
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
            None => self.bytes.extend_from_slice(&0_u32.to_le_bytes()),
        }
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
    use super::{
        build_psexec_script, build_psexec_service_command, build_smbexec_service_command,
        parse_create_service_response, parse_exit_code, parse_open_handle_response, CommandPaths,
        ExecMode, ExecRequest,
    };

    #[test]
    fn smbexec_command_redirects_output_and_exit_code() {
        let request = ExecRequest::command("whoami").with_working_directory(r"C:\");
        let command = build_smbexec_service_command(
            &request,
            r"C:\Windows\Temp\out.txt",
            r"C:\Windows\Temp\exit.txt",
        );
        assert!(command.contains(r#"cd /d "C:\" && whoami"#));
        assert!(command.contains(r#"> "C:\Windows\Temp\out.txt" 2>&1"#));
        assert!(command.contains(r#"echo !ERRORLEVEL! > "C:\Windows\Temp\exit.txt""#));
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
    fn psexec_command_redirects_stdout_and_stderr_separately() {
        let command = build_psexec_service_command(
            r"C:\Windows\Temp\runner.cmd",
            r"C:\Windows\Temp\stdout.txt",
            r"C:\Windows\Temp\stderr.txt",
            r"C:\Windows\Temp\exit.txt",
        );
        assert!(command.contains(r#""C:\Windows\Temp\runner.cmd" 1> "C:\Windows\Temp\stdout.txt""#));
        assert!(command.contains(r#"2> "C:\Windows\Temp\stderr.txt""#));
        assert!(command.contains(r#"echo !ERRORLEVEL! > "C:\Windows\Temp\exit.txt""#));
    }

    #[test]
    fn parses_open_handle_response() {
        let mut response = vec![0x11; 20];
        response.extend_from_slice(&0_u32.to_le_bytes());
        let handle =
            parse_open_handle_response(&response, "open_sc_manager").expect("response should parse");
        assert_eq!(handle.0, [0x11; 20]);
    }

    #[test]
    fn parses_create_service_response_with_tag_pointer() {
        let mut response = vec![0x22; 20];
        response.extend_from_slice(&1_u32.to_le_bytes());
        response.extend_from_slice(&9_u32.to_le_bytes());
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
        let paths = CommandPaths::new("Temp");
        assert!(paths.service_name.starts_with("SMOLDER"));
        assert!(paths.stdout_relative.starts_with(r"Temp\SMOLDER-"));
        assert!(matches!(ExecMode::SmbExec, ExecMode::SmbExec));
    }
}
