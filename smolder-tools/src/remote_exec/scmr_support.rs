use std::time::Duration;

use tokio::time::{Instant, sleep};

use smolder_core::error::CoreError;
use smolder_core::pipe::{NamedPipe, PipeAccess, SmbSessionConfig};
use smolder_core::rpc::PipeRpcClient;

use super::{
    ERROR_SERVICE_REQUEST_TIMEOUT, PIPE_CONNECT_RETRY_INTERVAL, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_DEMAND_START, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS, SVCCTL_CONNECT_TIMEOUT, SVCCTL_CONTEXT_ID, SVCCTL_SYNTAX,
    is_pipe_not_ready,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScHandle(pub(super) [u8; 20]);

pub(super) struct ScmClient {
    rpc: PipeRpcClient,
}

impl ScmClient {
    pub(super) async fn connect(
        config: &SmbSessionConfig,
        ipc_share: &str,
    ) -> Result<Self, CoreError> {
        let pipe = connect_pipe_with_retry(
            config,
            ipc_share,
            "svcctl",
            PipeAccess::ReadWrite,
            SVCCTL_CONNECT_TIMEOUT,
        )
        .await?;
        let mut rpc = PipeRpcClient::new(pipe);
        // `svcctl` over `ncacn_np` already rides an authenticated SMB session.
        // Forcing WinNT secure bind here reproduces Windows `rpc_s_cannot_support (0x6e4)`,
        // and Impacket's working service-control paths use a plain bind on this transport.
        rpc.bind_context(SVCCTL_CONTEXT_ID, SVCCTL_SYNTAX).await?;
        Ok(Self { rpc })
    }

    pub(super) async fn open_sc_manager(&mut self) -> Result<ScHandle, CoreError> {
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

    pub(super) async fn create_service(
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

    pub(super) async fn start_service(
        &mut self,
        service_handle: &ScHandle,
    ) -> Result<(), CoreError> {
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

    pub(super) async fn delete_service(
        &mut self,
        service_handle: &ScHandle,
    ) -> Result<(), CoreError> {
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

    pub(super) async fn wait_for_service_stop(
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

    pub(super) async fn query_service_status(
        &mut self,
        service_handle: &ScHandle,
    ) -> Result<u32, CoreError> {
        let mut stub = NdrWriter::new();
        stub.write_context_handle(service_handle);
        let response = self
            .rpc
            .call(SVCCTL_CONTEXT_ID, 6, stub.into_bytes())
            .await?;
        parse_query_service_status_response(&response)
    }

    pub(super) async fn close_handle(&mut self, handle: &ScHandle) -> Result<(), CoreError> {
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

pub(super) async fn connect_pipe_with_retry(
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

pub(super) fn parse_open_handle_response(
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

pub(super) fn parse_create_service_response(response: &[u8]) -> Result<ScHandle, CoreError> {
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
