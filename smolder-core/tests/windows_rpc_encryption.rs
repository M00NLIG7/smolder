use std::sync::OnceLock;

use smolder_core::prelude::{
    connect_tree, CoreError, NamedPipe, NtlmCredentials, PipeAccess, PipeRpcClient,
    SmbSessionConfig,
};
use smolder_proto::rpc::{SyntaxId, Uuid};
use smolder_proto::smb::smb2::{SessionId, TreeId};
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct WindowsRpcEncryptionConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsRpcEncryptionConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    fn session(&self) -> SmbSessionConfig {
        let mut credentials = NtlmCredentials::new(self.username.clone(), self.password.clone());
        if let Some(domain) = &self.domain {
            credentials = credentials.with_domain(domain.clone());
        }
        if let Some(workstation) = &self.workstation {
            credentials = credentials.with_workstation(workstation.clone());
        }
        SmbSessionConfig::new(self.host.clone(), credentials).with_port(self.port)
    }
}

fn windows_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

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
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_CONNECT: u32 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScHandle([u8; 20]);

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

fn open_sc_manager_stub() -> Vec<u8> {
    let mut stub = NdrWriter::new();
    stub.write_unique_wide_string(None);
    stub.write_unique_wide_string(Some("ServicesActive"));
    stub.write_u32(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    stub.into_bytes()
}

fn parse_open_handle_response(response: &[u8]) -> Result<ScHandle, CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "scmr open-handle response was too short",
        ));
    }
    let mut handle = [0_u8; 20];
    handle.copy_from_slice(&response[..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "open_sc_manager",
            code: status,
        });
    }
    Ok(ScHandle(handle))
}

#[tokio::test]
async fn opens_sc_manager_over_encrypted_windows_ipc_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = WindowsRpcEncryptionConfig::from_env() else {
        eprintln!(
            "skipping live Windows encrypted IPC test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return;
    };

    let connection = connect_tree(&config.session(), "IPC$")
        .await
        .expect("should connect to Windows IPC$");
    assert!(
        connection.state().encryption_required,
        "Windows IPC$ should require encryption for the encrypted fixture"
    );
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));

    let pipe = NamedPipe::open(connection, "svcctl", PipeAccess::ReadWrite)
        .await
        .expect("should open svcctl named pipe");
    let mut rpc = PipeRpcClient::new(pipe);
    let bind_ack = rpc
        .bind_context(SVCCTL_CONTEXT_ID, SVCCTL_SYNTAX)
        .await
        .expect("svcctl bind should succeed over encrypted IPC$");
    assert_eq!(bind_ack.result.result, 0);
    assert_eq!(bind_ack.result.reason, 0);

    let response = rpc
        .call(SVCCTL_CONTEXT_ID, 15, open_sc_manager_stub())
        .await
        .expect("OpenSCManagerW should succeed over encrypted IPC$");
    let handle = parse_open_handle_response(&response)
        .expect("OpenSCManagerW response should contain a valid SCM handle");
    assert!(handle.0.iter().any(|byte| *byte != 0));

    let connection = rpc
        .into_pipe()
        .close()
        .await
        .expect("pipe close should return the encrypted IPC$ tree");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    connection.logoff().await.expect("logoff should succeed");
}
