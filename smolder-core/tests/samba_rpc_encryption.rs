use std::sync::OnceLock;

use smolder_core::prelude::{
    connect_tree, NamedPipe, NtlmCredentials, PipeAccess, PipeRpcClient, SmbSessionConfig,
};
use smolder_proto::rpc::{SyntaxId, Uuid};
use smolder_proto::smb::smb2::{SessionId, TreeId};
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaRpcEncryptionConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaRpcEncryptionConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: required_env("SMOLDER_SAMBA_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            domain: required_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: required_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }
}

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

const SRVSVC_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x4b32_4fc8,
        0x1670,
        0x01d3,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    ),
    3,
    0,
);

#[tokio::test]
async fn binds_srvsvc_over_encrypted_ipc_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = SambaRpcEncryptionConfig::from_env() else {
        eprintln!(
            "skipping live Samba RPC encryption test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, and SMOLDER_SAMBA_PASSWORD must be set"
        );
        return;
    };

    let mut credentials = NtlmCredentials::new(config.username, config.password);
    if let Some(domain) = config.domain {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = config.workstation {
        credentials = credentials.with_workstation(workstation);
    }

    let session = SmbSessionConfig::new(config.host, credentials).with_port(config.port);
    let connection = connect_tree(&session, "IPC$")
        .await
        .expect("should connect to encrypted IPC$ tree");

    assert!(
        connection.state().encryption_required,
        "globally encrypted Samba fixture should require encryption on IPC$"
    );
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));

    let pipe = NamedPipe::open(connection, "srvsvc", PipeAccess::ReadWrite)
        .await
        .expect("should open srvsvc named pipe");
    let mut rpc = PipeRpcClient::new(pipe);
    let bind_ack = rpc
        .bind_context(0, SRVSVC_SYNTAX)
        .await
        .expect("srvsvc bind should succeed over encrypted IPC$");

    assert_eq!(bind_ack.result.result, 0);
    assert_eq!(bind_ack.result.reason, 0);

    let connection = rpc
        .into_pipe()
        .close()
        .await
        .expect("pipe close should return the encrypted tree connection");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    connection.logoff().await.expect("logoff should succeed");
}
