use std::sync::OnceLock;

use smolder_core::prelude::{
    connect_tree, NtlmCredentials, PipeAccess, PipeRpcClient, SmbSessionConfig, SrvsvcClient,
};
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

#[tokio::test]
async fn calls_netr_remote_tod_over_encrypted_ipc_when_configured() {
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

    let pipe = smolder_core::prelude::NamedPipe::open(connection, "srvsvc", PipeAccess::ReadWrite)
        .await
        .expect("should open srvsvc named pipe");
    let rpc = PipeRpcClient::new(pipe);
    let mut srvsvc = SrvsvcClient::bind(rpc)
        .await
        .expect("srvsvc bind should succeed over encrypted IPC$");

    let time_of_day = srvsvc
        .remote_tod()
        .await
        .expect("NetrRemoteTOD should succeed over encrypted IPC$");
    assert!(time_of_day.hours < 24);
    assert!(time_of_day.minutes < 60);
    assert!(time_of_day.seconds < 60);
    assert!((1..=31).contains(&time_of_day.day));
    assert!((1..=12).contains(&time_of_day.month));
    assert!(time_of_day.year >= 2020);
    assert!(time_of_day.weekday < 7);

    let shares = srvsvc
        .share_enum_level1()
        .await
        .expect("NetrShareEnum level 1 should succeed over encrypted IPC$");
    assert!(!shares.is_empty(), "srvsvc share enumeration should not be empty");
    assert!(
        shares.iter().any(|share| share.name.eq_ignore_ascii_case("IPC$")),
        "srvsvc share enumeration should include IPC$"
    );

    let connection = srvsvc
        .into_rpc()
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
