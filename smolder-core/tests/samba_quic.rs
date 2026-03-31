#![cfg(feature = "quic")]

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::auth::NtlmCredentials;
use smolder_core::facade::Client;
use smolder_core::transport::TransportTarget;
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaQuicConfig {
    server: String,
    connect_host: String,
    tls_server_name: String,
    port: u16,
    username: String,
    password: String,
    share: String,
    test_dir: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaQuicConfig {
    fn from_env() -> Option<Self> {
        let server = required_env("SMOLDER_SAMBA_QUIC_SERVER")?;
        Some(Self {
            connect_host: required_env("SMOLDER_SAMBA_QUIC_CONNECT_HOST")
                .unwrap_or_else(|| server.clone()),
            tls_server_name: required_env("SMOLDER_SAMBA_QUIC_TLS_SERVER_NAME")
                .unwrap_or_else(|| server.clone()),
            port: required_env("SMOLDER_SAMBA_QUIC_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(443),
            username: required_env("SMOLDER_SAMBA_QUIC_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_QUIC_PASSWORD")?,
            share: required_env("SMOLDER_SAMBA_QUIC_SHARE")?,
            test_dir: required_env("SMOLDER_SAMBA_QUIC_TEST_DIR").unwrap_or_default(),
            domain: required_env("SMOLDER_SAMBA_QUIC_DOMAIN"),
            workstation: required_env("SMOLDER_SAMBA_QUIC_WORKSTATION"),
            server,
        })
    }

    fn client(&self) -> Result<Client, smolder_core::error::CoreError> {
        let mut builder = Client::builder(self.server.clone())
            .with_transport_target(TransportTarget::quic(self.server.clone()))
            .with_port(self.port)
            .with_connect_host(self.connect_host.clone())
            .with_tls_server_name(self.tls_server_name.clone());

        let mut credentials = NtlmCredentials::new(self.username.clone(), self.password.clone());
        if let Some(domain) = &self.domain {
            credentials = credentials.with_domain(domain.clone());
        }
        if let Some(workstation) = &self.workstation {
            credentials = credentials.with_workstation(workstation.clone());
        }

        builder = builder.with_ntlm_credentials(credentials);
        builder.build()
    }
}

fn samba_quic_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn unique_test_file_path(test_dir: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let file_name = format!("smolder-samba-quic-{}-{stamp}.txt", std::process::id());
    if test_dir.trim_matches(['\\', '/']).is_empty() {
        file_name
    } else {
        format!("{}\\{file_name}", test_dir.trim_matches(['\\', '/']))
    }
}

#[tokio::test]
async fn authenticates_and_connects_tree_over_quic_when_configured() {
    let _guard = samba_quic_lock().lock().await;
    let Some(config) = SambaQuicConfig::from_env() else {
        eprintln!(
            "skipping Samba SMB over QUIC test: SMOLDER_SAMBA_QUIC_SERVER, SMOLDER_SAMBA_QUIC_USERNAME, SMOLDER_SAMBA_QUIC_PASSWORD, and SMOLDER_SAMBA_QUIC_SHARE must be set"
        );
        return;
    };

    let client = config.client().expect("client builder should accept QUIC config");
    let share = client
        .connect_share_quic(&config.share)
        .await
        .expect("Samba should accept SMB over QUIC tree connect");

    assert_ne!(share.session_id().0, 0, "session id should be assigned");
    assert_ne!(share.tree_id().0, 0, "tree id should be assigned");
    assert!(share.session_key().is_some(), "NTLM should export a session key");

    share.logoff().await.expect("logoff should succeed");
}

#[tokio::test]
async fn roundtrips_file_io_over_quic_when_configured() {
    let _guard = samba_quic_lock().lock().await;
    let Some(config) = SambaQuicConfig::from_env() else {
        eprintln!(
            "skipping Samba SMB over QUIC test: SMOLDER_SAMBA_QUIC_SERVER, SMOLDER_SAMBA_QUIC_USERNAME, SMOLDER_SAMBA_QUIC_PASSWORD, and SMOLDER_SAMBA_QUIC_SHARE must be set"
        );
        return;
    };

    let client = config.client().expect("client builder should accept QUIC config");
    let mut share = client
        .connect_share_quic(&config.share)
        .await
        .expect("Samba should accept SMB over QUIC tree connect");

    let path = unique_test_file_path(&config.test_dir);
    let payload = b"smolder samba quic interop".to_vec();
    share
        .put(&path, &payload)
        .await
        .expect("QUIC path should write the test payload");
    let read_back = share
        .get(&path)
        .await
        .expect("QUIC path should read back the test payload");
    share
        .remove(&path)
        .await
        .expect("QUIC path should remove the test payload");

    assert_eq!(read_back, payload);
    share.logoff().await.expect("logoff should succeed");
}
