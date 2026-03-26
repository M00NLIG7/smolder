use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::error::CoreError;
use smolder_tools::prelude::{NtlmCredentials, Share, SmbClient};
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct WindowsEncryptionConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    share: String,
    test_dir: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsEncryptionConfig {
    fn base_from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            share: String::new(),
            test_dir: required_env("SMOLDER_WINDOWS_ENCRYPTED_TEST_DIR").unwrap_or_default(),
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    fn from_env() -> Option<Self> {
        let mut config = Self::base_from_env()?;
        config.share = required_env("SMOLDER_WINDOWS_ENCRYPTED_SHARE")?;
        Some(config)
    }

    fn admin_share_probe_from_env() -> Option<Self> {
        let mut config = Self::base_from_env()?;
        config.share = "ADMIN$".to_string();
        config.test_dir.clear();
        Some(config)
    }
}

fn windows_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn unique_path(prefix: &str, test_dir: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let file_name = format!("{prefix}-{}-{stamp}.txt", std::process::id());
    if test_dir.trim_matches(['\\', '/']).is_empty() {
        file_name
    } else {
        format!("{}\\{file_name}", test_dir.trim_matches(['\\', '/']))
    }
}

async fn connect_share(
    config: &WindowsEncryptionConfig,
    require_encryption: bool,
) -> Result<Share, CoreError> {
    let mut credentials = NtlmCredentials::new(config.username.clone(), config.password.clone());
    if let Some(domain) = &config.domain {
        credentials = credentials.with_domain(domain.clone());
    }
    if let Some(workstation) = &config.workstation {
        credentials = credentials.with_workstation(workstation.clone());
    }

    let mut builder = SmbClient::builder()
        .server(config.host.clone())
        .port(config.port)
        .credentials(credentials);
    if require_encryption {
        builder = builder.require_encryption(true);
    }

    let client = builder.connect().await?;
    client.share(config.share.clone()).await
}

async fn connected_share() -> Option<(WindowsEncryptionConfig, Share)> {
    let Some(config) = WindowsEncryptionConfig::from_env() else {
        eprintln!(
            "skipping encrypted Windows test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, SMOLDER_WINDOWS_PASSWORD, and SMOLDER_WINDOWS_ENCRYPTED_SHARE must be set"
        );
        return None;
    };
    let share = connect_share(&config, true)
        .await
        .expect("should connect encrypted Windows share");

    Some((config, share))
}

#[tokio::test]
async fn writes_and_reads_with_required_encryption_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_path("smolder-win-encrypted", &config.test_dir);
    let payload = b"smolder windows encrypted io";

    share
        .write(&remote_path, payload)
        .await
        .expect("encrypted Windows write should succeed");
    let round_trip = share
        .read(&remote_path)
        .await
        .expect("encrypted Windows read should succeed");
    share
        .remove(&remote_path)
        .await
        .expect("encrypted Windows remove should succeed");

    assert_eq!(round_trip, payload);
}

#[tokio::test]
async fn require_encryption_rejects_admin_share_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = WindowsEncryptionConfig::admin_share_probe_from_env() else {
        eprintln!(
            "skipping Windows encryption enforcement test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return;
    };

    let admin_share = connect_share(&config, false)
        .await
        .expect("ADMIN$ should allow a baseline connection probe");
    if admin_share.encryption_required() {
        eprintln!(
            "skipping Windows encryption enforcement test: ADMIN$ already requires encryption on this fixture"
        );
        return;
    }

    let error = connect_share(&config, true)
        .await
        .expect_err("ADMIN$ should be rejected when encryption is required");
    assert!(
        matches!(
            error,
            CoreError::Unsupported(
                "SMB encryption was required but the connected share did not require encryption"
            )
        ),
        "unexpected error: {error:?}"
    );
}
