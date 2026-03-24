use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::prelude::{NtlmCredentials, SmbClient, Share};
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct SambaConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    share: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: required_env("SMOLDER_SAMBA_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            share: required_env("SMOLDER_SAMBA_SHARE")?,
            domain: required_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: required_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }
}

async fn connected_share() -> Option<(SambaConfig, Share)> {
    let Some(config) = SambaConfig::from_env() else {
        eprintln!(
            "skipping high-level Samba test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return None;
    };

    let mut credentials = NtlmCredentials::new(config.username.clone(), config.password.clone());
    if let Some(domain) = &config.domain {
        credentials = credentials.with_domain(domain.clone());
    }
    if let Some(workstation) = &config.workstation {
        credentials = credentials.with_workstation(workstation.clone());
    }

    let client = SmbClient::builder()
        .server(config.host.clone())
        .port(config.port)
        .credentials(credentials)
        .connect()
        .await
        .expect("should connect high-level SMB client");
    let share = client
        .share(config.share.clone())
        .await
        .expect("should connect high-level share");

    Some((config, share))
}

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn unique_name(prefix: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!("{prefix}-{}-{stamp}.txt", std::process::id())
}

fn temp_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(unique_name(prefix))
}

#[tokio::test]
async fn writes_and_reads_with_high_level_api_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-read");
    let payload = b"smolder high level io";

    share
        .write(&remote_path, payload)
        .await
        .expect("high-level write should succeed");
    let round_trip = share
        .read(&remote_path)
        .await
        .expect("high-level read should succeed");

    assert_eq!(round_trip, payload);
}

#[tokio::test]
async fn puts_and_gets_local_files_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-put");
    let local_upload = temp_path("smolder-upload");
    let local_download = temp_path("smolder-download");
    let payload = b"smolder high level transfer".to_vec();

    fs::write(&local_upload, &payload).expect("should create upload fixture");

    let uploaded = share
        .put(&local_upload, &remote_path)
        .await
        .expect("high-level put should succeed");
    let downloaded = share
        .get(&remote_path, &local_download)
        .await
        .expect("high-level get should succeed");
    let local_copy = fs::read(&local_download).expect("should read downloaded file");

    assert_eq!(uploaded, payload.len() as u64);
    assert_eq!(downloaded, payload.len() as u64);
    assert_eq!(local_copy, payload);

    let _ = fs::remove_file(local_upload);
    let _ = fs::remove_file(local_download);
}
