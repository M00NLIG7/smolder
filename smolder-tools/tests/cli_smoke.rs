use std::fs;
use std::path::PathBuf;
use std::process::Command;
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
            "skipping CLI Samba test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
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

fn smb_url(config: &SambaConfig, remote_path: &str) -> String {
    format!(
        "smb://{}:{}/{}/{}",
        config.host, config.port, config.share, remote_path
    )
}

fn configure_auth(command: &mut Command, config: &SambaConfig) {
    command.env("SMOLDER_SAMBA_USERNAME", &config.username);
    command.env("SMOLDER_SAMBA_PASSWORD", &config.password);
    if let Some(domain) = &config.domain {
        command.env("SMOLDER_SAMBA_DOMAIN", domain);
    }
    if let Some(workstation) = &config.workstation {
        command.env("SMOLDER_SAMBA_WORKSTATION", workstation);
    }
}

#[tokio::test]
async fn cat_command_streams_file_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-cli-cat");
    let payload = b"smolder cli cat payload";
    share
        .write(&remote_path, payload)
        .await
        .expect("should seed remote file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder"));
    command.arg("cat").arg(smb_url(&config, &remote_path));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "cat stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload);
}

#[tokio::test]
async fn put_command_uploads_file_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-cli-put");
    let local_path = temp_path("smolder-cli-put-local");
    let payload = b"smolder cli put payload".to_vec();
    fs::write(&local_path, &payload).expect("should create upload fixture");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder"));
    command
        .arg("put")
        .arg(&local_path)
        .arg(smb_url(&config, &remote_path));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "put stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let round_trip = share
        .read(&remote_path)
        .await
        .expect("remote file should exist after put");
    assert_eq!(round_trip, payload);

    let _ = fs::remove_file(local_path);
}

#[tokio::test]
async fn get_command_downloads_file_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-cli-get");
    let local_path = temp_path("smolder-cli-get-local");
    let payload = b"smolder cli get payload";
    share
        .write(&remote_path, payload)
        .await
        .expect("should seed remote file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder"));
    command
        .arg("get")
        .arg(smb_url(&config, &remote_path))
        .arg(&local_path);
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "get stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let downloaded = fs::read(&local_path).expect("should read downloaded file");
    assert_eq!(downloaded, payload);

    let _ = fs::remove_file(local_path);
}
