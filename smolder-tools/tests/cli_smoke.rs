use std::fs;
use std::process::Command;
use std::sync::OnceLock;

use smolder_tools::prelude::Share;
use tokio::sync::Mutex;

mod common;
use common::{SambaConfig, temp_path, unique_name};

async fn connected_share() -> Option<(SambaConfig, Share)> {
    let Some(config) = SambaConfig::from_env() else {
        eprintln!(
            "skipping CLI Samba test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return None;
    };
    let share = config
        .connect_share(false)
        .await
        .expect("should connect high-level share");

    Some((config, share))
}

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn smb_url(config: &SambaConfig, remote_path: &str) -> String {
    config.smb_url(remote_path)
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

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-cat"));
    command.arg(smb_url(&config, &remote_path));
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

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-put"));
    command.arg(&local_path).arg(smb_url(&config, &remote_path));
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

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-get"));
    command.arg(smb_url(&config, &remote_path)).arg(&local_path);
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

#[tokio::test]
async fn ls_command_lists_entries_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-cli-ls");
    share
        .write(&remote_path, b"smolder cli ls payload")
        .await
        .expect("should seed remote file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-ls"));
    command.arg(smb_url(&config, ""));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "ls stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("ls output should be UTF-8");
    assert!(stdout.lines().any(|line| line == remote_path));
}

#[tokio::test]
async fn stat_command_prints_metadata_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-cli-stat");
    let payload = b"smolder cli stat payload";
    share
        .write(&remote_path, payload)
        .await
        .expect("should seed remote file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-stat"));
    command.arg(smb_url(&config, &remote_path));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "stat stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stat output should be UTF-8");
    assert!(stdout.contains(&format!("Path: {remote_path}")));
    assert!(stdout.contains(&format!("Size: {}", payload.len())));
}

#[tokio::test]
async fn mv_command_renames_files_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let source = unique_name("smolder-cli-mv-old");
    let destination = unique_name("smolder-cli-mv-new");
    let payload = b"smolder cli mv payload";
    share
        .write(&source, payload)
        .await
        .expect("should seed remote file");
    drop(share);

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-mv"));
    command
        .arg(smb_url(&config, &source))
        .arg(smb_url(&config, &destination));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "mv stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let Some((_config, mut share)) = connected_share().await else {
        return;
    };
    let round_trip = share
        .read(&destination)
        .await
        .expect("renamed file should exist");
    assert_eq!(round_trip, payload);
    let listing = share.list("").await.expect("listing should succeed");
    assert!(!listing.iter().any(|entry| entry.name == source));
}

#[tokio::test]
async fn rm_command_deletes_files_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-cli-rm");
    share
        .write(&remote_path, b"smolder cli rm payload")
        .await
        .expect("should seed remote file");
    drop(share);

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-rm"));
    command.arg(smb_url(&config, &remote_path));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run");
    assert!(
        output.status.success(),
        "rm stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let Some((_config, mut share)) = connected_share().await else {
        return;
    };
    let listing = share.list("").await.expect("listing should succeed");
    assert!(!listing.iter().any(|entry| entry.name == remote_path));
}
