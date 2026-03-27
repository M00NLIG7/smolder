use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::dfs::UncPath;
use smolder_tools::prelude::{NtlmCredentials, SmbClient};
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct WindowsDfsConfig {
    port: u16,
    username: String,
    password: String,
    dfs_root: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsDfsConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            dfs_root: required_env("SMOLDER_WINDOWS_DFS_ROOT")?,
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    fn credentials(&self) -> NtlmCredentials {
        let mut credentials = NtlmCredentials::new(self.username.clone(), self.password.clone());
        if let Some(domain) = &self.domain {
            credentials = credentials.with_domain(domain.clone());
        }
        if let Some(workstation) = &self.workstation {
            credentials = credentials.with_workstation(workstation.clone());
        }
        credentials
    }

    fn dfs_root_path(&self) -> Option<UncPath> {
        match UncPath::parse(&self.dfs_root) {
            Ok(root) => Some(root),
            Err(error) => {
                eprintln!("skipping Windows DFS test: invalid SMOLDER_WINDOWS_DFS_ROOT: {error}");
                None
            }
        }
    }
}

fn dfs_lock() -> &'static Mutex<()> {
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

fn join_unc(root: &str, leaf: &str) -> String {
    let root = root.trim_end_matches(['\\', '/']);
    let leaf = leaf.trim_matches(['\\', '/']).replace('/', r"\");
    format!(r"{root}\{leaf}")
}

fn smb_url_from_dfs_root(config: &WindowsDfsConfig, root: &UncPath, leaf: &str) -> String {
    let mut segments = root.path().to_vec();
    segments.extend(
        leaf.split(['\\', '/'])
            .filter(|segment| !segment.is_empty())
            .map(ToString::to_string),
    );
    if segments.is_empty() {
        format!("smb://{}:{}/{}", root.server(), config.port, root.share())
    } else {
        format!(
            "smb://{}:{}/{}/{}",
            root.server(),
            config.port,
            root.share(),
            segments.join("/")
        )
    }
}

fn configure_auth(command: &mut Command, config: &WindowsDfsConfig) {
    command.arg("--username").arg(&config.username);
    command.arg("--password").arg(&config.password);
    if let Some(domain) = &config.domain {
        command.arg("--domain").arg(domain);
    }
    if let Some(workstation) = &config.workstation {
        command.arg("--workstation").arg(workstation);
    }
}

fn connected_builder() -> Option<(WindowsDfsConfig, UncPath, smolder_tools::prelude::SmbClientBuilder)> {
    let Some(config) = WindowsDfsConfig::from_env() else {
        eprintln!(
            "skipping Windows DFS test: SMOLDER_WINDOWS_USERNAME, SMOLDER_WINDOWS_PASSWORD, and SMOLDER_WINDOWS_DFS_ROOT must be set"
        );
        return None;
    };
    let Some(root) = config.dfs_root_path() else {
        return None;
    };

    let builder = SmbClient::builder()
        .server(root.server())
        .port(config.port)
        .credentials(config.credentials());
    Some((config, root, builder))
}

#[tokio::test]
async fn share_path_auto_reads_and_writes_through_live_windows_dfs_when_configured() {
    let _guard = dfs_lock().lock().await;
    let Some((config, _root, builder)) = connected_builder() else {
        return;
    };

    let remote_unc = join_unc(&config.dfs_root, &unique_name("smolder-win-dfs-read"));
    let payload = b"smolder windows dfs payload";

    let (mut share, relative_path) = builder
        .connect_share_path(&remote_unc)
        .await
        .expect("Windows DFS namespace should resolve to a writable share");

    share
        .write(&relative_path, payload)
        .await
        .expect("Windows DFS path should accept writes");
    let metadata = share
        .stat(&relative_path)
        .await
        .expect("Windows DFS path should stat after write");
    let round_trip = share
        .read(&relative_path)
        .await
        .expect("Windows DFS path should read after write");
    share
        .remove(&relative_path)
        .await
        .expect("Windows DFS path should remove test file");

    assert_eq!(round_trip, payload);
    assert_eq!(metadata.size, payload.len() as u64);
}

#[tokio::test]
async fn cli_mv_renames_through_live_windows_dfs_when_configured() {
    let _guard = dfs_lock().lock().await;
    let Some((config, root, builder)) = connected_builder() else {
        return;
    };

    let source_leaf = unique_name("smolder-win-dfs-mv-old");
    let destination_leaf = unique_name("smolder-win-dfs-mv-new");
    let source_unc = join_unc(&config.dfs_root, &source_leaf);
    let destination_unc = join_unc(&config.dfs_root, &destination_leaf);
    let payload = b"smolder windows dfs mv payload";

    let (mut share, source_path) = builder
        .clone()
        .connect_share_path(&source_unc)
        .await
        .expect("Windows DFS source path should resolve");
    share
        .write(&source_path, payload)
        .await
        .expect("Windows DFS source path should accept writes");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder-mv"));
    command
        .arg(smb_url_from_dfs_root(&config, &root, &source_leaf))
        .arg(smb_url_from_dfs_root(&config, &root, &destination_leaf));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run for Windows DFS mv");
    assert!(
        output.status.success(),
        "mv stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let (mut share, destination_path) = builder
        .connect_share_path(&destination_unc)
        .await
        .expect("Windows DFS destination path should resolve");
    let round_trip = share
        .read(&destination_path)
        .await
        .expect("Windows DFS destination path should exist after CLI mv");
    let _ = share.remove(&destination_path).await;

    assert_eq!(round_trip, payload);
}
