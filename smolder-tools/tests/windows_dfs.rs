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
    host: String,
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
            host: required_env("SMOLDER_WINDOWS_HOST")?,
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
            Ok(root) if root.server().eq_ignore_ascii_case(&self.host) => Some(root),
            Ok(_) => {
                eprintln!(
                    "skipping Windows DFS test: SMOLDER_WINDOWS_DFS_ROOT must use the same host as SMOLDER_WINDOWS_HOST for same-server DFS coverage"
                );
                None
            }
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
        format!("smb://{}:{}/{}", config.host, config.port, root.share())
    } else {
        format!(
            "smb://{}:{}/{}/{}",
            config.host,
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

async fn connected_client() -> Option<(WindowsDfsConfig, UncPath, SmbClient)> {
    let Some(config) = WindowsDfsConfig::from_env() else {
        eprintln!(
            "skipping Windows DFS test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, SMOLDER_WINDOWS_PASSWORD, and SMOLDER_WINDOWS_DFS_ROOT must be set"
        );
        return None;
    };
    let Some(root) = config.dfs_root_path() else {
        return None;
    };

    let client = SmbClient::builder()
        .server(config.host.clone())
        .port(config.port)
        .credentials(config.credentials())
        .connect()
        .await
        .expect("should connect authenticated SMB client for Windows DFS test");
    Some((config, root, client))
}

#[tokio::test]
async fn share_path_auto_reads_and_writes_through_live_windows_dfs_when_configured() {
    let _guard = dfs_lock().lock().await;
    let Some((config, _root, client)) = connected_client().await else {
        return;
    };

    let remote_unc = join_unc(&config.dfs_root, &unique_name("smolder-win-dfs-read"));
    let payload = b"smolder windows dfs payload";

    let (mut share, relative_path) = client
        .share_path_auto(&remote_unc)
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
    let Some((config, root, client)) = connected_client().await else {
        return;
    };

    let source_leaf = unique_name("smolder-win-dfs-mv-old");
    let destination_leaf = unique_name("smolder-win-dfs-mv-new");
    let source_unc = join_unc(&config.dfs_root, &source_leaf);
    let destination_unc = join_unc(&config.dfs_root, &destination_leaf);
    let payload = b"smolder windows dfs mv payload";

    let (mut share, source_path) = client
        .share_path_auto(&source_unc)
        .await
        .expect("Windows DFS source path should resolve");
    share
        .write(&source_path, payload)
        .await
        .expect("Windows DFS source path should accept writes");

    let mut command = Command::new(env!("CARGO_BIN_EXE_smolder"));
    command
        .arg("mv")
        .arg(smb_url_from_dfs_root(&config, &root, &source_leaf))
        .arg(smb_url_from_dfs_root(&config, &root, &destination_leaf));
    configure_auth(&mut command, &config);

    let output = command.output().expect("CLI should run for Windows DFS mv");
    assert!(
        output.status.success(),
        "mv stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let client = SmbClient::builder()
        .server(config.host.clone())
        .port(config.port)
        .credentials(config.credentials())
        .connect()
        .await
        .expect("should reconnect SMB client for Windows DFS verification");
    let (mut share, destination_path) = client
        .share_path_auto(&destination_unc)
        .await
        .expect("Windows DFS destination path should resolve");
    let round_trip = share
        .read(&destination_path)
        .await
        .expect("Windows DFS destination path should exist after CLI mv");
    let _ = share.remove(&destination_path).await;

    assert_eq!(round_trip, payload);
}
