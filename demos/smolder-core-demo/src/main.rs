use smolder_core::prelude::{connect_tree, NtlmCredentials, SmbSessionConfig};
use smolder_proto::smb::smb2::{
    CloseRequest, CreateOptions, CreateRequest, FlushRequest, ReadRequest, ShareAccess,
    WriteRequest,
};

const DEFAULT_PORT: u16 = 445;
const DEFAULT_SHARE: &str = "share";
const DEFAULT_PATH: &str = "smolder-demo.txt";
const EXAMPLE_CONTENT: &[u8] = b"hello from smolder-core-demo\n";

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program}\n\nRequired environment:\n  SMOLDER_EXAMPLE_HOST\n  SMOLDER_EXAMPLE_USERNAME\n  SMOLDER_EXAMPLE_PASSWORD\n\nOptional environment:\n  SMOLDER_EXAMPLE_PORT (default: 445)\n  SMOLDER_EXAMPLE_SHARE (default: share)\n  SMOLDER_EXAMPLE_PATH (default: smolder-demo.txt)\n  SMOLDER_EXAMPLE_DOMAIN\n  SMOLDER_EXAMPLE_WORKSTATION"
    )
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing required environment variable {name}"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "smolder-core-demo".to_owned());
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage(&program));
        return Ok(());
    }

    let host = required_env("SMOLDER_EXAMPLE_HOST")
        .map_err(|error| format!("{error}\n\n{}", usage(&program)))?;
    let port = optional_env("SMOLDER_EXAMPLE_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let share = optional_env("SMOLDER_EXAMPLE_SHARE").unwrap_or_else(|| DEFAULT_SHARE.to_owned());
    let path = optional_env("SMOLDER_EXAMPLE_PATH").unwrap_or_else(|| DEFAULT_PATH.to_owned());

    let mut credentials = NtlmCredentials::new(
        required_env("SMOLDER_EXAMPLE_USERNAME")?,
        required_env("SMOLDER_EXAMPLE_PASSWORD")?,
    );
    if let Some(domain) = optional_env("SMOLDER_EXAMPLE_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_EXAMPLE_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

    let config = SmbSessionConfig::new(host, credentials).with_port(port);
    let mut connection = connect_tree(&config, &share).await?;

    let mut create = CreateRequest::from_path(&path);
    create.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create.share_access |= ShareAccess::DELETE;
    let opened = connection.create(&create).await?;
    let file_id = opened.file_id;

    connection
        .write(&WriteRequest::for_file(
            file_id,
            0,
            EXAMPLE_CONTENT.to_vec(),
        ))
        .await?;
    connection.flush(&FlushRequest::for_file(file_id)).await?;

    let read = connection
        .read(&ReadRequest::for_file(
            file_id,
            0,
            EXAMPLE_CONTENT.len() as u32,
        ))
        .await?;
    if read.data != EXAMPLE_CONTENT {
        return Err(format!("roundtrip mismatch for {}", path).into());
    }

    connection
        .close(&CloseRequest { flags: 0, file_id })
        .await?;

    println!(
        "smolder-core-demo succeeded: share={} path={} bytes={}",
        share,
        path,
        read.data.len()
    );

    let connection = connection.tree_disconnect().await?;
    let _ = connection.logoff().await?;
    Ok(())
}
