//! Minimal high-level file roundtrip example using the core client facade.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --example client_file_roundtrip
//! ```
//!
//! Required environment:
//!
//! - `SMOLDER_EXAMPLE_HOST`
//! - `SMOLDER_EXAMPLE_USERNAME`
//! - `SMOLDER_EXAMPLE_PASSWORD`
//!
//! Optional environment:
//!
//! - `SMOLDER_EXAMPLE_PORT` (defaults to `445`)
//! - `SMOLDER_EXAMPLE_SHARE` (defaults to `share`)
//! - `SMOLDER_EXAMPLE_PATH` (defaults to `smolder-core-example.txt`)
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`

use smolder_core::auth::NtlmCredentials;
use smolder_core::facade::Client;

const DEFAULT_SHARE: &str = "share";
const DEFAULT_PATH: &str = "smolder-core-example.txt";
const EXAMPLE_CONTENT: &[u8] = b"hello from smolder-core\n";

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
    let host = required_env("SMOLDER_EXAMPLE_HOST")?;
    let port = optional_env("SMOLDER_EXAMPLE_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);
    let share_name =
        optional_env("SMOLDER_EXAMPLE_SHARE").unwrap_or_else(|| DEFAULT_SHARE.to_owned());
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

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let mut share = client.connect_share(&share_name).await?;

    share.write(&path, EXAMPLE_CONTENT).await?;
    let read_back = share.read(&path).await?;
    if read_back != EXAMPLE_CONTENT {
        return Err(format!("roundtrip mismatch for {}", path).into());
    }
    let metadata = share.stat(&path).await?;
    share.remove(&path).await?;

    println!(
        "client facade roundtrip succeeded: //{}/{}/{} ({} bytes)",
        share.server(),
        share.name(),
        path,
        metadata.size
    );

    share.logoff().await?;
    Ok(())
}
