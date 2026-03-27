//! Minimal high-level SMB file roundtrip example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder --example file_roundtrip
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
//! - `SMOLDER_EXAMPLE_PATH` (defaults to `smolder-example.txt`)
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`

use smolder_tools::prelude::{NtlmCredentials, SmbClientBuilder};

const DEFAULT_SHARE: &str = "share";
const DEFAULT_PATH: &str = "smolder-example.txt";
const EXAMPLE_CONTENT: &[u8] = b"hello from smolder\n";

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

    let client = SmbClientBuilder::new()
        .server(host.as_str())
        .port(port)
        .credentials(credentials)
        .connect()
        .await?;
    let mut share = client.share(share_name.as_str()).await?;

    share.write(path.as_str(), EXAMPLE_CONTENT).await?;
    let read_back = share.read(path.as_str()).await?;
    if read_back != EXAMPLE_CONTENT {
        return Err(format!("roundtrip mismatch for {}", path).into());
    }
    share.remove(path.as_str()).await?;

    println!(
        "high-level roundtrip succeeded: //{}/{}/{}",
        share.server(),
        share.name(),
        path
    );

    let client = share.disconnect().await?;
    client.logoff().await?;
    Ok(())
}
