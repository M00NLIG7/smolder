//! Minimal high-level SMB share listing example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --example client_share_list
//! ```
//!
//! Required environment:
//!
//! - `SMOLDER_EXAMPLE_HOST`
//! - `SMOLDER_EXAMPLE_USERNAME`
//! - `SMOLDER_EXAMPLE_PASSWORD`
//! - `SMOLDER_EXAMPLE_SHARE`
//!
//! Optional environment:
//!
//! - `SMOLDER_EXAMPLE_PORT` (defaults to `445`)
//! - `SMOLDER_EXAMPLE_PATH` (defaults to `\`)
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`

use smolder_core::auth::NtlmCredentials;
use smolder_core::facade::Client;

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
    let share_name = required_env("SMOLDER_EXAMPLE_SHARE")?;
    let path = optional_env("SMOLDER_EXAMPLE_PATH").unwrap_or_else(|| "\\".to_owned());
    let port = optional_env("SMOLDER_EXAMPLE_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);

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
    let entries = share.list(&path).await?;

    for entry in entries {
        let kind = if entry.is_directory() { "dir " } else { "file" };
        println!("{kind}\t{}\t{}", entry.metadata.size, entry.name);
    }

    share.logoff().await?;
    Ok(())
}
