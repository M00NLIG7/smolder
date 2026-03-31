//! Minimal high-level client facade example over NetBIOS session service.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --example client_netbios_session_connect
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
//! - `SMOLDER_EXAMPLE_PORT` (defaults to `139`)
//! - `SMOLDER_EXAMPLE_CONNECT_HOST`
//! - `SMOLDER_EXAMPLE_SHARE` (defaults to `IPC$`)
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`

use smolder_core::prelude::{Client, NtlmCredentials, TransportTarget};

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
        .unwrap_or(139);
    let share = optional_env("SMOLDER_EXAMPLE_SHARE").unwrap_or_else(|| "IPC$".to_owned());

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

    let mut target = TransportTarget::netbios(host.clone()).with_port(port);
    if let Some(connect_host) = optional_env("SMOLDER_EXAMPLE_CONNECT_HOST") {
        target = target.with_connect_host(connect_host);
    }

    let client = Client::builder(host)
        .with_transport_target(target)
        .with_ntlm_credentials(credentials)
        .build()?;
    let share = client.connect_share(&share).await?;

    println!(
        "NetBIOS facade connect succeeded: share={} session={} tree={}",
        share.name(),
        share.session_id().0,
        share.tree_id().0
    );

    share.logoff().await?;
    Ok(())
}
