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

use smolder_core::prelude::{Client, TransportTarget};

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 139)?;
    let share =
        optional_prefixed_env("SMOLDER_EXAMPLE", "SHARE").unwrap_or_else(|| "IPC$".to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

    let mut target = TransportTarget::netbios(host.clone()).with_port(port);
    if let Some(connect_host) = optional_prefixed_env("SMOLDER_EXAMPLE", "CONNECT_HOST") {
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
