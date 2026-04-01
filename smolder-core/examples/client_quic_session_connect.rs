//! Minimal high-level SMB-over-QUIC client facade example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --features quic --example client_quic_session_connect
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
//! - `SMOLDER_EXAMPLE_PORT` (defaults to `443`)
//! - `SMOLDER_EXAMPLE_SHARE` (defaults to `IPC$`)
//! - `SMOLDER_EXAMPLE_CONNECT_HOST` (defaults to `SMOLDER_EXAMPLE_HOST`)
//! - `SMOLDER_EXAMPLE_TLS_SERVER_NAME` (defaults to `SMOLDER_EXAMPLE_HOST`)
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`

use smolder_core::facade::Client;
use smolder_core::transport::TransportTarget;

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let connect_host = optional_prefixed_env("SMOLDER_EXAMPLE", "CONNECT_HOST");
    let tls_server_name = optional_prefixed_env("SMOLDER_EXAMPLE", "TLS_SERVER_NAME");
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 443)?;
    let share =
        optional_prefixed_env("SMOLDER_EXAMPLE", "SHARE").unwrap_or_else(|| "IPC$".to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

    let mut transport_target = TransportTarget::quic(host.clone()).with_port(port);
    if let Some(connect_host) = connect_host {
        transport_target = transport_target.with_connect_host(connect_host);
    }
    if let Some(tls_server_name) = tls_server_name {
        transport_target = transport_target.with_tls_server_name(tls_server_name);
    }

    let client = Client::builder(host)
        .with_transport_target(transport_target)
        .with_ntlm_credentials(credentials)
        .build()?;
    let share = client.connect_share_quic(&share).await?;

    println!(
        "client facade quic connect succeeded: share={} session={} tree={}",
        share.name(),
        share.session_id().0,
        share.tree_id().0
    );

    share.logoff().await?;
    Ok(())
}
