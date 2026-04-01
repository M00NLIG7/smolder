//! Minimal NTLM-authenticated SMB tree connect example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --example ntlm_tree_connect
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
//! - `SMOLDER_EXAMPLE_SHARE` (defaults to `IPC$`)
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`

use smolder_core::prelude::Client;

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 445)?;
    let share =
        optional_prefixed_env("SMOLDER_EXAMPLE", "SHARE").unwrap_or_else(|| "IPC$".to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let share = client.connect_share(&share).await?;

    println!(
        "NTLM tree connect succeeded: share={} session={} tree={}",
        share.name(),
        share.session_id().0,
        share.tree_id().0
    );

    share.logoff().await?;
    Ok(())
}
