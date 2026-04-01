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

use smolder_core::facade::Client;

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let share_name = required_prefixed_env("SMOLDER_EXAMPLE", "SHARE")?;
    let path = optional_prefixed_env("SMOLDER_EXAMPLE", "PATH").unwrap_or_else(|| "\\".to_owned());
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 445)?;
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

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
