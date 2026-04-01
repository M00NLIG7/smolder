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

use smolder_tools::prelude::SmbClientBuilder;

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

const DEFAULT_SHARE: &str = "share";
const DEFAULT_PATH: &str = "smolder-example.txt";
const EXAMPLE_CONTENT: &[u8] = b"hello from smolder\n";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 445)?;
    let share_name = optional_prefixed_env("SMOLDER_EXAMPLE", "SHARE")
        .unwrap_or_else(|| DEFAULT_SHARE.to_owned());
    let path =
        optional_prefixed_env("SMOLDER_EXAMPLE", "PATH").unwrap_or_else(|| DEFAULT_PATH.to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

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
