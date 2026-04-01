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

use smolder_core::facade::Client;

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

const DEFAULT_SHARE: &str = "share";
const DEFAULT_PATH: &str = "smolder-core-example.txt";
const EXAMPLE_CONTENT: &[u8] = b"hello from smolder-core\n";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 445)?;
    let share_name = optional_prefixed_env("SMOLDER_EXAMPLE", "SHARE")
        .unwrap_or_else(|| DEFAULT_SHARE.to_owned());
    let path =
        optional_prefixed_env("SMOLDER_EXAMPLE", "PATH").unwrap_or_else(|| DEFAULT_PATH.to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let mut share = client.connect_share(&share_name).await?;

    share.put(&path, EXAMPLE_CONTENT).await?;
    let read_back = share.get(&path).await?;
    if read_back != EXAMPLE_CONTENT {
        return Err(format!("roundtrip mismatch for {}", path).into());
    }
    let metadata = share.metadata(&path).await?;
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
