//! High-level SMB client RPC bind example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --example client_rpc_bind
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
//! - `SMOLDER_EXAMPLE_DOMAIN`
//! - `SMOLDER_EXAMPLE_WORKSTATION`
//! - `SMOLDER_EXAMPLE_PIPE` (defaults to `srvsvc`)

use smolder_core::prelude::Client;
use smolder_proto::rpc::{SyntaxId, Uuid};

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

const SRVSVC_CONTEXT_ID: u16 = 0;
const SRVSVC_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x4b32_4fc8,
        0x1670,
        0x01d3,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    ),
    3,
    0,
);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_EXAMPLE", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_EXAMPLE", "PORT", 445)?;
    let pipe_name =
        optional_prefixed_env("SMOLDER_EXAMPLE", "PIPE").unwrap_or_else(|| "srvsvc".to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_EXAMPLE")?;

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let rpc = client
        .connect()
        .await?
        .bind_rpc(&pipe_name, SRVSVC_CONTEXT_ID, SRVSVC_SYNTAX)
        .await?;

    println!(
        "RPC bind succeeded: pipe={} fragment_size={}",
        pipe_name,
        rpc.pipe().fragment_size()
    );

    let connection = rpc.into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    let _ = connection.logoff().await?;
    Ok(())
}
