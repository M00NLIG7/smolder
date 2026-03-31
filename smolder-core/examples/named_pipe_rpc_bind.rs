//! Minimal SMB named-pipe RPC bind example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --example named_pipe_rpc_bind
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

use smolder_core::prelude::{Client, NtlmCredentials, PipeAccess};
use smolder_proto::rpc::{SyntaxId, Uuid};

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
    let pipe_name = optional_env("SMOLDER_EXAMPLE_PIPE").unwrap_or_else(|| "srvsvc".to_owned());

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
    let session = client.connect().await?;
    let mut rpc = session
        .connect_rpc_pipe(&pipe_name, PipeAccess::ReadWrite)
        .await?;
    let bind_ack = rpc.bind_context(SRVSVC_CONTEXT_ID, SRVSVC_SYNTAX).await?;

    println!(
        "RPC bind succeeded: pipe={} max_xmit_frag={} max_recv_frag={}",
        pipe_name, bind_ack.max_xmit_frag, bind_ack.max_recv_frag
    );

    let connection = rpc.into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    let _ = connection.logoff().await?;
    Ok(())
}
