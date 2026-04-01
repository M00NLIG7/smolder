use smolder_core::facade::Client;

mod common;
use common::{ntlm_credentials_from_env_prefix, optional_prefixed_u16_env, required_prefixed_env};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_SRVSVC", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_SRVSVC", "PORT", 445)?;
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_SRVSVC")?;

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let session = client.connect().await?;
    let mut srvsvc = session.connect_srvsvc().await?;

    let server = srvsvc.server_get_info_level103().await?;
    let shares = srvsvc.share_enum_level1().await?;

    println!(
        "server={} version={}.{} shares={} capabilities=0x{:08x}",
        server.name,
        server.version_major,
        server.version_minor,
        shares.len(),
        server.capabilities
    );

    let connection = srvsvc.into_rpc().into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    connection.logoff().await?;
    Ok(())
}
