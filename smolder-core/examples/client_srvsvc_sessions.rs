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
    let sessions = srvsvc.session_enum_level10().await?;

    println!("sessions={}", sessions.len());
    for session in sessions {
        println!(
            "client={} user={} time={} idle={}",
            session.client_name.unwrap_or_default(),
            session.username.unwrap_or_default(),
            session.time,
            session.idle_time
        );
    }

    let connection = srvsvc.into_rpc().into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    connection.logoff().await?;
    Ok(())
}
