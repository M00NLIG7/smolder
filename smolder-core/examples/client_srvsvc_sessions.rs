use smolder_core::auth::NtlmCredentials;
use smolder_core::facade::Client;

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be set").into())
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_env("SMOLDER_SRVSVC_HOST")?;
    let username = required_env("SMOLDER_SRVSVC_USERNAME")?;
    let password = required_env("SMOLDER_SRVSVC_PASSWORD")?;
    let port = optional_env("SMOLDER_SRVSVC_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);

    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = optional_env("SMOLDER_SRVSVC_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_SRVSVC_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

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
