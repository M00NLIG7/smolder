use smolder_core::auth::NtlmCredentials;
use smolder_core::prelude::Client;

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name)
        .map_err(|_| format!("{name} must be set").into())
        .and_then(|value| {
            if value.is_empty() {
                Err(format!("{name} must not be empty").into())
            } else {
                Ok(value)
            }
        })
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_env("SMOLDER_LSARPC_HOST")?;
    let username = required_env("SMOLDER_LSARPC_USERNAME")?;
    let password = required_env("SMOLDER_LSARPC_PASSWORD")?;
    let port = optional_env("SMOLDER_LSARPC_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);

    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = optional_env("SMOLDER_LSARPC_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_LSARPC_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let mut lsarpc = client.connect_lsarpc().await?;

    let account_domain = lsarpc.account_domain_info().await?;
    println!("account domain: {}", account_domain.name);
    if let Some(sid) = account_domain.sid {
        println!("account domain SID revision: {}", sid.revision);
    }

    let primary_domain = lsarpc.primary_domain_info().await?;
    println!("primary domain: {}", primary_domain.name);

    let connection = lsarpc.into_rpc().into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    connection.logoff().await?;
    Ok(())
}
