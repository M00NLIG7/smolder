use smolder_core::auth::NtlmCredentials;
use smolder_core::prelude::{Client, LOOKUP_POLICY_ACCESS};

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
    let lookup_name = username.clone();
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
    let mut lsarpc = client
        .connect_lsarpc_with_access(LOOKUP_POLICY_ACCESS)
        .await?;

    let account_domain = lsarpc.account_domain_info().await?;
    println!("account domain: {}", account_domain.name);
    if let Some(sid) = account_domain.sid {
        println!("account domain SID revision: {}", sid.revision);
    }
    let qualified_lookup_name = format!(r"{}\{}", account_domain.name, lookup_name);
    if let Some(translated) = lsarpc.lookup_name(&qualified_lookup_name).await? {
        println!("lookup use: {:?}", translated.sid_name_use);
        if let Some(sid) = translated.sid {
            println!("lookup SID revision: {}", sid.revision);
        }
    }

    let primary_domain = lsarpc.primary_domain_info().await?;
    println!("primary domain: {}", primary_domain.name);

    let dns_domain = lsarpc.dns_domain_info().await?;
    println!("dns domain name: {}", dns_domain.name);
    if !dns_domain.dns_domain_name.is_empty() {
        println!("dns domain fqdn: {}", dns_domain.dns_domain_name);
    }
    if !dns_domain.dns_forest_name.is_empty() {
        println!("dns forest: {}", dns_domain.dns_forest_name);
    }
    if let Some(domain_guid) = dns_domain.domain_guid {
        println!(
            "dns domain guid: {:08x}-{:04x}-{:04x}-{:02x?}",
            domain_guid.data1, domain_guid.data2, domain_guid.data3, domain_guid.data4
        );
    }

    println!("server role: {:?}", lsarpc.server_role().await?);

    let connection = lsarpc.close().await?.into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    connection.logoff().await?;
    Ok(())
}
