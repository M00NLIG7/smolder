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
    let host = required_env("SMOLDER_SAMR_HOST")?;
    let username = required_env("SMOLDER_SAMR_USERNAME")?;
    let password = required_env("SMOLDER_SAMR_PASSWORD")?;
    let domain_name = required_env("SMOLDER_SAMR_DOMAIN_NAME")?;
    let alias_name = required_env("SMOLDER_SAMR_ALIAS_NAME")?;
    let port = optional_env("SMOLDER_SAMR_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);
    let pipe_name = optional_env("SMOLDER_SAMR_PIPE").unwrap_or_else(|| "lsarpc".to_owned());

    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = optional_env("SMOLDER_SAMR_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_SAMR_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()?;
    let session = client.connect().await?;
    let samr = session.connect_samr_pipe(&pipe_name).await?;
    let mut domain = samr.open_domain(&domain_name).await?;
    let aliases = domain.enumerate_aliases().await?;
    let alias = aliases
        .iter()
        .find(|alias| alias.name.eq_ignore_ascii_case(&alias_name))
        .ok_or_else(|| format!("alias {alias_name:?} not found in domain {domain_name:?}"))?
        .clone();

    let mut alias_client = domain.open_alias(alias.relative_id).await?;
    let alias_info = alias_client.query_general_information().await?;
    println!(
        "domain={} alias={} members={} comment={}",
        domain_name, alias_info.name, alias_info.member_count, alias_info.admin_comment
    );

    let domain = alias_client.close().await?;
    let connection = domain.close().await?.into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    connection.logoff().await?;
    Ok(())
}
