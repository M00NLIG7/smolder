use smolder_core::facade::Client;

mod common;
use common::{
    ntlm_credentials_from_env_prefix, optional_prefixed_env, optional_prefixed_u16_env,
    required_prefixed_env,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_SAMR", "HOST")?;
    let domain_name = required_prefixed_env("SMOLDER_SAMR", "DOMAIN_NAME")?;
    let alias_name = required_prefixed_env("SMOLDER_SAMR", "ALIAS_NAME")?;
    let port = optional_prefixed_u16_env("SMOLDER_SAMR", "PORT", 445)?;
    let pipe_name =
        optional_prefixed_env("SMOLDER_SAMR", "PIPE").unwrap_or_else(|| "lsarpc".to_owned());
    let credentials = ntlm_credentials_from_env_prefix("SMOLDER_SAMR")?;

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
    let members = alias_client.members().await?;
    println!(
        "domain={} alias={} members={} comment={}",
        domain_name, alias_info.name, alias_info.member_count, alias_info.admin_comment
    );
    println!("alias member sid count={}", members.len());
    if let Some(member_sid) = members.first() {
        println!(
            "first alias member sid revision={} sub_authorities={}",
            member_sid.revision,
            member_sid.sub_authorities.len()
        );
    }

    let domain = alias_client.close().await?;
    let connection = domain.close().await?.into_pipe().close().await?;
    let connection = connection.tree_disconnect().await?;
    connection.logoff().await?;
    Ok(())
}
