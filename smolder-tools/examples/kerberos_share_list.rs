//! Minimal high-level Kerberos-authenticated share listing example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder --features kerberos --example kerberos_share_list
//! ```
//!
//! Required environment:
//!
//! - `SMOLDER_KERBEROS_HOST`
//! - `SMOLDER_KERBEROS_USERNAME`
//! - `SMOLDER_KERBEROS_PASSWORD`
//!
//! Optional environment:
//!
//! - `SMOLDER_KERBEROS_PORT` (defaults to `445`)
//! - `SMOLDER_KERBEROS_SHARE` (defaults to `share`)
//! - `SMOLDER_KERBEROS_TARGET_HOST` (defaults to `SMOLDER_KERBEROS_HOST`)
//! - `SMOLDER_KERBEROS_PRINCIPAL` (explicit SPN override)
//! - `SMOLDER_KERBEROS_REALM`
//! - `SMOLDER_KERBEROS_KDC_URL`

use smolder_tools::prelude::{KerberosCredentials, KerberosTarget, SmbClientBuilder};

const DEFAULT_SHARE: &str = "share";

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
    let host = required_env("SMOLDER_KERBEROS_HOST")?;
    let port = optional_env("SMOLDER_KERBEROS_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);
    let share_name =
        optional_env("SMOLDER_KERBEROS_SHARE").unwrap_or_else(|| DEFAULT_SHARE.to_owned());

    let mut credentials = KerberosCredentials::new(
        required_env("SMOLDER_KERBEROS_USERNAME")?,
        required_env("SMOLDER_KERBEROS_PASSWORD")?,
    );
    if let Some(kdc_url) = optional_env("SMOLDER_KERBEROS_KDC_URL") {
        credentials = credentials.with_kdc_url(kdc_url);
    }

    let target_host = optional_env("SMOLDER_KERBEROS_TARGET_HOST").unwrap_or_else(|| host.clone());
    let mut target = KerberosTarget::for_smb_host(target_host);
    if let Some(principal) = optional_env("SMOLDER_KERBEROS_PRINCIPAL") {
        target = target.with_principal(principal);
    } else if let Some(realm) = optional_env("SMOLDER_KERBEROS_REALM") {
        target = target.with_realm(realm);
    }

    let client = SmbClientBuilder::new()
        .server(host.as_str())
        .port(port)
        .kerberos(credentials, target)
        .connect()
        .await?;
    let mut share = client.share(share_name.as_str()).await?;
    let entries = share.list("").await?;

    println!(
        "kerberos share listing succeeded: //{}/{} entries={}",
        share.server(),
        share.name(),
        entries.len()
    );

    let client = share.disconnect().await?;
    client.logoff().await?;
    Ok(())
}
