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

mod common;
use common::{optional_prefixed_env, optional_prefixed_u16_env, required_prefixed_env};

const DEFAULT_SHARE: &str = "share";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_KERBEROS", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_KERBEROS", "PORT", 445)?;
    let share_name = optional_prefixed_env("SMOLDER_KERBEROS", "SHARE")
        .unwrap_or_else(|| DEFAULT_SHARE.to_owned());

    let mut credentials = KerberosCredentials::new(
        required_prefixed_env("SMOLDER_KERBEROS", "USERNAME")?,
        required_prefixed_env("SMOLDER_KERBEROS", "PASSWORD")?,
    );
    if let Some(kdc_url) = optional_prefixed_env("SMOLDER_KERBEROS", "KDC_URL") {
        credentials = credentials.with_kdc_url(kdc_url);
    }

    let target_host =
        optional_prefixed_env("SMOLDER_KERBEROS", "TARGET_HOST").unwrap_or_else(|| host.clone());
    let mut target = KerberosTarget::for_smb_host(target_host);
    if let Some(principal) = optional_prefixed_env("SMOLDER_KERBEROS", "PRINCIPAL") {
        target = target.with_principal(principal);
    } else if let Some(realm) = optional_prefixed_env("SMOLDER_KERBEROS", "REALM") {
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
