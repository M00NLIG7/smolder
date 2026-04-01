//! Minimal Kerberos-authenticated SMB tree connect example.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smolder-smb-core --features kerberos --example kerberos_tree_connect
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
//! - `SMOLDER_KERBEROS_SHARE` (defaults to `IPC$`)
//! - `SMOLDER_KERBEROS_DOMAIN`
//! - `SMOLDER_KERBEROS_WORKSTATION`
//! - `SMOLDER_KERBEROS_REALM`
//! - `SMOLDER_KERBEROS_KDC_URL`
//! - `SMOLDER_KERBEROS_TARGET_HOST`
//! - `SMOLDER_KERBEROS_TARGET_PRINCIPAL`

use smolder_core::prelude::{Client, KerberosCredentials, KerberosTarget};

mod common;
use common::{optional_prefixed_env, optional_prefixed_u16_env, required_prefixed_env};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_prefixed_env("SMOLDER_KERBEROS", "HOST")?;
    let port = optional_prefixed_u16_env("SMOLDER_KERBEROS", "PORT", 445)?;
    let share =
        optional_prefixed_env("SMOLDER_KERBEROS", "SHARE").unwrap_or_else(|| "IPC$".to_owned());
    let target_host =
        optional_prefixed_env("SMOLDER_KERBEROS", "TARGET_HOST").unwrap_or_else(|| host.clone());
    let username = required_prefixed_env("SMOLDER_KERBEROS", "USERNAME")?;
    let password = required_prefixed_env("SMOLDER_KERBEROS", "PASSWORD")?;

    let mut credentials = KerberosCredentials::new(username, password);
    if let Some(domain) = optional_prefixed_env("SMOLDER_KERBEROS", "DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_prefixed_env("SMOLDER_KERBEROS", "WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }
    if let Some(kdc_url) = optional_prefixed_env("SMOLDER_KERBEROS", "KDC_URL") {
        credentials = credentials.with_kdc_url(kdc_url);
    }

    let mut target = KerberosTarget::for_smb_host(target_host.clone());
    if let Some(principal) = optional_prefixed_env("SMOLDER_KERBEROS", "TARGET_PRINCIPAL") {
        target = target.with_principal(principal);
    } else if let Some(realm) = optional_prefixed_env("SMOLDER_KERBEROS", "REALM") {
        target = target.with_realm(realm);
    }

    let mut builder = Client::builder(target_host.clone())
        .with_port(port)
        .with_kerberos_credentials(credentials, target);
    if host != target_host {
        builder = builder.with_connect_host(host);
    }
    let client = builder.build()?;
    let share = client.connect_share(&share).await?;

    println!(
        "Kerberos tree connect succeeded: share={} session={} tree={}",
        share.name(),
        share.session_id().0,
        share.tree_id().0
    );

    share.logoff().await?;
    Ok(())
}
