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

use smolder_core::prelude::{
    Connection, KerberosAuthenticator, KerberosCredentials, KerberosTarget, TokioTcpTransport,
};
use smolder_proto::smb::smb2::{
    CipherId, Dialect, EncryptionCapabilities, GlobalCapabilities, NegotiateContext,
    NegotiateRequest, PreauthIntegrityCapabilities, PreauthIntegrityHashId, SigningMode,
    TreeConnectRequest,
};

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing required environment variable {name}"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU
            | GlobalCapabilities::LEASING
            | GlobalCapabilities::ENCRYPTION,
        client_guid: *b"smolder-krbex001",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-kerberos-example".to_vec(),
            }),
            NegotiateContext::encryption_capabilities(EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            }),
        ],
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = required_env("SMOLDER_KERBEROS_HOST")?;
    let port = optional_env("SMOLDER_KERBEROS_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);
    let share = optional_env("SMOLDER_KERBEROS_SHARE").unwrap_or_else(|| "IPC$".to_owned());
    let target_host =
        optional_env("SMOLDER_KERBEROS_TARGET_HOST").unwrap_or_else(|| host.clone());
    let username = required_env("SMOLDER_KERBEROS_USERNAME")?;
    let password = required_env("SMOLDER_KERBEROS_PASSWORD")?;

    let mut credentials = KerberosCredentials::new(username, password);
    if let Some(domain) = optional_env("SMOLDER_KERBEROS_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_KERBEROS_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }
    if let Some(kdc_url) = optional_env("SMOLDER_KERBEROS_KDC_URL") {
        credentials = credentials.with_kdc_url(kdc_url);
    }

    let mut target = KerberosTarget::for_smb_host(target_host.clone());
    if let Some(principal) = optional_env("SMOLDER_KERBEROS_TARGET_PRINCIPAL") {
        target = target.with_principal(principal);
    } else if let Some(realm) = optional_env("SMOLDER_KERBEROS_REALM") {
        target = target.with_realm(realm);
    }

    let transport = TokioTcpTransport::connect((host.as_str(), port)).await?;
    let connection = Connection::new(transport);
    let connection = connection.negotiate(&negotiate_request()).await?;

    let mut auth = KerberosAuthenticator::new(credentials, target);
    let connection = connection.authenticate(&mut auth).await?;

    let unc = format!(r"\\{}\{}", target_host, share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await?;

    println!(
        "Kerberos tree connect succeeded: share={} session={} tree={}",
        share,
        connection.session_id().0,
        connection.tree_id().0
    );

    let connection = connection.tree_disconnect().await?;
    let _ = connection.logoff().await?;
    Ok(())
}
