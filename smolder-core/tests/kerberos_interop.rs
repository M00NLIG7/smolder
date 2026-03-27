use smolder_core::auth::AuthProvider;
use smolder_core::prelude::{
    Connection, KerberosAuthenticator, KerberosCredentials, KerberosTarget, TokioTcpTransport,
};
use smolder_proto::smb::smb2::{
    CipherId, Dialect, EncryptionCapabilities, GlobalCapabilities, NegotiateContext,
    NegotiateRequest, PreauthIntegrityCapabilities, PreauthIntegrityHashId, SigningMode,
    TreeConnectRequest,
};

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU
            | GlobalCapabilities::LEASING
            | GlobalCapabilities::ENCRYPTION,
        client_guid: *b"smolder-krbts001",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-kerberos-test".to_vec(),
            }),
            NegotiateContext::encryption_capabilities(EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            }),
        ],
    }
}

struct KerberosConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    share: String,
    domain: Option<String>,
    workstation: Option<String>,
    realm: Option<String>,
    kdc_url: Option<String>,
}

impl KerberosConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_KERBEROS_HOST")?,
            port: required_env("SMOLDER_KERBEROS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_KERBEROS_USERNAME")?,
            password: required_env("SMOLDER_KERBEROS_PASSWORD")?,
            share: required_env("SMOLDER_KERBEROS_SHARE").unwrap_or_else(|| "IPC$".to_owned()),
            domain: required_env("SMOLDER_KERBEROS_DOMAIN"),
            workstation: required_env("SMOLDER_KERBEROS_WORKSTATION"),
            realm: required_env("SMOLDER_KERBEROS_REALM"),
            kdc_url: required_env("SMOLDER_KERBEROS_KDC_URL"),
        })
    }
}

#[tokio::test]
async fn authenticates_and_connects_tree_with_kerberos_when_configured() {
    let Some(config) = KerberosConfig::from_env() else {
        eprintln!(
            "skipping kerberos interop test: SMOLDER_KERBEROS_HOST, SMOLDER_KERBEROS_USERNAME, and SMOLDER_KERBEROS_PASSWORD must be set"
        );
        return;
    };

    let transport = TokioTcpTransport::connect((config.host.as_str(), config.port))
        .await
        .expect("should connect to configured SMB endpoint");
    let connection = Connection::new(transport);
    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("server should respond to SMB negotiate");

    let mut credentials = KerberosCredentials::new(config.username, config.password);
    if let Some(domain) = config.domain {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = config.workstation {
        credentials = credentials.with_workstation(workstation);
    }
    if let Some(kdc_url) = config.kdc_url {
        credentials = credentials.with_kdc_url(kdc_url);
    }

    let mut target = KerberosTarget::for_smb_host(config.host.clone());
    if let Some(realm) = config.realm {
        target = target.with_realm(realm);
    }

    let mut auth = KerberosAuthenticator::new(credentials, target);
    let connection = connection
        .authenticate(&mut auth)
        .await
        .expect("server should accept Kerberos session setup");
    assert!(
        auth.session_key().is_some(),
        "Kerberos auth should export an SMB session key"
    );

    let unc = format!(r"\\{}\{}", config.host, config.share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
        .expect("server should allow tree connect after Kerberos auth");

    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    let _ = connection.logoff().await.expect("logoff should succeed");
}
