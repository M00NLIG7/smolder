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
    target_host: String,
    target_principal: Option<String>,
    username: String,
    password: Option<String>,
    keytab: Option<String>,
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
            target_host: required_env("SMOLDER_KERBEROS_TARGET_HOST")
                .or_else(|| required_env("SMOLDER_KERBEROS_HOST"))?,
            target_principal: required_env("SMOLDER_KERBEROS_TARGET_PRINCIPAL"),
            username: required_env("SMOLDER_KERBEROS_USERNAME")?,
            password: required_env("SMOLDER_KERBEROS_PASSWORD"),
            keytab: required_env("SMOLDER_KERBEROS_KEYTAB"),
            share: required_env("SMOLDER_KERBEROS_SHARE").unwrap_or_else(|| "IPC$".to_owned()),
            domain: required_env("SMOLDER_KERBEROS_DOMAIN"),
            workstation: required_env("SMOLDER_KERBEROS_WORKSTATION"),
            realm: required_env("SMOLDER_KERBEROS_REALM"),
            kdc_url: required_env("SMOLDER_KERBEROS_KDC_URL"),
        })
        .filter(|config| config.password.is_some() || config.keytab.is_some())
    }
}

#[tokio::test]
async fn authenticates_and_connects_tree_with_kerberos_when_configured() {
    let Some(config) = KerberosConfig::from_env() else {
        eprintln!(
            "skipping kerberos interop test: SMOLDER_KERBEROS_HOST, SMOLDER_KERBEROS_USERNAME, and either SMOLDER_KERBEROS_PASSWORD or SMOLDER_KERBEROS_KEYTAB must be set"
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

    let mut credentials = match (config.keytab, config.password) {
        #[cfg(all(unix, feature = "kerberos-gssapi"))]
        (Some(keytab), _) => KerberosCredentials::from_keytab(config.username, keytab),
        #[cfg(not(all(unix, feature = "kerberos-gssapi")))]
        (Some(_), _) => panic!("SMOLDER_KERBEROS_KEYTAB requires the kerberos-gssapi feature"),
        #[cfg(feature = "kerberos-sspi")]
        (None, Some(password)) => KerberosCredentials::new(config.username, password),
        #[cfg(not(feature = "kerberos-sspi"))]
        (None, Some(_)) => panic!("SMOLDER_KERBEROS_PASSWORD requires the kerberos or kerberos-sspi feature"),
        (None, None) => unreachable!("config construction requires password or keytab"),
    };
    if let Some(domain) = config.domain {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = config.workstation {
        credentials = credentials.with_workstation(workstation);
    }
    if let Some(kdc_url) = config.kdc_url {
        credentials = credentials.with_kdc_url(kdc_url);
    }

    let mut target = KerberosTarget::for_smb_host(config.target_host.clone());
    if let Some(principal) = config.target_principal {
        target = target.with_principal(principal);
    } else if let Some(realm) = config.realm {
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

    let unc = format!(r"\\{}\{}", config.target_host, config.share);
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
