use smolder_core::prelude::{Connection, NtlmAuthenticator, NtlmCredentials, TokioTcpTransport};
use smolder_proto::smb::smb2::{
    Dialect, GlobalCapabilities, NegotiateRequest, SessionId, SigningMode, TreeConnectRequest,
    TreeId,
};

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaEndpoint {
    host: String,
    port: u16,
}

impl SambaEndpoint {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: required_env("SMOLDER_SAMBA_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
        })
    }
}

#[tokio::test]
async fn negotiates_with_samba_when_configured() {
    let Some(endpoint) = SambaEndpoint::from_env() else {
        eprintln!("skipping live Samba negotiate test: SMOLDER_SAMBA_HOST is not set");
        return;
    };

    let transport = TokioTcpTransport::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .expect("should connect to configured Samba endpoint");
    let connection = Connection::new(transport);

    let request = NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU,
        client_guid: *b"smolder-client01",
        dialects: vec![Dialect::Smb210, Dialect::Smb302],
        negotiate_contexts: Vec::new(),
    };

    let connection = connection
        .negotiate(&request)
        .await
        .expect("Samba should respond to SMB2 negotiate");

    let dialect = connection.state().response.dialect_revision;
    assert!(matches!(dialect, Dialect::Smb210 | Dialect::Smb302));
}

#[tokio::test]
async fn authenticates_and_connects_tree_when_configured() {
    let Some(endpoint) = SambaEndpoint::from_env() else {
        eprintln!("skipping live Samba auth test: SMOLDER_SAMBA_HOST is not set");
        return;
    };
    let Some(username) = required_env("SMOLDER_SAMBA_USERNAME") else {
        eprintln!("skipping live Samba auth test: SMOLDER_SAMBA_USERNAME is not set");
        return;
    };
    let Some(password) = required_env("SMOLDER_SAMBA_PASSWORD") else {
        eprintln!("skipping live Samba auth test: SMOLDER_SAMBA_PASSWORD is not set");
        return;
    };
    let Some(share) = required_env("SMOLDER_SAMBA_SHARE") else {
        eprintln!("skipping live Samba auth test: SMOLDER_SAMBA_SHARE is not set");
        return;
    };

    let transport = TokioTcpTransport::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .expect("should connect to configured Samba endpoint");
    let connection = Connection::new(transport);

    let request = NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU,
        client_guid: *b"smolder-client01",
        dialects: vec![Dialect::Smb210, Dialect::Smb302],
        negotiate_contexts: Vec::new(),
    };

    let connection = connection
        .negotiate(&request)
        .await
        .expect("Samba should respond to SMB2 negotiate");

    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = required_env("SMOLDER_SAMBA_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = required_env("SMOLDER_SAMBA_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

    let mut auth = NtlmAuthenticator::new(credentials);
    let connection = connection
        .authenticate(&mut auth)
        .await
        .expect("Samba should accept NTLMv2 session setup");

    assert_ne!(connection.state().session_id, SessionId(0));
    assert!(connection.state().session_key.is_some());

    let unc = format!(r"\\{}\{}", endpoint.host, share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
        .expect("Samba should allow tree connect");

    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));
    assert!(connection.session_key().is_some());
}
