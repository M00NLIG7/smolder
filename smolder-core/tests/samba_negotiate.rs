use smolder_core::prelude::{Connection, TokioTcpTransport};
use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, NegotiateRequest, SigningMode};

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::test]
async fn negotiates_with_samba_when_configured() {
    let Some(host) = required_env("SMOLDER_SAMBA_HOST") else {
        eprintln!("skipping live Samba negotiate test: SMOLDER_SAMBA_HOST is not set");
        return;
    };
    let port = required_env("SMOLDER_SAMBA_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);

    let transport = TokioTcpTransport::connect((host.as_str(), port))
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
