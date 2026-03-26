use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::prelude::{
    Connection, DurableOpenOptions, NtlmAuthenticator, NtlmCredentials, ResilientHandle,
    TokioTcpTransport, TreeConnected,
};
use smolder_proto::smb::smb2::{
    CipherId, CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect,
    EncryptionCapabilities, FlushRequest, GlobalCapabilities, NegotiateContext, NegotiateRequest,
    PreauthIntegrityCapabilities, PreauthIntegrityHashId, ReadRequest, SessionId, ShareAccess,
    SigningMode, TreeConnectRequest, TreeId, WriteRequest,
};

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct WindowsEndpoint {
    host: String,
    port: u16,
}

impl WindowsEndpoint {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
        })
    }
}

struct WindowsConfig {
    endpoint: WindowsEndpoint,
    username: String,
    password: String,
    share: String,
    test_dir: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            endpoint: WindowsEndpoint::from_env()?,
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            share: required_env("SMOLDER_WINDOWS_SHARE").unwrap_or_else(|| "ADMIN$".to_string()),
            test_dir: required_env("SMOLDER_WINDOWS_TEST_DIR")
                .unwrap_or_else(|| "Temp".to_string()),
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }
}

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU
            | GlobalCapabilities::LEASING
            | GlobalCapabilities::ENCRYPTION,
        client_guid: *b"smolder-wincli01",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-windows-salt".to_vec(),
            }),
            NegotiateContext::encryption_capabilities(EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            }),
        ],
    }
}

async fn authenticated_tree_connection(
) -> Option<(WindowsConfig, Connection<TokioTcpTransport, TreeConnected>)> {
    let Some(config) = WindowsConfig::from_env() else {
        eprintln!(
            "skipping live Windows reconnect test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return None;
    };

    let transport =
        TokioTcpTransport::connect((config.endpoint.host.as_str(), config.endpoint.port))
            .await
            .expect("should connect to configured Windows endpoint");
    let connection = Connection::new(transport);
    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Windows should respond to SMB2 negotiate");

    let mut credentials = NtlmCredentials::new(config.username.clone(), config.password.clone());
    if let Some(domain) = &config.domain {
        credentials = credentials.with_domain(domain.clone());
    }
    if let Some(workstation) = &config.workstation {
        credentials = credentials.with_workstation(workstation.clone());
    }

    let mut auth = NtlmAuthenticator::new(credentials);
    let connection = connection
        .authenticate(&mut auth)
        .await
        .expect("Windows should accept NTLMv2 session setup");

    let unc = format!(r"\\{}\{}", config.endpoint.host, config.share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
        .expect("Windows should allow tree connect");

    Some((config, connection))
}

fn unique_test_file_path(test_dir: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!(
        "{}\\smolder-win-reconnect-{}-{}.txt",
        test_dir.trim_matches(['\\', '/']),
        std::process::id(),
        stamp
    )
}

#[tokio::test]
async fn reopens_durable_handle_after_transport_reconnect_when_configured() {
    let Some((config, mut connection_one)) = authenticated_tree_connection().await else {
        return;
    };

    if !matches!(
        connection_one.state().negotiated.dialect_revision,
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311
    ) {
        eprintln!("skipping Windows durable reconnect test: negotiated dialect is not SMB 3.x");
        return;
    }
    if !connection_one
        .state()
        .negotiated
        .capabilities
        .contains(GlobalCapabilities::LEASING)
    {
        eprintln!("skipping Windows durable reconnect test: server did not advertise leasing support");
        return;
    }

    let path = unique_test_file_path(&config.test_dir);
    let payload = b"smolder windows durable reconnect".to_vec();
    let timeout = 30_000;
    let create_guid = *b"durable-win-live";

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    let durable = connection_one
        .create_durable(
            &create_request,
            DurableOpenOptions::new()
                .with_create_guid(create_guid)
                .with_timeout(timeout),
        )
        .await
        .expect("Windows should create a durable test file");
    connection_one
        .write(&WriteRequest::for_file(durable.file_id(), 0, payload.clone()))
        .await
        .expect("Windows should write the durable test payload");
    connection_one
        .flush(&FlushRequest::for_file(durable.file_id()))
        .await
        .expect("Windows should flush the durable test payload");
    connection_one
        .request_resiliency(durable.file_id(), timeout)
        .await
        .expect("Windows should accept the durable resiliency request");
    let durable = durable.with_resilient_timeout(timeout);

    drop(connection_one.into_transport());

    let Some((_config, mut connection_two)) = authenticated_tree_connection().await else {
        return;
    };
    let (reopened, resilient) = connection_two
        .reconnect_durable_with_resiliency(&durable)
        .await
        .expect("Windows should reopen the durable handle after reconnect");
    let read = connection_two
        .read(&ReadRequest::for_file(
            reopened.file_id(),
            0,
            payload.len() as u32,
        ))
        .await
        .expect("Windows should read back the durable payload after reconnect");
    let closed = connection_two
        .close(&CloseRequest {
            flags: 0,
            file_id: reopened.file_id(),
        })
        .await
        .expect("Windows should close the reopened durable handle");

    assert_eq!(read.data, payload);
    assert_eq!(closed.flags, 0);
    assert_eq!(reopened.resilient_timeout(), Some(timeout));
    assert_eq!(
        resilient,
        Some(ResilientHandle {
            file_id: reopened.file_id(),
            timeout,
        })
    );

    let mut cleanup_request = CreateRequest::from_path(&path);
    cleanup_request.create_disposition = CreateDisposition::Open;
    cleanup_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    cleanup_request.desired_access |= 0x0001_0000;
    cleanup_request.share_access |= ShareAccess::DELETE;
    let cleanup = connection_two
        .create(&cleanup_request)
        .await
        .expect("Windows should reopen the durable test file for cleanup");
    connection_two
        .close(&CloseRequest {
            flags: 0,
            file_id: cleanup.file_id,
        })
        .await
        .expect("Windows should delete the durable test file during cleanup");

    assert_ne!(connection_two.session_id(), SessionId(0));
    assert_ne!(connection_two.tree_id(), TreeId(0));
}
