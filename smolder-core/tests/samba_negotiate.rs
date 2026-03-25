use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::prelude::{
    Connection, NtlmAuthenticator, NtlmCredentials, TokioTcpTransport, TreeConnected,
};
use smolder_proto::smb::smb2::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect, FlushRequest,
    GlobalCapabilities, NegotiateContext, NegotiateRequest, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId, ReadRequest, SessionId, ShareAccess, SigningMode, TreeConnectRequest,
    TreeId, WriteRequest,
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

struct SambaConfig {
    endpoint: SambaEndpoint,
    username: String,
    password: String,
    share: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            endpoint: SambaEndpoint::from_env()?,
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            share: required_env("SMOLDER_SAMBA_SHARE")?,
            domain: required_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: required_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }
}

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU,
        client_guid: *b"smolder-client01",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![NegotiateContext::preauth_integrity(
            PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-negotiate-salt".to_vec(),
            },
        )],
    }
}

async fn authenticated_tree_connection(
) -> Option<(SambaConfig, Connection<TokioTcpTransport, TreeConnected>)> {
    let Some(config) = SambaConfig::from_env() else {
        eprintln!(
            "skipping live Samba auth test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return None;
    };

    let transport =
        TokioTcpTransport::connect((config.endpoint.host.as_str(), config.endpoint.port))
            .await
            .expect("should connect to configured Samba endpoint");
    let connection = Connection::new(transport);

    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Samba should respond to SMB2 negotiate");

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
        .expect("Samba should accept NTLMv2 session setup");

    let unc = format!(r"\\{}\{}", config.endpoint.host, config.share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
        .expect("Samba should allow tree connect");

    Some((config, connection))
}

fn unique_test_file_path() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!("smolder-interop-{}-{}.txt", std::process::id(), stamp)
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

    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Samba should respond to SMB2 negotiate");

    let dialect = connection.state().response.dialect_revision;
    assert!(matches!(
        dialect,
        Dialect::Smb210 | Dialect::Smb302 | Dialect::Smb311
    ));
}

#[tokio::test]
async fn authenticates_and_connects_tree_when_configured() {
    let Some((_config, connection)) = authenticated_tree_connection().await else {
        return;
    };

    assert_ne!(connection.state().session_id, SessionId(0));
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));
    assert!(connection.session_key().is_some());
}

#[tokio::test]
async fn creates_writes_reads_and_closes_file_when_configured() {
    let Some((_config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let path = unique_test_file_path();
    let payload = b"smolder samba io".to_vec();

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Samba should create the test file");
    let wrote = connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload.clone()))
        .await
        .expect("Samba should write the test payload");
    let read = connection
        .read(&ReadRequest::for_file(
            created.file_id,
            0,
            payload.len() as u32,
        ))
        .await
        .expect("Samba should read back the test payload");
    let closed = connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Samba should close the test file");

    assert_eq!(wrote.count, payload.len() as u32);
    assert_eq!(read.data, payload);
    assert_eq!(closed.flags, 0);
}

#[tokio::test]
async fn flushes_disconnects_and_logs_off_when_configured() {
    let Some((_config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let path = unique_test_file_path();
    let payload = b"smolder lifecycle".to_vec();

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Samba should create the lifecycle test file");
    connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload))
        .await
        .expect("Samba should write the lifecycle test payload");
    connection
        .flush(&FlushRequest::for_file(created.file_id))
        .await
        .expect("Samba should flush the lifecycle test file");
    let closed = connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Samba should close the lifecycle test file");
    assert_eq!(closed.flags, 0);

    let connection = connection
        .tree_disconnect()
        .await
        .expect("Samba should disconnect the tree");
    connection
        .logoff()
        .await
        .expect("Samba should log off the session");
}

#[tokio::test]
async fn queries_network_interfaces_with_ioctl_when_configured() {
    let Some((_config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let dialect = connection.state().negotiated.dialect_revision;
    if !matches!(dialect, Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311) {
        eprintln!("skipping ioctl test: negotiated dialect {dialect:?} is not SMB 3.x");
        return;
    }
    if !connection
        .state()
        .negotiated
        .capabilities
        .contains(GlobalCapabilities::MULTI_CHANNEL)
    {
        eprintln!("skipping ioctl test: server did not advertise multi-channel support");
        return;
    }

    let interfaces = connection
        .query_network_interfaces(64 * 1024)
        .await
        .expect("Samba should answer FSCTL_QUERY_NETWORK_INTERFACE_INFO");

    assert!(
        !interfaces.interfaces.is_empty(),
        "server should report at least one network interface"
    );
}

#[tokio::test]
async fn requests_resume_key_with_ioctl_when_configured() {
    let Some((_config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let path = unique_test_file_path();
    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Samba should create the resume-key test file");
    let resume_key = connection
        .request_resume_key(created.file_id)
        .await
        .expect("Samba should answer FSCTL_SRV_REQUEST_RESUME_KEY");
    let closed = connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Samba should close the resume-key test file");

    assert_eq!(closed.flags, 0);
    assert!(
        resume_key.resume_key.iter().any(|byte| *byte != 0),
        "server should return a non-zero opaque resume key"
    );
}
