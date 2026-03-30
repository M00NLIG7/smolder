use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use smolder_core::compression::CompressionState;
use smolder_core::prelude::{
    Connection, NtlmAuthenticator, NtlmCredentials, TokioTcpTransport, Transport, TreeConnected,
};
use smolder_proto::smb::compression::{
    CompressionAlgorithm, CompressionCapabilityFlags, CompressionTransformHeader,
    COMPRESSION_TRANSFORM_PROTOCOL_ID,
};
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect, FlushRequest,
    GlobalCapabilities, NegotiateContext, NegotiateRequest, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId, SessionId, ShareAccess, SigningMode, TreeConnectRequest, TreeId,
    WriteRequest,
};
use tokio::sync::Mutex;

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

struct SambaCompressionConfig {
    endpoint: SambaEndpoint,
    username: String,
    password: String,
    share: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaCompressionConfig {
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

#[derive(Debug)]
struct RecordingTransport<T> {
    inner: T,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl<T> RecordingTransport<T> {
    fn new(inner: T) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inner,
                writes: Arc::clone(&writes),
            },
            writes,
        )
    }
}

#[async_trait]
impl<T> Transport for RecordingTransport<T>
where
    T: Transport + Send,
{
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        self.writes.lock().await.push(frame.to_vec());
        self.inner.send(frame).await
    }

    async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        self.inner.recv().await
    }
}

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::LEASING,
        client_guid: *b"smolder-scmp-001",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-samba-compression-salt".to_vec(),
            }),
            NegotiateContext::compression_capabilities(smolder_proto::smb::smb2::CompressionCapabilities {
                compression_algorithms: vec![CompressionAlgorithm::Lznt1],
                flags: CompressionCapabilityFlags::empty(),
            }),
        ],
    }
}

async fn authenticated_tree_connection() -> Option<(
    Arc<Mutex<Vec<Vec<u8>>>>,
    Connection<RecordingTransport<TokioTcpTransport>, TreeConnected>,
)> {
    let Some(config) = SambaCompressionConfig::from_env() else {
        eprintln!(
            "skipping live Samba compression test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return None;
    };

    let transport =
        TokioTcpTransport::connect((config.endpoint.host.as_str(), config.endpoint.port))
            .await
            .expect("should connect to configured Samba endpoint");
    let (transport, writes) = RecordingTransport::new(transport);
    let connection = Connection::new(transport);

    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Samba should respond to SMB3 negotiate");

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

    Some((writes, connection))
}

fn unique_test_file_path() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!("smolder-samba-compression-{}-{stamp}.txt", std::process::id())
}

fn decode_recorded_payload(frame: &[u8], compression: &CompressionState) -> (Vec<u8>, bool) {
    let frame = SessionMessage::decode(frame).expect("frame should decode");
    if frame.payload.starts_with(&COMPRESSION_TRANSFORM_PROTOCOL_ID) {
        let transform = CompressionTransformHeader::decode(&frame.payload)
            .expect("compression header should decode");
        (
            compression
                .decompress_message(&transform)
                .expect("compressed payload should decompress"),
            true,
        )
    } else {
        (frame.payload, false)
    }
}

#[tokio::test]
async fn writes_compressed_payloads_to_samba_when_negotiated() {
    let _guard = samba_lock().lock().await;
    let Some((writes, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    if !matches!(connection.state().negotiated.dialect_revision, Dialect::Smb311) {
        eprintln!("skipping Samba compression test: negotiated dialect is not SMB 3.1.1");
        return;
    }

    let Some(compression) = connection.state().compression.clone() else {
        eprintln!("skipping Samba compression test: server did not negotiate compression");
        return;
    };

    let path = unique_test_file_path();
    let payload = vec![b'B'; 32 * 1024];

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Samba should create the compression test file");
    connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload.clone()))
        .await
        .expect("Samba should write the compression test payload");
    connection
        .flush(&FlushRequest::for_file(created.file_id))
        .await
        .expect("Samba should flush the compression test payload");
    connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Samba should close the compression test file");

    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));

    let writes = writes.lock().await;
    let (decoded, compressed) = writes
        .iter()
        .map(|frame| decode_recorded_payload(frame, compression.as_ref()))
        .find(|(packet, _)| {
            smolder_proto::smb::smb2::Header::decode(
                &packet[..smolder_proto::smb::smb2::Header::LEN],
            )
            .map(|header| header.command == smolder_proto::smb::smb2::Command::Write)
            .unwrap_or(false)
        })
        .expect("recorded SMB frames should include a write request");
    let header = smolder_proto::smb::smb2::Header::decode(
        &decoded[..smolder_proto::smb::smb2::Header::LEN],
    )
    .expect("header should decode");
    let request = WriteRequest::decode(&decoded[smolder_proto::smb::smb2::Header::LEN..])
        .expect("write request should decode");

    assert_eq!(header.command, smolder_proto::smb::smb2::Command::Write);
    assert!(compressed, "write request should be compressed on the wire");
    assert_eq!(request.data, payload);
}
