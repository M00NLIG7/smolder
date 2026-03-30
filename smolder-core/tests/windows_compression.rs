use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use smolder_core::compression::CompressionState;
use smolder_core::crypto::EncryptionState;
use smolder_core::prelude::{
    Connection, NtlmAuthenticator, NtlmCredentials, TokioTcpTransport, Transport, TreeConnected,
};
use smolder_proto::smb::compression::{
    CompressionAlgorithm, CompressionCapabilityFlags, CompressionTransformHeader,
    COMPRESSION_TRANSFORM_PROTOCOL_ID,
};
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    CipherId, CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect,
    EncryptionCapabilities, FlushRequest, GlobalCapabilities, NegotiateContext, NegotiateRequest,
    PreauthIntegrityCapabilities, PreauthIntegrityHashId, SessionId, ShareAccess, SigningMode,
    TreeConnectRequest, TreeId, WriteRequest,
};
use smolder_proto::smb::transform::{TransformHeader, TRANSFORM_PROTOCOL_ID};
use tokio::sync::Mutex;

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

struct WindowsCompressionConfig {
    endpoint: WindowsEndpoint,
    username: String,
    password: String,
    share: String,
    test_dir: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsCompressionConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            endpoint: WindowsEndpoint::from_env()?,
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            share: required_env("SMOLDER_WINDOWS_ENCRYPTED_SHARE")?,
            test_dir: required_env("SMOLDER_WINDOWS_ENCRYPTED_TEST_DIR").unwrap_or_default(),
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
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

fn windows_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU
            | GlobalCapabilities::LEASING
            | GlobalCapabilities::ENCRYPTION,
        client_guid: *b"smolder-wcmp-001",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-windows-compression-salt".to_vec(),
            }),
            NegotiateContext::encryption_capabilities(EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            }),
            NegotiateContext::compression_capabilities(smolder_proto::smb::smb2::CompressionCapabilities {
                compression_algorithms: vec![CompressionAlgorithm::Lznt1],
                flags: CompressionCapabilityFlags::empty(),
            }),
        ],
    }
}

async fn authenticated_tree_connection() -> Option<(
    WindowsCompressionConfig,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Connection<RecordingTransport<TokioTcpTransport>, TreeConnected>,
)> {
    let Some(config) = WindowsCompressionConfig::from_env() else {
        eprintln!(
            "skipping live Windows compression test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, SMOLDER_WINDOWS_PASSWORD, and SMOLDER_WINDOWS_ENCRYPTED_SHARE must be set"
        );
        return None;
    };

    let transport =
        TokioTcpTransport::connect((config.endpoint.host.as_str(), config.endpoint.port))
            .await
            .expect("should connect to configured Windows endpoint");
    let (transport, writes) = RecordingTransport::new(transport);
    let connection = Connection::new(transport);
    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Windows should respond to SMB3 negotiate with compression support");

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
        .expect("Windows should allow tree connect to the encrypted share");

    Some((config, writes, connection))
}

fn unique_test_file_path(test_dir: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let file_name = format!("smolder-win-compression-{}-{stamp}.txt", std::process::id());
    if test_dir.trim_matches(['\\', '/']).is_empty() {
        file_name
    } else {
        format!("{}\\{file_name}", test_dir.trim_matches(['\\', '/']))
    }
}

fn decode_recorded_payload(
    frame: &[u8],
    encryption: Option<&EncryptionState>,
    compression: &CompressionState,
) -> (Vec<u8>, bool) {
    let frame = SessionMessage::decode(frame).expect("frame should decode");
    let payload = if frame.payload.starts_with(&TRANSFORM_PROTOCOL_ID) {
        let encryption = encryption.expect("encrypted frame should have encryption state");
        let transform =
            TransformHeader::decode(&frame.payload).expect("transform header should decode");
        encryption
            .decrypt_message(&transform)
            .expect("encrypted payload should decrypt")
    } else {
        frame.payload
    };

    let compressed = payload.starts_with(&COMPRESSION_TRANSFORM_PROTOCOL_ID);
    if compressed {
        let transform = CompressionTransformHeader::decode(&payload)
            .expect("compression transform should decode");
        (
            compression
                .decompress_message(&transform)
                .expect("compressed payload should decompress"),
            true,
        )
    } else {
        (payload, false)
    }
}

fn peer_encryption_state(state: &EncryptionState) -> EncryptionState {
    EncryptionState {
        dialect: state.dialect,
        cipher: state.cipher,
        encrypting_key: state.decrypting_key.clone(),
        decrypting_key: state.encrypting_key.clone(),
    }
}

#[tokio::test]
async fn writes_compressed_payloads_to_windows_when_negotiated() {
    let _guard = windows_lock().lock().await;
    let Some((config, writes, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    if !matches!(connection.state().negotiated.dialect_revision, Dialect::Smb311) {
        eprintln!("skipping Windows compression test: negotiated dialect is not SMB 3.1.1");
        return;
    }

    let Some(compression) = connection.state().compression.clone() else {
        eprintln!("skipping Windows compression test: server did not negotiate compression");
        return;
    };

    let path = unique_test_file_path(&config.test_dir);
    let payload = vec![b'A'; 32 * 1024];

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Windows should create the compression test file");
    connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload.clone()))
        .await
        .expect("Windows should write the compression test payload");
    connection
        .flush(&FlushRequest::for_file(created.file_id))
        .await
        .expect("Windows should flush the compression test payload");
    connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Windows should close the compression test file");

    assert!(
        connection.state().encryption_required,
        "the encrypted share should still require SMB encryption"
    );
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));

    let writes = writes.lock().await;
    let peer_encryption = connection
        .state()
        .encryption
        .as_deref()
        .map(peer_encryption_state);

    let (decoded, compressed) = writes
        .iter()
        .map(|frame| decode_recorded_payload(frame, peer_encryption.as_ref(), compression.as_ref()))
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
