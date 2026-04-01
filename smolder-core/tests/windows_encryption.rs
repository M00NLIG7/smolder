mod common;

use common::{unique_path_in_dir, windows_lock, WindowsShareConfig};
use smolder_core::prelude::{
    Connection, NtlmAuthenticator, TokioTcpTransport, TreeConnected,
};
use smolder_proto::smb::smb2::{
    CipherId, CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect,
    EncryptionCapabilities, FlushRequest, GlobalCapabilities, NegotiateContext, NegotiateRequest,
    PreauthIntegrityCapabilities, PreauthIntegrityHashId, ReadRequest, SessionId, ShareAccess,
    SigningMode, TreeConnectRequest, TreeId, WriteRequest,
};

fn negotiate_request() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU
            | GlobalCapabilities::LEASING
            | GlobalCapabilities::ENCRYPTION,
        client_guid: *b"smolder-winenc01",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-windows-encryption-salt".to_vec(),
            }),
            NegotiateContext::encryption_capabilities(EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            }),
        ],
    }
}

async fn authenticated_tree_connection() -> Option<(
    WindowsShareConfig,
    Connection<TokioTcpTransport, TreeConnected>,
)> {
    let Some(config) = WindowsShareConfig::encrypted_from_env() else {
        eprintln!(
            "skipping live Windows encryption test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, SMOLDER_WINDOWS_PASSWORD, and SMOLDER_WINDOWS_ENCRYPTED_SHARE must be set"
        );
        return None;
    };

    let transport = TokioTcpTransport::connect((config.host.as_str(), config.port))
        .await
        .expect("should connect to configured Windows endpoint");
    let connection = Connection::new(transport);
    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Windows should respond to SMB3 negotiate with encryption support");

    let mut auth = NtlmAuthenticator::new(config.credentials());
    let connection = connection
        .authenticate(&mut auth)
        .await
        .expect("Windows should accept NTLMv2 session setup");

    let unc = format!(r"\\{}\{}", config.host, config.share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
        .expect("Windows should allow tree connect to the encrypted share");

    Some((config, connection))
}

#[tokio::test]
async fn creates_writes_reads_and_closes_file_over_encrypted_tree_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    if !matches!(
        connection.state().negotiated.dialect_revision,
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311
    ) {
        eprintln!("skipping Windows encryption test: negotiated dialect is not SMB 3.x");
        return;
    }

    assert!(
        connection.state().encryption_required,
        "encrypted share should force encrypted SMB traffic"
    );

    let path = unique_path_in_dir("smolder-win-encryption", &config.test_dir);
    let payload = b"smolder windows encrypted core io".to_vec();

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Windows should create the encrypted test file");
    let wrote = connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload.clone()))
        .await
        .expect("Windows should write the encrypted test payload");
    connection
        .flush(&FlushRequest::for_file(created.file_id))
        .await
        .expect("Windows should flush the encrypted test payload");
    let read = connection
        .read(&ReadRequest::for_file(
            created.file_id,
            0,
            payload.len() as u32,
        ))
        .await
        .expect("Windows should read back the encrypted test payload");
    let closed = connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Windows should close the encrypted test file");

    assert_eq!(wrote.count, payload.len() as u32);
    assert_eq!(read.data, payload);
    assert_eq!(closed.flags, 0);
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));

    let connection = connection
        .tree_disconnect()
        .await
        .expect("Windows should disconnect the encrypted tree");
    connection
        .logoff()
        .await
        .expect("Windows should log off the encrypted SMB session");
}
