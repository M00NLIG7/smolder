mod common;

use common::{unique_path_in_dir, windows_lock, WindowsNtlmConfig, WindowsShareConfig};
use smolder_core::prelude::{
    Connection, NtlmAuthenticator, TokioTcpTransport, TreeConnected,
};
use smolder_proto::smb::smb2::{
    CipherId, CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect, EchoResponse,
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
        client_guid: *b"smolder-winint01",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: b"smolder-windows-interop-salt".to_vec(),
            }),
            NegotiateContext::encryption_capabilities(EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            }),
        ],
    }
}

async fn authenticated_tree_connection(
) -> Option<(WindowsShareConfig, Connection<TokioTcpTransport, TreeConnected>)> {
    let Some(config) = WindowsShareConfig::from_env() else {
        eprintln!(
            "skipping live Windows interop test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
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
        .expect("Windows should respond to SMB2 negotiate");

    let mut auth = NtlmAuthenticator::new(config.credentials());
    let connection = connection
        .authenticate(&mut auth)
        .await
        .expect("Windows should accept NTLMv2 session setup");

    let unc = format!(r"\\{}\{}", config.host, config.share);
    let connection = connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
        .expect("Windows should allow tree connect");

    Some((config, connection))
}

#[tokio::test]
async fn negotiates_with_windows_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = WindowsNtlmConfig::from_env() else {
        eprintln!("skipping live Windows negotiate test: SMOLDER_WINDOWS_HOST is not set");
        return;
    };

    let transport = TokioTcpTransport::connect((config.host.as_str(), config.port))
        .await
        .expect("should connect to configured Windows endpoint");
    let connection = Connection::new(transport);
    let connection = connection
        .negotiate(&negotiate_request())
        .await
        .expect("Windows should respond to SMB2 negotiate");

    let dialect = connection.state().response.dialect_revision;
    assert!(matches!(
        dialect,
        Dialect::Smb210 | Dialect::Smb302 | Dialect::Smb311
    ));
}

#[tokio::test]
async fn authenticates_and_connects_tree_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((_config, connection)) = authenticated_tree_connection().await else {
        return;
    };

    assert_ne!(connection.state().session_id, SessionId(0));
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));
    assert!(connection.session_key().is_some());
}

#[tokio::test]
async fn echoes_after_authentication_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((_config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let echoed = connection
        .echo()
        .await
        .expect("Windows should respond to SMB2 echo on an authenticated session");

    assert_eq!(echoed, EchoResponse);
}

#[tokio::test]
async fn creates_writes_reads_and_closes_file_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let path = unique_path_in_dir("smolder-win-interop", &config.test_dir);
    let payload = b"smolder windows core interop".to_vec();

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Windows should create the interop test file");
    let wrote = connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload.clone()))
        .await
        .expect("Windows should write the interop test payload");
    let read = connection
        .read(&ReadRequest::for_file(
            created.file_id,
            0,
            payload.len() as u32,
        ))
        .await
        .expect("Windows should read back the interop test payload");
    let closed = connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Windows should close the interop test file");

    assert_eq!(wrote.count, payload.len() as u32);
    assert_eq!(read.data, payload);
    assert_eq!(closed.flags, 0);
}

#[tokio::test]
async fn flushes_disconnects_and_logs_off_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((config, mut connection)) = authenticated_tree_connection().await else {
        return;
    };

    let path = unique_path_in_dir("smolder-win-interop", &config.test_dir);
    let payload = b"smolder windows lifecycle".to_vec();

    let mut create_request = CreateRequest::from_path(&path);
    create_request.create_disposition = CreateDisposition::Create;
    create_request.create_options |= CreateOptions::DELETE_ON_CLOSE;
    create_request.desired_access |= 0x0001_0000;
    create_request.share_access |= ShareAccess::DELETE;

    let created = connection
        .create(&create_request)
        .await
        .expect("Windows should create the lifecycle test file");
    connection
        .write(&WriteRequest::for_file(created.file_id, 0, payload))
        .await
        .expect("Windows should write the lifecycle test payload");
    connection
        .flush(&FlushRequest::for_file(created.file_id))
        .await
        .expect("Windows should flush the lifecycle test file");
    let closed = connection
        .close(&CloseRequest {
            flags: 0,
            file_id: created.file_id,
        })
        .await
        .expect("Windows should close the lifecycle test file");

    assert_eq!(closed.flags, 0);

    let connection = connection
        .tree_disconnect()
        .await
        .expect("Windows should disconnect the tree");
    connection
        .logoff()
        .await
        .expect("Windows should log off the session");
}
