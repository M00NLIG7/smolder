#![cfg(feature = "quic")]

mod common;

use common::{samba_lock, unique_path_in_dir, QuicNtlmConfig};

#[tokio::test]
async fn authenticates_and_connects_tree_over_quic_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = QuicNtlmConfig::from_env("SMOLDER_SAMBA_QUIC") else {
        eprintln!(
            "skipping Samba SMB over QUIC test: SMOLDER_SAMBA_QUIC_SERVER, SMOLDER_SAMBA_QUIC_USERNAME, SMOLDER_SAMBA_QUIC_PASSWORD, and SMOLDER_SAMBA_QUIC_SHARE must be set"
        );
        return;
    };

    let client = config
        .client()
        .expect("client builder should accept QUIC config");
    let share = client
        .connect_share_quic(&config.share)
        .await
        .expect("Samba should accept SMB over QUIC tree connect");

    assert_ne!(share.session_id().0, 0, "session id should be assigned");
    assert_ne!(share.tree_id().0, 0, "tree id should be assigned");
    assert!(
        share.session_key().is_some(),
        "NTLM should export a session key"
    );

    share.logoff().await.expect("logoff should succeed");
}

#[tokio::test]
async fn roundtrips_file_io_over_quic_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = QuicNtlmConfig::from_env("SMOLDER_SAMBA_QUIC") else {
        eprintln!(
            "skipping Samba SMB over QUIC test: SMOLDER_SAMBA_QUIC_SERVER, SMOLDER_SAMBA_QUIC_USERNAME, SMOLDER_SAMBA_QUIC_PASSWORD, and SMOLDER_SAMBA_QUIC_SHARE must be set"
        );
        return;
    };

    let client = config
        .client()
        .expect("client builder should accept QUIC config");
    let mut share = client
        .connect_share_quic(&config.share)
        .await
        .expect("Samba should accept SMB over QUIC tree connect");

    let path = unique_path_in_dir("smolder-samba-quic", &config.test_dir);
    let payload = b"smolder samba quic interop".to_vec();
    share
        .put(&path, &payload)
        .await
        .expect("QUIC path should write the test payload");
    let read_back = share
        .get(&path)
        .await
        .expect("QUIC path should read back the test payload");
    share
        .remove(&path)
        .await
        .expect("QUIC path should remove the test payload");

    assert_eq!(read_back, payload);
    share.logoff().await.expect("logoff should succeed");
}
