use smolder_core::error::CoreError;
use smolder_tools::prelude::Share;

mod common;
use common::{unique_windows_path, windows_lock, WindowsConfig};

async fn connected_share() -> Option<(WindowsConfig, Share)> {
    let Some(config) = WindowsConfig::encrypted_from_env() else {
        eprintln!(
            "skipping encrypted Windows test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, SMOLDER_WINDOWS_PASSWORD, and SMOLDER_WINDOWS_ENCRYPTED_SHARE must be set"
        );
        return None;
    };
    let share = config
        .connect_share(true)
        .await
        .expect("should connect encrypted Windows share");

    Some((config, share))
}

#[tokio::test]
async fn writes_and_reads_with_required_encryption_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some((config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_windows_path("smolder-win-encrypted", &config.test_dir);
    let payload = b"smolder windows encrypted io";

    share
        .write(&remote_path, payload)
        .await
        .expect("encrypted Windows write should succeed");
    let round_trip = share
        .read(&remote_path)
        .await
        .expect("encrypted Windows read should succeed");
    share
        .remove(&remote_path)
        .await
        .expect("encrypted Windows remove should succeed");

    assert_eq!(round_trip, payload);
}

#[tokio::test]
async fn require_encryption_rejects_admin_share_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = WindowsConfig::admin_share_probe_from_env() else {
        eprintln!(
            "skipping Windows encryption enforcement test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return;
    };

    let admin_share = config
        .connect_share(false)
        .await
        .expect("ADMIN$ should allow a baseline connection probe");
    if admin_share.encryption_required() {
        eprintln!(
            "skipping Windows encryption enforcement test: ADMIN$ already requires encryption on this fixture"
        );
        return;
    }

    let error = config
        .connect_share(true)
        .await
        .expect_err("ADMIN$ should be rejected when encryption is required");
    assert!(
        matches!(
            error,
            CoreError::Unsupported(
                "SMB encryption was required but the connected share did not require encryption"
            )
        ),
        "unexpected error: {error:?}"
    );
}
