use std::fs;
use std::sync::OnceLock;
use std::time::Duration;

use smolder_proto::smb::smb2::LeaseState;
use smolder_tools::prelude::{LeaseRequest, OpenOptions, Share, SmbDirectoryEntry};
use tokio::sync::Mutex;
use tokio::time::sleep;

mod common;
use common::{SambaConfig, temp_path, unique_name};

async fn connected_share() -> Option<(SambaConfig, Share)> {
    let Some(config) = SambaConfig::from_env() else {
        eprintln!(
            "skipping high-level Samba test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return None;
    };
    let share = config
        .connect_share(false)
        .await
        .expect("should connect high-level share");
    Some((config, share))
}

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn wait_for_listing_entry(
    share: &mut Share,
    name: &str,
    present: bool,
) -> Vec<SmbDirectoryEntry> {
    let mut last_listing = Vec::new();
    for _ in 0..10 {
        let listing = share.list("").await.expect("listing should succeed");
        if listing.iter().any(|entry| entry.name == name) == present {
            return listing;
        }
        last_listing = listing;
        sleep(Duration::from_millis(50)).await;
    }
    last_listing
}

#[tokio::test]
async fn writes_and_reads_with_high_level_api_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-read");
    let payload = b"smolder high level io";

    share
        .write(&remote_path, payload)
        .await
        .expect("high-level write should succeed");
    let round_trip = share
        .read(&remote_path)
        .await
        .expect("high-level read should succeed");

    assert_eq!(round_trip, payload);
}

#[tokio::test]
async fn removes_files_from_fresh_connection_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-remove");
    share
        .write(&remote_path, b"smolder high level remove")
        .await
        .expect("high-level write should succeed");
    drop(share);

    let Some((_config, mut share)) = connected_share().await else {
        return;
    };
    share
        .remove(&remote_path)
        .await
        .expect("fresh-connection remove should succeed");

    let listing = share.list("").await.expect("listing should succeed");
    assert!(!listing.iter().any(|entry| entry.name == remote_path));
}

#[tokio::test]
async fn puts_and_gets_local_files_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-put");
    let local_upload = temp_path("smolder-upload");
    let local_download = temp_path("smolder-download");
    let payload = b"smolder high level transfer".to_vec();

    fs::write(&local_upload, &payload).expect("should create upload fixture");

    let uploaded = share
        .put(&local_upload, &remote_path)
        .await
        .expect("high-level put should succeed");
    let downloaded = share
        .get(&remote_path, &local_download)
        .await
        .expect("high-level get should succeed");
    let local_copy = fs::read(&local_download).expect("should read downloaded file");

    assert_eq!(uploaded, payload.len() as u64);
    assert_eq!(downloaded, payload.len() as u64);
    assert_eq!(local_copy, payload);

    let _ = fs::remove_file(local_upload);
    let _ = fs::remove_file(local_download);
}

#[tokio::test]
async fn lists_stats_renames_and_removes_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let original_path = unique_name("smolder-high-level-meta");
    let renamed_path = format!("{original_path}.renamed");
    let payload = b"smolder high level metadata";

    share
        .write(&original_path, payload)
        .await
        .expect("should create file for metadata test");

    let listing = wait_for_listing_entry(&mut share, &original_path, true).await;
    assert!(listing.iter().any(|entry| entry.name == original_path));

    let metadata = share
        .stat(&original_path)
        .await
        .expect("stat should succeed");
    assert_eq!(metadata.size, payload.len() as u64);
    assert!(metadata.is_file());

    share
        .rename(&original_path, &renamed_path)
        .await
        .expect("rename should succeed");
    let renamed_listing = wait_for_listing_entry(&mut share, &renamed_path, true).await;
    assert!(
        !renamed_listing
            .iter()
            .any(|entry| entry.name == original_path)
    );
    assert!(
        renamed_listing
            .iter()
            .any(|entry| entry.name == renamed_path)
    );

    share
        .remove(&renamed_path)
        .await
        .expect("remove should succeed");
    let final_listing = wait_for_listing_entry(&mut share, &renamed_path, false).await;
    assert!(!final_listing.iter().any(|entry| entry.name == renamed_path));
}

#[tokio::test]
async fn flushes_disconnects_and_logs_off_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-lifecycle");
    let payload = b"smolder high level lifecycle";

    let mut file = share
        .open(
            &remote_path,
            OpenOptions::new().write(true).create(true).truncate(true),
        )
        .await
        .expect("open should succeed");
    file.write_all(payload).await.expect("write should succeed");
    file.flush().await.expect("flush should succeed");
    file.close().await.expect("close should succeed");

    let metadata = share.stat(&remote_path).await.expect("stat should succeed");
    assert_eq!(metadata.size, payload.len() as u64);

    share
        .remove(&remote_path)
        .await
        .expect("remove should succeed");

    let client = share.disconnect().await.expect("disconnect should succeed");
    client.logoff().await.expect("logoff should succeed");
}

#[tokio::test]
async fn opens_file_with_lease_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some((_config, mut share)) = connected_share().await else {
        return;
    };

    let remote_path = unique_name("smolder-high-level-lease");
    let lease_key = *b"lease-key-000000";
    let requested = LeaseRequest::new(
        lease_key,
        LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING,
    );

    let mut file = share
        .open(
            &remote_path,
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .lease(requested),
        )
        .await
        .expect("lease open should succeed");
    let Some(granted) = file.lease() else {
        eprintln!(
            "skipping lease grant assertion: Samba accepted the lease-aware high-level open but did not grant lease metadata under the current fixture policy"
        );
        file.close().await.expect("close should succeed");
        share
            .remove(&remote_path)
            .await
            .expect("remove should succeed");
        return;
    };
    assert_eq!(granted.key, lease_key);
    assert!(granted.state.contains(LeaseState::READ_CACHING));

    file.write_all(b"lease test")
        .await
        .expect("write should succeed");
    file.flush().await.expect("flush should succeed");
    file.close().await.expect("close should succeed");

    share
        .remove(&remote_path)
        .await
        .expect("remove should succeed");
}

#[tokio::test]
async fn writes_and_reads_with_required_encryption_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = SambaConfig::encrypted_share_from_env() else {
        eprintln!(
            "skipping encrypted Samba test: SMOLDER_SAMBA_ENCRYPTED_SHARE must be set to a share that requires SMB encryption"
        );
        return;
    };

    let mut share = config
        .connect_share(true)
        .await
        .expect("should connect encrypted high-level share");
    let remote_path = unique_name("smolder-high-level-encrypted");
    let payload = b"smolder high level encrypted io";

    share
        .write(&remote_path, payload)
        .await
        .expect("encrypted high-level write should succeed");
    let round_trip = share
        .read(&remote_path)
        .await
        .expect("encrypted high-level read should succeed");
    share
        .remove(&remote_path)
        .await
        .expect("encrypted high-level remove should succeed");

    assert_eq!(round_trip, payload);
}
