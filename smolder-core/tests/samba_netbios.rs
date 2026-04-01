mod common;

use common::{unique_path_in_dir, SambaShareConfig};
use smolder_core::prelude::{Client, TransportTarget};

#[tokio::test]
async fn authenticates_and_roundtrips_file_io_over_netbios_when_configured() {
    let Some(config) = SambaShareConfig::from_env_with_port_var("SMOLDER_SAMBA_NETBIOS_PORT", 1139)
    else {
        eprintln!(
            "skipping live Samba NetBIOS test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return;
    };

    let target = TransportTarget::netbios(config.host.clone())
        .with_connect_host(config.host.clone())
        .with_port(config.port);
    let client = Client::builder(config.host.clone())
        .with_transport_target(target)
        .with_ntlm_credentials(config.credentials())
        .build()
        .expect("client builder should succeed");

    let mut share = client
        .connect_share(&config.share)
        .await
        .expect("NetBIOS session should authenticate and tree-connect");
    assert_ne!(
        share.session_id().0,
        0,
        "NetBIOS session id should be non-zero"
    );
    assert_ne!(share.tree_id().0, 0, "NetBIOS tree id should be non-zero");

    let path = unique_path_in_dir("smolder-netbios", "");
    let payload = b"smolder samba netbios io".to_vec();

    share
        .put(&path, &payload)
        .await
        .expect("NetBIOS share should create and write the test file");
    let read_back = share
        .get(&path)
        .await
        .expect("NetBIOS share should read back the test file");
    assert_eq!(read_back, payload);

    share
        .remove(&path)
        .await
        .expect("NetBIOS share should delete the test file");
    share.logoff().await.expect("NetBIOS logoff should succeed");
}
