use smolder_core::auth::NtlmCredentials;
use smolder_core::facade::Client;

const DEFAULT_SHARE: &str = "share";
const DEFAULT_PATH: &str = "smolder-client-file-facade.txt";

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::test]
async fn client_file_facade_roundtrip_when_configured() {
    let Some(host) = required_env("SMOLDER_FACADE_HOST") else {
        eprintln!("skipping client file facade interop: SMOLDER_FACADE_HOST not set");
        return;
    };
    let Some(username) = required_env("SMOLDER_FACADE_USERNAME") else {
        eprintln!("skipping client file facade interop: SMOLDER_FACADE_USERNAME not set");
        return;
    };
    let Some(password) = required_env("SMOLDER_FACADE_PASSWORD") else {
        eprintln!("skipping client file facade interop: SMOLDER_FACADE_PASSWORD not set");
        return;
    };

    let port = optional_env("SMOLDER_FACADE_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);
    let share_name =
        optional_env("SMOLDER_FACADE_SHARE").unwrap_or_else(|| DEFAULT_SHARE.to_owned());
    let path = optional_env("SMOLDER_FACADE_PATH").unwrap_or_else(|| DEFAULT_PATH.to_owned());
    let alias_data = b"share-level facade roundtrip\n";
    let handle_data = b"open file facade roundtrip\n";

    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = optional_env("SMOLDER_FACADE_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_FACADE_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()
        .expect("client should build");
    let mut share = client
        .connect_share(&share_name)
        .await
        .expect("share connect should succeed");

    share
        .put(&path, alias_data)
        .await
        .expect("share put should succeed");
    let read_back = share.get(&path).await.expect("share get should succeed");
    assert_eq!(read_back, alias_data);
    let metadata = share
        .metadata(&path)
        .await
        .expect("share metadata should succeed");
    assert_eq!(metadata.size, alias_data.len() as u64);
    share
        .remove(&path)
        .await
        .expect("share remove should succeed");

    let mut writer = share
        .open_writer(&path)
        .await
        .expect("open_writer should succeed");
    writer
        .write_all(handle_data)
        .await
        .expect("file write_all should succeed");
    writer
        .sync_all()
        .await
        .expect("file sync_all should succeed");
    let share = writer.close().await.expect("file close should succeed");

    let mut reader = share
        .open_reader(&path)
        .await
        .expect("open_reader should succeed");
    let read_back = reader
        .read_to_end()
        .await
        .expect("file read_to_end should succeed");
    assert_eq!(read_back, handle_data);
    let mut share = reader.close().await.expect("file close should succeed");

    share
        .remove(&path)
        .await
        .expect("share remove should succeed");
    share.logoff().await.expect("share logoff should succeed");
}
