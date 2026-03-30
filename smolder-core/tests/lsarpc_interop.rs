use smolder_core::auth::NtlmCredentials;
use smolder_core::prelude::{Client, CoreError};
use smolder_proto::smb::status::NtStatus;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::test]
async fn queries_account_domain_info_when_configured() {
    let Some(host) = required_env("SMOLDER_WINDOWS_HOST") else {
        eprintln!("skipping live LSARPC test: SMOLDER_WINDOWS_HOST not set");
        return;
    };
    let Some(username) = required_env("SMOLDER_WINDOWS_USERNAME") else {
        eprintln!("skipping live LSARPC test: SMOLDER_WINDOWS_USERNAME not set");
        return;
    };
    let Some(password) = required_env("SMOLDER_WINDOWS_PASSWORD") else {
        eprintln!("skipping live LSARPC test: SMOLDER_WINDOWS_PASSWORD not set");
        return;
    };

    let port = optional_env("SMOLDER_WINDOWS_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(445);
    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = optional_env("SMOLDER_WINDOWS_DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_env("SMOLDER_WINDOWS_WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }

    let client = Client::builder(host)
        .with_port(port)
        .with_ntlm_credentials(credentials)
        .build()
        .expect("client should build");
    let mut lsarpc = match client.connect_lsarpc().await {
        Ok(lsarpc) => lsarpc,
        Err(CoreError::UnexpectedStatus {
            status,
            command: smolder_proto::smb::smb2::Command::Create,
        }) if status == NtStatus::OBJECT_NAME_NOT_FOUND.0 => {
            eprintln!("skipping live LSARPC test: the guest did not expose \\\\PIPE\\\\lsarpc");
            return;
        }
        Err(error) => panic!("LSARPC connect should succeed: {error:?}"),
    };

    let account_domain = lsarpc
        .account_domain_info()
        .await
        .expect("account domain query should succeed");
    assert!(
        !account_domain.name.is_empty(),
        "account domain name should not be empty"
    );
    assert!(
        account_domain.sid.is_some(),
        "account domain SID should be present"
    );

    let primary_domain = lsarpc
        .primary_domain_info()
        .await
        .expect("primary domain query should succeed");
    assert!(
        !primary_domain.name.is_empty(),
        "primary domain name should not be empty"
    );

    let connection = lsarpc
        .close()
        .await
        .expect("policy close should succeed")
        .into_pipe()
        .close()
        .await
        .expect("pipe close should succeed");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    connection.logoff().await.expect("logoff should succeed");
}
