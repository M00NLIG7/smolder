use smolder_core::auth::NtlmCredentials;
use smolder_core::lsarpc::LsaServerRole;
use smolder_core::prelude::{Client, CoreError, LOOKUP_POLICY_ACCESS, LsarpcClient};
use smolder_proto::smb::status::NtStatus;

const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

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
    let lookup_name = username.clone();

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
    let mut lsarpc = match client
        .connect_lsarpc_with_access(LOOKUP_POLICY_ACCESS)
        .await
    {
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
    assert_eq!(
        lsarpc.desired_access(),
        LOOKUP_POLICY_ACCESS,
        "typed Windows LSARPC client should retain its requested policy access"
    );

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
    let qualified_lookup_name = format!(r"{}\{}", account_domain.name, lookup_name);
    let translated_account_domain = lsarpc
        .lookup_name(&qualified_lookup_name)
        .await
        .expect("user lookup should succeed")
        .expect("the configured Windows user should translate to a SID");
    assert_eq!(
        translated_account_domain
            .domain
            .as_ref()
            .and_then(|domain| domain.sid.clone()),
        account_domain.sid,
        "LSARPC lookup should report the same account domain SID"
    );
    assert!(
        translated_account_domain.sid.is_some(),
        "LSARPC lookup should reconstruct a full user SID"
    );

    let primary_domain = lsarpc
        .primary_domain_info()
        .await
        .expect("primary domain query should succeed");
    assert!(
        !primary_domain.name.is_empty(),
        "primary domain name should not be empty"
    );

    let dns_domain = match lsarpc.dns_domain_info().await {
        Ok(info) => info,
        Err(error) if is_unsupported_policy_query_error(&error) => {
            eprintln!("skipping live LSARPC test: DNS domain policy queries are not supported");
            close_lsarpc(lsarpc).await;
            return;
        }
        Err(error) => panic!("DNS domain query should succeed: {error:?}"),
    };
    assert!(
        !dns_domain.name.is_empty(),
        "DNS domain info should include a primary domain name"
    );

    let server_role = match lsarpc.server_role().await {
        Ok(role) => role,
        Err(error) if is_unsupported_policy_query_error(&error) => {
            eprintln!("skipping live LSARPC test: server role policy queries are not supported");
            close_lsarpc(lsarpc).await;
            return;
        }
        Err(error) => panic!("server role query should succeed: {error:?}"),
    };
    assert!(
        matches!(
            server_role,
            LsaServerRole::Primary | LsaServerRole::Backup | LsaServerRole::Unknown(_)
        ),
        "server role query should decode a role value"
    );

    close_lsarpc(lsarpc).await;
}

fn is_unsupported_policy_query_error(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::RemoteOperation { code, .. }
            if *code == STATUS_INVALID_PARAMETER
                || *code == STATUS_NOT_SUPPORTED
                || *code == NtStatus::OBJECT_NAME_NOT_FOUND.0
    )
}

async fn close_lsarpc(lsarpc: LsarpcClient) {
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
