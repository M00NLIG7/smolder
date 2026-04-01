use smolder_core::lsarpc::LsaServerRole;
use smolder_core::prelude::{LOOKUP_POLICY_ACCESS, LsarpcClient};
use smolder_proto::smb::status::NtStatus;

const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_INVALID_INFO_CLASS: u32 = 0xc000_0003;

mod common;
use common::{SambaNtlmConfig, samba_lock};

#[tokio::test]
async fn queries_and_closes_samba_lsarpc_policy_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = SambaNtlmConfig::from_env_with_defaults() else {
        eprintln!("skipping live Samba LSARPC test: SMOLDER_SAMBA_HOST must be set");
        return;
    };

    let lookup_name = config.username.clone();
    let client = config.client().expect("client builder should succeed");
    let mut lsarpc = client
        .connect_lsarpc_with_access(LOOKUP_POLICY_ACCESS)
        .await
        .expect("should bind and open lsarpc on Samba");
    assert_eq!(
        lsarpc.desired_access(),
        LOOKUP_POLICY_ACCESS,
        "typed Samba LSARPC client should retain its requested policy access"
    );
    let primary_domain = lsarpc
        .primary_domain_info()
        .await
        .expect("primary domain query should succeed on standalone Samba");
    assert!(
        !primary_domain.name.is_empty(),
        "standalone Samba should report a primary domain or workgroup name"
    );
    let account_domain = lsarpc
        .account_domain_info()
        .await
        .expect("account domain query should succeed on standalone Samba");
    assert!(
        !account_domain.name.is_empty(),
        "standalone Samba should report an account domain name"
    );
    assert!(
        account_domain.sid.is_some(),
        "standalone Samba account domain information should include a SID"
    );
    let qualified_lookup_name = format!(r"{}\{}", account_domain.name, lookup_name);
    let translated_account_domain = lsarpc
        .lookup_name(&qualified_lookup_name)
        .await
        .expect("user lookup should succeed on standalone Samba")
        .expect("the configured Samba user should translate to a SID");
    assert_eq!(
        translated_account_domain
            .domain
            .as_ref()
            .and_then(|domain| domain.sid.clone()),
        account_domain.sid,
        "LSARPC lookup should report the same account domain SID: {:?}",
        translated_account_domain
    );
    assert!(
        translated_account_domain.sid.is_some(),
        "LSARPC lookup should reconstruct a full user SID: {:?}",
        translated_account_domain
    );

    let dns_domain = match lsarpc.dns_domain_info().await {
        Ok(info) => info,
        Err(error) if is_unsupported_policy_query_error(&error) => {
            eprintln!(
                "skipping live Samba LSARPC test: DNS domain policy queries are not supported"
            );
            close_lsarpc(lsarpc).await;
            return;
        }
        Err(error) => panic!("DNS domain query should succeed on standalone Samba: {error:?}"),
    };
    assert!(
        !dns_domain.name.is_empty(),
        "standalone Samba DNS domain info should include a primary domain name"
    );

    let server_role = match lsarpc.server_role().await {
        Ok(role) => role,
        Err(error) if is_unsupported_policy_query_error(&error) => {
            eprintln!(
                "skipping live Samba LSARPC test: server role policy queries are not supported"
            );
            close_lsarpc(lsarpc).await;
            return;
        }
        Err(error) => panic!("server role query should succeed on standalone Samba: {error:?}"),
    };
    assert!(
        matches!(
            server_role,
            LsaServerRole::Primary | LsaServerRole::Backup | LsaServerRole::Unknown(_)
        ),
        "standalone Samba server role should decode a role value"
    );

    let connection = close_lsarpc(lsarpc)
        .await
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

async fn close_lsarpc(lsarpc: LsarpcClient) -> smolder_core::rpc::PipeRpcClient {
    lsarpc.close().await.expect("policy close should succeed")
}

fn is_unsupported_policy_query_error(error: &smolder_core::prelude::CoreError) -> bool {
    matches!(
        error,
        smolder_core::prelude::CoreError::RemoteOperation { code, .. }
            if *code == STATUS_INVALID_PARAMETER
                || *code == STATUS_INVALID_INFO_CLASS
                || *code == STATUS_NOT_SUPPORTED
                || *code == NtStatus::OBJECT_NAME_NOT_FOUND.0
    )
}
