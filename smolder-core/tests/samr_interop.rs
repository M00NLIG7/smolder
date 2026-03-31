use std::sync::OnceLock;

use smolder_core::prelude::{Client, CoreError, NtlmCredentials};
use smolder_proto::smb::smb2::Command;
use smolder_proto::smb::status::NtStatus;
use tokio::sync::Mutex;

const SAMR_PIPE_CANDIDATES: &[&str] = &["samr", "lsarpc"];
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct WindowsSamrConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsSamrConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    fn credentials(&self) -> NtlmCredentials {
        let mut credentials = NtlmCredentials::new(self.username.clone(), self.password.clone());
        if let Some(domain) = &self.domain {
            credentials = credentials.with_domain(domain.clone());
        }
        if let Some(workstation) = &self.workstation {
            credentials = credentials.with_workstation(workstation.clone());
        }
        credentials
    }
}

fn windows_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn enumerates_windows_samr_domains_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = WindowsSamrConfig::from_env() else {
        eprintln!(
            "skipping live Windows SAMR test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return;
    };

    let client = Client::builder(config.host.clone())
        .with_port(config.port)
        .with_ntlm_credentials(config.credentials())
        .build()
        .expect("client builder should succeed");

    let mut samr = match connect_samr_from_client(&client).await {
        Ok(samr) => samr,
        Err(CoreError::UnexpectedStatus {
            command: Command::Create,
            status,
        }) if status == NtStatus::OBJECT_NAME_NOT_FOUND.0 => {
            eprintln!(
                "skipping live Windows SAMR test: the guest did not expose a reachable SAMR pipe endpoint"
            );
            return;
        }
        Err(error) => panic!("should bind and connect to samr: {error:?}"),
    };
    let domains = samr
        .enumerate_domains()
        .await
        .expect("SamrEnumerateDomainsInSamServer should succeed");

    assert!(
        !domains.is_empty(),
        "SAMR should enumerate at least one domain"
    );
    assert!(
        domains
            .iter()
            .any(|domain| domain.name.eq_ignore_ascii_case("Builtin")),
        "Windows SAMR enumeration should include the Builtin domain"
    );
    let builtin_domain = domains
        .iter()
        .find(|domain| domain.name.eq_ignore_ascii_case("Builtin"))
        .expect("Windows SAMR enumeration should include the Builtin domain")
        .name
        .clone();
    let account_domain = domains
        .iter()
        .find(|domain| !domain.name.eq_ignore_ascii_case("Builtin"))
        .expect("Windows SAMR enumeration should include a non-Builtin account domain")
        .name
        .clone();
    let mut domain = samr
        .open_domain(&account_domain)
        .await
        .expect("should open the enumerated account domain");
    let users = domain
        .enumerate_users(0)
        .await
        .expect("SamrEnumerateUsersInDomain should succeed");
    assert!(
        !users.is_empty(),
        "account-domain SAMR user enumeration should not be empty"
    );
    let first_user = users
        .first()
        .expect("enumerated account-domain users should include at least one entry")
        .clone();
    let mut user = domain
        .open_user(first_user.relative_id)
        .await
        .expect("should open the first enumerated user by RID");
    let user_info = user
        .query_account_name()
        .await
        .expect("SamrQueryInformationUser should succeed");
    assert_eq!(user_info.account_name, first_user.name);
    let domain = user.close().await.expect("samr user close should succeed");

    let rpc = domain
        .close()
        .await
        .expect("samr domain close should succeed");
    let connection = rpc
        .into_pipe()
        .close()
        .await
        .expect("pipe close should return the IPC$ tree");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    connection.logoff().await.expect("logoff should succeed");

    let samr = connect_samr_from_client(&client)
        .await
        .expect("should reconnect to samr for Builtin alias enumeration");
    let mut builtin = samr
        .open_domain(&builtin_domain)
        .await
        .expect("should open the Builtin domain");
    let aliases = builtin
        .enumerate_aliases()
        .await
        .expect("SamrEnumerateAliasesInDomain should succeed for Builtin");
    let administrators = aliases
        .iter()
        .find(|alias| alias.name.eq_ignore_ascii_case("Administrators"))
        .expect("Windows Builtin aliases should include Administrators")
        .clone();
    let mut alias = builtin
        .open_alias(administrators.relative_id)
        .await
        .expect("should open the Builtin Administrators alias");
    let alias_info = alias
        .query_general_information()
        .await
        .expect("SamrQueryInformationAlias should succeed for Builtin Administrators");
    assert_eq!(alias_info.name, administrators.name);
    let alias_members = match alias.enumerate_members().await {
        Ok(members) => members,
        Err(CoreError::RemoteOperation { code, .. })
            if code == STATUS_ACCESS_DENIED || code == STATUS_NOT_SUPPORTED =>
        {
            eprintln!("skipping Builtin alias member enumeration: alias membership is not available");
            let builtin = alias
                .close()
                .await
                .expect("samr alias close should succeed");
            let rpc = builtin
                .close()
                .await
                .expect("Builtin domain close should succeed");
            let connection = rpc
                .into_pipe()
                .close()
                .await
                .expect("pipe close should return the IPC$ tree");
            let connection = connection
                .tree_disconnect()
                .await
                .expect("tree disconnect should succeed");
            connection.logoff().await.expect("logoff should succeed");
            return;
        }
        Err(error) => panic!("SamrGetMembersInAlias should succeed for Builtin Administrators: {error:?}"),
    };
    assert!(
        !alias_members.is_empty(),
        "Builtin Administrators should have at least one member"
    );
    let builtin = alias
        .close()
        .await
        .expect("samr alias close should succeed");
    let rpc = builtin
        .close()
        .await
        .expect("Builtin domain close should succeed");
    let connection = rpc
        .into_pipe()
        .close()
        .await
        .expect("pipe close should return the IPC$ tree");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    connection.logoff().await.expect("logoff should succeed");
}

async fn connect_samr_from_client(
    client: &Client,
) -> Result<smolder_core::prelude::SamrClient, CoreError> {
    for pipe_name in SAMR_PIPE_CANDIDATES {
        let session = client.connect().await?;
        match session.connect_samr_pipe(pipe_name).await {
            Ok(samr) => return Ok(samr),
            Err(CoreError::UnexpectedStatus {
                command: Command::Create,
                status,
            }) if status == NtStatus::OBJECT_NAME_NOT_FOUND.0 => {}
            Err(error) => return Err(error),
        }
    }
    Err(CoreError::UnexpectedStatus {
        command: Command::Create,
        status: NtStatus::OBJECT_NAME_NOT_FOUND.0,
    })
}
