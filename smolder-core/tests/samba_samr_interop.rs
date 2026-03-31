use std::sync::OnceLock;

use smolder_core::prelude::{Client, CoreError, NtlmCredentials};
use smolder_proto::smb::smb2::Command;
use smolder_proto::smb::status::NtStatus;
use tokio::sync::Mutex;

const SAMR_PIPE_CANDIDATES: &[&str] = &["samr", "lsarpc"];
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaSamrConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaSamrConfig {
    fn from_env() -> Option<Self> {
        let host = optional_env("SMOLDER_SAMBA_AD_HOST")?;
        Some(Self {
            host,
            port: optional_env("SMOLDER_SAMBA_AD_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: optional_env("SMOLDER_SAMBA_AD_USERNAME")
                .unwrap_or_else(|| "smolder".to_owned()),
            password: optional_env("SMOLDER_SAMBA_AD_PASSWORD")
                .unwrap_or_else(|| "Passw0rd!".to_owned()),
            domain: optional_env("SMOLDER_SAMBA_AD_DOMAIN").or_else(|| Some("LAB".to_owned())),
            workstation: optional_env("SMOLDER_SAMBA_AD_WORKSTATION"),
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

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn enumerates_samba_ad_samr_domains_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = SambaSamrConfig::from_env() else {
        eprintln!("skipping live Samba AD SAMR test: SMOLDER_SAMBA_AD_HOST must be set");
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
                "skipping live Samba AD SAMR test: the DC did not expose a reachable SAMR pipe endpoint"
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
        "Samba AD SAMR enumeration should include the Builtin domain"
    );
    let builtin_domain = domains
        .iter()
        .find(|domain| domain.name.eq_ignore_ascii_case("Builtin"))
        .expect("Samba AD SAMR enumeration should include the Builtin domain")
        .name
        .clone();
    let account_domain = domains
        .iter()
        .find(|domain| !domain.name.eq_ignore_ascii_case("Builtin"))
        .expect("Samba AD SAMR enumeration should include an account domain")
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
        users
            .iter()
            .any(|user| user.name.eq_ignore_ascii_case("smolder")),
        "Samba AD SAMR user enumeration should include the fixture user"
    );
    let fixture_user = users
        .iter()
        .find(|user| user.name.eq_ignore_ascii_case("smolder"))
        .expect("Samba AD SAMR enumeration should include the fixture user")
        .clone();
    let mut user = domain
        .open_user(fixture_user.relative_id)
        .await
        .expect("should open the fixture user by RID");
    let user_info = user
        .query_account_name()
        .await
        .expect("SamrQueryInformationUser should succeed");
    assert_eq!(user_info.account_name, fixture_user.name);
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
        .expect("Samba AD Builtin aliases should include Administrators")
        .clone();
    let mut alias = builtin
        .open_alias(administrators.relative_id)
        .await
        .expect("should open the Samba AD Builtin Administrators alias");
    let alias_info = alias
        .query_general_information()
        .await
        .expect("SamrQueryInformationAlias should succeed for Samba AD Builtin Administrators");
    assert_eq!(alias_info.name, administrators.name);
    let alias_members = match alias.enumerate_members().await {
        Ok(members) => members,
        Err(CoreError::RemoteOperation { code, .. })
            if code == STATUS_ACCESS_DENIED || code == STATUS_NOT_SUPPORTED =>
        {
            eprintln!("skipping Samba AD alias member enumeration: alias membership is not available");
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
        Err(error) => panic!(
            "SamrGetMembersInAlias should succeed for Samba AD Builtin Administrators: {error:?}"
        ),
    };
    assert!(
        !alias_members.is_empty(),
        "Samba AD Builtin Administrators should have at least one member"
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
