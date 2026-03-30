use std::sync::OnceLock;

use smolder_core::prelude::{Client, CoreError, NtlmCredentials};
use smolder_proto::smb::smb2::Command;
use smolder_proto::smb::status::NtStatus;
use tokio::sync::Mutex;

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

    let session = client
        .connect()
        .await
        .expect("should authenticate to Windows over SMB");
    let mut samr = match session.connect_samr().await {
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

    assert!(!domains.is_empty(), "SAMR should enumerate at least one domain");
    assert!(
        domains
            .iter()
            .any(|domain| domain.name.eq_ignore_ascii_case("Builtin")),
        "Windows SAMR enumeration should include the Builtin domain"
    );
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

    let rpc = domain.close().await.expect("samr domain close should succeed");
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
