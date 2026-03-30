use std::sync::OnceLock;

use smolder_core::prelude::{Client, CoreError, NtlmCredentials};
use smolder_proto::smb::smb2::Command;
use smolder_proto::smb::status::NtStatus;
use tokio::sync::Mutex;

const SAMR_PIPE_CANDIDATES: &[&str] = &["samr", "lsarpc"];

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
        eprintln!(
            "skipping live Samba AD SAMR test: SMOLDER_SAMBA_AD_HOST must be set"
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
    assert!(!domains.is_empty(), "SAMR should enumerate at least one domain");
    assert!(
        domains
            .iter()
            .any(|domain| domain.name.eq_ignore_ascii_case("Builtin")),
        "Samba AD SAMR enumeration should include the Builtin domain"
    );
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
        users.iter().any(|user| user.name.eq_ignore_ascii_case("smolder")),
        "Samba AD SAMR user enumeration should include the fixture user"
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
