use std::sync::OnceLock;

use smolder_core::prelude::{Client, NtlmCredentials, SamrClient};
use tokio::sync::Mutex;

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaSamrStandaloneConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaSamrStandaloneConfig {
    fn from_env() -> Option<Self> {
        let host = optional_env("SMOLDER_SAMBA_HOST")?;
        Some(Self {
            host,
            port: optional_env("SMOLDER_SAMBA_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: optional_env("SMOLDER_SAMBA_USERNAME")
                .unwrap_or_else(|| "smolder".to_owned()),
            password: optional_env("SMOLDER_SAMBA_PASSWORD")
                .unwrap_or_else(|| "smolderpass".to_owned()),
            domain: optional_env("SMOLDER_SAMBA_DOMAIN")
                .or_else(|| Some("WORKGROUP".to_owned())),
            workstation: optional_env("SMOLDER_SAMBA_WORKSTATION"),
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
async fn enumerates_standalone_samba_samr_domains_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = SambaSamrStandaloneConfig::from_env() else {
        eprintln!("skipping live standalone Samba SAMR test: SMOLDER_SAMBA_HOST must be set");
        return;
    };

    let credentials = config.credentials();
    let client = Client::builder(config.host)
        .with_port(config.port)
        .with_ntlm_credentials(credentials)
        .build()
        .expect("client builder should succeed");

    let mut samr = client
        .connect()
        .await
        .expect("session connect should succeed")
        .connect_samr_pipe("samr")
        .await
        .expect("standalone Samba should expose a samr pipe");
    assert_eq!(
        samr.revision().revision,
        2,
        "standalone Samba should currently use the SamrConnect2 fallback path"
    );

    let domains = samr
        .enumerate_domains()
        .await
        .expect("SamrEnumerateDomainsInSamServer should succeed");
    assert!(
        domains.iter().any(|domain| domain.name.eq_ignore_ascii_case("Builtin")),
        "standalone Samba SAMR enumeration should include Builtin"
    );
    assert!(
        domains
            .iter()
            .any(|domain| !domain.name.eq_ignore_ascii_case("Builtin")),
        "standalone Samba SAMR enumeration should include the local server domain"
    );

    let connection = close_samr(samr)
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

async fn close_samr(samr: SamrClient) -> smolder_core::rpc::PipeRpcClient {
    samr.close().await.expect("server close should succeed")
}
