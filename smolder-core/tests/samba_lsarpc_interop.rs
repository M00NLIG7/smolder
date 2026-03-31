use std::sync::OnceLock;

use smolder_core::prelude::{Client, LsarpcClient, NtlmCredentials};
use tokio::sync::Mutex;

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaLsarpcConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaLsarpcConfig {
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
async fn queries_and_closes_samba_lsarpc_policy_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = SambaLsarpcConfig::from_env() else {
        eprintln!("skipping live Samba LSARPC test: SMOLDER_SAMBA_HOST must be set");
        return;
    };

    let credentials = config.credentials();
    let client = Client::builder(config.host)
        .with_port(config.port)
        .with_ntlm_credentials(credentials)
        .build()
        .expect("client builder should succeed");
    let mut lsarpc = client
        .connect_lsarpc()
        .await
        .expect("should bind and open lsarpc on Samba");
    assert_eq!(
        lsarpc.desired_access(),
        smolder_core::prelude::DEFAULT_POLICY_ACCESS,
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
