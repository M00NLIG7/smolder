use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::prelude::{Client, NtlmCredentials, TransportTarget};

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct SambaNetbiosConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    share: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl SambaNetbiosConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: required_env("SMOLDER_SAMBA_NETBIOS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(1139),
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            share: required_env("SMOLDER_SAMBA_SHARE")?,
            domain: required_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: required_env("SMOLDER_SAMBA_WORKSTATION"),
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

fn unique_test_file_path() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!("smolder-netbios-{}-{}.txt", std::process::id(), stamp)
}

#[tokio::test]
async fn authenticates_and_roundtrips_file_io_over_netbios_when_configured() {
    let Some(config) = SambaNetbiosConfig::from_env() else {
        eprintln!(
            "skipping live Samba NetBIOS test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, SMOLDER_SAMBA_PASSWORD, and SMOLDER_SAMBA_SHARE must be set"
        );
        return;
    };

    let target = TransportTarget::netbios(config.host.clone())
        .with_connect_host(config.host.clone())
        .with_port(config.port);
    let client = Client::builder(config.host.clone())
        .with_transport_target(target)
        .with_ntlm_credentials(config.credentials())
        .build()
        .expect("client builder should succeed");

    let mut share = client
        .connect_share(&config.share)
        .await
        .expect("NetBIOS session should authenticate and tree-connect");
    assert_ne!(share.session_id().0, 0, "NetBIOS session id should be non-zero");
    assert_ne!(share.tree_id().0, 0, "NetBIOS tree id should be non-zero");

    let path = unique_test_file_path();
    let payload = b"smolder samba netbios io".to_vec();

    share
        .put(&path, &payload)
        .await
        .expect("NetBIOS share should create and write the test file");
    let read_back = share
        .get(&path)
        .await
        .expect("NetBIOS share should read back the test file");
    assert_eq!(read_back, payload);

    share
        .remove(&path)
        .await
        .expect("NetBIOS share should delete the test file");
    share.logoff().await.expect("NetBIOS logoff should succeed");
}
