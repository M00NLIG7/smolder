#![allow(dead_code)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::error::CoreError;
use smolder_tools::prelude::{NtlmCredentials, Share, ShareReconnectPlan, SmbClient};

pub fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn optional_env(name: &str) -> Option<String> {
    required_env(name)
}

fn optional_u16_env(name: &str, default: u16) -> u16 {
    optional_env(name)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(default)
}

pub fn ntlm_credentials(
    username: &str,
    password: &str,
    domain: Option<&str>,
    workstation: Option<&str>,
) -> NtlmCredentials {
    let mut credentials = NtlmCredentials::new(username, password);
    if let Some(domain) = domain {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = workstation {
        credentials = credentials.with_workstation(workstation);
    }
    credentials
}

#[derive(Debug, Clone)]
pub struct SambaConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub share: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl SambaConfig {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: optional_u16_env("SMOLDER_SAMBA_PORT", 445),
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            share: required_env("SMOLDER_SAMBA_SHARE")?,
            domain: optional_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: optional_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }

    pub fn encrypted_share_from_env() -> Option<Self> {
        let mut config = Self::from_env()?;
        config.share = required_env("SMOLDER_SAMBA_ENCRYPTED_SHARE")?;
        Some(config)
    }

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }

    pub async fn connect_share(&self, require_encryption: bool) -> Result<Share, CoreError> {
        let mut builder = SmbClient::builder()
            .server(self.host.clone())
            .port(self.port)
            .credentials(self.credentials());
        if require_encryption {
            builder = builder.require_encryption(true);
        }

        let client = builder.connect().await?;
        client.share(self.share.clone()).await
    }

    pub fn smb_url(&self, remote_path: &str) -> String {
        if remote_path.is_empty() {
            format!("smb://{}:{}/{}", self.host, self.port, self.share)
        } else {
            format!(
                "smb://{}:{}/{}/{}",
                self.host, self.port, self.share, remote_path
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowsConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub share: String,
    pub test_dir: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl WindowsConfig {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: optional_u16_env("SMOLDER_WINDOWS_PORT", 445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            share: optional_env("SMOLDER_WINDOWS_SHARE").unwrap_or_else(|| "ADMIN$".to_string()),
            test_dir: optional_env("SMOLDER_WINDOWS_TEST_DIR")
                .unwrap_or_else(|| "Temp".to_string()),
            domain: optional_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: optional_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    pub fn encrypted_from_env() -> Option<Self> {
        let mut config = Self::from_env()?;
        config.share = required_env("SMOLDER_WINDOWS_ENCRYPTED_SHARE")?;
        config.test_dir = optional_env("SMOLDER_WINDOWS_ENCRYPTED_TEST_DIR").unwrap_or_default();
        Some(config)
    }

    pub fn admin_share_probe_from_env() -> Option<Self> {
        let mut config = Self::from_env()?;
        config.share = "ADMIN$".to_string();
        config.test_dir.clear();
        Some(config)
    }

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }

    pub async fn connect_share(&self, require_encryption: bool) -> Result<Share, CoreError> {
        let mut builder = SmbClient::builder()
            .server(self.host.clone())
            .port(self.port)
            .credentials(self.credentials());
        if require_encryption {
            builder = builder.require_encryption(true);
        }

        let client = builder.connect().await?;
        client.share(self.share.clone()).await
    }

    pub fn reconnect_plan(&self) -> ShareReconnectPlan {
        ShareReconnectPlan::new(self.host.clone(), self.share.clone(), self.credentials())
            .port(self.port)
    }
}

pub fn unique_name(prefix: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!("{prefix}-{}-{stamp}.txt", std::process::id())
}

pub fn temp_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(unique_name(prefix))
}

pub fn unique_windows_path(prefix: &str, test_dir: &str) -> String {
    let file_name = unique_name(prefix);
    if test_dir.trim_matches(['\\', '/']).is_empty() {
        file_name
    } else {
        format!("{}\\{file_name}", test_dir.trim_matches(['\\', '/']))
    }
}
