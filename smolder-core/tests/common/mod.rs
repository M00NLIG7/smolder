#![allow(dead_code)]

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::auth::NtlmCredentials;
use smolder_core::error::CoreError;
use smolder_core::prelude::{Client, SmbSessionConfig};
use smolder_core::transport::TransportTarget;
use smolder_proto::rpc::{SyntaxId, Uuid};
use tokio::sync::Mutex;

pub fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn optional_env(name: &str) -> Option<String> {
    required_env(name)
}

pub fn optional_u16_env(name: &str, default: u16) -> u16 {
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
pub struct WindowsNtlmConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl WindowsNtlmConfig {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: optional_u16_env("SMOLDER_WINDOWS_PORT", 445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            domain: optional_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: optional_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }

    pub fn session(&self) -> SmbSessionConfig {
        SmbSessionConfig::new(self.host.clone(), self.credentials()).with_port(self.port)
    }

    pub fn client(&self) -> Result<Client, CoreError> {
        Client::builder(self.host.clone())
            .with_port(self.port)
            .with_ntlm_credentials(self.credentials())
            .build()
    }
}

#[derive(Debug, Clone)]
pub struct SambaShareConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub share: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl SambaShareConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_env_with_port_var("SMOLDER_SAMBA_PORT", 445)
    }

    pub fn encrypted_share_from_env() -> Option<Self> {
        let mut config = Self::from_env()?;
        config.share = required_env("SMOLDER_SAMBA_ENCRYPTED_SHARE")?;
        Some(config)
    }

    pub fn from_env_with_port_var(port_var: &str, default_port: u16) -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: optional_u16_env(port_var, default_port),
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            share: required_env("SMOLDER_SAMBA_SHARE")?,
            domain: optional_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: optional_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct WindowsShareConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub share: String,
    pub test_dir: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl WindowsShareConfig {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: optional_u16_env("SMOLDER_WINDOWS_PORT", 445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            share: optional_env("SMOLDER_WINDOWS_SHARE").unwrap_or_else(|| "ADMIN$".to_owned()),
            test_dir: optional_env("SMOLDER_WINDOWS_TEST_DIR").unwrap_or_else(|| "Temp".to_owned()),
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

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct QuicNtlmConfig {
    pub server: String,
    pub connect_host: String,
    pub tls_server_name: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub share: String,
    pub test_dir: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl QuicNtlmConfig {
    pub fn from_env(prefix: &str) -> Option<Self> {
        let server = required_env(&prefixed_key(prefix, "SERVER"))?;
        Some(Self {
            connect_host: optional_env(&prefixed_key(prefix, "CONNECT_HOST"))
                .unwrap_or_else(|| server.clone()),
            tls_server_name: optional_env(&prefixed_key(prefix, "TLS_SERVER_NAME"))
                .unwrap_or_else(|| server.clone()),
            port: optional_u16_env(&prefixed_key(prefix, "PORT"), 443),
            username: required_env(&prefixed_key(prefix, "USERNAME"))?,
            password: required_env(&prefixed_key(prefix, "PASSWORD"))?,
            share: required_env(&prefixed_key(prefix, "SHARE"))?,
            test_dir: optional_env(&prefixed_key(prefix, "TEST_DIR")).unwrap_or_default(),
            domain: optional_env(&prefixed_key(prefix, "DOMAIN")),
            workstation: optional_env(&prefixed_key(prefix, "WORKSTATION")),
            server,
        })
    }

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }

    pub fn client(&self) -> Result<Client, CoreError> {
        Client::builder(self.server.clone())
            .with_transport_target(TransportTarget::quic(self.server.clone()))
            .with_port(self.port)
            .with_connect_host(self.connect_host.clone())
            .with_tls_server_name(self.tls_server_name.clone())
            .with_ntlm_credentials(self.credentials())
            .build()
    }
}

#[derive(Debug, Clone)]
pub struct SambaNtlmConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub workstation: Option<String>,
}

impl SambaNtlmConfig {
    pub fn from_env_with_defaults() -> Option<Self> {
        let host = optional_env("SMOLDER_SAMBA_HOST")?;
        Some(Self {
            host,
            port: optional_u16_env("SMOLDER_SAMBA_PORT", 445),
            username: optional_env("SMOLDER_SAMBA_USERNAME")
                .unwrap_or_else(|| "smolder".to_owned()),
            password: optional_env("SMOLDER_SAMBA_PASSWORD")
                .unwrap_or_else(|| "smolderpass".to_owned()),
            domain: optional_env("SMOLDER_SAMBA_DOMAIN").or_else(|| Some("WORKGROUP".to_owned())),
            workstation: optional_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }

    pub fn credentials(&self) -> NtlmCredentials {
        ntlm_credentials(
            &self.username,
            &self.password,
            self.domain.as_deref(),
            self.workstation.as_deref(),
        )
    }

    pub fn session(&self) -> SmbSessionConfig {
        SmbSessionConfig::new(self.host.clone(), self.credentials()).with_port(self.port)
    }

    pub fn client(&self) -> Result<Client, CoreError> {
        Client::builder(self.host.clone())
            .with_port(self.port)
            .with_ntlm_credentials(self.credentials())
            .build()
    }
}

pub fn windows_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn unique_name(prefix: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!("{prefix}-{}-{stamp}", std::process::id())
}

pub fn unique_path_in_dir(prefix: &str, directory: &str) -> String {
    let file_name = format!("{}.txt", unique_name(prefix));
    if directory.trim_matches(['\\', '/']).is_empty() {
        file_name
    } else {
        format!("{}\\{file_name}", directory.trim_matches(['\\', '/']))
    }
}

pub const SVCCTL_CONTEXT_ID: u16 = 0;
pub const SVCCTL_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x367a_bb81,
        0x9844,
        0x35f1,
        [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
    ),
    2,
    0,
);
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_CONNECT: u32 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScHandle(pub [u8; 20]);

pub fn open_sc_manager_stub() -> Vec<u8> {
    let mut stub = NdrWriter::new();
    stub.write_unique_wide_string(None);
    stub.write_unique_wide_string(Some("ServicesActive"));
    stub.write_u32(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    stub.into_bytes()
}

pub fn parse_open_handle_response(response: &[u8]) -> Result<ScHandle, CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "scmr open-handle response was too short",
        ));
    }
    let mut handle = [0_u8; 20];
    handle.copy_from_slice(&response[..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "open_sc_manager",
            code: status,
        });
    }
    Ok(ScHandle(handle))
}

struct NdrWriter {
    bytes: Vec<u8>,
    referent: u32,
}

impl NdrWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            referent: 1,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn write_u32(&mut self, value: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_unique_wide_string(&mut self, value: Option<&str>) {
        self.align(4);
        match value {
            Some(value) => {
                let referent = self.next_referent();
                self.bytes.extend_from_slice(&referent.to_le_bytes());
                self.write_wide_string_body(value);
            }
            None => self.bytes.extend_from_slice(&0_u32.to_le_bytes()),
        }
    }

    fn write_wide_string_body(&mut self, value: &str) {
        self.align(4);
        let mut encoded = value.encode_utf16().collect::<Vec<_>>();
        encoded.push(0);
        let count = encoded.len() as u32;
        self.bytes.extend_from_slice(&count.to_le_bytes());
        self.bytes.extend_from_slice(&0_u32.to_le_bytes());
        self.bytes.extend_from_slice(&count.to_le_bytes());
        for code_unit in encoded {
            self.bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        self.align(4);
    }

    fn align(&mut self, alignment: usize) {
        let padding = (alignment - (self.bytes.len() % alignment)) % alignment;
        self.bytes.resize(self.bytes.len() + padding, 0);
    }

    fn next_referent(&mut self) -> u32 {
        let current = self.referent;
        self.referent += 1;
        current
    }
}

fn prefixed_key(prefix: &str, suffix: &str) -> String {
    format!("{prefix}_{suffix}")
}
