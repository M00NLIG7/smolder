//! Shared parsing and execution helpers for CLI binaries.

use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[cfg(feature = "kerberos")]
use smolder_core::auth::{KerberosCredentials, KerberosTarget};
use smolder_core::auth::NtlmCredentials;

use crate::fs::{Share, SmbClient, SmbClientBuilder, SmbMetadata};
use crate::remote_exec::{
    ExecMode, ExecRequest, InteractiveReader, InteractiveStdin, RemoteExecClient,
};

const ENV_AUTH_MODE: [&str; 2] = ["SMOLDER_SMB_AUTH", "SMOLDER_SAMBA_AUTH"];
const ENV_USERNAME: [&str; 2] = ["SMOLDER_SMB_USERNAME", "SMOLDER_SAMBA_USERNAME"];
const ENV_PASSWORD: [&str; 2] = ["SMOLDER_SMB_PASSWORD", "SMOLDER_SAMBA_PASSWORD"];
const ENV_DOMAIN: [&str; 3] = [
    "SMOLDER_SMB_DOMAIN",
    "SMOLDER_SAMBA_DOMAIN",
    "SMOLDER_KERBEROS_DOMAIN",
];
const ENV_WORKSTATION: [&str; 3] = [
    "SMOLDER_SMB_WORKSTATION",
    "SMOLDER_SAMBA_WORKSTATION",
    "SMOLDER_KERBEROS_WORKSTATION",
];
const ENV_KERBEROS_TARGET_HOST: [&str; 1] = ["SMOLDER_KERBEROS_TARGET_HOST"];
const ENV_KERBEROS_TARGET_PRINCIPAL: [&str; 1] = ["SMOLDER_KERBEROS_TARGET_PRINCIPAL"];
const ENV_KERBEROS_REALM: [&str; 1] = ["SMOLDER_KERBEROS_REALM"];
const ENV_KERBEROS_KDC_URL: [&str; 1] = ["SMOLDER_KERBEROS_KDC_URL"];
const ENV_PSEXEC_SERVICE_BINARY: [&str; 1] = ["SMOLDER_PSEXEC_SERVICE_BINARY"];
const INTERACTIVE_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthMode {
    Ntlm,
    Kerberos,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct KerberosOptions {
    pub(super) target_host: Option<String>,
    pub(super) target_principal: Option<String>,
    pub(super) realm: Option<String>,
    pub(super) kdc_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthOptions {
    pub(super) mode: AuthMode,
    pub(super) username: String,
    pub(super) password: String,
    pub(super) domain: Option<String>,
    pub(super) workstation: Option<String>,
    pub(super) kerberos: KerberosOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct AuthArgAccumulator {
    auth_mode: Option<String>,
    kerberos: bool,
    username: Option<String>,
    password: Option<String>,
    domain: Option<String>,
    workstation: Option<String>,
    target_host: Option<String>,
    target_principal: Option<String>,
    realm: Option<String>,
    kdc_url: Option<String>,
}

impl AuthArgAccumulator {
    pub(super) fn parse_flag(
        &mut self,
        args: &[String],
        index: &mut usize,
        token: &str,
    ) -> Result<bool, String> {
        if let Some(value) = token.strip_prefix("--auth=") {
            self.auth_mode = Some(value.to_string());
            return Ok(true);
        }
        if token == "--kerberos" {
            self.kerberos = true;
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--username=") {
            self.username = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--password=") {
            self.password = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--domain=") {
            self.domain = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--workstation=") {
            self.workstation = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--target-host=") {
            self.target_host = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--principal=") {
            self.target_principal = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--realm=") {
            self.realm = Some(value.to_string());
            return Ok(true);
        }
        if let Some(value) = token.strip_prefix("--kdc-url=") {
            self.kdc_url = Some(value.to_string());
            return Ok(true);
        }

        match token {
            "--auth" => {
                self.auth_mode = Some(next_value(args, index, "--auth")?);
                Ok(true)
            }
            "--username" => {
                self.username = Some(next_value(args, index, "--username")?);
                Ok(true)
            }
            "--password" => {
                self.password = Some(next_value(args, index, "--password")?);
                Ok(true)
            }
            "--domain" => {
                self.domain = Some(next_value(args, index, "--domain")?);
                Ok(true)
            }
            "--workstation" => {
                self.workstation = Some(next_value(args, index, "--workstation")?);
                Ok(true)
            }
            "--target-host" => {
                self.target_host = Some(next_value(args, index, "--target-host")?);
                Ok(true)
            }
            "--principal" => {
                self.target_principal = Some(next_value(args, index, "--principal")?);
                Ok(true)
            }
            "--realm" => {
                self.realm = Some(next_value(args, index, "--realm")?);
                Ok(true)
            }
            "--kdc-url" => {
                self.kdc_url = Some(next_value(args, index, "--kdc-url")?);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn resolve(self, usage: &str) -> Result<AuthOptions, String> {
        let username = self
            .username
            .or_else(|| env_value(&ENV_USERNAME))
            .ok_or_else(|| missing_env_error("username", &ENV_USERNAME, usage))?;
        let password = self
            .password
            .or_else(|| env_value(&ENV_PASSWORD))
            .ok_or_else(|| missing_env_error("password", &ENV_PASSWORD, usage))?;

        let kerberos = KerberosOptions {
            target_host: self
                .target_host
                .or_else(|| env_value(&ENV_KERBEROS_TARGET_HOST)),
            target_principal: self
                .target_principal
                .or_else(|| env_value(&ENV_KERBEROS_TARGET_PRINCIPAL)),
            realm: self.realm.or_else(|| env_value(&ENV_KERBEROS_REALM)),
            kdc_url: self.kdc_url.or_else(|| env_value(&ENV_KERBEROS_KDC_URL)),
        };

        let mode = resolve_auth_mode(self.auth_mode, self.kerberos, &kerberos)?;

        Ok(AuthOptions {
            mode,
            username,
            password,
            domain: self.domain.or_else(|| env_value(&ENV_DOMAIN)),
            workstation: self.workstation.or_else(|| env_value(&ENV_WORKSTATION)),
            kerberos,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteLocation {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) share: String,
    pub(super) path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecTarget {
    pub(super) host: String,
    pub(super) port: u16,
}

fn share_builder(options: &AuthOptions, remote: &RemoteLocation) -> SmbClientBuilder {
    let builder = SmbClient::builder()
        .server(remote.host.as_str())
        .port(remote.port);

    match options.mode {
        AuthMode::Ntlm => {
            let mut credentials = NtlmCredentials::new(&options.username, &options.password);
            if let Some(domain) = &options.domain {
                credentials = credentials.with_domain(domain.as_str());
            }
            if let Some(workstation) = &options.workstation {
                credentials = credentials.with_workstation(workstation.as_str());
            }
            builder.credentials(credentials)
        }
        AuthMode::Kerberos => {
            #[cfg(feature = "kerberos")]
            {
                let mut credentials = KerberosCredentials::new(&options.username, &options.password);
                if let Some(domain) = &options.domain {
                    credentials = credentials.with_domain(domain.as_str());
                }
                if let Some(workstation) = &options.workstation {
                    credentials = credentials.with_workstation(workstation.as_str());
                }
                if let Some(kdc_url) = &options.kerberos.kdc_url {
                    credentials = credentials.with_kdc_url(kdc_url.as_str());
                }

                let target_host = options
                    .kerberos
                    .target_host
                    .as_deref()
                    .unwrap_or(remote.host.as_str());
                let mut target = KerberosTarget::for_smb_host(target_host);
                if let Some(principal) = &options.kerberos.target_principal {
                    target = target.with_principal(principal.as_str());
                } else if let Some(realm) = &options.kerberos.realm {
                    target = target.with_realm(realm.as_str());
                }

                builder.kerberos(credentials, target)
            }
            #[cfg(not(feature = "kerberos"))]
            {
                let _ = remote;
                unreachable!("kerberos mode should be rejected before building a share client")
            }
        }
    }
}

pub(super) async fn connect_share_path(
    options: &AuthOptions,
    remote: &RemoteLocation,
) -> Result<(Share, String), String> {
    share_builder(options, remote)
        .connect_share_path(remote_unc(remote))
        .await
        .map_err(|error| error.to_string())
}

pub(super) async fn connect_share_move_paths(
    options: &AuthOptions,
    source: &RemoteLocation,
    destination: &RemoteLocation,
) -> Result<(Share, String, String), String> {
    let builder = share_builder(options, source);
    let (source_share, source_path) = builder
        .clone()
        .connect_share_path(remote_unc(source))
        .await
        .map_err(|error| error.to_string())?;
    let source_server = source_share.server().to_string();
    let source_share_name = source_share.name().to_string();
    drop(source_share);

    let (share, destination_path) = builder
        .connect_share_path(remote_unc(destination))
        .await
        .map_err(|error| error.to_string())?;

    if !share.server().eq_ignore_ascii_case(&source_server)
        || !share.name().eq_ignore_ascii_case(&source_share_name)
    {
        return Err(
            "mv requires both SMB URLs to resolve to the same backend server and share"
                .to_string(),
        );
    }

    Ok((share, source_path, destination_path))
}

pub(super) async fn connect_remote_exec(
    options: &AuthOptions,
    target: &ExecTarget,
    mode: ExecMode,
    service_binary: Option<&Path>,
) -> Result<RemoteExecClient, String> {
    let mut builder = RemoteExecClient::builder()
        .server(target.host.as_str())
        .port(target.port)
        .mode(mode);

    match options.mode {
        AuthMode::Ntlm => {
            let mut credentials = NtlmCredentials::new(&options.username, &options.password);
            if let Some(domain) = &options.domain {
                credentials = credentials.with_domain(domain.as_str());
            }
            if let Some(workstation) = &options.workstation {
                credentials = credentials.with_workstation(workstation.as_str());
            }
            builder = builder.credentials(credentials);
        }
        AuthMode::Kerberos => {
            #[cfg(feature = "kerberos")]
            {
                let mut credentials = KerberosCredentials::new(&options.username, &options.password);
                if let Some(domain) = &options.domain {
                    credentials = credentials.with_domain(domain.as_str());
                }
                if let Some(workstation) = &options.workstation {
                    credentials = credentials.with_workstation(workstation.as_str());
                }
                if let Some(kdc_url) = &options.kerberos.kdc_url {
                    credentials = credentials.with_kdc_url(kdc_url.as_str());
                }

                let target_host = options
                    .kerberos
                    .target_host
                    .as_deref()
                    .unwrap_or(target.host.as_str());
                let mut kerberos_target = KerberosTarget::for_smb_host(target_host);
                if let Some(principal) = &options.kerberos.target_principal {
                    kerberos_target = kerberos_target.with_principal(principal.as_str());
                } else if let Some(realm) = &options.kerberos.realm {
                    kerberos_target = kerberos_target.with_realm(realm.as_str());
                }

                builder = builder.kerberos(credentials, kerberos_target);
            }
            #[cfg(not(feature = "kerberos"))]
            {
                let _ = target;
                unreachable!(
                    "kerberos mode should be rejected before building a remote exec client"
                )
            }
        }
    }

    if let Some(service_binary) = service_binary {
        builder = builder.psexec_service_binary(service_binary.to_path_buf());
    }

    builder.connect().await.map_err(|error| error.to_string())
}

pub(super) fn next_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

pub(super) fn psexec_service_binary_from_env() -> Option<PathBuf> {
    env_value(&ENV_PSEXEC_SERVICE_BINARY).map(PathBuf::from)
}

fn env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.is_empty()))
}

fn resolve_auth_mode(
    explicit_mode: Option<String>,
    explicit_kerberos: bool,
    kerberos: &KerberosOptions,
) -> Result<AuthMode, String> {
    let explicit_mode = explicit_mode.or_else(|| env_value(&ENV_AUTH_MODE));
    let explicit_mode = explicit_mode
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase());

    let inferred_kerberos = explicit_kerberos
        || kerberos.target_host.is_some()
        || kerberos.target_principal.is_some()
        || kerberos.realm.is_some()
        || kerberos.kdc_url.is_some();

    let mode = match explicit_mode.as_deref() {
        Some("ntlm") => AuthMode::Ntlm,
        Some("kerberos") => AuthMode::Kerberos,
        Some(other) => {
            return Err(format!(
                "unsupported auth mode `{other}`; expected `ntlm` or `kerberos`"
            ))
        }
        None if inferred_kerberos => AuthMode::Kerberos,
        None => AuthMode::Ntlm,
    };

    #[cfg(not(feature = "kerberos"))]
    if matches!(mode, AuthMode::Kerberos) {
        return Err(
            "this smolder build was not compiled with kerberos support; rebuild with `--features kerberos`"
                .to_string(),
        );
    }

    Ok(mode)
}

fn missing_env_error(field: &str, keys: &[&str], usage: &str) -> String {
    format!(
        "missing {field}; pass --{field} or set one of: {}\n\n{usage}",
        keys.join(", ")
    )
}

pub(super) fn parse_remote_location(input: &str) -> Result<RemoteLocation, String> {
    parse_remote_location_with_options(input, false)
}

pub(super) fn parse_exec_target(input: &str) -> Result<ExecTarget, String> {
    let authority = input
        .strip_prefix("smb://")
        .ok_or_else(|| "remote targets must start with smb://".to_string())?;
    if authority.contains('/') {
        return Err(
            "remote exec targets must use smb://host[:port] without a share path".to_string(),
        );
    }

    let (host, port) = parse_host_port(authority)?;
    Ok(ExecTarget { host, port })
}

pub(super) fn parse_remote_location_with_options(
    input: &str,
    allow_empty_path: bool,
) -> Result<RemoteLocation, String> {
    let remainder = input
        .strip_prefix("smb://")
        .ok_or_else(|| "remote paths must start with smb://".to_string())?;
    let (authority, path) = remainder
        .split_once('/')
        .ok_or_else(|| "remote paths must include a share name".to_string())?;

    let (host, port) = parse_host_port(authority)?;
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    let share = segments
        .next()
        .ok_or_else(|| "remote paths must include a share name".to_string())?;
    let file_path = segments.collect::<Vec<_>>().join("/");
    if file_path.is_empty() && !allow_empty_path {
        return Err("remote paths must include a file path after the share".to_string());
    }

    Ok(RemoteLocation {
        host,
        port,
        share: share.to_string(),
        path: file_path,
    })
}

fn parse_host_port(authority: &str) -> Result<(String, u16), String> {
    if authority.is_empty() {
        return Err("remote paths must include a host".to_string());
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Err("IPv6 SMB URLs are not supported yet".to_string());
        }

        let port = port
            .parse::<u16>()
            .map_err(|_| "SMB URL port must be a valid u16".to_string())?;
        return Ok((host.to_string(), port));
    }

    Ok((authority.to_string(), 445))
}

pub(super) fn parse_duration(input: &str) -> Result<Duration, String> {
    if let Some(milliseconds) = input.strip_suffix("ms") {
        return milliseconds
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|_| "timeout milliseconds must be a whole number, e.g. 500ms".to_string());
    }
    if let Some(seconds) = input.strip_suffix('s') {
        return seconds
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| "timeout must be a whole number of seconds, e.g. 30s".to_string());
    }

    Err("timeout must end with `s` or `ms`".to_string())
}

pub(super) fn remote_unc(remote: &RemoteLocation) -> String {
    if remote.path.is_empty() {
        format!(r"\\{}\{}", remote.host, remote.share)
    } else {
        let path = remote.path.replace('/', r"\");
        format!(r"\\{}\{}\{}", remote.host, remote.share, path)
    }
}

pub(super) fn ensure_same_share(
    source: &RemoteLocation,
    destination: &RemoteLocation,
) -> Result<(), String> {
    if source.host != destination.host
        || source.port != destination.port
        || source.share != destination.share
    {
        return Err("mv requires both SMB URLs to use the same host, port, and share".to_string());
    }
    Ok(())
}

pub(super) fn print_metadata(path: &str, metadata: &SmbMetadata) {
    println!("Path: {path}");
    println!(
        "Type: {}",
        if metadata.is_directory() {
            "directory"
        } else {
            "file"
        }
    );
    println!("Size: {}", metadata.size);
    println!("AllocationSize: {}", metadata.allocation_size);
    println!("Attributes: 0x{:08x}", metadata.attributes.bits());
    println!("Created: {}", format_time(metadata.created));
    println!("Accessed: {}", format_time(metadata.accessed));
    println!("Written: {}", format_time(metadata.written));
    println!("Changed: {}", format_time(metadata.changed));
}

fn format_time(value: Option<std::time::SystemTime>) -> String {
    value
        .map(|time| format!("{time:?}"))
        .unwrap_or_else(|| "<none>".to_string())
}

pub(super) async fn run_interactive_exec(
    exec: &RemoteExecClient,
    request: ExecRequest,
) -> Result<i32, String> {
    let close_on_exit_command = request.launches_default_shell();
    let session = exec
        .spawn(request)
        .await
        .map_err(|error| error.to_string())?;
    let (mut stdin, mut stdout, mut stderr, waiter) = session.into_parts();

    let stdin_task =
        tokio::spawn(async move { pump_local_stdin(&mut stdin, close_on_exit_command).await });
    let stdout_task =
        tokio::spawn(async move { pump_remote_output(&mut stdout, tokio::io::stdout()).await });
    let stderr_task =
        tokio::spawn(async move { pump_remote_output(&mut stderr, tokio::io::stderr()).await });

    let exit_code = waiter.wait().await.map_err(|error| error.to_string())?;
    stdin_task.abort();

    match stdin_task.await {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.to_string()),
    }

    wait_for_interactive_output_task(stdout_task).await?;
    wait_for_interactive_output_task(stderr_task).await?;

    Ok(exit_code)
}

async fn wait_for_interactive_output_task(
    mut task: JoinHandle<Result<(), String>>,
) -> Result<(), String> {
    match timeout(INTERACTIVE_OUTPUT_DRAIN_TIMEOUT, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => {
            task.abort();
            match task.await {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        }
    }
}

async fn pump_local_stdin(
    stdin: &mut InteractiveStdin,
    close_on_exit_command: bool,
) -> Result<(), String> {
    let mut local_stdin = tokio::io::stdin();
    let mut buffer = [0_u8; 8192];
    let mut pending_line = Vec::new();
    loop {
        let count = local_stdin
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return stdin.close().await.map_err(|error| error.to_string());
        }
        let saw_exit_command = close_on_exit_command
            && update_exit_command_state(&mut pending_line, &buffer[..count]);
        stdin
            .write_all(&buffer[..count])
            .await
            .map_err(|error| error.to_string())?;
        if saw_exit_command {
            return stdin.close().await.map_err(|error| error.to_string());
        }
    }
}

fn update_exit_command_state(pending_line: &mut Vec<u8>, bytes: &[u8]) -> bool {
    let mut saw_exit_command = false;
    for &byte in bytes {
        pending_line.push(byte);
        if byte == b'\n' {
            let line = String::from_utf8_lossy(pending_line);
            if line.trim() == "exit" {
                saw_exit_command = true;
            }
            pending_line.clear();
        }
    }
    saw_exit_command
}

async fn pump_remote_output<W>(reader: &mut InteractiveReader, mut writer: W) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = reader
        .read_chunk()
        .await
        .map_err(|error| error.to_string())?
    {
        writer
            .write_all(&chunk)
            .await
            .map_err(|error| error.to_string())?;
        writer.flush().await.map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        parse_duration, parse_exec_target, parse_remote_location,
        parse_remote_location_with_options, remote_unc, ExecTarget, RemoteLocation,
    };

    #[test]
    fn parse_remote_location_rejects_missing_file_path() {
        let error = parse_remote_location("smb://server/share")
            .expect_err("share-only URLs should be rejected");
        assert!(error.contains("file path"));
    }

    #[test]
    fn parse_remote_location_with_options_accepts_empty_path() {
        let location = parse_remote_location_with_options("smb://server/share", true)
            .expect("share root should be accepted");
        assert_eq!(location.path, "");
    }

    #[test]
    fn parse_exec_target_rejects_share_paths() {
        let error = parse_exec_target("smb://server/share").expect_err("share path should fail");
        assert!(error.contains("without a share path"));
    }

    #[test]
    fn parse_exec_target_accepts_target_only_url() {
        assert_eq!(
            parse_exec_target("smb://server:1445").expect("target should parse"),
            ExecTarget {
                host: "server".to_string(),
                port: 1445,
            }
        );
    }

    #[test]
    fn remote_unc_formats_nested_and_share_root_paths() {
        let nested = RemoteLocation {
            host: "server".to_string(),
            port: 445,
            share: "share".to_string(),
            path: "docs/file.txt".to_string(),
        };
        assert_eq!(remote_unc(&nested), r"\\server\share\docs\file.txt");

        let root = RemoteLocation {
            host: "server".to_string(),
            port: 445,
            share: "share".to_string(),
            path: String::new(),
        };
        assert_eq!(remote_unc(&root), r"\\server\share");
    }

    #[test]
    fn parse_duration_accepts_seconds_and_milliseconds() {
        assert_eq!(
            parse_duration("30s").expect("seconds should parse"),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration("500ms").expect("milliseconds should parse"),
            Duration::from_millis(500)
        );
    }
}
