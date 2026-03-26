//! Primitive SMB2 command-line client.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use smolder_core::prelude::{NtlmCredentials, SmbClient, SmbMetadata};
use smolder_tools::prelude::{
    ExecMode, ExecRequest, InteractiveReader, InteractiveStdin, RemoteExecClient,
};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

const ENV_USERNAME: [&str; 2] = ["SMOLDER_SMB_USERNAME", "SMOLDER_SAMBA_USERNAME"];
const ENV_PASSWORD: [&str; 2] = ["SMOLDER_SMB_PASSWORD", "SMOLDER_SAMBA_PASSWORD"];
const ENV_DOMAIN: [&str; 2] = ["SMOLDER_SMB_DOMAIN", "SMOLDER_SAMBA_DOMAIN"];
const ENV_WORKSTATION: [&str; 2] = ["SMOLDER_SMB_WORKSTATION", "SMOLDER_SAMBA_WORKSTATION"];
const ENV_PSEXEC_SERVICE_BINARY: [&str; 1] = ["SMOLDER_PSEXEC_SERVICE_BINARY"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliOptions {
    command: Command,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthOptions {
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    SmbExec {
        target: ExecTarget,
        request: ExecRequest,
    },
    PsExec {
        target: ExecTarget,
        request: ExecRequest,
        service_binary: Option<PathBuf>,
        interactive: bool,
    },
    Cat {
        remote: RemoteLocation,
    },
    Ls {
        remote: RemoteLocation,
    },
    Stat {
        remote: RemoteLocation,
    },
    Get {
        remote: RemoteLocation,
        local: PathBuf,
    },
    Put {
        local: PathBuf,
        remote: RemoteLocation,
    },
    Remove {
        remote: RemoteLocation,
    },
    Move {
        source: RemoteLocation,
        destination: RemoteLocation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteLocation {
    host: String,
    port: u16,
    share: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecTarget {
    host: String,
    port: u16,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match run(env::args().collect()).await {
        Ok(code) => {
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

async fn run(args: Vec<String>) -> Result<i32, String> {
    let CliOptions {
        command,
        username,
        password,
        domain,
        workstation,
    } = parse_cli(args)?;
    let auth = AuthOptions {
        username,
        password,
        domain,
        workstation,
    };
    match command {
        Command::SmbExec { target, request } => {
            let exec = connect_remote_exec(&auth, &target, ExecMode::SmbExec, None).await?;
            let result = exec.run(request).await.map_err(|error| error.to_string())?;
            print!("{}", String::from_utf8_lossy(&result.stdout));
            if !result.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&result.stderr));
            }
            return Ok(result.exit_code);
        }
        Command::PsExec {
            target,
            request,
            service_binary,
            interactive,
        } => {
            let exec =
                connect_remote_exec(&auth, &target, ExecMode::PsExec, service_binary.as_deref())
                    .await?;
            if interactive {
                return run_interactive_exec(&exec, request).await;
            }
            let result = exec.run(request).await.map_err(|error| error.to_string())?;
            print!("{}", String::from_utf8_lossy(&result.stdout));
            if !result.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&result.stderr));
            }
            return Ok(result.exit_code);
        }
        Command::Cat { remote } => {
            let mut share = connect_share(&auth, &remote).await?;
            let mut stdout = tokio::io::stdout();
            share
                .cat_into(&remote.path, &mut stdout)
                .await
                .map_err(|error| error.to_string())?;
        }
        Command::Ls { remote } => {
            let mut share = connect_share(&auth, &remote).await?;
            let mut entries = share
                .list(&remote.path)
                .await
                .map_err(|error| error.to_string())?;
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            for entry in entries {
                if entry.metadata.is_directory() {
                    println!("{}/", entry.name);
                } else {
                    println!("{}", entry.name);
                }
            }
        }
        Command::Stat { remote } => {
            let mut share = connect_share(&auth, &remote).await?;
            let metadata = share
                .stat(&remote.path)
                .await
                .map_err(|error| error.to_string())?;
            print_metadata(&remote.path, &metadata);
        }
        Command::Get { remote, local } => {
            let mut share = connect_share(&auth, &remote).await?;
            share
                .get(&remote.path, local)
                .await
                .map_err(|error| error.to_string())?;
        }
        Command::Put { local, remote } => {
            let mut share = connect_share(&auth, &remote).await?;
            share
                .put(local, &remote.path)
                .await
                .map_err(|error| error.to_string())?;
        }
        Command::Remove { remote } => {
            let mut share = connect_share(&auth, &remote).await?;
            share
                .remove(&remote.path)
                .await
                .map_err(|error| error.to_string())?;
        }
        Command::Move {
            source,
            destination,
        } => {
            ensure_same_share(&source, &destination)?;
            let mut share = connect_share(&auth, &source).await?;
            share
                .rename(&source.path, &destination.path)
                .await
                .map_err(|error| error.to_string())?;
        }
    }

    Ok(0)
}

async fn connect_share(
    options: &AuthOptions,
    remote: &RemoteLocation,
) -> Result<smolder_core::prelude::Share, String> {
    let mut credentials = NtlmCredentials::new(&options.username, &options.password);
    if let Some(domain) = &options.domain {
        credentials = credentials.with_domain(domain.as_str());
    }
    if let Some(workstation) = &options.workstation {
        credentials = credentials.with_workstation(workstation.as_str());
    }

    let client = SmbClient::builder()
        .server(remote.host.as_str())
        .port(remote.port)
        .credentials(credentials)
        .connect()
        .await
        .map_err(|error| error.to_string())?;
    client
        .share(remote.share.as_str())
        .await
        .map_err(|error| error.to_string())
}

async fn connect_remote_exec(
    options: &AuthOptions,
    target: &ExecTarget,
    mode: ExecMode,
    service_binary: Option<&std::path::Path>,
) -> Result<RemoteExecClient, String> {
    let mut credentials = NtlmCredentials::new(&options.username, &options.password);
    if let Some(domain) = &options.domain {
        credentials = credentials.with_domain(domain.as_str());
    }
    if let Some(workstation) = &options.workstation {
        credentials = credentials.with_workstation(workstation.as_str());
    }
    let mut builder = RemoteExecClient::builder()
        .server(target.host.as_str())
        .port(target.port)
        .credentials(credentials)
        .mode(mode);
    if let Some(service_binary) = service_binary {
        builder = builder.psexec_service_binary(service_binary.to_path_buf());
    }
    builder.connect().await.map_err(|error| error.to_string())
}

fn parse_cli(args: Vec<String>) -> Result<CliOptions, String> {
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| "smolder".to_string());
    if args.len() < 2 {
        return Err(usage(&program));
    }

    let command_name = args[1].as_str();
    let mut positionals = Vec::new();
    let mut username = None;
    let mut password = None;
    let mut domain = None;
    let mut workstation = None;
    let mut command_text = None;
    let mut workdir = None;
    let mut timeout = None;
    let mut service_binary = None;
    let mut interactive = false;

    let mut index = 2;
    while index < args.len() {
        let token = &args[index];
        if token == "-h" || token == "--help" {
            return Err(usage(&program));
        }
        if let Some(value) = token.strip_prefix("--username=") {
            username = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--password=") {
            password = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--domain=") {
            domain = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--workstation=") {
            workstation = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--command=") {
            command_text = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--workdir=") {
            workdir = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--timeout=") {
            timeout = Some(parse_duration(value)?);
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--service-binary=") {
            service_binary = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        match token.as_str() {
            "--username" => {
                username = Some(next_value(&args, &mut index, "--username")?);
            }
            "--password" => {
                password = Some(next_value(&args, &mut index, "--password")?);
            }
            "--domain" => {
                domain = Some(next_value(&args, &mut index, "--domain")?);
            }
            "--workstation" => {
                workstation = Some(next_value(&args, &mut index, "--workstation")?);
            }
            "--command" => {
                command_text = Some(next_value(&args, &mut index, "--command")?);
            }
            "--workdir" => {
                workdir = Some(next_value(&args, &mut index, "--workdir")?);
            }
            "--timeout" => {
                let value = next_value(&args, &mut index, "--timeout")?;
                timeout = Some(parse_duration(&value)?);
            }
            "--service-binary" => {
                service_binary = Some(PathBuf::from(next_value(
                    &args,
                    &mut index,
                    "--service-binary",
                )?));
            }
            "--interactive" => {
                interactive = true;
            }
            _ if token.starts_with("--") => {
                return Err(format!("unknown option: {token}\n\n{}", usage(&program)));
            }
            _ => {
                positionals.push(token.as_str());
            }
        }
        index += 1;
    }

    let exec_request = || -> Result<ExecRequest, String> {
        let command_text = command_text.clone().ok_or_else(|| {
            format!(
                "missing --command for `{command_name}`\n\n{}",
                usage(&program)
            )
        })?;
        let mut request = ExecRequest::command(command_text);
        if let Some(workdir) = workdir.clone() {
            request = request.with_working_directory(workdir);
        }
        if let Some(timeout) = timeout {
            request = request.with_timeout(timeout);
        }
        Ok(request)
    };

    let command = match command_name {
        "smbexec" => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`smbexec` expects exactly 1 target SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::SmbExec {
                target: parse_exec_target(positionals[0])?,
                request: exec_request()?,
            }
        }
        "psexec" => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`psexec` expects exactly 1 target SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            let request = match (interactive, command_text.clone()) {
                (true, Some(command_text)) => {
                    let mut request = ExecRequest::command(command_text);
                    if let Some(workdir) = workdir.clone() {
                        request = request.with_working_directory(workdir);
                    }
                    if let Some(timeout) = timeout {
                        request = request.with_timeout(timeout);
                    }
                    request
                }
                (true, None) => {
                    let mut request = ExecRequest::command(String::new());
                    if let Some(workdir) = workdir.clone() {
                        request = request.with_working_directory(workdir);
                    }
                    if let Some(timeout) = timeout {
                        request = request.with_timeout(timeout);
                    }
                    request
                }
                (false, _) => exec_request()?,
            };
            Command::PsExec {
                target: parse_exec_target(positionals[0])?,
                request,
                service_binary: service_binary
                    .or_else(|| env_value(&ENV_PSEXEC_SERVICE_BINARY).map(PathBuf::from)),
                interactive,
            }
        }
        "cat" => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`cat` expects exactly 1 remote SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::Cat {
                remote: parse_remote_location(positionals[0])?,
            }
        }
        "ls" => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`ls` expects exactly 1 remote SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::Ls {
                remote: parse_remote_location_with_options(positionals[0], true)?,
            }
        }
        "stat" => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`stat` expects exactly 1 remote SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::Stat {
                remote: parse_remote_location(positionals[0])?,
            }
        }
        "get" => {
            if positionals.len() != 2 {
                return Err(format!(
                    "`get` expects a remote SMB URL and a local path\n\n{}",
                    usage(&program)
                ));
            }
            Command::Get {
                remote: parse_remote_location(positionals[0])?,
                local: PathBuf::from(positionals[1]),
            }
        }
        "put" => {
            if positionals.len() != 2 {
                return Err(format!(
                    "`put` expects a local path and a remote SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::Put {
                local: PathBuf::from(positionals[0]),
                remote: parse_remote_location(positionals[1])?,
            }
        }
        "rm" => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`rm` expects exactly 1 remote SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::Remove {
                remote: parse_remote_location(positionals[0])?,
            }
        }
        "mv" => {
            if positionals.len() != 2 {
                return Err(format!(
                    "`mv` expects a source SMB URL and a destination SMB URL\n\n{}",
                    usage(&program)
                ));
            }
            Command::Move {
                source: parse_remote_location(positionals[0])?,
                destination: parse_remote_location(positionals[1])?,
            }
        }
        _ => {
            return Err(format!(
                "unknown command: {command_name}\n\n{}",
                usage(&program)
            ))
        }
    };

    let username = username
        .or_else(|| env_value(&ENV_USERNAME))
        .ok_or_else(|| missing_env_error("username", &ENV_USERNAME, &program))?;
    let password = password
        .or_else(|| env_value(&ENV_PASSWORD))
        .ok_or_else(|| missing_env_error("password", &ENV_PASSWORD, &program))?;
    let domain = domain.or_else(|| env_value(&ENV_DOMAIN));
    let workstation = workstation.or_else(|| env_value(&ENV_WORKSTATION));

    Ok(CliOptions {
        command,
        username,
        password,
        domain,
        workstation,
    })
}

fn next_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.is_empty()))
}

fn missing_env_error(field: &str, keys: &[&str], program: &str) -> String {
    format!(
        "missing {field}; pass --{field} or set one of: {}\n\n{}",
        keys.join(", "),
        usage(program)
    )
}

fn usage(program: &str) -> String {
    format!(
        "\
Usage:
  {program} smbexec smb://host[:port] --command COMMAND [--workdir PATH] [--timeout 30s] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} psexec smb://host[:port] --command COMMAND [--service-binary PATH] [--workdir PATH] [--timeout 30s] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} psexec smb://host[:port] --interactive [--command COMMAND] [--service-binary PATH] [--workdir PATH] [--timeout 30s] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} cat smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} ls smb://host[:port]/share[/path] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} stat smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} get smb://host[:port]/share/path LOCAL_PATH [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} put LOCAL_PATH smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} rm smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]
  {program} mv smb://host[:port]/share/path smb://host[:port]/share/new-path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
    )
}

fn parse_remote_location(input: &str) -> Result<RemoteLocation, String> {
    parse_remote_location_with_options(input, false)
}

fn parse_exec_target(input: &str) -> Result<ExecTarget, String> {
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

fn parse_remote_location_with_options(
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

fn parse_duration(input: &str) -> Result<Duration, String> {
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

fn ensure_same_share(source: &RemoteLocation, destination: &RemoteLocation) -> Result<(), String> {
    if source.host != destination.host
        || source.port != destination.port
        || source.share != destination.share
    {
        return Err("mv requires both SMB URLs to use the same host, port, and share".to_string());
    }
    Ok(())
}

fn print_metadata(path: &str, metadata: &SmbMetadata) {
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

async fn run_interactive_exec(
    exec: &RemoteExecClient,
    request: ExecRequest,
) -> Result<i32, String> {
    let session = exec
        .spawn(request)
        .await
        .map_err(|error| error.to_string())?;
    let (mut stdin, mut stdout, mut stderr, waiter) = session.into_parts();

    let stdin_task = async { pump_local_stdin(&mut stdin).await };
    let stdout_task = async { pump_remote_output(&mut stdout, tokio::io::stdout()).await };
    let stderr_task = async { pump_remote_output(&mut stderr, tokio::io::stderr()).await };
    let wait_task = async { waiter.wait().await.map_err(|error| error.to_string()) };

    let (stdin_result, stdout_result, stderr_result, exit_result) =
        tokio::join!(stdin_task, stdout_task, stderr_task, wait_task);
    stdin_result?;
    stdout_result?;
    stderr_result?;
    exit_result
}

async fn pump_local_stdin(stdin: &mut InteractiveStdin) -> Result<(), String> {
    let mut local_stdin = tokio::io::stdin();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = local_stdin
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return stdin.close().await.map_err(|error| error.to_string());
        }
        stdin
            .write_all(&buffer[..count])
            .await
            .map_err(|error| error.to_string())?;
    }
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
    use std::path::PathBuf;
    use std::time::Duration;

    use smolder_tools::prelude::ExecRequest;

    use super::{
        parse_cli, parse_duration, parse_exec_target, parse_remote_location,
        parse_remote_location_with_options, Command, ExecTarget, RemoteLocation,
    };

    #[test]
    fn parse_cat_command_with_inline_credentials() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "cat".to_string(),
            "smb://127.0.0.1:1445/share/docs/file.txt".to_string(),
            "--username=smolder".to_string(),
            "--password=smolderpass".to_string(),
            "--domain=WORKGROUP".to_string(),
        ])
        .expect("parser should accept cat arguments");

        assert_eq!(options.username, "smolder");
        assert_eq!(options.password, "smolderpass");
        assert_eq!(options.domain.as_deref(), Some("WORKGROUP"));
        assert_eq!(
            options.command,
            Command::Cat {
                remote: RemoteLocation {
                    host: "127.0.0.1".to_string(),
                    port: 1445,
                    share: "share".to_string(),
                    path: "docs/file.txt".to_string(),
                },
            }
        );
    }

    #[test]
    fn parse_put_command_with_split_flags() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "put".to_string(),
            "local.txt".to_string(),
            "smb://server/share/remote.txt".to_string(),
            "--username".to_string(),
            "user".to_string(),
            "--password".to_string(),
            "pass".to_string(),
            "--workstation".to_string(),
            "ws1".to_string(),
        ])
        .expect("parser should accept put arguments");

        assert_eq!(options.workstation.as_deref(), Some("ws1"));
        assert_eq!(
            options.command,
            Command::Put {
                local: PathBuf::from("local.txt"),
                remote: RemoteLocation {
                    host: "server".to_string(),
                    port: 445,
                    share: "share".to_string(),
                    path: "remote.txt".to_string(),
                },
            }
        );
    }

    #[test]
    fn parse_remote_location_rejects_missing_file_path() {
        let error = parse_remote_location("smb://server/share")
            .expect_err("share-only URLs should be rejected");
        assert!(error.contains("file path"));
    }

    #[test]
    fn parse_ls_command_allows_share_root() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "ls".to_string(),
            "smb://server/share".to_string(),
            "--username=user".to_string(),
            "--password=pass".to_string(),
        ])
        .expect("parser should accept ls arguments");

        assert_eq!(
            options.command,
            Command::Ls {
                remote: RemoteLocation {
                    host: "server".to_string(),
                    port: 445,
                    share: "share".to_string(),
                    path: String::new(),
                },
            }
        );
    }

    #[test]
    fn parse_mv_command_accepts_two_remote_urls() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "mv".to_string(),
            "smb://server/share/old.txt".to_string(),
            "smb://server/share/new.txt".to_string(),
            "--username=user".to_string(),
            "--password=pass".to_string(),
        ])
        .expect("parser should accept mv arguments");

        assert_eq!(
            options.command,
            Command::Move {
                source: RemoteLocation {
                    host: "server".to_string(),
                    port: 445,
                    share: "share".to_string(),
                    path: "old.txt".to_string(),
                },
                destination: RemoteLocation {
                    host: "server".to_string(),
                    port: 445,
                    share: "share".to_string(),
                    path: "new.txt".to_string(),
                },
            }
        );
    }

    #[test]
    fn parse_remote_location_with_options_accepts_empty_path() {
        let location = parse_remote_location_with_options("smb://server/share", true)
            .expect("share root should be accepted");
        assert_eq!(location.path, "");
    }

    #[test]
    fn parse_smbexec_command_with_target_only_url() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "smbexec".to_string(),
            "smb://server:1445".to_string(),
            "--command=whoami".to_string(),
            "--timeout=30s".to_string(),
            "--username=user".to_string(),
            "--password=pass".to_string(),
        ])
        .expect("parser should accept smbexec arguments");

        match options.command {
            Command::SmbExec { target, request } => {
                assert_eq!(
                    target,
                    ExecTarget {
                        host: "server".to_string(),
                        port: 1445,
                    }
                );
                assert_eq!(
                    request,
                    ExecRequest::command("whoami").with_timeout(Duration::from_secs(30))
                );
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_psexec_command_accepts_workdir() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "psexec".to_string(),
            "smb://server".to_string(),
            "--command".to_string(),
            "dir".to_string(),
            "--workdir".to_string(),
            "C:\\Temp".to_string(),
            "--username=user".to_string(),
            "--password=pass".to_string(),
        ])
        .expect("parser should accept psexec arguments");

        match options.command {
            Command::PsExec {
                target,
                request,
                service_binary,
                interactive,
            } => {
                assert_eq!(
                    target,
                    ExecTarget {
                        host: "server".to_string(),
                        port: 445,
                    }
                );
                assert_eq!(
                    request,
                    ExecRequest::command("dir").with_working_directory("C:\\Temp")
                );
                assert_eq!(service_binary, None);
                assert!(!interactive);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_psexec_command_accepts_service_binary() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "psexec".to_string(),
            "smb://server".to_string(),
            "--command=dir".to_string(),
            "--service-binary".to_string(),
            "target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe".to_string(),
            "--username=user".to_string(),
            "--password=pass".to_string(),
        ])
        .expect("parser should accept psexec service-binary arguments");

        match options.command {
            Command::PsExec {
                service_binary,
                interactive,
                ..
            } => {
                assert!(!interactive);
                assert_eq!(
                    service_binary,
                    Some(PathBuf::from(
                        "target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe"
                    ))
                )
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_interactive_psexec_allows_missing_command() {
        let options = parse_cli(vec![
            "smolder".to_string(),
            "psexec".to_string(),
            "smb://server".to_string(),
            "--interactive".to_string(),
            "--username=user".to_string(),
            "--password=pass".to_string(),
        ])
        .expect("parser should accept interactive psexec arguments");

        match options.command {
            Command::PsExec {
                interactive,
                request,
                ..
            } => {
                assert!(interactive);
                assert_eq!(request, ExecRequest::command(String::new()));
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_exec_target_rejects_share_paths() {
        let error = parse_exec_target("smb://server/share").expect_err("share path should fail");
        assert!(error.contains("without a share path"));
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
