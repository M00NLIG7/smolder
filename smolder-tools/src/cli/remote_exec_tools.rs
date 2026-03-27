//! Standalone remote execution binaries.

use std::path::PathBuf;

use super::common::{
    connect_remote_exec, next_value, parse_duration, parse_exec_target,
    psexec_service_binary_from_env, run_interactive_exec, AuthArgAccumulator, AuthOptions,
    ExecTarget,
};
use crate::prelude::{ExecMode, ExecRequest};

/// One standalone remote execution workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteExecTool {
    /// Runs the inline service command workflow.
    SmbExec,
    /// Runs the staged service payload workflow.
    PsExec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRemoteExecArgs {
    auth: AuthOptions,
    target: ExecTarget,
    request: ExecRequest,
    service_binary: Option<PathBuf>,
    interactive: bool,
}

impl RemoteExecTool {
    fn usage(self, program: &str) -> String {
        match self {
            Self::SmbExec => format!(
                "Usage:\n  {program} smb://host[:port] --command COMMAND [--workdir PATH] [--timeout 30s] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME] [--kerberos] [--target-host HOST] [--principal SPN] [--realm REALM] [--kdc-url URL]"
            ),
            Self::PsExec => format!(
                "Usage:\n  {program} smb://host[:port] --command COMMAND [--service-binary PATH] [--workdir PATH] [--timeout 30s] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME] [--kerberos] [--target-host HOST] [--principal SPN] [--realm REALM] [--kdc-url URL]\n  {program} smb://host[:port] --interactive [--command COMMAND] [--service-binary PATH] [--workdir PATH] [--timeout 30s] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME] [--kerberos] [--target-host HOST] [--principal SPN] [--realm REALM] [--kdc-url URL]"
            ),
        }
    }

    fn expected_program(self) -> &'static str {
        match self {
            Self::SmbExec => "smbexec",
            Self::PsExec => "psexec",
        }
    }

    fn mode(self) -> ExecMode {
        match self {
            Self::SmbExec => ExecMode::SmbExec,
            Self::PsExec => ExecMode::PsExec,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::SmbExec => "smbexec",
            Self::PsExec => "psexec",
        }
    }
}

/// Runs one standalone remote execution tool.
pub async fn run_remote_exec_tool(
    tool: RemoteExecTool,
    args: Vec<String>,
) -> Result<i32, String> {
    let parsed = parse_args(tool, args)?;
    let exec = connect_remote_exec(
        &parsed.auth,
        &parsed.target,
        tool.mode(),
        parsed.service_binary.as_deref(),
    )
    .await?;

    if matches!(tool, RemoteExecTool::PsExec) && parsed.interactive {
        return run_interactive_exec(&exec, parsed.request).await;
    }

    let result = exec.run(parsed.request).await.map_err(|error| error.to_string())?;
    print!("{}", String::from_utf8_lossy(&result.stdout));
    if !result.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }

    Ok(result.exit_code)
}

fn parse_args(tool: RemoteExecTool, args: Vec<String>) -> Result<ParsedRemoteExecArgs, String> {
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| tool.expected_program().to_string());
    let usage = tool.usage(&program);
    if args.len() < 2 {
        return Err(usage);
    }

    let mut auth = AuthArgAccumulator::default();
    let mut positionals = Vec::new();
    let mut command_text = None;
    let mut workdir = None;
    let mut timeout = None;
    let mut service_binary = None;
    let mut interactive = false;

    let mut index = 1;
    while index < args.len() {
        let token = &args[index];
        if token == "-h" || token == "--help" {
            return Err(tool.usage(&program));
        }
        if auth.parse_flag(&args, &mut index, token)? {
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
                return Err(format!("unknown option: {token}\n\n{}", tool.usage(&program)));
            }
            _ => {
                positionals.push(token.as_str());
            }
        }
        index += 1;
    }

    if positionals.len() != 1 {
        return Err(format!(
            "`{}` expects exactly 1 target SMB URL\n\n{}",
            tool.label(),
            tool.usage(&program)
        ));
    }

    let auth = auth.resolve(&usage)?;
    let target = parse_exec_target(positionals[0])?;
    let request = match (tool, interactive, command_text) {
        (RemoteExecTool::SmbExec, _, Some(command_text))
        | (RemoteExecTool::PsExec, false, Some(command_text))
        | (RemoteExecTool::PsExec, true, Some(command_text)) => {
            let mut request = ExecRequest::command(command_text);
            if let Some(workdir) = workdir {
                request = request.with_working_directory(workdir);
            }
            if let Some(timeout) = timeout {
                request = request.with_timeout(timeout);
            }
            request
        }
        (RemoteExecTool::PsExec, true, None) => {
            let mut request = ExecRequest::command(String::new());
            if let Some(workdir) = workdir {
                request = request.with_working_directory(workdir);
            }
            if let Some(timeout) = timeout {
                request = request.with_timeout(timeout);
            }
            request
        }
        _ => {
            return Err(format!(
                "missing --command for `{}`\n\n{}",
                tool.label(),
                tool.usage(&program)
            ))
        }
    };

    Ok(ParsedRemoteExecArgs {
        auth,
        target,
        request,
        service_binary: if matches!(tool, RemoteExecTool::PsExec) {
            service_binary.or_else(psexec_service_binary_from_env)
        } else {
            None
        },
        interactive,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{parse_args, RemoteExecTool};
    use crate::cli::common::ExecTarget;
    use crate::prelude::ExecRequest;

    #[test]
    fn parse_smbexec_command_with_target_only_url() {
        let options = parse_args(
            RemoteExecTool::SmbExec,
            vec![
                "smbexec".to_string(),
                "smb://server:1445".to_string(),
                "--command=whoami".to_string(),
                "--timeout=30s".to_string(),
                "--username=user".to_string(),
                "--password=pass".to_string(),
            ],
        )
        .expect("parser should accept smbexec arguments");

        assert_eq!(options.auth.username, "user");
        assert_eq!(options.auth.password, "pass");
        assert_eq!(
            options.target,
            ExecTarget {
                host: "server".to_string(),
                port: 1445,
            }
        );
        assert_eq!(
            options.request,
            ExecRequest::command("whoami").with_timeout(Duration::from_secs(30))
        );
        assert_eq!(options.service_binary, None);
        assert!(!options.interactive);
    }

    #[test]
    fn parse_psexec_command_accepts_workdir() {
        let options = parse_args(
            RemoteExecTool::PsExec,
            vec![
                "psexec".to_string(),
                "smb://server".to_string(),
                "--command".to_string(),
                "dir".to_string(),
                "--workdir".to_string(),
                "C:\\Temp".to_string(),
                "--username=user".to_string(),
                "--password=pass".to_string(),
            ],
        )
        .expect("parser should accept psexec arguments");

        assert_eq!(options.auth.username, "user");
        assert_eq!(options.auth.password, "pass");
        assert_eq!(
            options.target,
            ExecTarget {
                host: "server".to_string(),
                port: 445,
            }
        );
        assert_eq!(
            options.request,
            ExecRequest::command("dir").with_working_directory("C:\\Temp")
        );
        assert_eq!(options.service_binary, None);
        assert!(!options.interactive);
    }

    #[test]
    fn parse_psexec_command_accepts_service_binary() {
        let options = parse_args(
            RemoteExecTool::PsExec,
            vec![
                "psexec".to_string(),
                "smb://server".to_string(),
                "--command=dir".to_string(),
                "--service-binary".to_string(),
                "target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe".to_string(),
                "--username=user".to_string(),
                "--password=pass".to_string(),
            ],
        )
        .expect("parser should accept psexec service-binary arguments");

        assert_eq!(
            options.service_binary,
            Some(PathBuf::from(
                "target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe"
            ))
        );
        assert!(!options.interactive);
    }

    #[test]
    fn parse_interactive_psexec_allows_missing_command() {
        let options = parse_args(
            RemoteExecTool::PsExec,
            vec![
                "psexec".to_string(),
                "smb://server".to_string(),
                "--interactive".to_string(),
                "--username=user".to_string(),
                "--password=pass".to_string(),
            ],
        )
        .expect("parser should accept interactive psexec arguments");

        assert!(options.interactive);
        assert_eq!(options.request, ExecRequest::command(String::new()));
    }

    #[cfg(feature = "kerberos")]
    #[test]
    fn parse_smbexec_command_accepts_kerberos_flags() {
        let options = parse_args(
            RemoteExecTool::SmbExec,
            vec![
                "smbexec".to_string(),
                "smb://127.0.0.1".to_string(),
                "--command".to_string(),
                "whoami".to_string(),
                "--kerberos".to_string(),
                "--username".to_string(),
                "smolder@LAB.EXAMPLE".to_string(),
                "--password".to_string(),
                "Passw0rd!".to_string(),
                "--target-host".to_string(),
                "DESKTOP-PTNJUS5.lab.example".to_string(),
                "--realm".to_string(),
                "LAB.EXAMPLE".to_string(),
                "--kdc-url".to_string(),
                "tcp://dc1.lab.example:1088".to_string(),
            ],
        )
        .expect("parser should accept kerberos smbexec arguments");

        assert!(matches!(options.auth.mode, crate::cli::common::AuthMode::Kerberos));
        assert_eq!(
            options.auth.kerberos.target_host.as_deref(),
            Some("DESKTOP-PTNJUS5.lab.example")
        );
        assert_eq!(options.auth.kerberos.realm.as_deref(), Some("LAB.EXAMPLE"));
        assert_eq!(
            options.auth.kerberos.kdc_url.as_deref(),
            Some("tcp://dc1.lab.example:1088")
        );
    }
}
