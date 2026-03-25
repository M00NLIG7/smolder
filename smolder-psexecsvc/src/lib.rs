//! Shared argument parsing and command execution for the Smolder PsExec service.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Launch configuration used by the Windows service host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchConfig {
    /// Service name registered with the SCM dispatcher.
    pub service_name: String,
    /// Whether to run the service logic directly in the foreground.
    pub console_mode: bool,
    /// Remaining service arguments.
    pub service_args: Vec<OsString>,
}

/// One execution request consumed by the payload binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceArgs {
    /// Script file to execute with `%COMSPEC% /Q /C`.
    pub script_path: PathBuf,
    /// File path used for captured stdout.
    pub stdout_path: PathBuf,
    /// File path used for captured stderr.
    pub stderr_path: PathBuf,
    /// File path used for the numeric exit code.
    pub exit_code_path: PathBuf,
}

/// Payload execution mode selected by the SCM-delivered service arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadRequest {
    /// One-shot command execution with file capture.
    File(ServiceArgs),
    /// Interactive or pipe-streamed execution via named pipes.
    Pipe(PipeServiceArgs),
}

/// Named-pipe execution parameters consumed by the interactive service mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeServiceArgs {
    /// Pipe namespace prefix shared by stdin/stdout/stderr/control pipes.
    pub pipe_prefix: String,
    /// Optional one-shot command. When omitted, the service starts an interactive shell.
    pub command: Option<String>,
    /// Optional working directory for the child process.
    pub working_directory: Option<PathBuf>,
}

/// Parses the process command line into the SCM dispatch configuration.
pub fn parse_launch_config(args: &[OsString]) -> Result<LaunchConfig, String> {
    let mut service_name = None;
    let mut console_mode = false;
    let mut service_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--service-name" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "missing value for --service-name".to_string())?;
                service_name = Some(value.to_string_lossy().into_owned());
            }
            "--console" => {
                console_mode = true;
            }
            _ => {
                service_args.push(args[index].clone());
            }
        }
        index += 1;
    }

    Ok(LaunchConfig {
        service_name: service_name.unwrap_or_else(|| "smolder-psexecsvc".to_string()),
        console_mode,
        service_args,
    })
}

/// Parses the SCM-delivered service arguments into one execution request.
pub fn parse_service_args(args: &[OsString]) -> Result<ServiceArgs, String> {
    let mut script_path = None;
    let mut stdout_path = None;
    let mut stderr_path = None;
    let mut exit_code_path = None;
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_string_lossy();
        let value = match key.as_ref() {
            "--script" | "--stdout" | "--stderr" | "--exit-code" => {
                index += 1;
                args.get(index)
                    .ok_or_else(|| format!("missing value for {key}"))?
                    .clone()
            }
            _ => return Err(format!("unknown service argument: {key}")),
        };

        match key.as_ref() {
            "--script" => script_path = Some(PathBuf::from(value)),
            "--stdout" => stdout_path = Some(PathBuf::from(value)),
            "--stderr" => stderr_path = Some(PathBuf::from(value)),
            "--exit-code" => exit_code_path = Some(PathBuf::from(value)),
            _ => unreachable!(),
        }
        index += 1;
    }

    Ok(ServiceArgs {
        script_path: script_path.ok_or_else(|| "missing --script".to_string())?,
        stdout_path: stdout_path.ok_or_else(|| "missing --stdout".to_string())?,
        stderr_path: stderr_path.ok_or_else(|| "missing --stderr".to_string())?,
        exit_code_path: exit_code_path.ok_or_else(|| "missing --exit-code".to_string())?,
    })
}

/// Parses the SCM-delivered service arguments into either file-capture or pipe mode.
pub fn parse_payload_request(args: &[OsString]) -> Result<PayloadRequest, String> {
    if args
        .iter()
        .any(|arg| arg.to_string_lossy() == "--pipe-prefix")
    {
        return parse_pipe_service_args(args).map(PayloadRequest::Pipe);
    }
    parse_service_args(args).map(PayloadRequest::File)
}

/// Parses the SCM-delivered service arguments into one named-pipe execution request.
pub fn parse_pipe_service_args(args: &[OsString]) -> Result<PipeServiceArgs, String> {
    let mut pipe_prefix = None;
    let mut command = None;
    let mut working_directory = None;
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_string_lossy();
        let value = match key.as_ref() {
            "--pipe-prefix" | "--command" | "--workdir" => {
                index += 1;
                args.get(index)
                    .ok_or_else(|| format!("missing value for {key}"))?
                    .clone()
            }
            _ => return Err(format!("unknown service argument: {key}")),
        };

        match key.as_ref() {
            "--pipe-prefix" => pipe_prefix = Some(value.to_string_lossy().into_owned()),
            "--command" => command = Some(value.to_string_lossy().into_owned()),
            "--workdir" => working_directory = Some(PathBuf::from(value)),
            _ => unreachable!(),
        }
        index += 1;
    }

    Ok(PipeServiceArgs {
        pipe_prefix: pipe_prefix.ok_or_else(|| "missing --pipe-prefix".to_string())?,
        command,
        working_directory,
    })
}

/// Local Windows named-pipe names derived from one prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeNames {
    /// Full stdin pipe name.
    pub stdin: String,
    /// Full stdout pipe name.
    pub stdout: String,
    /// Full stderr pipe name.
    pub stderr: String,
    /// Full control pipe name.
    pub control: String,
}

impl PipeNames {
    /// Builds the full local pipe names for the given prefix.
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self {
            stdin: format!(r"\\.\pipe\{prefix}.stdin"),
            stdout: format!(r"\\.\pipe\{prefix}.stdout"),
            stderr: format!(r"\\.\pipe\{prefix}.stderr"),
            control: format!(r"\\.\pipe\{prefix}.control"),
        }
    }
}

/// Runs the requested script once and persists the resulting exit code.
pub fn run_service_once(args: &ServiceArgs) -> io::Result<i32> {
    let stdout = File::create(&args.stdout_path)?;
    let stderr = File::create(&args.stderr_path)?;
    let status = child_command(&args.script_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()?;
    let exit_code = status.code().unwrap_or(1);
    write_exit_code(&args.exit_code_path, exit_code)?;
    Ok(exit_code)
}

fn child_command(script_path: &Path) -> Command {
    #[cfg(windows)]
    {
        let mut command =
            Command::new(current_comspec().unwrap_or_else(|| OsString::from("cmd.exe")));
        command.arg("/Q").arg("/C").arg(script_path.as_os_str());
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg(script_path.as_os_str());
        command
    }
}

#[cfg(windows)]
fn current_comspec() -> Option<OsString> {
    std::env::var_os("COMSPEC")
}

fn write_exit_code(path: &Path, exit_code: i32) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "{exit_code}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        parse_launch_config, parse_payload_request, parse_pipe_service_args, parse_service_args,
        run_service_once, LaunchConfig, PayloadRequest, PipeNames, PipeServiceArgs, ServiceArgs,
    };

    #[test]
    fn parse_launch_config_extracts_service_name_and_console_mode() {
        let config = parse_launch_config(&[
            "--service-name".into(),
            "SMOLDERTEST".into(),
            "--console".into(),
            "--script".into(),
            "run.cmd".into(),
        ])
        .expect("launch config should parse");
        assert_eq!(
            config,
            LaunchConfig {
                service_name: "SMOLDERTEST".to_string(),
                console_mode: true,
                service_args: vec!["--script".into(), "run.cmd".into()],
            }
        );
    }

    #[test]
    fn parse_service_args_extracts_required_paths() {
        let args = parse_service_args(&[
            "--script".into(),
            "run.cmd".into(),
            "--stdout".into(),
            "stdout.txt".into(),
            "--stderr".into(),
            "stderr.txt".into(),
            "--exit-code".into(),
            "exit.txt".into(),
        ])
        .expect("service args should parse");
        assert_eq!(args.script_path, PathBuf::from("run.cmd"));
        assert_eq!(args.stdout_path, PathBuf::from("stdout.txt"));
        assert_eq!(args.stderr_path, PathBuf::from("stderr.txt"));
        assert_eq!(args.exit_code_path, PathBuf::from("exit.txt"));
    }

    #[test]
    fn parse_pipe_service_args_extracts_prefix_command_and_workdir() {
        let args = parse_pipe_service_args(&[
            "--pipe-prefix".into(),
            "SMOLDER-ABC".into(),
            "--command".into(),
            "whoami".into(),
            "--workdir".into(),
            "C:\\Temp".into(),
        ])
        .expect("pipe service args should parse");
        assert_eq!(
            args,
            PipeServiceArgs {
                pipe_prefix: "SMOLDER-ABC".to_string(),
                command: Some("whoami".to_string()),
                working_directory: Some(PathBuf::from("C:\\Temp")),
            }
        );
    }

    #[test]
    fn pipe_names_expand_from_prefix() {
        let pipes = PipeNames::new("SMOLDER-ABC");
        assert_eq!(pipes.stdin, r"\\.\pipe\SMOLDER-ABC.stdin");
        assert_eq!(pipes.stdout, r"\\.\pipe\SMOLDER-ABC.stdout");
        assert_eq!(pipes.stderr, r"\\.\pipe\SMOLDER-ABC.stderr");
        assert_eq!(pipes.control, r"\\.\pipe\SMOLDER-ABC.control");
    }

    #[test]
    fn parse_payload_request_detects_pipe_mode() {
        let request = parse_payload_request(&[
            "--pipe-prefix".into(),
            "SMOLDER-ABC".into(),
            "--command".into(),
            "whoami".into(),
        ])
        .expect("payload request should parse");

        assert_eq!(
            request,
            PayloadRequest::Pipe(PipeServiceArgs {
                pipe_prefix: "SMOLDER-ABC".to_string(),
                command: Some("whoami".to_string()),
                working_directory: None,
            })
        );
    }

    #[test]
    fn run_service_once_executes_script_and_writes_exit_code() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("smolder-psexecsvc-{unique}"));
        fs::create_dir_all(&base).expect("temp dir should create");

        #[cfg(windows)]
        let script_path = {
            let path = base.join("run.cmd");
            fs::write(&path, "@echo hello\r\n@echo oops 1>&2\r\n@exit /b 7\r\n")
                .expect("script should write");
            path
        };

        #[cfg(not(windows))]
        let script_path = {
            let path = base.join("run.sh");
            fs::write(&path, "#!/bin/sh\necho hello\necho oops >&2\nexit 7\n")
                .expect("script should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&path)
                    .expect("metadata should load")
                    .permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&path, perms).expect("permissions should set");
            }
            path
        };

        let stdout_path = base.join("stdout.txt");
        let stderr_path = base.join("stderr.txt");
        let exit_code_path = base.join("exit.txt");
        let exit_code = run_service_once(&ServiceArgs {
            script_path,
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            exit_code_path: exit_code_path.clone(),
        })
        .expect("service execution should succeed");

        assert_eq!(exit_code, 7);
        assert!(fs::read_to_string(&stdout_path)
            .expect("stdout should read")
            .contains("hello"));
        assert!(fs::read_to_string(&stderr_path)
            .expect("stderr should read")
            .contains("oops"));
        assert_eq!(
            fs::read_to_string(&exit_code_path)
                .expect("exit code should read")
                .trim(),
            "7"
        );
        let _ = fs::remove_dir_all(base);
    }
}
