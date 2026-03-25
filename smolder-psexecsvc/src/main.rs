//! Windows service entrypoint for the Smolder PsExec payload.

#[cfg(windows)]
mod windows_main {
    use std::ffi::OsString;
    use std::io;
    use std::process::Stdio;
    use std::sync::OnceLock;

    use smolder_psexecsvc::{
        parse_launch_config, parse_payload_request, run_service_once, PayloadRequest, PipeNames,
        PipeServiceArgs,
    };
    use tokio::io::{copy, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
    use tokio::process::{ChildStdin, Command};
    use tokio::runtime::Builder;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    static SERVICE_NAME: OnceLock<OsString> = OnceLock::new();

    windows_service::define_windows_service!(ffi_service_main, service_main);

    pub fn main() -> windows_service::Result<()> {
        let args = std::env::args_os().skip(1).collect::<Vec<_>>();
        let launch = parse_launch_config(&args).map_err(|_| {
            windows_service::Error::Winapi(std::io::Error::from_raw_os_error(87).into())
        })?;
        let _ = SERVICE_NAME.set(OsString::from(&launch.service_name));
        if launch.console_mode {
            let _ = run_payload(&launch.service_args)?;
            return Ok(());
        }
        service_dispatcher::start(&launch.service_name, ffi_service_main)
    }

    fn service_main(arguments: Vec<OsString>) {
        let _ = run_service(arguments);
    }

    fn run_service(arguments: Vec<OsString>) -> windows_service::Result<()> {
        let service_name = SERVICE_NAME
            .get()
            .cloned()
            .unwrap_or_else(|| OsString::from("smolder-psexecsvc"));
        let status_handle =
            service_control_handler::register(service_name, move |control| match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::ZERO,
            process_id: None,
        })?;

        let exit_code = run_payload(&arguments)?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: std::time::Duration::ZERO,
            process_id: None,
        })?;
        Ok(())
    }

    fn run_payload(arguments: &[OsString]) -> windows_service::Result<u32> {
        match parse_payload_request(arguments)
            .map_err(|_| windows_service::Error::Winapi(io::Error::from_raw_os_error(87).into()))?
        {
            PayloadRequest::File(args) => {
                let exit_code = run_service_once(&args)
                    .map_err(|error| windows_service::Error::Winapi(error.into()))?;
                Ok(exit_code as u32)
            }
            PayloadRequest::Pipe(args) => {
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| windows_service::Error::Winapi(error.into()))?;
                runtime
                    .block_on(run_pipe_service(args))
                    .map(|exit_code| exit_code as u32)
                    .map_err(|error| windows_service::Error::Winapi(error.into()))
            }
        }
    }

    async fn run_pipe_service(args: PipeServiceArgs) -> io::Result<i32> {
        let pipes = PipeNames::new(&args.pipe_prefix);
        let mut stdin_pipe = create_named_pipe(&pipes.stdin, true, false)?;
        let mut stdout_pipe = create_named_pipe(&pipes.stdout, false, true)?;
        let mut stderr_pipe = create_named_pipe(&pipes.stderr, false, true)?;
        let mut control_pipe = create_named_pipe(&pipes.control, false, true)?;

        tokio::try_join!(
            stdin_pipe.connect(),
            stdout_pipe.connect(),
            stderr_pipe.connect(),
            control_pipe.connect(),
        )?;

        let mut child = pipe_child_command(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "child stdin pipe missing"))?;
        let mut child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "child stdout pipe missing"))?;
        let mut child_stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "child stderr pipe missing"))?;

        write_control_line(&mut control_pipe, "READY\n").await?;

        let stdin_task = relay_stdin(&mut stdin_pipe, &mut child_stdin);
        let stdout_task = relay_stdout(&mut child_stdout, &mut stdout_pipe);
        let stderr_task = relay_stdout(&mut child_stderr, &mut stderr_pipe);
        let wait_task = async { child.wait().await };

        let (stdin_result, stdout_result, stderr_result, status_result) =
            tokio::join!(stdin_task, stdout_task, stderr_task, wait_task);
        stdin_result?;
        stdout_result?;
        stderr_result?;

        let exit_code = status_result?.code().unwrap_or(1);
        write_control_line(&mut control_pipe, &format!("EXIT {exit_code}\n")).await?;
        Ok(exit_code)
    }

    fn create_named_pipe(
        name: &str,
        access_inbound: bool,
        access_outbound: bool,
    ) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options
            .access_inbound(access_inbound)
            .access_outbound(access_outbound)
            .pipe_mode(PipeMode::Byte)
            .reject_remote_clients(false)
            .max_instances(1)
            .in_buffer_size(64 * 1024)
            .out_buffer_size(64 * 1024);
        options.create(name)
    }

    fn pipe_child_command(args: &PipeServiceArgs) -> Command {
        let mut command =
            Command::new(std::env::var_os("COMSPEC").unwrap_or_else(|| OsString::from("cmd.exe")));
        command.arg("/Q");
        if let Some(request) = &args.command {
            command.arg("/C").arg(request);
        }
        if let Some(working_directory) = &args.working_directory {
            command.current_dir(working_directory);
        }
        command
    }

    async fn relay_stdin(
        pipe: &mut NamedPipeServer,
        child_stdin: &mut ChildStdin,
    ) -> io::Result<()> {
        match copy(pipe, child_stdin).await {
            Ok(_) => child_stdin.shutdown().await,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn relay_stdout<R>(reader: &mut R, pipe: &mut NamedPipeServer) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        match copy(reader, pipe).await {
            Ok(_) => {
                pipe.shutdown().await?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn write_control_line(pipe: &mut NamedPipeServer, line: &str) -> io::Result<()> {
        pipe.write_all(line.as_bytes()).await?;
        pipe.flush().await
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows_main::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("smolder-psexecsvc is intended to be built for Windows targets");
}
