//! Windows service entrypoint for the Smolder PsExec payload.

#[cfg(windows)]
mod windows_main {
    use std::ffi::OsString;
    use std::sync::OnceLock;

    use smolder_psexecsvc::{parse_launch_config, parse_service_args, run_service_once};
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
        let launch = parse_launch_config(&args)
            .map_err(|_| windows_service::Error::Winapi(std::io::Error::from_raw_os_error(87).into()))?;
        let _ = SERVICE_NAME.set(OsString::from(&launch.service_name));
        if launch.console_mode {
            let service_args = parse_service_args(&launch.service_args)
                .map_err(|_| windows_service::Error::Winapi(std::io::Error::from_raw_os_error(87).into()))?;
            let _ = run_service_once(&service_args)
                .map_err(|error| windows_service::Error::Winapi(error.into()))?;
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
        let status_handle = service_control_handler::register(service_name, move |control| match control {
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

        let args = parse_service_args(&arguments)
            .map_err(|_| windows_service::Error::Winapi(std::io::Error::from_raw_os_error(87).into()))?;
        let exit_code = run_service_once(&args)
            .map_err(|error| windows_service::Error::Winapi(error.into()))?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(exit_code as u32),
            checkpoint: 0,
            wait_hint: std::time::Duration::ZERO,
            process_id: None,
        })?;
        Ok(())
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
