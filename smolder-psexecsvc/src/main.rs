//! Windows service entrypoint for the Smolder PsExec payload.

#[cfg(windows)]
mod windows_main {
    use std::ffi::{c_void, OsStr, OsString};
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::{self, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::ptr;
    use std::thread;
    use std::sync::OnceLock;

    use smolder_psexecsvc::{
        parse_launch_config, parse_payload_request, run_service_once, PayloadRequest, PipeNames,
        PipeServiceArgs,
    };

    type Bool = i32;
    type Dword = u32;
    type Word = u16;
    type SizeT = usize;
    type Hresult = i32;
    type Handle = *mut c_void;
    type HpcOn = Handle;
    type ServiceStatusHandle = *mut c_void;
    type ServiceMainFn = unsafe extern "system" fn(Dword, *mut *mut u16);
    type HandlerExFn = unsafe extern "system" fn(Dword, Dword, *mut c_void, *mut c_void) -> Dword;
    type CreatePseudoConsoleFn =
        unsafe extern "system" fn(Coord, Handle, Handle, Dword, *mut HpcOn) -> Hresult;
    type ClosePseudoConsoleFn = unsafe extern "system" fn(HpcOn);

    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const NO_ERROR: Dword = 0;
    const ERROR_CALL_NOT_IMPLEMENTED: Dword = 120;
    const ERROR_INVALID_PARAMETER: Dword = 87;
    const ERROR_PIPE_CONNECTED: i32 = 535;
    const PIPE_ACCESS_INBOUND: Dword = 0x0000_0001;
    const PIPE_ACCESS_OUTBOUND: Dword = 0x0000_0002;
    const PIPE_TYPE_BYTE: Dword = 0x0000_0000;
    const PIPE_READMODE_BYTE: Dword = 0x0000_0000;
    const PIPE_WAIT: Dword = 0x0000_0000;
    const PIPE_INSTANCE_COUNT: Dword = 1;
    const PIPE_BUFFER_SIZE: Dword = 8192;
    const SERVICE_WIN32_OWN_PROCESS: Dword = 0x0000_0010;
    const SERVICE_STOPPED: Dword = 0x0000_0001;
    const SERVICE_RUNNING: Dword = 0x0000_0004;
    const SERVICE_CONTROL_INTERROGATE: Dword = 0x0000_0004;
    const EXTENDED_STARTUPINFO_PRESENT: Dword = 0x0008_0000;
    const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: SizeT = 0x0002_0016;
    const INFINITE: Dword = 0xffff_ffff;
    const DEFAULT_CONSOLE_COLUMNS: u16 = 120;
    const DEFAULT_CONSOLE_ROWS: u16 = 40;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Coord {
        x: i16,
        y: i16,
    }

    #[repr(C)]
    struct SecurityAttributes {
        length: Dword,
        security_descriptor: *mut c_void,
        inherit_handle: Bool,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: Dword,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: Dword,
        y: Dword,
        x_size: Dword,
        y_size: Dword,
        x_count_chars: Dword,
        y_count_chars: Dword,
        fill_attribute: Dword,
        flags: Dword,
        show_window: Word,
        cb_reserved2: Word,
        lp_reserved2: *mut u8,
        std_input: Handle,
        std_output: Handle,
        std_error: Handle,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        attribute_list: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: Handle,
        thread: Handle,
        process_id: Dword,
        thread_id: Dword,
    }

    #[repr(C)]
    struct ServiceStatus {
        service_type: Dword,
        current_state: Dword,
        controls_accepted: Dword,
        win32_exit_code: Dword,
        service_specific_exit_code: Dword,
        checkpoint: Dword,
        wait_hint: Dword,
    }

    #[repr(C)]
    struct ServiceTableEntryW {
        service_name: *mut u16,
        service_proc: Option<ServiceMainFn>,
    }

    #[derive(Clone, Copy)]
    struct PseudoConsoleApi {
        create: CreatePseudoConsoleFn,
        close: ClosePseudoConsoleFn,
    }

    struct PseudoConsoleChild {
        process: Handle,
        hpc: HpcOn,
        api: PseudoConsoleApi,
    }

    impl PseudoConsoleChild {
        fn wait(self) -> io::Result<u32> {
            if unsafe { WaitForSingleObject(self.process, INFINITE) } == u32::MAX {
                let error = io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(self.process);
                    (self.api.close)(self.hpc);
                }
                return Err(error);
            }

            let mut exit_code = 1;
            let exit_result = unsafe { GetExitCodeProcess(self.process, &mut exit_code) };
            unsafe {
                let _ = CloseHandle(self.process);
                (self.api.close)(self.hpc);
            }
            if exit_result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(exit_code)
        }
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegisterServiceCtrlHandlerExW(
            service_name: *const u16,
            handler: Option<HandlerExFn>,
            context: *mut c_void,
        ) -> ServiceStatusHandle;
        fn SetServiceStatus(
            status_handle: ServiceStatusHandle,
            service_status: *const ServiceStatus,
        ) -> Bool;
        fn StartServiceCtrlDispatcherW(service_table: *const ServiceTableEntryW) -> Bool;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: Dword,
            pipe_mode: Dword,
            max_instances: Dword,
            out_buffer_size: Dword,
            in_buffer_size: Dword,
            default_timeout: Dword,
            security_attributes: *mut c_void,
        ) -> Handle;
        fn CreatePipe(
            read_pipe: *mut Handle,
            write_pipe: *mut Handle,
            security_attributes: *const SecurityAttributes,
            size: Dword,
        ) -> Bool;
        fn CloseHandle(handle: Handle) -> Bool;
        fn ConnectNamedPipe(handle: Handle, overlapped: *mut c_void) -> Bool;
        fn CreateProcessW(
            application_name: *const u16,
            command_line: *mut u16,
            process_attributes: *mut SecurityAttributes,
            thread_attributes: *mut SecurityAttributes,
            inherit_handles: Bool,
            creation_flags: Dword,
            environment: *mut c_void,
            current_directory: *const u16,
            startup_info: *mut StartupInfoW,
            process_information: *mut ProcessInformation,
        ) -> Bool;
        fn FlushFileBuffers(handle: Handle) -> Bool;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut Dword) -> Bool;
        fn GetModuleHandleW(module_name: *const u16) -> Handle;
        fn GetProcAddress(module: Handle, proc_name: *const u8) -> *mut c_void;
        fn InitializeProcThreadAttributeList(
            attribute_list: *mut c_void,
            attribute_count: Dword,
            flags: Dword,
            size: *mut SizeT,
        ) -> Bool;
        fn UpdateProcThreadAttribute(
            attribute_list: *mut c_void,
            flags: Dword,
            attribute: SizeT,
            value: *mut c_void,
            size: SizeT,
            previous_value: *mut c_void,
            return_size: *mut SizeT,
        ) -> Bool;
        fn DeleteProcThreadAttributeList(attribute_list: *mut c_void);
        fn WaitForSingleObject(handle: Handle, milliseconds: Dword) -> Dword;
    }

    #[derive(Debug, Clone)]
    struct LaunchState {
        service_name_wide: Vec<u16>,
        debug_log_path: Option<PathBuf>,
        service_args: Vec<OsString>,
    }

    static LAUNCH_STATE: OnceLock<LaunchState> = OnceLock::new();

    pub fn main() -> io::Result<()> {
        let args = std::env::args_os().skip(1).collect::<Vec<_>>();
        let launch = parse_launch_config(&args).map_err(|_| invalid_parameter_error())?;
        append_debug_log(
            launch.debug_log_path.as_deref(),
            &format!(
                "main console={} service_name={} raw_args={:?} service_args={:?}",
                launch.console_mode, launch.service_name, args, launch.service_args
            ),
        );
        if launch.console_mode {
            let exit_code = run_payload(launch.debug_log_path.as_deref(), &launch.service_args);
            append_debug_log(
                launch.debug_log_path.as_deref(),
                &format!("console exit_code={exit_code}"),
            );
            std::process::exit(exit_code as i32);
        }
        LAUNCH_STATE
            .set(LaunchState {
                service_name_wide: wide_null(OsStr::new(&launch.service_name)),
                debug_log_path: launch.debug_log_path,
                service_args: launch.service_args,
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::AlreadyExists, "launch state already set")
            })?;
        append_debug_log(
            state().debug_log_path.as_deref(),
            "starting service dispatcher",
        );

        let service_name = &state().service_name_wide;
        let service_table = [
            ServiceTableEntryW {
                service_name: service_name.as_ptr() as *mut u16,
                service_proc: Some(service_main),
            },
            ServiceTableEntryW {
                service_name: ptr::null_mut(),
                service_proc: None,
            },
        ];

        if unsafe { StartServiceCtrlDispatcherW(service_table.as_ptr()) } == 0 {
            append_debug_log(
                state().debug_log_path.as_deref(),
                &format!(
                    "StartServiceCtrlDispatcherW failed: {:?}",
                    io::Error::last_os_error()
                ),
            );
            return Err(io::Error::last_os_error());
        }
        append_debug_log(
            state().debug_log_path.as_deref(),
            "service dispatcher returned",
        );
        Ok(())
    }

    unsafe extern "system" fn service_main(_argc: Dword, _argv: *mut *mut u16) {
        append_debug_log(state().debug_log_path.as_deref(), "service_main entered");
        let _ = run_service();
    }

    fn run_service() -> io::Result<()> {
        let status_handle = unsafe {
            RegisterServiceCtrlHandlerExW(
                state().service_name_wide.as_ptr(),
                Some(service_control_handler),
                ptr::null_mut(),
            )
        };
        if status_handle.is_null() {
            append_debug_log(
                state().debug_log_path.as_deref(),
                &format!(
                    "RegisterServiceCtrlHandlerExW failed: {:?}",
                    io::Error::last_os_error()
                ),
            );
            return Err(io::Error::last_os_error());
        }
        append_debug_log(
            state().debug_log_path.as_deref(),
            "service control handler registered",
        );
        set_service_status(status_handle, SERVICE_RUNNING, NO_ERROR)?;
        append_debug_log(
            state().debug_log_path.as_deref(),
            "service status set to running",
        );

        let exit_code = run_payload(state().debug_log_path.as_deref(), &state().service_args);
        append_debug_log(
            state().debug_log_path.as_deref(),
            &format!("payload exit_code={exit_code}"),
        );

        set_service_status(status_handle, SERVICE_STOPPED, exit_code)?;
        append_debug_log(
            state().debug_log_path.as_deref(),
            "service status set to stopped",
        );
        Ok(())
    }

    fn run_payload(debug_log_path: Option<&Path>, arguments: &[OsString]) -> u32 {
        append_debug_log(
            debug_log_path,
            &format!("run_payload arguments={arguments:?}"),
        );
        match parse_payload_request(arguments) {
            Ok(PayloadRequest::File(args)) => match run_service_once(&args) {
                Ok(exit_code) if exit_code >= 0 => {
                    append_debug_log(
                        debug_log_path,
                        &format!("run_service_once exit={exit_code}"),
                    );
                    exit_code as u32
                }
                Ok(_) => {
                    append_debug_log(
                        debug_log_path,
                        "run_service_once returned negative exit code",
                    );
                    1
                }
                Err(error) => {
                    append_debug_log(
                        debug_log_path,
                        &format!("run_service_once failed: {error:?}"),
                    );
                    error_code(&error)
                }
            },
            Ok(PayloadRequest::Pipe(args)) => match run_pipe_service(debug_log_path, &args) {
                Ok(exit_code) => {
                    append_debug_log(
                        debug_log_path,
                        &format!("run_pipe_service exit={exit_code}"),
                    );
                    exit_code
                }
                Err(error) => {
                    append_debug_log(
                        debug_log_path,
                        &format!("run_pipe_service failed: {error:?}"),
                    );
                    error_code(&error)
                }
            }
            Err(error) => {
                append_debug_log(
                    debug_log_path,
                    &format!("parse_payload_request failed: {error}"),
                );
                ERROR_INVALID_PARAMETER
            }
        }
    }

    fn run_pipe_service(
        debug_log_path: Option<&Path>,
        args: &PipeServiceArgs,
    ) -> io::Result<u32> {
        let pipes = PipeNames::new(&args.pipe_prefix);
        append_debug_log(
            debug_log_path,
            &format!("creating pipe set for prefix={}", args.pipe_prefix),
        );

        let stdin_pipe = create_named_pipe(OsStr::new(&pipes.stdin), PIPE_ACCESS_INBOUND)?;
        let stdout_pipe = create_named_pipe(OsStr::new(&pipes.stdout), PIPE_ACCESS_OUTBOUND)?;
        let stderr_pipe = create_named_pipe(OsStr::new(&pipes.stderr), PIPE_ACCESS_OUTBOUND)?;
        let control_pipe = create_named_pipe(OsStr::new(&pipes.control), PIPE_ACCESS_OUTBOUND)?;

        connect_named_pipe(&stdin_pipe)?;
        connect_named_pipe(&stdout_pipe)?;
        connect_named_pipe(&stderr_pipe)?;
        connect_named_pipe(&control_pipe)?;
        append_debug_log(debug_log_path, "interactive pipes connected");

        if let Some(api) = pseudo_console_api() {
            append_debug_log(debug_log_path, "starting interactive child with ConPTY");
            return run_conpty_pipe_service(
                debug_log_path,
                args,
                api,
                stdin_pipe,
                stdout_pipe,
                stderr_pipe,
                control_pipe,
            );
        }

        append_debug_log(
            debug_log_path,
            "CreatePseudoConsole unavailable, falling back to redirected pipes",
        );
        run_legacy_pipe_service(debug_log_path, args, stdin_pipe, stdout_pipe, stderr_pipe, control_pipe)
    }

    fn run_legacy_pipe_service(
        debug_log_path: Option<&Path>,
        args: &PipeServiceArgs,
        stdin_pipe: File,
        stdout_pipe: File,
        stderr_pipe: File,
        mut control_pipe: File,
    ) -> io::Result<u32> {
        let mut command = interactive_child_command(args);
        command
            .stdin(Stdio::from(stdin_pipe))
            .stdout(Stdio::from(stdout_pipe))
            .stderr(Stdio::from(stderr_pipe));
        if let Some(working_directory) = &args.working_directory {
            command.current_dir(working_directory);
        }

        let mut child = command.spawn()?;
        append_debug_log(debug_log_path, "interactive child spawned");
        write_control_line(&mut control_pipe, "READY")?;

        let status = child.wait()?;
        let exit_code = status.code().unwrap_or(1);
        append_debug_log(
            debug_log_path,
            &format!("interactive child exited with code={exit_code}"),
        );
        write_control_line(&mut control_pipe, &format!("EXIT {exit_code}"))?;
        Ok(exit_code as u32)
    }

    fn run_conpty_pipe_service(
        debug_log_path: Option<&Path>,
        args: &PipeServiceArgs,
        api: PseudoConsoleApi,
        stdin_pipe: File,
        stdout_pipe: File,
        stderr_pipe: File,
        mut control_pipe: File,
    ) -> io::Result<u32> {
        let (pty_input_read, mut pty_input_write) = create_anonymous_pipe()?;
        let (mut pty_output_read, pty_output_write) = create_anonymous_pipe()?;
        let hpc = create_pseudo_console(
            api,
            console_size(args),
            pty_input_read.as_raw_handle() as Handle,
            pty_output_write.as_raw_handle() as Handle,
        )?;
        drop(pty_input_read);
        drop(pty_output_write);
        drop(stderr_pipe);

        let stdin_thread = thread::spawn(move || {
            let mut stdin_pipe = stdin_pipe;
            let _ = io::copy(&mut stdin_pipe, &mut pty_input_write);
            let _ = pty_input_write.flush();
        });
        let stdout_thread = thread::spawn(move || {
            let mut stdout_pipe = stdout_pipe;
            let _ = io::copy(&mut pty_output_read, &mut stdout_pipe);
            let _ = stdout_pipe.flush();
        });

        let child = spawn_pseudoconsole_child(debug_log_path, args, api, hpc)?;
        append_debug_log(debug_log_path, "interactive ConPTY child spawned");
        write_control_line(&mut control_pipe, "READY")?;
        let exit_code = child.wait()?;
        append_debug_log(
            debug_log_path,
            &format!("interactive ConPTY child exited with code={exit_code}"),
        );
        let _ = stdout_thread.join();
        write_control_line(&mut control_pipe, &format!("EXIT {exit_code}"))?;
        let _ = stdin_thread.join();
        Ok(exit_code as u32)
    }

    unsafe extern "system" fn service_control_handler(
        control: Dword,
        _event_type: Dword,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> Dword {
        match control {
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    fn set_service_status(
        status_handle: ServiceStatusHandle,
        current_state: Dword,
        win32_exit_code: Dword,
    ) -> io::Result<()> {
        let status = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state,
            controls_accepted: 0,
            win32_exit_code,
            service_specific_exit_code: 0,
            checkpoint: 0,
            wait_hint: 0,
        };
        if unsafe { SetServiceStatus(status_handle, &status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn state() -> &'static LaunchState {
        LAUNCH_STATE
            .get()
            .expect("launch state must be initialized before starting the dispatcher")
    }

    fn append_debug_log(path: Option<&Path>, line: &str) {
        let Some(path) = path else {
            return;
        };
        let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
            return;
        };
        let _ = std::io::Write::write_all(&mut file, line.as_bytes());
        let _ = std::io::Write::write_all(&mut file, b"\r\n");
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn create_named_pipe(name: &OsStr, open_mode: Dword) -> io::Result<File> {
        let name = wide_null(name);
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_INSTANCE_COUNT,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn connect_named_pipe(pipe: &File) -> io::Result<()> {
        if unsafe { ConnectNamedPipe(pipe.as_raw_handle() as Handle, ptr::null_mut()) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED) {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }

    fn write_control_line(control_pipe: &mut File, line: &str) -> io::Result<()> {
        control_pipe.write_all(line.as_bytes())?;
        control_pipe.write_all(b"\n")?;
        control_pipe.flush()?;
        if unsafe { FlushFileBuffers(control_pipe.as_raw_handle() as Handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn pseudo_console_api() -> Option<PseudoConsoleApi> {
        static API: OnceLock<Option<PseudoConsoleApi>> = OnceLock::new();
        *API.get_or_init(|| unsafe {
            let module_name = wide_null(OsStr::new("kernel32.dll"));
            let module = GetModuleHandleW(module_name.as_ptr());
            if module.is_null() {
                return None;
            }

            let create = GetProcAddress(module, b"CreatePseudoConsole\0".as_ptr());
            let close = GetProcAddress(module, b"ClosePseudoConsole\0".as_ptr());
            if create.is_null() || close.is_null() {
                return None;
            }

            Some(PseudoConsoleApi {
                create: std::mem::transmute::<*mut c_void, CreatePseudoConsoleFn>(create),
                close: std::mem::transmute::<*mut c_void, ClosePseudoConsoleFn>(close),
            })
        })
    }

    fn create_anonymous_pipe() -> io::Result<(File, File)> {
        let security_attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as Dword,
            security_descriptor: ptr::null_mut(),
            inherit_handle: 0,
        };
        let mut read_handle = ptr::null_mut();
        let mut write_handle = ptr::null_mut();
        if unsafe {
            CreatePipe(
                &mut read_handle,
                &mut write_handle,
                &security_attributes,
                PIPE_BUFFER_SIZE,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe {
            (
                File::from_raw_handle(read_handle),
                File::from_raw_handle(write_handle),
            )
        })
    }

    fn create_pseudo_console(
        api: PseudoConsoleApi,
        size: Coord,
        input: Handle,
        output: Handle,
    ) -> io::Result<HpcOn> {
        let mut hpc = ptr::null_mut();
        let hr = unsafe { (api.create)(size, input, output, 0, &mut hpc) };
        if hr < 0 {
            return Err(io::Error::from_raw_os_error(hr));
        }
        Ok(hpc)
    }

    fn spawn_pseudoconsole_child(
        debug_log_path: Option<&Path>,
        args: &PipeServiceArgs,
        api: PseudoConsoleApi,
        hpc: HpcOn,
    ) -> io::Result<PseudoConsoleChild> {
        let mut attribute_list_size = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(
                ptr::null_mut(),
                1,
                0,
                &mut attribute_list_size,
            );
        }
        let mut attribute_list = vec![0_u8; attribute_list_size];
        if unsafe {
            InitializeProcThreadAttributeList(
                attribute_list.as_mut_ptr() as *mut c_void,
                1,
                0,
                &mut attribute_list_size,
            )
        } == 0
        {
            unsafe { (api.close)(hpc) };
            return Err(io::Error::last_os_error());
        }

        let mut hpc_value = hpc;
        if unsafe {
            UpdateProcThreadAttribute(
                attribute_list.as_mut_ptr() as *mut c_void,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                (&mut hpc_value as *mut HpcOn).cast::<c_void>(),
                std::mem::size_of::<HpcOn>(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            unsafe {
                DeleteProcThreadAttributeList(attribute_list.as_mut_ptr() as *mut c_void);
                (api.close)(hpc);
            }
            return Err(io::Error::last_os_error());
        }

        let mut startup_info = StartupInfoExW {
            startup_info: StartupInfoW {
                cb: std::mem::size_of::<StartupInfoExW>() as Dword,
                reserved: ptr::null_mut(),
                desktop: ptr::null_mut(),
                title: ptr::null_mut(),
                x: 0,
                y: 0,
                x_size: 0,
                y_size: 0,
                x_count_chars: 0,
                y_count_chars: 0,
                fill_attribute: 0,
                flags: 0,
                show_window: 0,
                cb_reserved2: 0,
                lp_reserved2: ptr::null_mut(),
                std_input: ptr::null_mut(),
                std_output: ptr::null_mut(),
                std_error: ptr::null_mut(),
            },
            attribute_list: attribute_list.as_mut_ptr() as *mut c_void,
        };
        let mut process_info = ProcessInformation {
            process: ptr::null_mut(),
            thread: ptr::null_mut(),
            process_id: 0,
            thread_id: 0,
        };
        let mut command_line = interactive_child_command_line(args);
        let current_directory = args
            .working_directory
            .as_ref()
            .map(|path| wide_null(path.as_os_str()));

        if unsafe {
            CreateProcessW(
                ptr::null(),
                command_line.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                EXTENDED_STARTUPINFO_PRESENT,
                ptr::null_mut(),
                current_directory
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
                &mut startup_info.startup_info,
                &mut process_info,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            append_debug_log(
                debug_log_path,
                &format!("CreateProcessW with ConPTY failed: {error:?}"),
            );
            unsafe {
                DeleteProcThreadAttributeList(attribute_list.as_mut_ptr() as *mut c_void);
                (api.close)(hpc);
            }
            return Err(error);
        }

        unsafe {
            DeleteProcThreadAttributeList(attribute_list.as_mut_ptr() as *mut c_void);
            let _ = CloseHandle(process_info.thread);
        }

        Ok(PseudoConsoleChild {
            process: process_info.process,
            hpc,
            api,
        })
    }

    fn console_size(args: &PipeServiceArgs) -> Coord {
        Coord {
            x: args.columns.unwrap_or(DEFAULT_CONSOLE_COLUMNS) as i16,
            y: args.rows.unwrap_or(DEFAULT_CONSOLE_ROWS) as i16,
        }
    }

    fn interactive_child_command(args: &PipeServiceArgs) -> Command {
        let mut command =
            Command::new(std::env::var_os("COMSPEC").unwrap_or_else(|| OsString::from("cmd.exe")));
        command.arg("/Q");
        command.arg("/F:ON");
        if let Some(command_text) = &args.command {
            command.arg("/C").arg(command_text);
        }
        command
    }

    fn interactive_child_command_line(args: &PipeServiceArgs) -> Vec<u16> {
        let comspec = std::env::var_os("COMSPEC").unwrap_or_else(|| OsString::from("cmd.exe"));
        let mut command_line = quote_windows_arg(&comspec.to_string_lossy());
        command_line.push_str(" /Q /F:ON");
        if let Some(command_text) = &args.command {
            command_line.push_str(" /C ");
            command_line.push_str(&quote_windows_arg(command_text));
        }
        wide_null(OsStr::new(&command_line))
    }

    fn quote_windows_arg(value: &str) -> String {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    }

    fn invalid_parameter_error() -> io::Error {
        io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32)
    }

    fn error_code(error: &io::Error) -> u32 {
        match error.raw_os_error() {
            Some(code) if code >= 0 => code as u32,
            _ => 1,
        }
    }
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    windows_main::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("smolder-psexecsvc is intended to be built for Windows targets");
}
