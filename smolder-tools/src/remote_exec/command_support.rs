use std::path::Path;

use rand::random;

use smolder_core::error::CoreError;
use smolder_proto::smb::status::NtStatus;

use super::{ExecRequest, ADMIN_SHARE_ROOT};

#[derive(Debug, Clone)]
pub(super) struct CommandPaths {
    pub(super) service_name: String,
    pub(super) pipe_prefix: String,
    pub(super) stdout_relative: String,
    pub(super) stderr_relative: String,
    pub(super) exit_relative: String,
    pub(super) debug_relative: String,
    pub(super) script_relative: String,
    pub(super) runner_relative: String,
    pub(super) service_binary_relative: String,
    pub(super) stdout_absolute: String,
    pub(super) stderr_absolute: String,
    pub(super) exit_absolute: String,
    pub(super) debug_absolute: String,
    pub(super) script_absolute: String,
    pub(super) runner_absolute: String,
    pub(super) service_binary_absolute: String,
}

impl CommandPaths {
    pub(super) fn new(staging_directory: &str, psexec_binary_name: &str) -> Self {
        let token = random::<u64>();
        let prefix = format!("SMOLDER-{token:016x}");
        let stdout_relative = join_share_path(staging_directory, &format!("{prefix}.out"));
        let stderr_relative = join_share_path(staging_directory, &format!("{prefix}.err"));
        let exit_relative = join_share_path(staging_directory, &format!("{prefix}.exit"));
        let debug_relative = join_share_path(staging_directory, &format!("{prefix}.dbg"));
        let script_relative = join_share_path(staging_directory, &format!("{prefix}.cmd"));
        let runner_relative = join_share_path(staging_directory, &format!("{prefix}.bat"));
        let service_binary_relative =
            join_share_path(staging_directory, &format!("{prefix}-{psexec_binary_name}"));
        let service_name = format!("SMOLDER{token:016X}");
        Self {
            service_name,
            pipe_prefix: prefix.clone(),
            stdout_absolute: admin_absolute_path(&stdout_relative),
            stderr_absolute: admin_absolute_path(&stderr_relative),
            exit_absolute: admin_absolute_path(&exit_relative),
            debug_absolute: admin_absolute_path(&debug_relative),
            script_absolute: admin_absolute_path(&script_relative),
            runner_absolute: admin_absolute_path(&runner_relative),
            service_binary_absolute: admin_absolute_path(&service_binary_relative),
            stdout_relative,
            stderr_relative,
            exit_relative,
            debug_relative,
            script_relative,
            runner_relative,
            service_binary_relative,
        }
    }

    pub(super) fn stdin_pipe_name(&self) -> String {
        format!("{}.stdin", self.pipe_prefix)
    }

    pub(super) fn stdout_pipe_name(&self) -> String {
        format!("{}.stdout", self.pipe_prefix)
    }

    pub(super) fn stderr_pipe_name(&self) -> String {
        format!("{}.stderr", self.pipe_prefix)
    }

    pub(super) fn control_pipe_name(&self) -> String {
        format!("{}.control", self.pipe_prefix)
    }
}

pub(super) fn build_smbexec_service_command(command_paths: &CommandPaths) -> String {
    format!(r#"%COMSPEC% /Q /c {}"#, command_paths.script_absolute)
}

pub(super) fn build_psexec_service_command(
    psexec_service_binary: Option<&Path>,
    command_paths: &CommandPaths,
) -> String {
    match psexec_service_binary {
        Some(_) => format!(
            "{} --service-name {}{} --script {} --stdout {} --stderr {} --exit-code {}",
            quote_windows_arg(&command_paths.service_binary_absolute),
            quote_windows_arg(&command_paths.service_name),
            psexec_debug_log_arg(command_paths),
            quote_windows_arg(&command_paths.script_absolute),
            quote_windows_arg(&command_paths.stdout_absolute),
            quote_windows_arg(&command_paths.stderr_absolute),
            quote_windows_arg(&command_paths.exit_absolute),
        ),
        None => format!(
            r#"%COMSPEC% /Q /c {}"#,
            quote_windows_arg(&command_paths.script_absolute)
        ),
    }
}

fn psexec_debug_log_arg(command_paths: &CommandPaths) -> String {
    if std::env::var_os("SMOLDER_NTLM_DEBUG").is_some() {
        format!(
            " --debug-log {}",
            quote_windows_arg(&command_paths.debug_absolute)
        )
    } else {
        String::new()
    }
}

pub(super) fn build_psexec_interactive_service_command(
    request: &ExecRequest,
    command_paths: &CommandPaths,
) -> String {
    let mut command = format!(
        "{} --service-name {}{} --pipe-prefix {}",
        quote_windows_arg(&command_paths.service_binary_absolute),
        quote_windows_arg(&command_paths.service_name),
        psexec_debug_log_arg(command_paths),
        quote_windows_arg(&command_paths.pipe_prefix),
    );
    if let Some(command_text) = request.command_text() {
        command.push_str(" --command ");
        command.push_str(&quote_windows_arg(command_text));
    }
    if let Some(working_directory) = &request.working_directory {
        command.push_str(" --workdir ");
        command.push_str(&quote_windows_arg(working_directory));
    }
    if let Some((columns, rows)) = request.terminal_size() {
        command.push_str(" --cols ");
        command.push_str(&columns.to_string());
        command.push_str(" --rows ");
        command.push_str(&rows.to_string());
    }
    command
}

pub(super) fn build_psexec_script(request: &ExecRequest) -> String {
    let mut script = String::from("@echo off\r\n");
    if let Some(working_directory) = &request.working_directory {
        script.push_str(&format!(r#"cd /d "{}" || exit /b 1"#, working_directory));
        script.push_str("\r\n");
    }
    script.push_str(&request.command);
    script.push_str("\r\n");
    script
}

pub(super) fn build_psexec_wrapper_script(command_paths: &CommandPaths) -> String {
    let runner_path = quote_windows_arg(&command_paths.runner_absolute);
    let mut script = String::from("@echo off\r\n");
    script.push_str(&format!(r#"%COMSPEC% /Q /c {runner_path}"#));
    script.push_str("\r\n");
    script
}

pub(super) fn build_psexec_runner_script(
    request: &ExecRequest,
    command_paths: &CommandPaths,
) -> String {
    let stdout_path = quote_windows_arg(&command_paths.stdout_absolute);
    let stderr_path = quote_windows_arg(&command_paths.stderr_absolute);
    let exit_path = quote_windows_arg(&command_paths.exit_absolute);
    let mut script = String::from("@echo off\r\n");
    if let Some(working_directory) = &request.working_directory {
        script.push_str(&format!(r#"cd /d "{working_directory}""#));
        script.push_str("\r\n");
        script.push_str("if errorlevel 1 goto write_exit\r\n");
    }
    script.push_str(request.command_text().expect("validated non-empty command"));
    script.push_str(&format!(r#" 1> {stdout_path} 2> {stderr_path}"#));
    script.push_str("\r\n");
    script.push_str(":write_exit\r\n");
    script.push_str(&format!(r#"echo %ERRORLEVEL% > {exit_path}"#));
    script.push_str("\r\n");
    script
}

pub(super) fn build_smbexec_script(request: &ExecRequest, command_paths: &CommandPaths) -> String {
    let runner_script = build_smbexec_runner_script(request, command_paths);
    let runner_path = quote_windows_arg(&command_paths.runner_absolute);
    let mut script = String::from("@echo off\r\n");
    for (index, line) in runner_script
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let redirect = if index == 0 { ">" } else { ">>" };
        script.push_str("echo ");
        script.push_str(&escape_cmd_for_echo(line));
        script.push(' ');
        script.push_str(redirect);
        script.push(' ');
        script.push_str(&runner_path);
        script.push_str("\r\n");
    }
    script.push_str(&format!(r#"%COMSPEC% /Q /c {runner_path}"#));
    script.push_str("\r\n");
    script.push_str(&format!(r#"del {runner_path}"#));
    script.push_str("\r\n");
    script
}

pub(super) fn build_smbexec_runner_script(
    request: &ExecRequest,
    command_paths: &CommandPaths,
) -> String {
    let stdout_path = quote_windows_arg(&command_paths.stdout_absolute);
    let exit_path = quote_windows_arg(&command_paths.exit_absolute);
    let mut script = String::from("@echo off\r\n");
    if let Some(working_directory) = &request.working_directory {
        script.push_str(&format!(r#"cd /d "{working_directory}""#));
        script.push_str("\r\n");
        script.push_str("if errorlevel 1 goto write_exit\r\n");
    }
    script.push_str(request.command_text().expect("validated non-empty command"));
    script.push_str(&format!(r#" > {stdout_path} 2>&1"#));
    script.push_str("\r\n");
    script.push_str(":write_exit\r\n");
    script.push_str(&format!(r#"echo %ERRORLEVEL% > {exit_path}"#));
    script.push_str("\r\n");
    script
}

pub(super) fn escape_cmd_for_echo(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '^' => escaped.push_str("^^"),
            '&' => escaped.push_str("^&"),
            '|' => escaped.push_str("^|"),
            '<' => escaped.push_str("^<"),
            '>' => escaped.push_str("^>"),
            '(' => escaped.push_str("^("),
            ')' => escaped.push_str("^)"),
            '%' => escaped.push_str("%%"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn admin_absolute_path(relative: &str) -> String {
    format!(r"{ADMIN_SHARE_ROOT}\{}", relative.replace('/', r"\"))
}

fn join_share_path(base: &str, leaf: &str) -> String {
    if base.is_empty() {
        leaf.to_string()
    } else {
        format!(r"{}\{}", base.trim_matches(['\\', '/']), leaf)
    }
}

pub(super) fn normalize_remote_file_name(name: &str) -> Result<String, CoreError> {
    let name = name.trim_matches(['\\', '/']);
    if name.is_empty() {
        return Err(CoreError::PathInvalid(
            "remote psexec binary name must not be empty",
        ));
    }
    if name.contains(['\\', '/', '\0']) {
        return Err(CoreError::PathInvalid(
            "remote psexec binary name must not contain separators or NUL bytes",
        ));
    }
    Ok(name.to_string())
}

pub(super) fn quote_windows_arg(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

pub(super) fn normalize_share_name(share: &str) -> Result<String, CoreError> {
    let share = share.trim_matches(['\\', '/']);
    if share.is_empty() {
        return Err(CoreError::PathInvalid("share name must not be empty"));
    }
    if share.contains(['\\', '/', '\0']) {
        return Err(CoreError::PathInvalid(
            "share name must not contain separators or NUL bytes",
        ));
    }
    Ok(share.to_string())
}

pub(super) fn normalize_share_path(path: &str) -> Result<String, CoreError> {
    if path.contains('\0') {
        return Err(CoreError::PathInvalid("path must not contain NUL bytes"));
    }
    let mut segments = Vec::new();
    for segment in path
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
    {
        if segment == "." || segment == ".." {
            return Err(CoreError::PathInvalid(
                "path must not contain relative segments",
            ));
        }
        segments.push(segment);
    }

    let normalized = segments.join("\\");
    if normalized.is_empty() {
        return Err(CoreError::PathInvalid("path must not be empty"));
    }
    Ok(normalized)
}

pub(super) fn is_not_found(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::UnexpectedStatus { status, .. }
            if *status == NtStatus::OBJECT_NAME_NOT_FOUND.to_u32()
                || *status == NtStatus::OBJECT_PATH_NOT_FOUND.to_u32()
    )
}

pub(super) fn is_end_of_file(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::UnexpectedStatus { status, .. } if *status == NtStatus::END_OF_FILE.to_u32()
    )
}

pub(super) fn is_pipe_not_ready(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::UnexpectedStatus { status, .. }
            if *status == NtStatus::PIPE_NOT_AVAILABLE.to_u32()
    ) || is_not_found(error)
}
