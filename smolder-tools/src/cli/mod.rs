//! Shared CLI entrypoints for the Smolder tool suite.
//!
//! The standalone binaries and the temporary compatibility `smolder` wrapper
//! reuse these helpers so operator workflows stay on one implementation path.

mod common;
mod file_tools;
mod remote_exec_tools;

pub use file_tools::{run_file_tool, FileTool};
pub use remote_exec_tools::{run_remote_exec_tool, RemoteExecTool};

/// Runs the temporary compatibility `smolder <subcommand>` wrapper.
pub async fn run_smolder(args: Vec<String>) -> Result<i32, String> {
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| "smolder".to_string());
    let Some(command) = args.get(1).cloned() else {
        return Err(wrapper_usage(&program));
    };
    if command == "-h" || command == "--help" {
        return Err(wrapper_usage(&program));
    }

    let mut tool_args = Vec::with_capacity(args.len().saturating_sub(1));
    tool_args.push(format!("{program} {command}"));
    tool_args.extend(args.into_iter().skip(2));

    match command.as_str() {
        "smbexec" => run_remote_exec_tool(RemoteExecTool::SmbExec, tool_args).await,
        "psexec" => run_remote_exec_tool(RemoteExecTool::PsExec, tool_args).await,
        "cat" => run_file_tool(FileTool::Cat, tool_args).await,
        "ls" => run_file_tool(FileTool::Ls, tool_args).await,
        "stat" => run_file_tool(FileTool::Stat, tool_args).await,
        "get" => run_file_tool(FileTool::Get, tool_args).await,
        "put" => run_file_tool(FileTool::Put, tool_args).await,
        "rm" => run_file_tool(FileTool::Remove, tool_args).await,
        "mv" => run_file_tool(FileTool::Move, tool_args).await,
        _ => Err(format!(
            "unknown command: {command}\n\n{}",
            wrapper_usage(&program)
        )),
    }
}

fn wrapper_usage(program: &str) -> String {
    format!(
        "\
Usage:
  {program} <command> [options]

Commands:
  smbexec
  psexec
  cat
  ls
  stat
  get
  put
  rm
  mv

Standalone binaries:
  smbexec
  psexec
  smolder-cat
  smolder-ls
  smolder-stat
  smolder-get
  smolder-put
  smolder-rm
  smolder-mv"
    )
}
