use std::env;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match smolder_tools::cli::run_remote_exec_tool(
        smolder_tools::cli::RemoteExecTool::PsExec,
        env::args().collect(),
    )
    .await
    {
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
