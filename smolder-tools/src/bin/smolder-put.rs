use std::env;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match smolder_tools::cli::run_file_tool(
        smolder_tools::cli::FileTool::Put,
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
