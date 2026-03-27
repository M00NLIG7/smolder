use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use smolder_tools::prelude::{ExecMode, ExecRequest, NtlmCredentials, RemoteExecClient};

const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

fn env_required(key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    env::var(key).map_err(|_| format!("missing required environment variable: {key}").into())
}

fn env_port(key: &str, default: u16) -> Result<u16, Box<dyn Error + Send + Sync>> {
    match env::var(key) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| format!("invalid u16 in {key}: {value}").into()),
        Err(_) => Ok(default),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let host = env_required("SMOLDER_WINDOWS_HOST")?;
    let port = env_port("SMOLDER_WINDOWS_PORT", 445)?;
    let username = env_required("SMOLDER_WINDOWS_USERNAME")?;
    let password = env_required("SMOLDER_WINDOWS_PASSWORD")?;
    let service_binary = PathBuf::from(env_required("SMOLDER_PSEXEC_SERVICE_BINARY")?);

    let request = match env::var("SMOLDER_PSEXEC_COMMAND") {
        Ok(command) if !command.trim().is_empty() => ExecRequest::command(command),
        _ => ExecRequest::command(String::new()),
    };
    let close_on_exit_command = request.launches_default_shell();

    let client = RemoteExecClient::builder()
        .server(host)
        .port(port)
        .mode(ExecMode::PsExec)
        .credentials(NtlmCredentials::new(username, password))
        .psexec_service_binary(service_binary)
        .connect()
        .await?;

    let session = client.spawn(request).await?;
    let (mut stdin, mut stdout, mut stderr, waiter) = session.into_parts();

    let stdin_task = tokio::spawn(async move {
        pump_local_stdin(&mut stdin, close_on_exit_command).await
    });
    let stdout_task =
        tokio::spawn(async move { pump_remote_output(&mut stdout, tokio::io::stdout()).await });
    let stderr_task =
        tokio::spawn(async move { pump_remote_output(&mut stderr, tokio::io::stderr()).await });

    let exit_code = waiter.wait().await?;
    stdin_task.abort();

    match stdin_task.await {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.into()),
    }
    wait_for_output_task(stdout_task).await?;
    wait_for_output_task(stderr_task).await?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

async fn pump_local_stdin(
    stdin: &mut smolder_tools::prelude::InteractiveStdin,
    close_on_exit_command: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut local_stdin = tokio::io::stdin();
    let mut buffer = [0_u8; 8192];
    let mut pending_line = Vec::new();
    loop {
        let count = local_stdin.read(&mut buffer).await?;
        if count == 0 {
            stdin.close().await?;
            return Ok(());
        }
        let saw_exit_command = close_on_exit_command
            && update_exit_command_state(&mut pending_line, &buffer[..count]);
        stdin.write_all(&buffer[..count]).await?;
        if saw_exit_command {
            stdin.close().await?;
            return Ok(());
        }
    }
}

async fn pump_remote_output<W>(
    reader: &mut smolder_tools::prelude::InteractiveReader,
    mut writer: W,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = reader.read_chunk().await? {
        writer.write_all(&chunk).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn wait_for_output_task(
    mut task: JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match timeout(OUTPUT_DRAIN_TIMEOUT, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(_) => {
            task.abort();
            match task.await {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
    }
}

fn update_exit_command_state(pending_line: &mut Vec<u8>, bytes: &[u8]) -> bool {
    let mut saw_exit_command = false;
    for &byte in bytes {
        pending_line.push(byte);
        if byte == b'\n' {
            let line = String::from_utf8_lossy(pending_line);
            if line.trim() == "exit" {
                saw_exit_command = true;
            }
            pending_line.clear();
        }
    }
    saw_exit_command
}
