use smolder_core::prelude::{NamedPipe, PipeAccess, PipeRpcClient, connect_tree};
mod common;
use common::{
    SVCCTL_CONTEXT_ID, SVCCTL_SYNTAX, WindowsNtlmConfig, open_sc_manager_stub,
    parse_open_handle_response, windows_lock,
};

#[tokio::test]
async fn opens_sc_manager_over_windows_rpc_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = WindowsNtlmConfig::from_env() else {
        eprintln!(
            "skipping live Windows RPC test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return;
    };

    let connection = connect_tree(&config.session(), "IPC$")
        .await
        .expect("should connect to Windows IPC$");
    let pipe = NamedPipe::open(connection, "svcctl", PipeAccess::ReadWrite)
        .await
        .expect("should open svcctl named pipe");
    let mut rpc = PipeRpcClient::new(pipe);
    let bind_ack = rpc
        .bind_context(SVCCTL_CONTEXT_ID, SVCCTL_SYNTAX)
        .await
        .expect("svcctl bind should succeed");
    assert_eq!(bind_ack.result.result, 0);
    assert_eq!(bind_ack.result.reason, 0);

    let response = rpc
        .call(SVCCTL_CONTEXT_ID, 15, open_sc_manager_stub())
        .await
        .expect("OpenSCManagerW should succeed over svcctl");
    let handle = parse_open_handle_response(&response)
        .expect("OpenSCManagerW response should contain a valid SC handle");
    assert!(handle.0.iter().any(|byte| *byte != 0));

    let connection = rpc
        .into_pipe()
        .close()
        .await
        .expect("pipe close should return the IPC$ tree");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("tree disconnect should succeed");
    connection.logoff().await.expect("logoff should succeed");
}
