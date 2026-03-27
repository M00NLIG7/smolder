# smolder-smb-core

`smolder-smb-core` is the reusable SMB/RPC library layer for Smolder.

The published package name is `smolder-smb-core`, while the Rust library crate
name remains `smolder_core`.

It owns SMB auth/session state, transport logic, signing, encryption, named
pipes, RPC transport, DFS helpers, and durable/reconnect primitives.

Recommended entry points:

- `smolder_core::client::Connection` for typed SMB negotiate/session/tree flow
- `smolder_core::pipe::{SmbSessionConfig, NamedPipe, connect_tree}` for `IPC$`
  and named-pipe usage
- `smolder_core::rpc::PipeRpcClient` for DCE/RPC over named pipes
- `smolder_core::prelude` for the curated surface

API guidance:

- repository API notes:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/smolder-core-api.md>

Examples:

- `cargo run -p smolder-smb-core --example ntlm_tree_connect`
- `cargo run -p smolder-smb-core --example named_pipe_rpc_bind`
- `cargo run -p smolder-smb-core --features kerberos --example kerberos_tree_connect`

Repository: <https://github.com/M00NLIG7/smolder>
