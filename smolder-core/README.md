# smolder-smb-core

`smolder-smb-core` is the reusable SMB/RPC library layer for Smolder.

The published package name is `smolder-smb-core`, while the Rust library crate
name remains `smolder_core`.

It owns SMB auth/session state, transport logic, signing, encryption, named
pipes, RPC transport, DFS helpers, and durable/reconnect primitives.

Real-project readiness:

- intended for direct library use within the documented `0.2.x` support policy
- additive API evolution is preferred over churn
- pre-`1.0` breaking changes are still possible, but they should be deliberate
  and reflected in the versioning policy rather than landing silently

Start here:

- examples guide:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md>
- cookbook:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/cookbook.md>
- support policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md>
- versioning policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md>

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
