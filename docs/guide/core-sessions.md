# Core Sessions

Use `smolder-smb-core` when you want explicit SMB session control rather than
the higher-level file facade from `smolder`.

The intended entry points are:

- [`SmbSessionConfig`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`connect_tree`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`Connection`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/client.rs)
- [`NtlmCredentials`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/auth/ntlm.rs)

## Minimal NTLM Tree Connect

The smallest useful flow is:

```rust
use smolder_core::prelude::{connect_tree, NtlmCredentials, SmbSessionConfig};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let credentials = NtlmCredentials::new("alice", "secret");
let config = SmbSessionConfig::new("fileserver.lab.example", credentials);
let connection = connect_tree(&config, "IPC$").await?;

println!(
    "session={} tree={}",
    connection.session_id().0,
    connection.tree_id().0
);

let connection = connection.tree_disconnect().await?;
let _ = connection.logoff().await?;
# Ok(())
# }
```

For a compile-checked version, see
[ntlm_tree_connect.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/examples/ntlm_tree_connect.rs).

## When To Stay In Core

Stay in `smolder-smb-core` when you need:

- explicit negotiate/auth/tree control
- named pipes and RPC over `IPC$`
- reusable library integration in another Rust application
- direct access to SMB signing, encryption, and reconnect primitives

Move to `smolder` when you want:

- high-level file operations
- DFS-aware share-path handling
- reconnect plans
- `smbexec` / `psexec`

## Related APIs

- [`pipe.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`client.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/client.rs)
- [`error.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/error.rs)
