# Tools File Workflows

Use `smolder` when you want a higher-level SMB file API instead of explicit
protocol orchestration.

The intended entry points are:

- [`SmbClientBuilder`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- [`SmbClient`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- [`Share`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- [`RemoteFile`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- [`ShareReconnectPlan`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/reconnect.rs)

## Minimal File Roundtrip

The shipped compile-checked version of this flow is:

- [smolder-tools/examples/file_roundtrip.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/examples/file_roundtrip.rs)

```rust
use smolder_tools::prelude::SmbClientBuilder;
use smolder_tools::prelude::NtlmCredentials;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let client = SmbClientBuilder::new()
    .server("fileserver.lab.example")
    .credentials(NtlmCredentials::new("alice", "secret"))
    .connect()
    .await?;
let share = client.share("share").await?;

let mut file = share.create("notes.txt").await?;
file.write_all(b"hello from smolder\n").await?;
file.flush().await?;
file.close().await?;
# Ok(())
# }
```

## DFS And Reconnect

Use the tools layer when you need:

- DFS-aware path resolution with [`connect_share_path`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- higher-level share path fallback with [`share_path_auto`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- reconnect orchestration with [`ShareReconnectPlan`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/reconnect.rs)

That is the main difference from `smolder-smb-core`: the core crate gives you
the reusable primitives, while `smolder` gives you the ergonomic workflow.

## Encryption Expectations

The high-level builder advertises SMB encryption by default and can require it
explicitly.

That policy lives in:

- [`smolder-tools/src/fs/implementation.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/src/fs/implementation.rs)
- [support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md)
