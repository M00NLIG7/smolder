# Tools File Workflows

Use `smolder` when you want a higher-level SMB file API instead of explicit
protocol orchestration.

The intended entry points are:

- [`SmbClientBuilder`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- [`SmbClient`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- [`Share`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- [`RemoteFile`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- [`ShareReconnectPlan`](/Users/cmagana/Projects/smolder/smolder-tools/src/reconnect.rs)

## Minimal File Roundtrip

```rust
use smolder_tools::prelude::SmbClientBuilder;
use smolder_core::prelude::NtlmCredentials;

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

- DFS-aware path resolution with [`connect_share_path`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- higher-level share path fallback with [`share_path_auto`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- reconnect orchestration with [`ShareReconnectPlan`](/Users/cmagana/Projects/smolder/smolder-tools/src/reconnect.rs)

That is the main difference from `smolder-smb-core`: the core crate gives you
the reusable primitives, while `smolder` gives you the ergonomic workflow.

## Encryption Expectations

The high-level builder advertises SMB encryption by default and can require it
explicitly.

That policy lives in:

- [`smolder-tools/src/fs/implementation.rs`](/Users/cmagana/Projects/smolder/smolder-tools/src/fs/implementation.rs)
- [support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md)
