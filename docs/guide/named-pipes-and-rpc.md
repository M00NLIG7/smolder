# Named Pipes And RPC

Smolder treats `IPC$` and named pipes as first-class library primitives in
`smolder-smb-core`.

The intended entry points are:

- [`connect_tree`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`NamedPipe`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`PipeAccess`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`PipeRpcClient`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/rpc.rs)

## Minimal Pipe RPC Bind

```rust
use smolder_core::prelude::{
    connect_tree, NamedPipe, NtlmCredentials, PipeAccess, PipeRpcClient, SmbSessionConfig,
};
use smolder_proto::rpc::{SyntaxId, Uuid};

const SRVSVC_CONTEXT_ID: u16 = 0;
const SRVSVC_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x4b32_4fc8,
        0x1670,
        0x01d3,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    ),
    3,
    0,
);

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let credentials = NtlmCredentials::new("alice", "secret");
let config = SmbSessionConfig::new("fileserver.lab.example", credentials);
let connection = connect_tree(&config, "IPC$").await?;
let pipe = NamedPipe::open(connection, "srvsvc", PipeAccess::ReadWrite).await?;
let mut rpc = PipeRpcClient::new(pipe);

let bind_ack = rpc.bind_context(SRVSVC_CONTEXT_ID, SRVSVC_SYNTAX).await?;
println!("rpc bind ok: max_xmit_frag={}", bind_ack.max_xmit_frag);

let connection = rpc.into_pipe().close().await?;
let connection = connection.tree_disconnect().await?;
let _ = connection.logoff().await?;
# Ok(())
# }
```

For a shipped example, see
[named_pipe_rpc_bind.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/examples/named_pipe_rpc_bind.rs).

## Stream Traits

[`NamedPipe`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs) also
implements `tokio::io::AsyncRead` and `AsyncWrite`.

That means you can:

- use standard Tokio `read` / `write_all` flows
- keep protocol-specific helpers like `read_pdu()` and `read_line()`
- avoid inventing a custom byte-stream abstraction for normal pipe usage

## Related APIs

- [`pipe.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/pipe.rs)
- [`rpc.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/rpc.rs)
- [`smolder-proto/src/rpc/mod.rs`](https://github.com/M00NLIG7/smolder/blob/main/smolder-proto/src/rpc/mod.rs)
