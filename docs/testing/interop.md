# Interop Matrix

This document is the current live interoperability matrix for `smolder-core` and
`smolder-tools`.

Use it as the repeatable verification gate for protocol changes, transport
changes, auth changes, pipe/RPC work, and tools-layer workflow changes.

Detailed Samba fixture notes still live in [samba.md](/Users/cmagana/Projects/smolder/docs/testing/samba.md).
The Tiny11 / Windows release-style gate is documented in
[windows.md](/Users/cmagana/Projects/smolder/docs/testing/windows.md).

For a single entrypoint instead of running each command manually, use
[scripts/run-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-interop.sh).

The repository also includes a GitHub Actions workflow at
[interop-samba.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-samba.yml)
that runs the Samba-backed subset on hosted Linux runners.
Release policy and required gate selection live in
[release.md](/Users/cmagana/Projects/smolder/docs/testing/release.md).

## Targets

### Tiny11 / Windows

- Host: `127.0.0.1`
- Default port: `445`
- Username: `windowsfixture`
- Password: `windowsfixture`
- Plain share fixture: `ADMIN$`
- Encrypted share fixture: `SMOLDERENC`
- Global encrypted `IPC$` fixture: server `EncryptData=True`
- DFS fixture: `SMOLDER_WINDOWS_DFS_ROOT`

Base environment:

```bash
export SMOLDER_WINDOWS_HOST=127.0.0.1
export SMOLDER_WINDOWS_USERNAME=windowsfixture
export SMOLDER_WINDOWS_PASSWORD=windowsfixture
```

### Local Samba

- Host: `127.0.0.1`
- Plain/file-share port: `1445`
- Encrypted `IPC$` / named-pipe port: `1446`
- Username: `smolder`
- Password: `smolderpass`
- Plain share fixture: `share`
- Encrypted share fixture: `SMOLDERENC`

Base environment:

```bash
export SMOLDER_SAMBA_HOST=127.0.0.1
export SMOLDER_SAMBA_USERNAME=smolder
export SMOLDER_SAMBA_PASSWORD=smolderpass
```

Start the local fixtures with:

```bash
docker compose -f docker/samba/compose.yaml up -d
docker compose -f docker/samba/compose.yaml up -d samba-global-encryption
```

## Current Matrix

| Layer | Target | Capability | Gate |
| --- | --- | --- | --- |
| `smolder-core` | Windows | negotiate, auth, tree connect, echo, file lifecycle | `windows_interop.rs` |
| `smolder-core` | Windows | durable reconnect | `windows_reconnect.rs` |
| `smolder-core` | Windows | encrypted file I/O | `windows_encryption.rs` |
| `smolder-core` | Windows | named-pipe open/write/read over `IPC$` | `named_pipe_interop.rs` |
| `smolder-core` | Windows | RPC bind plus `OpenSCManagerW` over `svcctl` | `rpc_interop.rs` |
| `smolder-core` | Windows | encrypted `IPC$`, named pipe, and `OpenSCManagerW` over `svcctl` | `windows_rpc_encryption.rs` |
| `smolder-core` | Samba | negotiate, auth, file I/O, IOCTLs, lease-aware create, durable reconnect attempt | `samba_negotiate.rs` |
| `smolder-core` | Samba | encrypted file I/O | `samba_encryption.rs` |
| `smolder-core` | Samba | named-pipe open/write/read over encrypted `IPC$` | `named_pipe_interop.rs` |
| `smolder-core` | Samba | encrypted RPC bind over `srvsvc` | `samba_rpc_encryption.rs` |
| `smolder-tools` | Windows | durable reconnect helper | `windows_reconnect.rs` |
| `smolder-tools` | Windows | encrypted-share requirement enforcement | `windows_encryption.rs` |
| `smolder-tools` | Windows | DFS path resolution and CLI `mv` | `windows_dfs.rs` |
| `smolder-tools` | Samba | high-level file facade and CLI smoke paths | `samba_high_level.rs`, `cli_smoke.rs` |

## Harness

Run every available target/layer from the currently configured environment:

```bash
scripts/run-interop.sh
```

Run only the Windows core matrix:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
scripts/run-interop.sh --windows --core
```

Run the full Windows release-style gate, including remote execution smoke
checks:

```bash
scripts/run-windows-release-gate.sh
```

Run only the Samba matrix:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
scripts/run-interop.sh --samba
```

Add `--remote-exec` to include `smbexec` / `psexec` Windows smoke commands.

## CI Boundary

- GitHub Actions runs the Samba-backed subset through `scripts/run-interop.sh --samba --core --tools`.
- Tiny11 / Windows gates stay manual or self-hosted because they depend on the local VM fixture, local credentials, and the current port-forward setup.

## Core Commands

### Windows

Baseline SMB session/file path:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-core --test windows_interop -- --nocapture
```

Durable reconnect:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-core --test windows_reconnect -- --nocapture
```

Encrypted file I/O:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
SMOLDER_WINDOWS_ENCRYPTED_SHARE=SMOLDERENC \
cargo test -p smolder-core --test windows_encryption -- --nocapture
```

Named-pipe interop:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-core --test named_pipe_interop \
  exchanges_srvsvc_bind_over_windows_named_pipe_when_configured -- --nocapture
```

RPC interop:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-core --test rpc_interop -- --nocapture
```

Encrypted `IPC$` / RPC interop:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-core --test windows_rpc_encryption -- --nocapture
```

### Samba

Baseline SMB session/file path:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_SHARE=share \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo test -p smolder-core --test samba_negotiate -- --nocapture
```

Encrypted file I/O:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_ENCRYPTED_SHARE=SMOLDERENC \
cargo test -p smolder-core --test samba_encryption -- --nocapture
```

Named-pipe interop on encrypted `IPC$`:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1446 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
cargo test -p smolder-core --test named_pipe_interop \
  exchanges_srvsvc_bind_over_samba_named_pipe_when_configured -- --nocapture
```

Encrypted RPC bind:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1446 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
cargo test -p smolder-core --test samba_rpc_encryption -- --nocapture
```

## Tools Commands

### Windows

Encrypted-share enforcement:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
SMOLDER_WINDOWS_ENCRYPTED_SHARE=SMOLDERENC \
cargo test -p smolder-tools --test windows_encryption -- --nocapture
```

Reconnect helper:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-tools --test windows_reconnect -- --nocapture
```

DFS path resolution:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
SMOLDER_WINDOWS_DFS_ROOT='\\\\127.0.0.1\\your-dfs-root' \
cargo test -p smolder-tools --test windows_dfs -- --nocapture
```

Remote execution smoke checks:

```bash
target/debug/smolder smbexec smb://127.0.0.1 --command whoami --username windowsfixture --password windowsfixture
target/debug/smolder psexec smb://127.0.0.1 --command whoami --username windowsfixture --password windowsfixture
```

### Samba

High-level facade:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_SHARE=share \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo test -p smolder-tools --test samba_high_level -- --nocapture
```

CLI smoke:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_SHARE=share \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo test -p smolder-tools --test cli_smoke -- --nocapture --test-threads=1
```

## Expected Policy Boundaries

- `smolder-core` proves protocol, transport, auth, named-pipe, and RPC behavior.
- `smolder-tools` proves reconnection orchestration, DFS host-following, CLI behavior, and remote execution.
- `svcctl` over `ncacn_np` is currently validated as plain DCE/RPC bind over an already-authenticated SMB session.
- The local Samba encrypted `IPC$` fixture is the current pipe/RPC regression target for cross-server encryption behavior.
- The local Samba fixture can reject the resiliency IOCTL and lose durable reopen state after transport drop; the live durable reconnect gate records that as a skip instead of a hard failure.
