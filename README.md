# Smolder

An SMB research toolkit in Rust. The current codebase is being rebuilt around a typed SMB2/3 protocol layer first, with transport, authentication, and higher-level tooling layered on top once the wire model is stable.

## Overview

Smolder is organized as a small workspace:

- `smolder-proto`: SMB wire types, framing, codecs, and packet validation.
- `smolder-core`: reusable SMB/RPC primitives, transport logic, and auth/session state.
- `smolder-tools`: CLI commands and higher-level integrations such as SMB file workflows and remote execution.

Boundary rule:

- `smolder-core` stays library-only and protocol-focused.
- `smolder-tools` owns operator-facing behavior like `smbexec` and `psexec`.
- If something depends on Windows shell behavior, SCM orchestration, or execution UX, it belongs in `smolder-tools`.

## Status

Implemented now:

- SMB2/3 packet header types
- RFC1002 session framing
- Typed wire bodies for `NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`, and `CLOSE`
- Unit tests for packet encode/decode round-trips

Planned next:

- Async transport and request dispatcher in `smolder-core`
- NTLMv2/SPNEGO authentication
- Live interoperability tests against Samba

Not implemented yet:

- Kerberos
- Read/write/query operations
- SMB1 compatibility
- Full Samba `selftest` coverage

## Quick Start

```rust
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{Command, Header, MessageId, NegotiateRequest, Dialect, SigningMode, GlobalCapabilities};

let header = Header::new(Command::Negotiate, MessageId(1));
let body = NegotiateRequest {
    security_mode: SigningMode::ENABLED,
    capabilities: GlobalCapabilities::LARGE_MTU,
    client_guid: *b"0123456789abcdef",
    dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
    negotiate_contexts: Vec::new(),
};

let mut packet = header.encode();
packet.extend_from_slice(&body.encode()?);
let frame = SessionMessage::new(packet).encode()?;
```

## Building The PsExec Service Payload

Build the Windows service payload with `cross`:

```bash
cross build -p smolder-psexecsvc --target aarch64-pc-windows-gnullvm --release
```

The workspace now carries a target-specific `Cross.toml` and
`docker/cross/Dockerfile.aarch64-pc-windows-gnullvm` that:

- pass through the host's proxy environment variables into `cross`
- emit the service payload at
  `target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe`

If your network requires additional CA certificates or proxy customization, use
an untracked local override under `docker/cross/private/` or
`docker/cross/*.local`.

## Live SMB Encryption Fixture

The tools-layer encryption tests are opt-in. On Tiny11, create an encrypted
share once and point the tests at it:

```powershell
$path = 'C:\SmolderEncrypted'
New-Item -ItemType Directory -Path $path -Force | Out-Null
icacls $path /grant 'Everyone:(OI)(CI)F' /T /C | Out-Null

if (Get-SmbShare -Name 'SMOLDERENC' -ErrorAction SilentlyContinue) {
    Set-SmbShare -Name 'SMOLDERENC' -EncryptData $true | Out-Null
} else {
    New-SmbShare -Name 'SMOLDERENC' -Path $path -FullAccess 'Everyone' -EncryptData $true | Out-Null
}

Get-SmbShare -Name 'SMOLDERENC' | Select-Object Name, Path, EncryptData
```

Then run the positive Windows encryption test:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
SMOLDER_WINDOWS_ENCRYPTED_SHARE=SMOLDERENC \
cargo test -p smolder-tools --test windows_encryption -- --nocapture
```

The local Samba fixture now includes an encrypted share named `SMOLDERENC` on
port `1445`. Run the core encryption interop test with:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_ENCRYPTED_SHARE=SMOLDERENC \
cargo test -p smolder-core --test samba_encryption -- --nocapture
```

For encrypted `IPC$` / named-pipe RPC coverage, the local Samba compose stack
also exposes a second instance on port `1446` with `server smb encrypt =
required`. Run the core RPC bind test with:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1446 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
cargo test -p smolder-core --test samba_rpc_encryption -- --nocapture
```

## Live Interop Matrix

The current supported live matrix, target fixtures, and repeatable verification
commands are documented in [docs/testing/interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md).
Use [scripts/run-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-interop.sh) for a single
entrypoint that fans out to the enabled Windows and Samba gates from the current
environment.

## Security Notice

This tool is designed for security research and penetration testing. Always ensure you have proper authorization before testing any systems or networks.

## License

MIT License - Copyright (c) 2025 M00NLIG7

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
