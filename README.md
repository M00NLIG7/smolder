# Smolder

An SMB research toolkit in Rust. The current codebase is being rebuilt around a typed SMB2/3 protocol layer first, with transport, authentication, and higher-level tooling layered on top once the wire model is stable.

## Overview

Smolder is organized as a small workspace:

- `smolder-proto`: SMB wire types, framing, codecs, and packet validation.
- `smolder-core`: reusable SMB/RPC primitives, transport logic, and auth/session state.
- `smolder-tools`: CLI commands and higher-level integrations such as SMB file workflows and remote execution.

Published package names:

- `smolder-proto`: wire-format crate
- `smolder-smb-core`: library package for the `smolder_core` crate
- `smolder`: CLI package and library package for the `smolder_tools` crate
- `smolder-psexecsvc`: Windows service payload package

Boundary rule:

- `smolder-core` stays library-only and protocol-focused.
- `smolder-tools` owns operator-facing behavior like `smbexec` and `psexec`.
- If something depends on Windows shell behavior, SCM orchestration, or execution UX, it belongs in `smolder-tools`.

## Status

Implemented now:

- `smolder-proto`: typed SMB2/3 and DCE/RPC codecs, including compound headers,
  durable-handle create contexts, named-pipe/RPC packets, and SMB3 transform
  headers
- `smolder-core`: SMB negotiate/session setup, NTLMv2/SPNEGO auth, signing,
  SMB3 encryption, named pipes, DCE/RPC transport, DFS referral handling,
  compound requests, and durable/resilient reconnect primitives
- `smolder-tools`: high-level SMB file APIs, DFS-aware path resolution,
  reconnect helpers, CLI file workflows, `smbexec`, and `psexec`
- Live interop coverage against both Tiny11/Windows and local Samba fixtures,
  with a repeatable harness and release gates

Validated now:

- Windows: negotiate, auth, tree connect, file I/O, durable reconnect,
  encrypted share I/O, named pipes, RPC, DFS, `smbexec`, and `psexec`
- Samba: negotiate, file I/O, IOCTLs, encrypted shares, encrypted `IPC$`,
  named pipes, and RPC bind over encrypted SMB

Not implemented on this track:

- Kerberos
- SMB1 compatibility
- Fully automated Windows CI; the Tiny11 gate is still manual/self-hosted
- Full Samba `selftest` parity

## Future Tracks

- Kerberos in `smolder-core` is the next major protocol track. The target is a
  production-grade SMB Kerberos module with ticket-cache, password, and keytab
  flows, plus signing/encryption integration and real Windows/Samba interop.
  The scoped plan is in
  [plans/kerberos-auth-roadmap.md](/Users/cmagana/Projects/smolder/plans/kerberos-auth-roadmap.md).

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
cargo test -p smolder --test windows_encryption -- --nocapture
```

For encrypted `IPC$` / named-pipe / RPC coverage on Tiny11, enable SMB server
encryption globally once:

```powershell
Set-SmbServerConfiguration -EncryptData $true -Force
(Get-SmbServerConfiguration).EncryptData
```

Then run the core encrypted `IPC$` test:

```bash
SMOLDER_WINDOWS_HOST=127.0.0.1 \
SMOLDER_WINDOWS_USERNAME=windowsfixture \
SMOLDER_WINDOWS_PASSWORD=windowsfixture \
cargo test -p smolder-smb-core --test windows_rpc_encryption -- --nocapture
```

The local Samba fixture now includes an encrypted share named `SMOLDERENC` on
port `1445`. Run the core encryption interop test with:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_ENCRYPTED_SHARE=SMOLDERENC \
cargo test -p smolder-smb-core --test samba_encryption -- --nocapture
```

For encrypted `IPC$` / named-pipe RPC coverage, the local Samba compose stack
also exposes a second instance on port `1446` with `server smb encrypt =
required`. Run the core `srvsvc` RPC call test with:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1446 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
cargo test -p smolder-smb-core --test samba_rpc_encryption -- --nocapture
```

## Live Interop Matrix

The current supported live matrix, target fixtures, and repeatable verification
commands are documented in [docs/testing/interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md).
Use [scripts/run-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-interop.sh) for a single
entrypoint that fans out to the enabled Windows and Samba gates from the current
environment. The Samba-backed subset is also wired into GitHub Actions via
[interop-samba.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-samba.yml).
The Tiny11 / Windows gate can now run through the optional self-hosted workflow
[interop-windows-self-hosted.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-windows-self-hosted.yml),
which uses [ensure-tiny11-smb-forward.sh](/Users/cmagana/Projects/smolder/scripts/ensure-tiny11-smb-forward.sh)
to verify the local VirtualBox port forward before running the release gate.
Runner bootstrap and secret setup are documented in
[windows-runner.md](/Users/cmagana/Projects/smolder/docs/testing/windows-runner.md).
For the full manual Tiny11 pass, including remote execution smoke checks, use
[run-windows-release-gate.sh](/Users/cmagana/Projects/smolder/scripts/run-windows-release-gate.sh)
and [docs/testing/windows.md](/Users/cmagana/Projects/smolder/docs/testing/windows.md).
For merge/release policy, required gate selection, and failure triage, use
[docs/testing/release.md](/Users/cmagana/Projects/smolder/docs/testing/release.md).

## Security Notice

This tool is designed for security research and penetration testing. Always ensure you have proper authorization before testing any systems or networks.

## License

MIT License - Copyright (c) 2025 M00NLIG7

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
