# Smolder

A typed SMB2/3, DCE/RPC, and operator toolkit in Rust.

## Overview

Smolder is organized as a small workspace:

- `smolder-proto`: SMB wire types, framing, codecs, and packet validation.
- `smolder-core`: reusable SMB/RPC primitives, transport logic, and auth/session state.
- `smolder-tools`: CLI commands and higher-level integrations such as SMB file workflows and remote execution.

The `smolder` package now builds standalone operator binaries such as
`smbexec`, `psexec`, `smolder-cat`, and `smolder-mv`. The `smolder`
executable remains as a compatibility wrapper around those shared code paths.

For library-first usage, `smolder-smb-core` now ships compile-checked examples
for:

- high-level client session/share connect
- high-level share listing
- high-level file roundtrip
- typed `srvsvc` RPC
- typed `lsarpc` RPC
- NTLM tree connect
- named-pipe RPC bind
- Kerberos tree connect
- QUIC session connect

The shared examples guide, including the high-level file roundtrip and
interactive `psexec` tools examples, is in
[docs/guide/examples.md](https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md).
That guide also includes the feature-gated high-level Kerberos tools example.
The repo also includes a tiny standalone reference client at
[demos/smolder-core-demo](https://github.com/M00NLIG7/smolder/tree/main/demos/smolder-core-demo)
for users who want a small copy-and-adapt binary crate instead of an example
target.
The task-oriented cookbook is in
[docs/guide/cookbook.md](https://github.com/M00NLIG7/smolder/blob/main/docs/guide/cookbook.md).
That guide now documents the stable interactive remote-exec path as direct
`cmd.exe` or direct `powershell.exe` startup through the staged payload, not as
a full nested-shell terminal emulator.

Published package names:

- `smolder-proto`: wire-format crate
- `smolder-smb-core`: library package for the `smolder_core` crate
- `smolder`: CLI package and library package for the `smolder_tools` crate
- `smolder-psexecsvc`: Windows service payload package

## Start Here

Pick the crate by the layer you actually need:

- need typed SMB/DCE-RPC codecs only:
  [`smolder-proto`](https://github.com/M00NLIG7/smolder/blob/main/smolder-proto/README.md)
- need direct SMB/RPC client primitives:
  [`smolder-smb-core`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/README.md)
- need high-level file workflows or remote-exec tooling:
  [`smolder`](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/README.md)
- need the Windows `psexec` payload itself:
  [`smolder-psexecsvc`](https://github.com/M00NLIG7/smolder/blob/main/smolder-psexecsvc/README.md)

If you are evaluating adoption, start with:

- [docs/guide/examples.md](https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md)
- [docs/reference/support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md)
- [docs/reference/versioning-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md)

Release notes and published change summaries live in
[CHANGELOG.md](https://github.com/M00NLIG7/smolder/blob/main/CHANGELOG.md).

## Can I Use This In A Real Project?

Yes, if your usage fits the documented `0.2.x` support surface.

The practical promise is:

- real-project use is expected and supported for the documented SMB2/3, auth,
  encryption, named-pipe/RPC, DFS, reconnect, and tools workflows
- additive change is preferred over public API churn
- deliberate breaking changes are still possible before `1.0`, but they should
  be infrequent, documented, and shipped as minor-version changes

Read these together before depending on the crates in production:

- [docs/reference/support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md)
- [docs/reference/versioning-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md)
- [CHANGELOG.md](https://github.com/M00NLIG7/smolder/blob/main/CHANGELOG.md)

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
  SMB3 encryption, SMB compression, named pipes, DCE/RPC transport, DFS
  referral handling, compound requests, durable/resilient reconnect
  primitives, an embedded client facade, typed `srvsvc` / `lsarpc` / `samr`
  clients, SMB over QUIC, and feature-gated Kerberos support
- `smolder-tools`: high-level SMB file APIs, DFS-aware path resolution,
  reconnect helpers, CLI file workflows, feature-gated Kerberos file auth,
  `smbexec`, and `psexec`
- Live interop coverage against both Tiny11/Windows and local Samba fixtures,
  with a repeatable harness and release gates

Validated now:

- Windows: negotiate, auth, tree connect, file I/O, durable reconnect,
  encrypted share I/O, named pipes, RPC, DFS, Kerberos core auth, Kerberos file
  CLI workflows, Kerberos `smbexec`, Kerberos `psexec`, `smbexec`, and `psexec`
- Samba: negotiate, file I/O, IOCTLs, encrypted shares, encrypted `IPC$`,
  named pipes, encrypted RPC, standalone `lsarpc` policy queries,
  standalone `samr` domain enumeration and user queries, SMB compression, SMB
  over QUIC, and Kerberos core auth

Current priorities:

- public Windows Server QUIC proof alongside the current Samba QUIC lane
- full Samba `selftest` parity
- stronger Windows automation; the Tiny11 gate is still manual/self-hosted
- NetBIOS transport and additional embedders-first polish
- SMB1 remains deferred behind the modern SMB2/3 library and tooling work

- Kerberos in `smolder-core` is implemented behind the `kerberos` feature. The
  current slice covers mechanism-aware SPNEGO, a
  password-backed Kerberos authenticator that exports the SMB session key,
  plus a Unix ticket-cache and keytab backend behind `kerberos-gssapi`, and
  live Samba AD plus Windows domain-member interop in both core and
  Kerberos-enabled tools workflows, including `smbexec` and `psexec`.
  The Samba AD fixture and Windows member flow are documented in
  [docs/testing/samba-ad-kerberos.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/samba-ad-kerberos.md)
  and
  [docs/testing/windows-kerberos.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/windows-kerberos.md).
  The standalone Samba RPC fixture is documented in
  [docs/testing/samba-rpc.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/samba-rpc.md).
  The default build remains static-friendlier because `kerberos-gssapi`
  no longer drags in Unix GSS/Kerberos libraries unless it is explicitly
  enabled.

- `smolder-core` is moving into an API-stability and docs phase. The current
  public-surface notes are in
  [docs/reference/smolder-core-api.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/smolder-core-api.md).
  The formal `0.2.x` support contract is in
  [docs/reference/support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md).
  MSRV and semver rules are in
  [docs/reference/versioning-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md).
  The current wire-layer hardening entrypoints are documented in
  [docs/testing/fuzzing.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/fuzzing.md).
  The current perf harness is documented in
  [docs/testing/benchmarks.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/benchmarks.md),
  with a compile-only CI smoke workflow at
  [bench-smoke.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/bench-smoke.yml).

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
SMOLDER_WINDOWS_USERNAME='<windows-username>' \
SMOLDER_WINDOWS_PASSWORD='<windows-password>' \
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
SMOLDER_WINDOWS_USERNAME='<windows-username>' \
SMOLDER_WINDOWS_PASSWORD='<windows-password>' \
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
commands are documented in [docs/testing/interop.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/interop.md).
Use [scripts/run-interop.sh](https://github.com/M00NLIG7/smolder/blob/main/scripts/run-interop.sh) for a single
entrypoint that fans out to the enabled Windows and Samba gates from the current
environment. The Samba-backed subset is also wired into GitHub Actions via
[interop-samba.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/interop-samba.yml).
The Tiny11 / Windows gate can now run through the optional self-hosted workflow
[interop-windows-self-hosted.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/interop-windows-self-hosted.yml),
which uses [ensure-tiny11-smb-forward.sh](https://github.com/M00NLIG7/smolder/blob/main/scripts/ensure-tiny11-smb-forward.sh)
to verify the local VirtualBox port forward before running the release gate.
Runner bootstrap and secret setup are documented in
[windows-runner.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/windows-runner.md).
For the full manual Tiny11 pass, including remote execution smoke checks, use
[run-windows-release-gate.sh](https://github.com/M00NLIG7/smolder/blob/main/scripts/run-windows-release-gate.sh)
and [docs/testing/windows.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/windows.md).
For Samba-side SMB over QUIC on a Linux host with kernel QUIC support, use
[docs/testing/samba-quic.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/samba-quic.md).
On Apple Silicon, the local UTM-backed Linux path is documented in
[docs/testing/samba-quic-utm.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/samba-quic-utm.md).
For merge/release policy, required gate selection, and failure triage, use
[docs/testing/release.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/release.md).
For the formal `0.2.x` support scope and guarantees behind those gates, use
[docs/reference/support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md).

## Security Notice

This tool is designed for security research and penetration testing. Always ensure you have proper authorization before testing any systems or networks.

## License

MIT License - Copyright (c) 2025 M00NLIG7

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
