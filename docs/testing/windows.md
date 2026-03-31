# Windows Interop Gate

This is the manual release-style gate for the Tiny11 / Windows fixture.

Use it when you need confidence beyond the Samba-backed GitHub Actions workflow,
especially for:

- NTLM / SPNEGO compatibility against Windows
- Kerberos compatibility once Tiny11 is joined to the local Samba AD fixture
- `IPC$` named-pipe behavior
- `svcctl` RPC behavior
- encrypted-share behavior on Windows
- `smbexec` / `psexec` smoke validation

This document does not cover SMB over QUIC. That requires a dedicated Windows
Server target and is documented separately in
[windows-quic.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic.md).

## Fixture

Current local fixture assumptions:

- VM: `Tiny11`
- Guest host: `DESKTOP-PTNJUS5`
- Port forward: host `127.0.0.1:445` -> guest `445`
- Windows test credentials: set `SMOLDER_WINDOWS_USERNAME` and
  `SMOLDER_WINDOWS_PASSWORD` for your local VM account
- Encrypted share: `SMOLDERENC`
- Global SMB encryption: `Set-SmbServerConfiguration -EncryptData $true`
- Optional DFS namespace root: `SMOLDER_WINDOWS_DFS_ROOT`
- Optional local Kerberos realm: `LAB.EXAMPLE` via
  [samba-ad-kerberos.md](/Users/cmagana/Projects/smolder/docs/testing/samba-ad-kerberos.md)
  and [windows-kerberos.md](/Users/cmagana/Projects/smolder/docs/testing/windows-kerberos.md)

Ensure the NAT rule exists:

```bash
VBoxManage controlvm Tiny11 natpf1 "smb445,tcp,,445,,445"
```

## Environment

Minimum environment:

```bash
export SMOLDER_WINDOWS_HOST=127.0.0.1
export SMOLDER_WINDOWS_USERNAME='<windows-username>'
export SMOLDER_WINDOWS_PASSWORD='<windows-password>'
```

Recommended full environment:

```bash
export SMOLDER_WINDOWS_HOST=127.0.0.1
export SMOLDER_WINDOWS_USERNAME='<windows-username>'
export SMOLDER_WINDOWS_PASSWORD='<windows-password>'
export SMOLDER_WINDOWS_ENCRYPTED_SHARE=SMOLDERENC
```

One-time fixture setup for encrypted `IPC$` / named-pipe coverage:

```powershell
Set-SmbServerConfiguration -EncryptData $true -Force
(Get-SmbServerConfiguration).EncryptData
```

Optional DFS gate:

```bash
export SMOLDER_WINDOWS_DFS_ROOT='\\\\127.0.0.1\\your-dfs-root'
```

## Full Gate

Run the full Windows release-style pass with:

```bash
scripts/run-windows-release-gate.sh
```

That runs:

- Windows `smolder-core` interop tests
- Windows `smolder-tools` interop tests
- `smbexec whoami`
- `psexec whoami`

If you want to skip remote execution smoke commands:

```bash
scripts/run-windows-release-gate.sh --no-remote-exec
```

## Optional Kerberos Lane

When you want to prove `smolder-core` Kerberos auth against Windows, join Tiny11
to the local Samba AD fixture first:

```bash
scripts/join-tiny11-to-samba-ad.sh
```

Then run the Windows Kerberos core gate:

```bash
scripts/run-windows-kerberos-interop.sh
```

That wrapper drives the existing
[kerberos_interop.rs](/Users/cmagana/Projects/smolder/smolder-core/tests/kerberos_interop.rs)
test with the Windows-specific defaults:

- SMB transport: `127.0.0.1:445`
- Kerberos target host: `DESKTOP-PTNJUS5.lab.example`
- Share: `IPC$`
- Realm: `LAB.EXAMPLE`
- KDC: `dc1.lab.example:1088`

The Windows join helper provisions an offline domain-join blob from the local
Samba AD member server, applies it through the existing `psexec` SYSTEM path,
reboots Tiny11, and verifies the result with `systeminfo`.

## Expected Results

When the fixture is healthy:

- `windows_interop`, `windows_reconnect`, `windows_encryption`, `named_pipe_interop`, `rpc_interop`, and `windows_rpc_encryption` pass
- `scripts/run-windows-kerberos-interop.sh` passes once Tiny11 is joined to
  `LAB.EXAMPLE`
- `smolder-tools` Windows reconnect and encryption tests pass
- the `ADMIN$` encryption-enforcement probe skips when the fixture is globally encrypted
- Windows DFS runs only when `SMOLDER_WINDOWS_DFS_ROOT` is set
- `smbexec ... whoami` prints `nt authority\system`
- `psexec ... whoami` prints `nt authority\system`

## Relationship To CI

- GitHub Actions covers the Samba-backed subset automatically.
- The repository now includes an optional self-hosted workflow at [interop-windows-self-hosted.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-windows-self-hosted.yml).
- That workflow expects a self-hosted runner labeled `smolder-windows-gate`, local access to the Tiny11 fixture, `VBoxManage`, and repository secrets `SMOLDER_WINDOWS_USERNAME` / `SMOLDER_WINDOWS_PASSWORD`.
- The workflow uses [ensure-tiny11-smb-forward.sh](/Users/cmagana/Projects/smolder/scripts/ensure-tiny11-smb-forward.sh) to verify the `127.0.0.1:445` NAT forward before running the release gate.
- Runner bootstrap and GitHub secret setup are documented in [windows-runner.md](/Users/cmagana/Projects/smolder/docs/testing/windows-runner.md).
- If the self-hosted runner is unavailable, the local `scripts/run-windows-release-gate.sh` path remains the fallback.
