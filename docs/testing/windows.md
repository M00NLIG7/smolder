# Windows Interop Gate

This is the manual release-style gate for the Tiny11 / Windows fixture.

Use it when you need confidence beyond the Samba-backed GitHub Actions workflow,
especially for:

- NTLM / SPNEGO compatibility against Windows
- `IPC$` named-pipe behavior
- `svcctl` RPC behavior
- encrypted-share behavior on Windows
- `smbexec` / `psexec` smoke validation

## Fixture

Current local fixture assumptions:

- VM: `Tiny11`
- Guest host: `DESKTOP-PTNJUS5`
- Port forward: host `127.0.0.1:445` -> guest `445`
- Username: `windowsfixture`
- Password: `windowsfixture`
- Encrypted share: `SMOLDERENC`
- Global SMB encryption: `Set-SmbServerConfiguration -EncryptData $true`
- Optional DFS namespace root: `SMOLDER_WINDOWS_DFS_ROOT`

Ensure the NAT rule exists:

```bash
VBoxManage controlvm Tiny11 natpf1 "smb445,tcp,,445,,445"
```

## Environment

Minimum environment:

```bash
export SMOLDER_WINDOWS_HOST=127.0.0.1
export SMOLDER_WINDOWS_USERNAME=windowsfixture
export SMOLDER_WINDOWS_PASSWORD=windowsfixture
```

Recommended full environment:

```bash
export SMOLDER_WINDOWS_HOST=127.0.0.1
export SMOLDER_WINDOWS_USERNAME=windowsfixture
export SMOLDER_WINDOWS_PASSWORD=windowsfixture
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

## Expected Results

When the fixture is healthy:

- `windows_interop`, `windows_reconnect`, `windows_encryption`, `named_pipe_interop`, `rpc_interop`, and `windows_rpc_encryption` pass
- `smolder-tools` Windows reconnect and encryption tests pass
- the `ADMIN$` encryption-enforcement probe skips when the fixture is globally encrypted
- Windows DFS runs only when `SMOLDER_WINDOWS_DFS_ROOT` is set
- `smbexec ... whoami` prints `nt authority\system`
- `psexec ... whoami` prints `nt authority\system`

## Relationship To CI

- GitHub Actions covers the Samba-backed subset automatically.
- This Windows gate stays manual unless you add a self-hosted runner with access to the Tiny11 fixture and the local SMB port-forward setup.
