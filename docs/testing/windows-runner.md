# Windows Self-Hosted Runner Setup

Use this when you want GitHub Actions to run the Tiny11 / Windows interop gate
automatically through
[interop-windows-self-hosted.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/interop-windows-self-hosted.yml).

This workflow is intended for a self-hosted runner on the same machine that can:

- access the local Tiny11 VirtualBox VM
- run `VBoxManage`
- reach the host-side SMB port forward at `127.0.0.1:445`

## Prerequisites

- `gh` installed and authenticated for the repository owner
- `curl`, `tar`, `git`, and `bash`
- `VBoxManage`
- Tiny11 available locally
- SMB server encryption enabled on Tiny11:

```powershell
Set-SmbServerConfiguration -EncryptData $true -Force
```

## Repository Configuration

Set these GitHub repository secrets:

- `SMOLDER_WINDOWS_USERNAME`
- `SMOLDER_WINDOWS_PASSWORD`

Optional repository variable:

- `SMOLDER_WINDOWS_DFS_ROOT`

Example commands after `gh auth login`:

```bash
printf '%s' '<windows-username>' | gh secret set SMOLDER_WINDOWS_USERNAME --repo M00NLIG7/smolder
printf '%s' '<windows-password>' | gh secret set SMOLDER_WINDOWS_PASSWORD --repo M00NLIG7/smolder
gh variable set SMOLDER_WINDOWS_DFS_ROOT --repo M00NLIG7/smolder --body '\\\\127.0.0.1\\your-dfs-root'
```

## Runner Bootstrap

The repository includes a helper to download and configure the runner:

```bash
scripts/setup-windows-self-hosted-runner.sh
```

Defaults:

- install root: `.tmp/github-runner/windows-gate`
- runner label: `smolder-windows-gate`
- runner name: `<hostname>-smolder-windows-gate`

After configuration, start the runner interactively:

```bash
cd .tmp/github-runner/windows-gate
./run.sh
```

Or install it as a background service:

```bash
cd .tmp/github-runner/windows-gate
./svc.sh install
./svc.sh start
```

## Fixture Prep

Before running the workflow, verify the Tiny11 NAT forward:

```bash
scripts/ensure-tiny11-smb-forward.sh
```

That helper is also invoked by the workflow itself before the release gate runs.

## Workflow Dispatch

Trigger the workflow manually with:

```bash
scripts/dispatch-windows-interop.sh
```

That script dispatches `interop-windows-self-hosted.yml` on `main` and watches
the latest run to completion by default.

If you only want to dispatch without waiting:

```bash
scripts/dispatch-windows-interop.sh --no-watch
```
