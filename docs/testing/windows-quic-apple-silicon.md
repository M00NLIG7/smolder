# Windows Server QUIC On Apple Silicon

This is the local Apple Silicon path for the SMB over QUIC lane in
[windows-quic.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic.md).

Use it on ARM Macs where the x64 VirtualBox flow in
[windows-quic-provisioning.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic-provisioning.md)
does not apply.

## What This Path Uses

- an ARM64 Windows Server install image generated from UUP Dump
- `UTM` for the local Windows Server VM
- the existing guest-side QUIC setup script:
  [configure-windows-quic-server.ps1](/Users/cmagana/Projects/smolder/scripts/configure-windows-quic-server.ps1)
- the existing Smolder QUIC interop harness:
  [run-windows-quic-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-windows-quic-interop.sh)

This path is necessary because the public Microsoft evaluation media currently
available from the Evaluation Center is x64, while this host is ARM64. The
community walkthrough that matches this approach is:

- <https://github.com/0x9r/Windows-server-2025-on-Apple-Silicon>

## Current Reality

As of March 30, 2026, the ARM64 UUP path is real but not stable:

- the UUP summary pages for recent ARM64 Windows Server builds still load
- multiple tested ARM64 build ids returned `#UUPDUMP_ERROR:EMPTY_FILELIST` from
  the actual package endpoint

The tested build ids that were empty on March 30, 2026 were:

- `bc94140e-c654-47ce-96ea-fbdffba7c6f1`
- `30c86080-114b-4a51-bd6c-59a01b092aeb`
- `32833df7-ff91-424f-8087-9895b395a1b0`

So the working rule is simple: pick a current ARM64 Windows Server build from
UUP Dump, and if the package endpoint is empty, pick a newer one.

## Prerequisites

- Apple Silicon Mac
- `UTM` installed
- enough free disk for a Windows Server VM plus the ISO build
- either:
  - a Windows machine to run `uup_download_windows.cmd`, or
  - a macOS host with the UUP conversion tools installed

If you already have Tiny11 running locally, that Windows guest is the simplest
place to run the UUP conversion step.

## Step 1: Pick A Live ARM64 Build

Go to:

- <https://uupdump.net/known.php?q=Windows+Server>

Pick an entry that is:

- `arm64`
- Windows Server
- recent enough that the package files are still live

Then choose:

- language: `English (United States)` or your preferred language
- edition: `Windows Server Datacenter: Azure Edition` (`SERVERTURBINE`) or the
  edition you actually want to test

## Step 2: Fetch The UUP Package

Use:

```bash
scripts/fetch-windows-server-arm64-uup.sh <uup-build-id>
```

Optional overrides:

```bash
export SMOLDER_WINDOWS_QUIC_UUP_PACK='en-us'
export SMOLDER_WINDOWS_QUIC_UUP_EDITION='serverturbine'
export SMOLDER_WINDOWS_QUIC_UUP_OUTDIR="$HOME/Downloads"
```

If UUP Dump returns `#UUPDUMP_ERROR:EMPTY_FILELIST`, the build id is not usable
anymore. The helper script checks that before it claims success. Go back to the
`known.php` page and pick a newer ARM64 build.

## Step 3: Build The ARM64 ISO

Unzip the downloaded package.

### Preferred: Run The Windows Builder

Inside Tiny11 or another Windows machine, run:

```powershell
uup_download_windows.cmd
```

That is the most reliable path because it matches the package’s primary
workflow.

### Alternate: Run The macOS Builder

If you want to build on macOS directly, use the package’s
`uup_download_macos.sh` and install the conversion tools it expects first. The
package README currently points macOS users at Homebrew packages for:

- `aria2c`
- `cabextract`
- `wimlib`
- `chntpw`
- `mkisofs` or `genisoimage`

This route is workable, but it is less proven in this repo than the Windows
builder path.

## Step 4: Boot Windows Server In UTM

Create a new `UTM` virtual machine with:

- architecture: `ARM64`
- firmware/OS type appropriate for modern Windows
- the generated ARM64 Windows Server ISO attached as installer media
- at least `4` vCPUs
- at least `8 GB` memory
- at least `128 GB` disk

Use guest networking that lets the host reach:

- UDP `443` for SMB over QUIC
- TCP `3389` for RDP during setup

If you use NAT/shared networking, add host-to-guest forwards for those ports in
the UTM VM configuration.

## Step 5: Configure SMB Over QUIC In The Guest

Once Windows Server is installed, copy
[configure-windows-quic-server.ps1](/Users/cmagana/Projects/smolder/scripts/configure-windows-quic-server.ps1)
into the guest and run it from an elevated PowerShell session:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\configure-windows-quic-server.ps1 `
  -ServerName files.lab.example `
  -ShareName smolder `
  -LocalUsername smolder `
  -LocalPassword 'Passw0rd!'
```

That configures:

- a local test user
- a writable SMB share
- a self-signed certificate
- SMB over QUIC server mapping
- firewall rules

## Step 6: Trust The Certificate And Run Smolder

Trust the exported guest certificate on the host, then export:

```bash
export SMOLDER_WINDOWS_QUIC_SERVER='files.lab.example'
export SMOLDER_WINDOWS_QUIC_CONNECT_HOST='127.0.0.1'
export SMOLDER_WINDOWS_QUIC_TLS_SERVER_NAME='files.lab.example'
export SMOLDER_WINDOWS_QUIC_USERNAME='smolder'
export SMOLDER_WINDOWS_QUIC_PASSWORD='Passw0rd!'
export SMOLDER_WINDOWS_QUIC_SHARE='smolder'
```

Then run:

```bash
scripts/run-windows-quic-interop.sh
```

## Boundaries

This Apple Silicon path is for the current live QUIC lane only:

- NTLM over QUIC
- tree connect over QUIC
- file write/read/remove roundtrip over QUIC

It does not yet automate:

- ISO generation from inside the repo end to end
- UTM VM creation from the repo
- Kerberos over QUIC
- named pipes or RPC over QUIC
