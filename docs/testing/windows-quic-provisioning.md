# Windows Server QUIC Provisioning

This is the practical fixture setup for the live SMB over QUIC lane in
[windows-quic.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic.md).

Use it when you want a local VirtualBox target instead of a preexisting Windows
Server deployment.

## What This Gives You

- a local Windows Server 2025 VM shell in VirtualBox
- UDP `443` NAT-forwarded to the guest for SMB over QUIC
- RDP NAT-forwarded to the guest for initial administration
- one local test user
- one writable SMB share
- one certificate mapped for SMB over QUIC

This path targets Windows Server 2025 because Microsoft’s current SMB over QUIC
guidance documents PowerShell-based configuration there, and the public
Evaluation Center offers a current ISO and VHD. Sources:

- <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic>
- <https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025>

## What You Need First

- VirtualBox available on the host
- a Windows Server 2025 ISO already downloaded locally
- enough disk for a new VM

This repo does not download the ISO for you. Microsoft currently requires
registration for the evaluation media.

## Host Bootstrap

Create the VM shell with:

```bash
scripts/provision-windows-quic-vm.sh /absolute/path/to/windows-server-2025.iso
```

Optional environment overrides:

```bash
export SMOLDER_WINDOWS_QUIC_VM='SmolderServer2025'
export SMOLDER_WINDOWS_QUIC_SERVER_NAME='files.lab.example'
export SMOLDER_WINDOWS_QUIC_HOST_PORT=443
export SMOLDER_WINDOWS_QUIC_RDP_PORT=3389
```

That script:

- registers a new VirtualBox VM
- attaches the ISO
- creates a VDI disk
- forwards host UDP `443` to guest `443`
- forwards host TCP `3389` to guest `3389`

Then start the installer:

```bash
VBoxManage startvm SmolderServer2025 --type gui
```

Install Windows Server 2025 with Desktop Experience.

## Guest Setup

Once the OS is installed, copy
[configure-windows-quic-server.ps1](/Users/cmagana/Projects/smolder/scripts/configure-windows-quic-server.ps1)
into the guest and run it from an elevated PowerShell session:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\configure-windows-quic-server.ps1 `
  -ServerName files.lab.example `
  -ShareName smolder `
  -LocalUsername smolder `
  -LocalPassword 'Passw0rd!'
```

That script:

- creates the local test user if needed
- creates the share directory
- creates or updates the SMB share
- creates a certificate if needed
- maps that certificate for SMB over QUIC
- enables SMB over QUIC on the server
- opens the guest firewall for UDP `443`
- exports the certificate to `C:\Users\Public\smolder-smb-quic.cer`

## Trust And Name Resolution

Because the guest script creates a self-signed certificate by default, the host
must trust it before Smolder’s QUIC client will connect.

Copy the exported certificate to the host, then trust it in the System keychain.
On macOS that typically means:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/smolder-smb-quic.cer
```

If you forward QUIC to `127.0.0.1:443`, add a hosts entry so the certificate
name resolves correctly:

```text
127.0.0.1 files.lab.example
```

## Run Smolder

Export:

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

## Current Boundaries

This provisioning flow is for the current live QUIC lane only:

- NTLM over QUIC
- tree connect over QUIC
- file write/read/remove roundtrip over QUIC

It is not yet a full automated Windows Server installer, and it does not yet
cover:

- Kerberos over QUIC
- named pipes or RPC over QUIC
- unattended certificate trust on the host
