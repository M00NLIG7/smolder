# Windows SMB Over QUIC

This is the manual live interop lane for `smolder-smb-core` SMB over QUIC.

It is not part of the Tiny11 gate. Tiny11 is a Windows client fixture, not an
SMB over QUIC server. Microsoft documents SMB over QUIC server support on
Windows Server, not Windows 11 client SKUs.

Use this lane when you need to validate:

- the `quic` transport feature
- QUIC TLS server-name handling
- SMB session setup over QUIC
- post-auth tree connect and basic file I/O over QUIC

## Required Target

You need a real SMB over QUIC server, for example:

- Windows Server 2022 Azure Edition with SMB over QUIC enabled
- Windows Server 2025 with SMB over QUIC enabled

Microsoft reference:

- <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic>
- <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83>

If you need to create a local Windows Server 2025 fixture from scratch, use
[windows-quic-provisioning.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic-provisioning.md).
On Apple Silicon, use
[windows-quic-apple-silicon.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic-apple-silicon.md)
instead of the x64 VirtualBox flow.

## Environment

Required:

```bash
export SMOLDER_WINDOWS_QUIC_SERVER='files.lab.example'
export SMOLDER_WINDOWS_QUIC_USERNAME='<username>'
export SMOLDER_WINDOWS_QUIC_PASSWORD='<password>'
export SMOLDER_WINDOWS_QUIC_SHARE='<share-name>'
```

Optional:

```bash
export SMOLDER_WINDOWS_QUIC_CONNECT_HOST='203.0.113.10'
export SMOLDER_WINDOWS_QUIC_TLS_SERVER_NAME='files.lab.example'
export SMOLDER_WINDOWS_QUIC_PORT=443
export SMOLDER_WINDOWS_QUIC_TEST_DIR='Temp'
export SMOLDER_WINDOWS_QUIC_DOMAIN='<domain>'
export SMOLDER_WINDOWS_QUIC_WORKSTATION='<workstation>'
```

Use the optional variables when:

- the SMB server FQDN differs from the public dial address
- the certificate server name differs from the dial address
- you want file roundtrip coverage inside a specific writable subdirectory

## Harness

Run:

```bash
scripts/run-windows-quic-interop.sh
```

That runs:

```bash
cargo test -p smolder-smb-core --features quic --test windows_quic -- --nocapture
```

## Current Coverage

The QUIC gate currently proves:

- NTLM-authenticated SMB session setup over QUIC
- tree connect over QUIC
- high-level file write/read/remove roundtrip over QUIC

It does not yet prove:

- named pipes or RPC over QUIC
- Kerberos over QUIC
- release-style automation in GitHub Actions

## Notes

- `SMOLDER_WINDOWS_QUIC_SERVER` is the logical SMB server identity.
- `SMOLDER_WINDOWS_QUIC_CONNECT_HOST` is the dial host or IP.
- `SMOLDER_WINDOWS_QUIC_TLS_SERVER_NAME` is the certificate name used for the
  QUIC/TLS handshake.
- Smolder’s QUIC transport now sends raw SMB2 messages inside QUIC instead of
  RFC1002 session frames, which matches the SMB transport model documented by
  Microsoft.
