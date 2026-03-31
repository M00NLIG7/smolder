# Samba SMB Over QUIC

This is the dedicated Samba-side fixture path for SMB over QUIC.

It is separate from the normal local Samba fixture in
[samba.md](/Users/cmagana/Projects/smolder/docs/testing/samba.md) because QUIC
has different server requirements.

## What This Lane Is For

Use it when you need to validate:

- `smolder-smb-core` QUIC transport logic against Samba, not Windows Server
- NTLM-authenticated SMB session setup over QUIC
- tree connect over QUIC
- basic file I/O over QUIC

## Important Boundaries

This is not the same as the current local Samba compose stack in
[docker/samba/compose.yaml](/Users/cmagana/Projects/smolder/docker/samba/compose.yaml).
That stack currently uses `crazymax/samba:latest`, which is Samba `4.21.4` on
this host and does not provide the new Samba 4.23 QUIC server path.

Samba’s official documentation says server-side QUIC support requires:

- Samba 4.23 or newer
- `server smb transports = +quic`
- TLS material configured for Samba
- the Linux `quic.ko` kernel module on the server side

Relevant official sources:

- <https://www.samba.org/samba/history/samba-4.23.0.html>
- <https://www.samba.org/samba/docs/current/man-html/smb.conf.5>

The current Docker Desktop Linux VM on this Mac is not a proven QUIC server
host. This fixture is therefore intended for:

- a real Linux host, or
- a Linux VM

where `quic.ko` is available.

This repo now has two local proof paths:

- a Linux-host path when the host kernel already provides `quic.ko`
- an Apple Silicon path through UTM, documented in
  [samba-quic-utm.md](/Users/cmagana/Projects/smolder/docs/testing/samba-quic-utm.md)

On Apple Silicon Macs, the recommended local path is now the UTM-backed Linux
guest flow in
[samba-quic-utm.md](/Users/cmagana/Projects/smolder/docs/testing/samba-quic-utm.md).

## Linux Host Requirement

Before using this fixture, verify the server host can actually support Samba
QUIC:

```bash
uname -r
grep -w quic /proc/modules
```

If `quic` is not loaded, try:

```bash
sudo modprobe quic
grep -w quic /proc/modules
```

If the host kernel does not provide `quic.ko`, this fixture is not the right
path.

## Container Fixture

The repo includes a Linux-only Samba QUIC scaffold in:

- [docker/samba-quic/Dockerfile](/Users/cmagana/Projects/smolder/docker/samba-quic/Dockerfile)
- [docker/samba-quic/bootstrap.sh](/Users/cmagana/Projects/smolder/docker/samba-quic/bootstrap.sh)
- [docker/samba-quic/compose.yaml](/Users/cmagana/Projects/smolder/docker/samba-quic/compose.yaml)

This scaffold uses `debian:sid-slim` so the container can install a Samba
package new enough for QUIC support.

Bring it up on a Linux host with:

```bash
docker compose -f docker/samba-quic/compose.yaml up -d --build
```

It exposes:

- TCP `1445` -> guest `445`
- UDP `1443` -> guest `443`

The bootstrap creates:

- local SMB user: `smolder`
- password: `smolderpass`
- share: `share`
- self-signed certificate with CN `files.lab.example`

If you need a local Apple Silicon-compatible Linux host for this same fixture,
use the UTM path in
[samba-quic-utm.md](/Users/cmagana/Projects/smolder/docs/testing/samba-quic-utm.md).

## Trust And Name Resolution

Because the fixture generates a self-signed certificate, the Smolder client
host must trust it before QUIC will work.

The generated certificate is written into:

- `docker/samba-quic/certs/cert.pem`

Also make sure the certificate name matches the client configuration. A simple
local path is:

```text
127.0.0.1 files.lab.example
```

## Environment

Required:

```bash
export SMOLDER_SAMBA_QUIC_SERVER='files.lab.example'
export SMOLDER_SAMBA_QUIC_USERNAME='smolder'
export SMOLDER_SAMBA_QUIC_PASSWORD='smolderpass'
export SMOLDER_SAMBA_QUIC_SHARE='share'
```

Recommended local Linux-host overrides:

```bash
export SMOLDER_SAMBA_QUIC_CONNECT_HOST='127.0.0.1'
export SMOLDER_SAMBA_QUIC_TLS_SERVER_NAME='files.lab.example'
export SMOLDER_SAMBA_QUIC_PORT=1443
```

Optional:

```bash
export SMOLDER_SAMBA_QUIC_TEST_DIR='Temp'
export SMOLDER_SAMBA_QUIC_DOMAIN='WORKGROUP'
export SMOLDER_SAMBA_QUIC_WORKSTATION='<workstation>'
```

## Harness

Run:

```bash
scripts/run-samba-quic-interop.sh
```

That runs:

```bash
cargo test -p smolder-smb-core --features quic --test samba_quic -- --nocapture
```

## Harness Coverage

When run against a real Samba QUIC server, this lane is intended to prove:

- NTLM-authenticated SMB session setup over QUIC
- tree connect over QUIC
- high-level file write/read/remove roundtrip over QUIC

It does not yet cover:

- named pipes or RPC over QUIC
- Kerberos over QUIC
- GitHub Actions automation
