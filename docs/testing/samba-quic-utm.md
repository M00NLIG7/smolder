# Samba QUIC On UTM

This is the Apple Silicon local path for the Samba SMB over QUIC lane in
[samba-quic.md](/Users/cmagana/Projects/smolder/docs/testing/samba-quic.md).

Use it when Docker Desktop cannot host Samba QUIC because the underlying Linux
VM does not expose the kernel QUIC socket path that Samba needs.

## Why UTM

Containers are not enough here by themselves. Samba’s server-side QUIC support
depends on a Linux kernel QUIC implementation, and containers do not bring
their own kernel.

On this Mac, the local Docker-based Samba QUIC scaffold reached:

- Samba `4.23.6`
- valid TLS material
- correct QUIC client framing from `smolder-smb-core`

but still failed with `Protocol not supported` when Samba tried to open its
QUIC listener. That points at the host runtime, not the Smolder client.

UTM gives us a small ARM64 Linux VM with:

- a real guest kernel
- QEMU port forwarding for both TCP and UDP
- headless boot via a cloud image
- a clean place to build and load `quic.ko`

The guest is intentionally headless. A black UTM window is expected; use the
forwarded SSH port for control and test execution.

Official references:

- UTM scripting cheat sheet:
  <https://docs.getutm.app/scripting/cheat-sheet/>
- UTM QEMU port forwarding:
  <https://docs.getutm.app/settings-qemu/devices/network/port-forwarding/>
- Ubuntu 25.04 ARM64 cloud image:
  <https://cloud-images.ubuntu.com/releases/plucky/release/ubuntu-25.04-server-cloudimg-arm64.img>
- Linux kernel QUIC module:
  <https://github.com/lxin/quic>

## Layout

The UTM path uses three scripts:

- [provision-samba-quic-utm.sh](/Users/cmagana/Projects/smolder/scripts/provision-samba-quic-utm.sh)
- [configure-samba-quic-utm.sh](/Users/cmagana/Projects/smolder/scripts/configure-samba-quic-utm.sh)
- [setup-samba-quic-guest.sh](/Users/cmagana/Projects/smolder/scripts/setup-samba-quic-guest.sh)

The current flow is:

1. create a UTM QEMU VM from the Ubuntu ARM64 cloud image
2. inject cloud-init with SSH access and guest agent startup
3. forward host ports:
   - TCP `2422` -> guest `22`
   - TCP `2445` -> guest `445`
   - UDP `2443` -> guest `443`
4. SSH into the guest
5. install Docker, `ktls-utils`, and QUIC build dependencies
6. build and install `quic.ko`
7. enable `tlshd`
8. run the repo’s existing [docker/samba-quic](/Users/cmagana/Projects/smolder/docker/samba-quic)
   fixture inside the guest on guest ports `443/udp` and `445/tcp`

## Provision The VM

Run:

```bash
scripts/provision-samba-quic-utm.sh
```

Default assumptions:

- VM name: `SmolderSambaQuic`
- image URL:
  `https://cloud-images.ubuntu.com/releases/plucky/release/ubuntu-25.04-server-cloudimg-arm64.img`
- host artifact directory: `/tmp/smolder-samba-quic-utm`
- guest username: `smolder`
- guest password: `smolderpass`

Useful overrides:

```bash
export SMOLDER_SAMBA_QUIC_VM='SmolderSambaQuic'
export SMOLDER_SAMBA_QUIC_UTM_DIR='/tmp/smolder-samba-quic-utm'
export SMOLDER_SAMBA_QUIC_SSH_PORT=2422
export SMOLDER_SAMBA_QUIC_HOST_PORT=2445
export SMOLDER_SAMBA_QUIC_QUIC_PORT=2443
export SMOLDER_SAMBA_QUIC_REPLACE_VM=1
```

## Configure The Guest

Once the VM is booted and SSH is reachable, run:

```bash
scripts/configure-samba-quic-utm.sh
```

That script:

- copies the repo’s `docker/samba-quic` fixture into the guest
- builds and installs `quic.ko` from `lxin/quic`
- enables `tlshd`
- generates a local self-signed cert for `files.lab.example`
- starts the Samba 4.23 container inside the guest
- pulls the generated root CA back to the host

## Trust The Certificate

The guest script generates a local root CA and signs the Samba server
certificate with it. Trust that CA on the macOS host before running host-side
Smolder QUIC tests:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/smolder-samba-quic-utm/samba-quic-ca.pem
```

Also make sure the certificate name resolves locally:

```text
127.0.0.1 files.lab.example
```

## Run The Smolder QUIC Lane

Export:

```bash
export SMOLDER_SAMBA_QUIC_SERVER='files.lab.example'
export SMOLDER_SAMBA_QUIC_CONNECT_HOST='127.0.0.1'
export SMOLDER_SAMBA_QUIC_TLS_SERVER_NAME='files.lab.example'
export SMOLDER_SAMBA_QUIC_PORT=2443
export SMOLDER_SAMBA_QUIC_USERNAME='smolder'
export SMOLDER_SAMBA_QUIC_PASSWORD='smolderpass'
export SMOLDER_SAMBA_QUIC_SHARE='share'
```

Then run:

```bash
scripts/run-samba-quic-interop.sh
```

For the guest-local proof path that avoids macOS trust-store changes, SSH into
the guest and run:

```bash
ssh -i /tmp/smolder-samba-quic-utm/id_ed25519 -p 2422 smolder@127.0.0.1
cd /home/smolder/smolder-guest
. "$HOME/.cargo/env"
SMOLDER_SAMBA_QUIC_SERVER=files.lab.example \
SMOLDER_SAMBA_QUIC_CONNECT_HOST=127.0.0.1 \
SMOLDER_SAMBA_QUIC_TLS_SERVER_NAME=files.lab.example \
SMOLDER_SAMBA_QUIC_PORT=443 \
SMOLDER_SAMBA_QUIC_USERNAME=smolder \
SMOLDER_SAMBA_QUIC_PASSWORD=smolderpass \
SMOLDER_SAMBA_QUIC_SHARE=share \
cargo test -p smolder-smb-core --features quic --test samba_quic -- --nocapture
```

## Current Scope

This path is for proving the current QUIC client lane against Samba:

- NTLM-authenticated session setup over QUIC
- tree connect over QUIC
- file write/read/remove roundtrip over QUIC

It does not yet cover:

- Kerberos over QUIC
- named pipes or RPC over QUIC
- unattended CI automation
