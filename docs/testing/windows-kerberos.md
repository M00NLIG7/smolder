# Windows Kerberos Gate

This document captures the local Windows Kerberos validation lane for
`smolder-core` and the Kerberos-enabled file CLI path in `smolder-tools`.

It uses:

- the local Samba AD fixture in
  [docker/samba-ad/compose.yaml](/Users/cmagana/Projects/smolder/docker/samba-ad/compose.yaml)
- Tiny11 as the SMB target on `127.0.0.1:445`
- the generic core Kerberos test in
  [kerberos_interop.rs](/Users/cmagana/Projects/smolder/smolder-core/tests/kerberos_interop.rs)

The important detail is that the SMB transport target and the Kerberos target
host are different:

- transport target: `127.0.0.1:445`
- Kerberos/SPN target: `DESKTOP-PTNJUS5.lab.example`

That keeps the VirtualBox NAT-forwarded SMB transport simple while still using
the correct `cifs/<hostname>` SPN.

## Prerequisites

- Tiny11 reachable on host port `445`
- working Windows credentials:
  - username `windowsfixture`
  - password `windowsfixture`
- local Samba AD fixture reachable as:
  - `dc1.lab.example:1088`
  - `files1.lab.example:2445`
- host `/etc/hosts` mapping for:
  - `dc1.lab.example`
  - `files1.lab.example`

## Join Tiny11 To The Realm

Join Tiny11 to the local realm with:

```bash
scripts/join-tiny11-to-samba-ad.sh
```

That helper:

- provisions an offline domain-join blob from the Samba AD member server
- copies the blob into Tiny11
- applies it through `psexec` as `SYSTEM`
- reboots Tiny11
- verifies the resulting `systeminfo` domain line

The helper intentionally rebuilds or reprovisions the Samba AD fixture, so it is
the right command to rerun whenever the realm state has been reset.

## Run The Kerberos Gate

Once Tiny11 is joined, run:

```bash
scripts/run-windows-kerberos-interop.sh
```

That wrapper preserves the existing AD realm state, checks that the Tiny11
machine account is still present in the KDC, and then runs:

```bash
cargo test -p smolder-smb-core --features kerberos --test kerberos_interop -- --nocapture
```

followed by a Kerberos-enabled file CLI smoke command:

```bash
target/debug/smolder-ls smb://127.0.0.1/IPC$ --kerberos ...
```

with these defaults:

- `SMOLDER_KERBEROS_HOST=127.0.0.1`
- `SMOLDER_KERBEROS_PORT=445`
- `SMOLDER_KERBEROS_TARGET_HOST=DESKTOP-PTNJUS5.lab.example`
- `SMOLDER_KERBEROS_USERNAME=smolder@LAB.EXAMPLE`
- `SMOLDER_KERBEROS_PASSWORD=Passw0rd!`
- `SMOLDER_KERBEROS_SHARE=IPC$`
- `SMOLDER_KERBEROS_REALM=LAB.EXAMPLE`
- `SMOLDER_KERBEROS_KDC_URL=tcp://dc1.lab.example:1088`

## Expected Result

When the fixture is healthy:

- the Tiny11 domain line reports `lab.example`
- `scripts/run-windows-kerberos-interop.sh` passes
- `kerberos_interop.rs` authenticates with Kerberos and connects `IPC$`
- `smolder-ls` can list `IPC$` over Kerberos

This gate currently covers the file-workflow side of `smolder-tools`.
`smbexec` and `psexec` remain NTLM-only until the core pipe/session config gains
Kerberos support.

If the wrapper reports that the machine account is missing, the local Samba AD
realm was reset and Tiny11 needs to be rejoined with
`scripts/join-tiny11-to-samba-ad.sh`.
