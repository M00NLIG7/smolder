# Windows Kerberos Gate

This document captures the local Windows Kerberos validation lane for
`smolder-core`, the Kerberos-enabled file CLI path in `smolder-tools`, and the
Kerberos `smbexec` smoke path.

It uses:

- the local Samba AD fixture in
  [docker/samba-ad/compose.yaml](https://github.com/M00NLIG7/smolder/blob/main/docker/samba-ad/compose.yaml)
- Tiny11 as the SMB target on `127.0.0.1:445`
- the generic core Kerberos test in
  [kerberos_interop.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/tests/kerberos_interop.rs)

The important detail is that the SMB transport target and the Kerberos target
host are different:

- transport target: `127.0.0.1:445`
- Kerberos/SPN target: `DESKTOP-PTNJUS5.lab.example`

That keeps the VirtualBox NAT-forwarded SMB transport simple while still using
the correct `cifs/<hostname>` SPN.

## Prerequisites

- Tiny11 reachable on host port `445`
- working Windows credentials:
  - username from `SMOLDER_WINDOWS_USERNAME`
  - password from `SMOLDER_WINDOWS_PASSWORD`
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

It also ensures the default domain test user `LAB\smolder` is in Tiny11's local
`Administrators` group so the Kerberos remote-exec lane can access `ADMIN$`,
`IPC$`, and SCMR.

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

followed by Kerberos-enabled CLI smoke commands:

```bash
target/debug/smolder-ls smb://127.0.0.1/IPC$ --kerberos ...
target/debug/smolder smbexec smb://127.0.0.1 --kerberos --command whoami ...
target/debug/smolder psexec smb://127.0.0.1 --kerberos --command whoami ...
```

Before the `smbexec` smoke, the wrapper re-applies local `Administrators`
membership for the default domain test user using the existing local Tiny11
admin credentials. That makes the Kerberos gate self-healing after realm resets
or user-profile drift.

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

This gate currently covers the file-workflow side of `smolder-tools` plus both
Kerberos remote-exec modes: `smbexec` and `psexec`.

If the wrapper reports that the machine account is missing, the local Samba AD
realm was reset and Tiny11 needs to be rejoined with
`scripts/join-tiny11-to-samba-ad.sh`.
