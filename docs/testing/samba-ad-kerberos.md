# Samba AD Kerberos Fixture

This document describes the local fixture Smolder now uses for its Kerberos
track: a Docker Compose topology that provides a real AD-backed SMB target for
[kerberos_interop.rs](/Users/cmagana/Projects/smolder/smolder-core/tests/kerberos_interop.rs).

The immediate goal is not "generic LDAP lab". The current goals are narrower:

1. issue a real Kerberos service ticket for `cifs/files1.lab.example`
2. authenticate SMB `SESSION_SETUP` with Kerberos
3. prove Smolder can sign post-auth SMB traffic with the exported session key
4. use the same realm to domain-join Tiny11 and prove Kerberos SMB against a
   Windows member server

This fixture is now the first reproducible Kerberos gate and the local realm
used by the Tiny11 Windows member flow before the feature is wired into
`smolder-tools`.

## Why A Separate Fixture

The current [docker/samba/compose.yaml](/Users/cmagana/Projects/smolder/docker/samba/compose.yaml)
stack is a WORKGROUP-style Samba fixture. It is excellent for SMB2/3, signing,
encryption, pipes, and RPC, but it is not an AD realm and therefore cannot
exercise:

- KDC discovery
- service-ticket acquisition
- `cifs/<hostname>` SPN validation
- Kerberos-backed SMB signing

Kerberos needs a real AD realm, a domain member file server, working DNS, and
time discipline.

## Proposed Topology

Use a dedicated Compose project under `docker/samba-ad/`.

Planned services:

- `dc1`
  - Samba AD DC
  - FQDN: `dc1.lab.example`
  - Realm: `LAB.EXAMPLE`
  - NetBIOS domain: `LAB`
- `files1`
  - Samba domain member and SMB file server
  - FQDN: `files1.lab.example`
  - joined to `LAB.EXAMPLE`
  - exports the `share` test share

Optional later:

- `client`
  - Linux domain member used for `kinit`, `smbclient`, and debugging
  - not required for the first Smolder gate because the repo harness now uses a
    Linux/MIT container directly for the keytab lane

## Network Plan

Use a dedicated user-defined bridge network with fixed service IPs so the DC and
member can resolve each other deterministically during provisioning and join.

Suggested internal layout:

- `dc1`: `10.42.0.10`
- `files1`: `10.42.0.20`
- subnet: `10.42.0.0/24`

Expose only the host-facing ports needed by Smolder:

- DC:
  - `1053 -> 53/tcp`
  - `1053 -> 53/udp`
  - `1088 -> 88/tcp`
  - `1088 -> 88/udp`
  - `1464 -> 464/tcp`
  - `1464 -> 464/udp`
- file server:
  - `2445 -> 445/tcp`

The host-side test lane should connect to:

- KDC: `tcp://dc1.lab.example:1088`
- SMB: `files1.lab.example:2445`

That avoids collision with the existing local Samba fixtures on `1445` and
`1446`.

## Host Name Resolution

Do not run Kerberos against raw IPs or `127.0.0.1` as the logical SMB host.
Smolder builds the service principal name from the hostname, so the fixture must
use a real FQDN.

For the first local version, add host aliases on the development machine:

```text
127.0.0.1 dc1.lab.example files1.lab.example
```

This keeps the host-side test configuration simple while still driving Kerberos
with the correct SPN:

- `cifs/files1.lab.example`

The containers themselves must not resolve their own hostnames to loopback. Use
the internal bridge IPs inside the Compose network and container `/etc/hosts`
entries only where strictly necessary.

## Bootstrap Order

Bring the fixture up in phases.

### Phase 1: Provision The AD DC

The DC container should:

1. set hostname/FQDN to `dc1.lab.example`
2. provision the AD with:
   - realm `LAB.EXAMPLE`
   - domain `LAB`
   - `--use-rfc2307`
   - `SAMBA_INTERNAL` DNS
3. install the generated `krb5.conf`
4. start the `samba` AD DC service
5. create the test user:
   - `smolder@LAB.EXAMPLE`
6. create or verify DNS records for `dc1` and `files1`

Suggested verification inside the DC:

- `samba-tool user show smolder`
- `host -t SRV _kerberos._tcp.lab.example`
- `host -t SRV _ldap._tcp.lab.example`

### Phase 2: Join The File Server

The file-server container should:

1. set hostname/FQDN to `files1.lab.example`
2. point `/etc/resolv.conf` at the AD DC
3. install a minimal `krb5.conf` for `LAB.EXAMPLE`
4. join the domain as a member
5. start `winbindd` and `smbd`
6. export the `share` SMB test share

Suggested verification inside the member:

- `net ads testjoin`
- `wbinfo -t`
- `getent hosts files1`
- `kinit smolder@LAB.EXAMPLE` as a sanity probe

### Phase 3: Verify SPN Shape

Before blaming Smolder, verify the member has the correct service identity for
SMB.

The expected SPN is:

```text
cifs/files1.lab.example
```

If an alias name is introduced later, add the matching SPN explicitly instead
of assuming the computer account already covers it.

## Planned Repo Layout

These are the repo paths I would add next when implementing the fixture:

- `docker/samba-ad/compose.yaml`
- `docker/samba-ad/dc/Containerfile`
- `docker/samba-ad/dc/bootstrap.sh`
- `docker/samba-ad/member/Containerfile`
- `docker/samba-ad/member/bootstrap.sh`
- `docker/samba-ad/member/smb.conf`
- `docker/samba-ad/member/share/.gitkeep`
- `scripts/prepare-samba-ad-fixture.sh`
- `scripts/run-kerberos-interop.sh`

The first implementation should prefer explicit bootstrap scripts over opaque
image magic so the provisioning and join steps are inspectable.

## Environment For Smolder

Once the fixture is up, the first host-side password-backed Kerberos lane is:

```bash
export SMOLDER_KERBEROS_HOST=files1.lab.example
export SMOLDER_KERBEROS_PORT=2445
export SMOLDER_KERBEROS_USERNAME=smolder@LAB.EXAMPLE
export SMOLDER_KERBEROS_PASSWORD='Passw0rd!'
export SMOLDER_KERBEROS_SHARE=share
export SMOLDER_KERBEROS_REALM=LAB.EXAMPLE
export SMOLDER_KERBEROS_KDC_URL=tcp://dc1.lab.example:1088
```

Then run:

```bash
cargo test -p smolder-smb-core --features kerberos --test kerberos_interop -- --nocapture
cargo run -p smolder-smb-core --features kerberos --example kerberos_tree_connect
```

The repo harness at [scripts/run-kerberos-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-kerberos-interop.sh)
now drives two live gates:

1. host-side password-backed Kerberos against `files1.lab.example:2445`
2. Linux/MIT containerized keytab-backed Kerberos against `files1.lab.example:445`

The second lane exists so the published `kerberos-gssapi` backend is validated
against the same GSS/Kerberos family it uses in practice, instead of depending
on host-specific macOS GSS behavior.

## Success Criteria

The fixture is "good enough" for the first merge gate when all of these are
true:

1. `kerberos_interop.rs` passes against the fixture
2. `kerberos_interop.rs` passes with a Linux/MIT keytab lane
3. `KerberosAuthenticator::session_key()` is non-empty after auth
4. a post-auth SMB tree connect succeeds without falling back to NTLM
5. the fixture can be brought up and torn down by script
6. the topology is isolated from the existing WORKGROUP Samba fixtures

## Failure Checklist

If the first live run fails, check these in order:

1. `files1.lab.example` resolves on the host
2. `dc1.lab.example` resolves on the host
3. `SMOLDER_KERBEROS_KDC_URL` points at the exposed DC port
4. DC and member clocks are within 5 minutes
5. `_kerberos._tcp.lab.example` and `_ldap._tcp.lab.example` resolve inside the
   member container
6. `files1` is actually joined to the domain
7. the `cifs/files1.lab.example` SPN exists on the member account

## Why This Order

This gives Smolder the fastest credible Kerberos path:

1. Samba AD fixture first for local reproducibility
2. Smolder core Kerberos interop second
3. `smolder-tools` wiring third
4. Windows AD-backed validation after the core Samba AD lane is green

That order keeps protocol debugging local and cheap before spending time on
heavier Windows domain automation.

## References

- Samba AD DC setup:
  https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
- Samba domain member setup:
  https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member
- Samba time synchronisation:
  https://wiki.samba.org/index.php/Time_Synchronisation
- Joining Windows to a Samba AD:
  https://wiki.samba.org/index.php/Joining_a_Windows_Client_or_Server_to_a_Domain
- Microsoft `setspn` reference:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn
