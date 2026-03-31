# Samba RPC Fixture

This fixture is the local standalone Samba lane for RPC-capable `IPC$`
validation outside the AD/Kerberos topology.

It exists to answer a different question than the AD-backed fixture:

- does the local Samba server actually expose `lsarpc` / `samr` over `IPC$`
- can Smolder open and bind those pipes against the same standalone server
- can the repo prove that with a repeatable harness instead of skip-only tests

## Target

- Host: `127.0.0.1`
- Port: `1445`
- Username: `smolder`
- Password: `smolderpass`
- Domain/workgroup: `WORKGROUP`
- Container: `smolder-samba`

The fixture is backed by
[compose.yaml](https://github.com/M00NLIG7/smolder/blob/main/docker/samba/compose.yaml).

## Preflight

Before relying on Smolder's RPC tests, the harness proves the standalone Samba
server itself exposes the expected RPC surface with `rpcclient`:

- `lsaquery`
- `enumdomusers`

That keeps the fixture honest. If those preflight commands fail, the environment
is wrong before the Rust tests even start.

## Harness

Run the fixture with:

```bash
scripts/run-samba-rpc-interop.sh
```

That command:

1. starts the standalone Samba container if needed
2. runs the `rpcclient` preflight inside `smolder-samba`
3. runs the live Smolder LSARPC interop test

## Current Smolder Gate

The current Rust-side gate is:

- [samba_lsarpc_interop.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/tests/samba_lsarpc_interop.rs)

Today that test proves:

- `IPC$` access against the standalone Samba fixture
- `\\PIPE\\lsarpc` open via the high-level client facade
- typed `LsarpcClient` bind plus primary/account-domain policy queries

The same harness now also includes:

- [samba_samr_standalone_interop.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/tests/samba_samr_standalone_interop.rs)

Today that test proves:

- `\\PIPE\\samr` access against the standalone Samba fixture
- typed `SamrClient` bind with the current `SamrConnect2` fallback path
- `SamrEnumerateDomainsInSamServer` against the standalone server
- `SamrOpenDomain` against the local server domain
- `SamrEnumerateUsersInDomain` against the opened domain
- `SamrOpenUser` for the fixture user
- `SamrQueryInformationUser` account-name lookup for that user
