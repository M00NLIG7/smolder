# Why Smolder

Smolder exists to be two things at once:

- a serious pure-Rust SMB2/3 library for embedders
- a serious SMB/RPC toolkit for security testing and operator workflows

The project is intentionally organized around that split:

- `smolder-proto` owns wire types and codecs
- `smolder-smb-core` owns transport, auth, session state, file workflows, and
  typed RPC clients
- `smolder` owns user-facing tools and operator behavior
- `smolder-psexecsvc` owns the optional Windows service payload used by
  `psexec`

That separation keeps the library layer usable in normal applications without
forcing tool-specific behavior into the core crate.

## Why Choose It

### One library story, not just a packet codec

The intended starting point is now the high-level facade:

- `ClientBuilder -> Client -> Session -> Share`

That path covers common connect, authenticate, file, and directory workflows
without forcing callers to drive raw SMB request sequences by hand.

When you need lower-level control, the typestate connection flow and named-pipe
transport are still available underneath the facade.

## Typed RPC Over `IPC$`

Smolder treats named pipes and DCE/RPC as first-class library capabilities, not
just incidental implementation details.

The current stable surface includes typed clients for:

- `srvsvc`
- `lsarpc`
- `samr`

That matters if your application needs more than file sharing, including host
metadata, policy queries, account lookups, or other Windows-management and
security workflows.

## Security Workflows Share The Same Core

The operator-facing workflows are built on the same SMB/RPC stack that the
library exposes.

That means features like:

- `smbexec`
- `psexec`
- DFS-aware path handling
- named-pipe RPC
- Kerberos-enabled remote workflows

are not implemented as a completely separate code path from the reusable core.

## Modern Transport Coverage

The current `0.3.x` line supports:

- Direct TCP
- NetBIOS session service
- QUIC

The transport choice is expressed through `TransportTarget`, so callers can
keep the facade as the main API while selecting the transport explicitly.

## Explicit Support Contract

Smolder is opinionated about documenting what is actually supported now.

The main contract lives in:

- [support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md)
- [versioning-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md)
- [smolder-core-api.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/smolder-core-api.md)

That is deliberate. The goal is to make it easy for downstream users to know
which parts of the surface are intended entry points and which parts remain
expert-oriented.

## Live Interop Matters

Smolder is not trying to be correct only in unit tests.

The current matrix includes live validation against:

- Windows / Tiny11
- local Samba fixtures
- Samba AD Kerberos
- Samba QUIC through the UTM-backed Linux fixture

Interop commands and release gates are documented in
[docs/testing/interop.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/interop.md).

## Static-Friendly Default Direction

The default build keeps native Unix Kerberos linkage out of the common path.

Feature-gated Kerberos support is available, but `kerberos-gssapi` remains an
explicit opt-in rather than a silent dependency in the default build.

## Good Fit

Smolder is a strong fit when you want:

- a pure-Rust SMB2/3 library with a facade-first entry point
- typed RPC over named pipes
- SMB plus operator-facing workflows in one project
- explicit Windows and Samba validation
- a library that is trying to be useful both to embedders and to security
  practitioners

## Start Here

- [examples.md](https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md)
- [smolder-core-api.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/smolder-core-api.md)
- [support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md)
