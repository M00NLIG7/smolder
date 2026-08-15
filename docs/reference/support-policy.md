# Smolder `0.4.x` Support Policy

This document defines the current support contract for the published `0.4.x`
line of `smolder-proto`, `smolder-smb-core`, and `smolder`. The separately
versioned `smolder-psexecsvc` package remains at `0.3.0` and is not part of the
`0.4.0` release.

It is intentionally stricter than "whatever exists in the repo." The goal is to
separate:

- supported behavior we expect to preserve
- feature-gated behavior that is real but still backend- or fixture-dependent
- non-goals and explicitly unsupported scope

The operational test commands that back this policy live in
[docs/testing/interop.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/interop.md)
and
[docs/testing/release.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/release.md).
MSRV and semver rules live in
[versioning-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md).

## Versioning Direction

For the `0.4.x` line:

- additive changes are preferred over public API churn
- public behavior that is documented here should not change casually
- feature-gated capability expansion is acceptable when it preserves the
  top-level API shape
- breaking changes are still possible before a `1.0`, but they should be
  deliberate, infrequent, and justified by a clearly wrong or blocking design

## Readiness Statement

The `0.4.x` line is intended to be usable in real projects.

That does not mean "frozen forever." It means:

- documented supported flows are expected to remain stable enough for
  downstream use
- patch releases should not casually break code that stays within this policy
- if a supported public workflow needs to change, it should be treated as a
  versioning-policy event rather than incidental churn

## Crate Scope

### `smolder-proto`

Supported:

- typed SMB2/3 codecs
- typed DCE/RPC codecs
- public encode/decode entry points used by `smolder-smb-core`
- property-tested and fuzz-harnessed decode surfaces

Not in scope:

- SMB1
- claiming every public wire type is frozen forever

### `smolder-smb-core`

Supported:

- high-level embedded client facade for connect/authenticate/session/share/file
  workflows
- SMB2/3 negotiate, session setup, tree connect, file lifecycle primitives
- NTLMv2 / SPNEGO auth
- SMB signing
- SMB3 encryption
- SMB compression
- SMB over NetBIOS session service
- SMB over QUIC
- named pipes over `IPC$`
- DCE/RPC transport over named pipes
- typed `srvsvc`, `lsarpc`, and `samr` clients for the currently implemented
  operations, including `srvsvc` host/session queries, `lsarpc` policy and
  name lookup, and `samr` user/alias enumeration
- DFS referral handling and path resolution primitives
- compound request dispatch
- durable and resilient handle reconnect primitives
- feature-gated Kerberos auth/session setup

Supported public entry points are documented in
[smolder-core-api.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/smolder-core-api.md).

Not in scope:

- SMB1
- full Samba `selftest` parity
- every expert-oriented helper being treated as a first-class ergonomic API

### `smolder`

Supported:

- high-level SMB file workflows
- DFS-aware path resolution
- reconnect helpers
- Kerberos-enabled file workflows when the `kerberos` feature is enabled
- Windows `smbexec`
- Windows `psexec`

Not in scope:

- claiming operator workflows are as stable as the lower-level core primitives
- non-Windows parity for remote-exec backends

### `smolder-psexecsvc` (separately versioned)

The optional Windows helper payload remains published at `0.3.0`. The
`smolder` `0.4.0` package does not depend on it; tools workflows may explicitly
stage a compatible helper binary. Source changes to this workspace member are
excluded from the public `0.4.0` crate set.

Supported:

- Windows helper-binary path when explicitly used by tools workflows

Not guaranteed:

- universal execution on locked-down Windows targets
- parity with the built-in no-helper `psexec` fallback on every policy regime

## Target Support

### Explicit live-fixture support matrix

The lanes below are represented by ignored live tests and dedicated workflows. They count as
live-validated for a release only when those fixture workflows run and pass; ordinary unit and
workspace test runs report them as ignored and do not establish live coverage.

- Windows / Tiny11:
  - SMB session/file flows
  - durable reconnect
  - encryption
  - named pipes and RPC
  - DFS
  - `smbexec` and `psexec`
- Local Samba fixtures:
  - SMB session/file flows over Direct TCP and NetBIOS session service
  - encryption
  - compression
  - named pipes and RPC
  - typed `lsarpc` policy and name lookup coverage
  - typed `samr` standalone domain, user, and alias-member coverage
  - typed `srvsvc` host and session query coverage
- Samba QUIC:
  - SMB session/file flows over QUIC through the UTM-backed Linux fixture
- Samba AD:
  - Kerberos SMB auth in core
  - password, ticket-cache, and keytab-backed Kerberos lanes
- Windows domain-member path:
  - Kerberos SMB auth in core
  - Kerberos-enabled file and remote-exec workflows in tools

### Best-effort, not a guarantee

- arbitrary third-party SMB servers not covered by the current matrix
- non-local AD topologies that differ materially from the documented fixtures
- environments that require features outside the tested dialect/auth/encryption
  combinations

## Authentication Policy

### NTLM / SPNEGO

Supported in `0.4.x`:

- NTLMv2 over SPNEGO for SMB `SESSION_SETUP`
- NTLM Authenticate MIC binding when `MsvAvFlags` requires it
- session-key derivation feeding SMB signing and SMB3 encryption
- Windows interop as part of the normal release gates

Raw Type 1/2/3 token diagnostics are absent unless the deliberately dangerous
`dangerous-ntlm-diagnostics` build feature is enabled and
`SMOLDER_NTLM_DEBUG=UNSAFE_RAW_TOKENS` is also set at runtime. Those diagnostics must never be
used with real credentials.

Credentialed constructors require signing and reject guest/null fallback by default. The explicit
`SecurityPolicy::pandora()` construction path additionally requires SMB 3.1.1 and requires SMB
encryption unless the physical connection is certificate-authenticated SMB over QUIC. Negotiation
selections are checked against the immutable client offer and trusted transport identity before any
session typestate is constructed.

### Kerberos

Supported in `0.4.x`, but feature-gated:

- `kerberos` is the target-selecting umbrella: native SSPI on Windows and the
  internal bounded GSSAPI wrapper on Unix
- `kerberos-sspi` is a Windows-only password-backed lane
- `kerberos-gssapi` is a Unix-only password/ticket-cache lane and supports
  client keytabs outside macOS
- Kerberos support includes session-key export for SMB signing and encryption

Current constraints:

- `kerberos-gssapi` is not the static-friendly build path
- native GSSAPI and SSPI backends reject per-operation custom KDC URLs; configure the native
  provider before process launch rather than mutating process-global Kerberos state
- backend-specific capability growth should preserve
  `KerberosCredentials` / `KerberosAuthenticator`

## Transport, Encryption, and RPC Policy

Supported in `0.4.x`:

- SMB2/3 only
- SMB signing
- SMB3 encryption and transform handling
- SMB compression
- SMB over NetBIOS session service
- SMB over QUIC
- named pipes over `IPC$`
- DCE/RPC bind/call transport over named pipes, including bounded FIRST/LAST fragment reassembly,
  buffered coalesced PDUs, and call/context correlation
- typed `srvsvc` coverage for paginated share/session enumeration plus share/server query operations
- typed `lsarpc` coverage for policy open/query and name lookup operations
- typed `samr` coverage for paginated domain, user, group, and alias enumeration plus alias members
- DFS referral resolution
- durable/resilient reconnect primitives
- explicit remote-resource maxima for transport frames, authentication tokens/keys, RPC stubs/pages,
  NDR collections/strings, whole-file helpers, directory enumeration, control records, and credits

Every SMB request has an internal end-to-end deadline. Once a request write can have started, the
connection remains poisoned until the complete correlated response has been drained and validated.
Dropping or externally cancelling that future therefore makes the connection non-reusable; callers
must discard it. Responses are checked for server direction, message/async identity, active
session/tree identity, credit accounting, and signing/encryption policy before reuse is allowed.

Explicitly not promised yet:

- SMB multichannel as an end-to-end transport feature
- full DFS client behavior beyond the documented resolution path
- authenticated RPC coverage for every Windows interface

## Static Build Policy

The default build is intended to stay as static-friendly as practical.

Current rule:

- default build: no Unix GSS/Kerberos native-linking dependency
- `kerberos`: documented target-selecting Kerberos feature surface
- `kerberos-sspi`: Windows OS-ABI backend; no pure-Rust network sidecar
- `kerberos-gssapi`: explicit Unix native-linking exception

This means a fully self-contained static Unix story is not guaranteed once
`kerberos` or `kerberos-gssapi` is enabled. Pandora's static path must either
use Windows SSPI or leave Unix GSS Kerberos disabled.

## Release Gates Required By This Policy

The policy is only as strong as the gates behind it.

### Required before release

- deterministic verification workflow green (MSRV, all features/targets, unit/release/property,
  docs, extracted packages, and installed cross targets):
  - [verify.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/verify.yml)
- locked offline supply-chain checks recorded as described in
  [release.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/release.md)
- Samba interop workflow green:
  - [interop-samba.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/interop-samba.yml)
- Windows release gate green:
  - [run-windows-release-gate.sh](https://github.com/M00NLIG7/smolder/blob/main/scripts/run-windows-release-gate.sh)
  - or the self-hosted workflow equivalent

### Required for Kerberos-affecting changes

- Samba AD Kerberos gate green:
  - [run-kerberos-interop.sh](https://github.com/M00NLIG7/smolder/blob/main/scripts/run-kerberos-interop.sh)
- Windows Kerberos gate green:
  - [run-windows-kerberos-interop.sh](https://github.com/M00NLIG7/smolder/blob/main/scripts/run-windows-kerberos-interop.sh)

### Required for remote-exec-affecting changes

- Windows release gate green, including:
  - `smbexec ... whoami`
  - `psexec ... whoami`

The narrower change-to-gate mapping remains in
[release.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/release.md).

## Non-Goals for `0.4.x`

- SMB1 support
- claiming universal parity with every Windows or Samba deployment
- hosted fully automatic Windows CI without self-hosted infrastructure
- treating every internal helper as permanently stable public API
- claiming fully static Kerberos support across all backend combinations

## How To Read This Policy

If behavior is:

- documented here
- backed by the interop matrix
- and covered by the required gates

then it is part of the `0.4.x` support story and should not be changed lightly.
