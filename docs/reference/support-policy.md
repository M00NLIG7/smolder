# Smolder `0.1.x` Support Policy

This document defines the current support contract for the published `0.1.x`
line.

It is intentionally stricter than "whatever exists in the repo." The goal is to
separate:

- supported behavior we expect to preserve
- feature-gated behavior that is real but still backend- or fixture-dependent
- non-goals and explicitly unsupported scope

The operational test commands that back this policy live in
[docs/testing/interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md)
and
[docs/testing/release.md](/Users/cmagana/Projects/smolder/docs/testing/release.md).
MSRV and semver rules live in
[versioning-policy.md](/Users/cmagana/Projects/smolder/docs/reference/versioning-policy.md).

## Versioning Direction

For the `0.1.x` line:

- additive changes are preferred over public API churn
- public behavior that is documented here should not change casually
- feature-gated capability expansion is acceptable when it preserves the
  top-level API shape
- breaking changes are still possible before a `1.0`, but they should be
  deliberate, infrequent, and justified by a clearly wrong or blocking design

## Readiness Statement

The `0.1.x` line is intended to be usable in real projects.

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

- SMB2/3 negotiate, session setup, tree connect, file lifecycle primitives
- NTLMv2 / SPNEGO auth
- SMB signing
- SMB3 encryption
- named pipes over `IPC$`
- DCE/RPC transport over named pipes
- DFS referral handling and path resolution primitives
- compound request dispatch
- durable and resilient handle reconnect primitives
- feature-gated Kerberos auth/session setup

Supported public entry points are documented in
[smolder-core-api.md](/Users/cmagana/Projects/smolder/docs/reference/smolder-core-api.md).

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

### `smolder-psexecsvc`

Supported:

- published remote service payload crate
- Windows helper-binary path when explicitly used by tools workflows

Not guaranteed:

- universal execution on locked-down Windows targets
- parity with the built-in no-helper `psexec` fallback on every policy regime

## Target Support

### Supported and live-tested

- Windows / Tiny11:
  - SMB session/file flows
  - durable reconnect
  - encryption
  - named pipes and RPC
  - DFS
  - `smbexec` and `psexec`
- Local Samba fixtures:
  - SMB session/file flows
  - encryption
  - named pipes and RPC
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

Supported in `0.1.x`:

- NTLMv2 over SPNEGO for SMB `SESSION_SETUP`
- session-key derivation feeding SMB signing and SMB3 encryption
- Windows interop as part of the normal release gates

### Kerberos

Supported in `0.1.x`, but feature-gated:

- enable with `kerberos`
- default documented backend path is the password-backed `kerberos-sspi` lane
- Unix ticket-cache and keytab lanes exist behind `kerberos-gssapi`
- Kerberos support includes session-key export for SMB signing and encryption

Current constraints:

- `kerberos-gssapi` is not the static-friendly build path
- backend-specific capability growth should preserve
  `KerberosCredentials` / `KerberosAuthenticator`

## Transport, Encryption, and RPC Policy

Supported in `0.1.x`:

- SMB2/3 only
- SMB signing
- SMB3 encryption and transform handling
- named pipes over `IPC$`
- DCE/RPC bind/call transport over named pipes
- DFS referral resolution
- durable/resilient reconnect primitives

Explicitly not promised yet:

- SMB multichannel as an end-to-end transport feature
- SMB compression
- full DFS client behavior beyond the documented resolution path
- authenticated RPC coverage for every Windows interface

## Static Build Policy

The default build is intended to stay as static-friendly as practical.

Current rule:

- default build: no Unix GSS/Kerberos native-linking dependency
- `kerberos`: documented stable Kerberos feature surface
- `kerberos-gssapi`: explicit native-linking exception for Unix ticket-cache and
  keytab support

This means a fully self-contained static story is not guaranteed once
`kerberos-gssapi` is enabled.

## Release Gates Required By This Policy

The policy is only as strong as the gates behind it.

### Required before release

- Samba interop workflow green:
  - [interop-samba.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-samba.yml)
- Windows release gate green:
  - [run-windows-release-gate.sh](/Users/cmagana/Projects/smolder/scripts/run-windows-release-gate.sh)
  - or the self-hosted workflow equivalent

### Required for Kerberos-affecting changes

- Samba AD Kerberos gate green:
  - [run-kerberos-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-kerberos-interop.sh)
- Windows Kerberos gate green:
  - [run-windows-kerberos-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-windows-kerberos-interop.sh)

### Required for remote-exec-affecting changes

- Windows release gate green, including:
  - `smbexec ... whoami`
  - `psexec ... whoami`

The narrower change-to-gate mapping remains in
[release.md](/Users/cmagana/Projects/smolder/docs/testing/release.md).

## Non-Goals for `0.1.x`

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

then it is part of the `0.1.x` support story and should not be changed lightly.
