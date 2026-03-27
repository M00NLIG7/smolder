# Changelog

All notable changes to the published Smolder crates are documented in this
file.

This changelog covers:

- `smolder-proto`
- `smolder-smb-core`
- `smolder`
- `smolder-psexecsvc`

The support scope behind each release is defined in
[docs/reference/support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md),
and the versioning/MSRV rules are defined in
[docs/reference/versioning-policy.md](/Users/cmagana/Projects/smolder/docs/reference/versioning-policy.md).

## [Unreleased]

### Added

- Added a compile-only GitHub Actions benchmark smoke workflow for
  `smolder-proto` and `smolder-smb-core`.

### Release Notes Flow

- Add user-visible changes here as they land.
- Keep entries grouped by `Added`, `Changed`, `Fixed`, `Docs`, or `Security`
  where possible.
- Before tagging a release:
  - move the accumulated notes into a dated version section
  - keep the wording user-facing rather than commit-by-commit
  - include any support-policy or MSRV changes explicitly
  - note the required validation gates that were run for that release
- After tagging:
  - recreate an empty `Unreleased` section
  - use the matching version section as the basis for the GitHub release body

## [0.1.0] - 2026-03-27

### Added

- Published the initial crate set:
  - `smolder-proto`
  - `smolder-smb-core`
  - `smolder`
  - `smolder-psexecsvc`
- Built a typed SMB2/3 and DCE/RPC codec layer in `smolder-proto`.
- Built a reusable SMB/RPC library layer in `smolder-smb-core` covering:
  - negotiate, session setup, tree connect, file lifecycle primitives
  - NTLMv2 / SPNEGO auth
  - SMB signing
  - SMB3 encryption
  - named pipes and DCE/RPC transport
  - DFS referral handling
  - durable and resilient reconnect primitives
  - feature-gated Kerberos auth
- Built the operator-facing `smolder` tools layer covering:
  - high-level file workflows
  - DFS-aware path resolution
  - reconnect helpers
  - `smbexec`
  - `psexec`
  - feature-gated Kerberos file and remote-exec workflows
- Added live interop fixtures and harnesses for:
  - Tiny11 / Windows
  - local Samba
  - Samba AD Kerberos
  - Windows domain-member Kerberos
- Added property-test, fuzz, and benchmark harnesses for the protocol and core
  hot paths.

### Changed

- Split the workspace cleanly so `smolder-smb-core` remains protocol- and
  library-focused while operator behavior lives in `smolder`.
- Pinned the current MSRV policy at Rust `1.85`.

### Fixed

- Windows `SESSION_SETUP` / SPNEGO / NTLM compatibility for SMB auth.
- Windows `smbexec` and `psexec` behavior against the Tiny11 fixture.
- Samba CI fixture permissions and hosted-runner interoperability issues.
- Kerberos build-shape issues so the default documented build remains more
  static-friendly unless `kerberos-gssapi` is enabled explicitly.

### Docs

- Added API-surface notes, support policy, versioning policy, fixture docs,
  release checklist, fuzzing guide, and benchmark guide.

### Validation

- Samba interop workflow in GitHub Actions
- Tiny11 / Windows release gate
- Samba AD Kerberos gate
- Windows Kerberos gate
