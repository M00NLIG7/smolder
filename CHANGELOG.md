# Changelog

All notable changes to the published Smolder crates are documented in this
file.

This changelog covers:

- `smolder-proto`
- `smolder-smb-core`
- `smolder`
- `smolder-psexecsvc`

The support scope behind each release is defined in
[docs/reference/support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md),
and the versioning/MSRV rules are defined in
[docs/reference/versioning-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md).

## [Unreleased]

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

## [0.3.0] - 2026-03-31

### Added

- Added a high-level embedded client facade to `smolder-smb-core` with
  `ClientBuilder`, `Client`, authenticated session wrappers, and tree-connected
  share wrappers on top of the existing typestate SMB client.
- Extended the high-level `smolder-smb-core` facade with share/file operations,
  including `OpenOptions`, `File`, metadata queries, and a compile-checked
  `client_file_roundtrip` example.
- Added deeper standalone Samba `SAMR` coverage to `smolder-smb-core`,
  including domain open, user enumeration, user open, and account-name query
  flows over `\\PIPE\\samr`.
- Added deeper standalone Samba `LSARPC` coverage to `smolder-smb-core`,
  including primary-domain and account-domain policy queries over
  `\\PIPE\\lsarpc`.
- Added a working local Apple Silicon Samba QUIC validation path through UTM,
  including guest provisioning, Samba fixture setup, and live QUIC interop
  coverage against the current `smolder-smb-core` QUIC lane.
- Added SMB transport-capability negotiate contexts to `smolder-proto` so
  SMB over QUIC transport-level security can be represented at the wire layer.

### Fixed

- Fixed `SAMR` NDR encoding and decoding for lookup-domain, open-domain, and
  account-name query paths against standalone Samba fixtures.
- Refactored `smolder-smb-core` so the SMB client speaks raw SMB messages
  internally while framed TCP transport remains a compatibility layer for
  custom transports.
- Fixed standalone Samba `LSARPC` compatibility by falling back from
  `LsarQueryInformationPolicy2` to the legacy query opnum and by decoding the
  union/string/SID layouts returned by the live fixture.
- Fixed SMB over QUIC message handling so `smolder-smb-core` preserves the SMB
  4-byte message framing over QUIC instead of treating QUIC as an unframed
  byte stream.
- Switched `smolder` high-level session setup onto the `smolder-smb-core`
  client facade so the published tools layer no longer reimplements negotiate
  and auth orchestration separately.

### Docs

- Updated crate docs and examples to prefer the embedded client facade,
  including the NTLM, Kerberos, and named-pipe examples.
- Replaced workstation-local absolute links in crate docs and repository docs
  with GitHub/docs.rs-friendly links.
- Updated the public README and crate metadata to reflect compression, typed
  RPC clients, QUIC, and the current validated surface.

### Changed

- Promoted the documented support line from `0.2.x` to `0.3.x`.

### Validation

- `cargo test -p smolder-proto`
- `cargo test -p smolder-smb-core --features quic --lib`
- `cargo test -p smolder --lib`
- `cargo build -p smolder-smb-core --features "kerberos quic" --example kerberos_tree_connect --example ntlm_tree_connect --example named_pipe_rpc_bind --example client_quic_session_connect`
- `cargo doc -p smolder-smb-core --no-deps --features "kerberos quic"`
- `cargo doc -p smolder --no-deps --features kerberos`
- `cargo doc -p smolder-proto --no-deps`

## [0.2.0] - 2026-03-27

### Added

- Added Kerberos support as a real feature track across the published crates,
  including:
  - mechanism-aware SPNEGO
  - password-backed Kerberos
  - Unix ticket-cache and keytab support behind `kerberos-gssapi`
  - Samba AD and Windows domain-member interop gates
  - Kerberos-enabled file and remote-exec workflows in `smolder`
- Added stronger protocol hardening and release discipline:
  - property tests and fuzz entrypoints for `smolder-proto`
  - benchmark harnesses for `smolder-proto` and `smolder-smb-core`
  - formal support policy, versioning policy, and release checklist
- Added a larger docs/examples surface:
  - cookbook pages
  - direct-library core examples
  - high-level tools examples
  - a standalone `smolder-core-demo` reference client crate in the repo

### Changed

- Moved the project from the initial `0.1.0` publish baseline into a documented
  `0.2.x` support line aimed at real-project use.
- Improved crate onboarding and docs.rs/crates.io presentation across
  `smolder-proto`, `smolder-smb-core`, `smolder`, and `smolder-psexecsvc`.
- Split Kerberos backend features so the default documented build remains more
  static-friendly unless `kerberos-gssapi` is enabled explicitly.

### Fixed

- Stabilized interactive `psexec` so direct interactive `cmd.exe` and direct
  interactive `powershell.exe` use a real Windows pseudoconsole-backed session.
- Improved Windows and Samba interop coverage and fixture reliability,
  including Kerberos and remote-exec paths.

### Docs

- Clarified real-project readiness expectations for the `0.2.x` line.
- Added start-here guidance and adoption-oriented crate docs for all published
  packages.

### Validation

- Samba interop workflow in GitHub Actions
- Tiny11 / Windows release gate
- Samba AD Kerberos gate
- Windows Kerberos gate
- Benchmark smoke workflow

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
