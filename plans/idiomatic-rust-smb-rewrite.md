# Idiomatic Rust SMB Rewrite Plan

## Objective

Replace the current `smolder-proto` sketch with a real SMB implementation that is:

- protocol-correct against the Microsoft SMB specs,
- validated against Samba's real integration tooling,
- structured as idiomatic Rust instead of a monolithic socket wrapper.

This plan assumes Smolder is primarily a client/toolkit, because the current public surface is `SMBClient` in [smolder-proto/src/smb.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb.rs). If the real goal is a server/fileserver, keep phases 1-4 and add the server track in phase 6.

## Current State

The existing code should be treated as a throwaway spike, not a foundation:

- [smolder-proto/src/smb.rs#L8](/Users/cmagana/Projects/smolder/smolder-proto/src/smb.rs#L8) hardcodes the SMB1 dialect string `NT LM 0.12`.
- [smolder-proto/src/smb.rs#L116](/Users/cmagana/Projects/smolder/smolder-proto/src/smb.rs#L116) mixes transport, protocol, auth placeholders, and session state in one struct.
- [smolder-proto/src/smb.rs#L167-L172](/Users/cmagana/Projects/smolder/smolder-proto/src/smb.rs#L167) writes raw bytes to a live TCP socket and then calls `read_to_end()`, which is not a viable SMB exchange model.
- [README.md#L11-L16](/Users/cmagana/Projects/smolder/README.md#L11) promises async I/O, NTLM, Kerberos, and broader capabilities that do not exist yet.

## Architecture Directives

1. Target SMB2/3 first, not SMB1.
2. Keep wire encoding/decoding separate from transport and session logic.
3. Model negotiated state explicitly with typed structs and enums.
4. Make authentication pluggable; do not let NTLM/SPNEGO logic leak into packet codecs.
5. Use real interoperability tests early, not after the API is already frozen.
6. Treat Samba tests as behavior gates, but use Microsoft Open Specifications as the normative source.

## Recommended Crate Shape

- `smolder-proto`
  - Pure wire types, codecs, flags, status codes, dialect enums, packet validation.
- `smolder-core`
  - Async transport, request/response dispatch, session state machine, auth providers, high-level client API.
- `smolder-tools`
  - CLI probes, packet dump tools, interop helpers, test harness commands.

Inside `smolder-proto`, replace the single `smb.rs` file with modules roughly like:

- `netbios.rs`
- `smb2/header.rs`
- `smb2/negotiate.rs`
- `smb2/session.rs`
- `smb2/tree.rs`
- `smb2/create.rs`
- `status.rs`
- `capabilities.rs`

## Phase Plan

### Phase 1: Reset Scope and Contracts

Goal: stop building on the wrong protocol and freeze the first supported slice.

Tasks:

- Decide whether Smolder is a client/toolkit or a server/fileserver. Recommendation: keep it client-first.
- Declare the initial supported dialect set: `2.1`, `3.0.2`, `3.1.1`.
- Move SMB1 into one of these buckets:
  - deferred completely, or
  - isolated behind a separate `smb1` module/feature with no shared control flow.
- Replace the README claims with a feature matrix that distinguishes implemented, planned, and unsupported features.
- Add an ADR or design note documenting non-goals for the first milestone:
  - no SMB1 by default,
  - no Kerberos in v1,
  - no DFS, durable handles, leasing, encryption, or compounding until the base path is stable.

Verification:

- `cargo test`
- README and crate docs no longer advertise unimplemented behavior.

Exit criteria:

- There is one agreed "happy path" flow:
  - `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> CREATE -> CLOSE -> TREE_DISCONNECT -> LOGOFF`

### Phase 2: Rebuild the Protocol Layer

Goal: create a usable, testable Rust wire layer.

Tasks:

- Introduce `bytes`, `bitflags`, and `thiserror` or equivalent minimal dependencies.
- Implement RFC1002/NetBIOS session framing separately from SMB packet encoding.
- Add typed newtypes for protocol identifiers:
  - `MessageId`
  - `SessionId`
  - `TreeId`
  - `FileId`
  - `CreditCharge`
- Define strongly typed SMB2 headers and message bodies with checked parse/serialize routines.
- Add exhaustive unit tests from captured packet fixtures for:
  - negotiate request/response
  - session setup request/response
  - tree connect request/response
  - create/close request/response
- Add property-style round-trip tests for header and flag serialization.

Verification:

- `cargo test -p smolder-proto`
- `cargo clippy --workspace --all-targets -- -D warnings`

Exit criteria:

- `smolder-proto` contains no socket code.
- All packet parsing boundaries validate lengths, offsets, flags, and dialect-specific invariants.

### Phase 3: Build an Idiomatic Async Session Engine

Goal: move I/O and state management into `smolder-core`.

Tasks:

- Switch transport to `tokio::net::TcpStream`.
- Implement a small request dispatcher that:
  - frames RFC1002 messages,
  - assigns message IDs,
  - reads exact responses instead of `read_to_end()`,
  - preserves negotiated connection state.
- Model connection state as explicit structs:
  - `Unconnected`
  - `Negotiated`
  - `Authenticated`
  - `TreeConnected`
- Keep signing/preauth state on the session object, not in ad hoc mutable fields.
- Add tracing spans around every request/response boundary.

Verification:

- `cargo test -p smolder-core`
- targeted integration tests using a fake transport and canned packet transcripts

Exit criteria:

- The core library can drive the full happy-path exchange over a mock transport without touching auth internals directly.

### Phase 4: Implement Authentication and Minimal Operations

Goal: support the first real interop flow against Samba.

Tasks:

- Implement SPNEGO container handling and NTLMv2 first.
- Do not implement LM authentication on the default path.
- Make auth a trait boundary, for example:
  - `AuthProvider`
  - `NtlmProvider`
  - later `KerberosProvider`
- Implement signing for the first supported dialect family before broadening the operation set.
- Implement the minimal operation set:
  - negotiate
  - session setup
  - tree connect
  - create/open
  - close
  - logoff

Verification:

- unit tests for NTLMv2 message construction and signing
- packet-level regression fixtures from successful Samba exchanges
- `cargo test --workspace`

Exit criteria:

- Smolder can connect to a Samba share, authenticate with NTLMv2, open a file, close it, and disconnect cleanly.

### Phase 5: Add Real Samba Interop Gates

Goal: use Samba as a real compatibility target before expanding features.

Tasks:

- Add a reproducible Samba test target:
  - preferably a pinned container image for routine interop runs,
  - optionally a source-built Samba checkout for deeper `selftest` and `smbtorture` usage.
- Add ignored integration tests that run against a live Samba instance from CI or local opt-in scripts.
- Capture packet traces for each green-path scenario and keep them as regression artifacts.
- Maintain a conformance matrix with rows for:
  - dialect
  - signing
  - auth mechanism
  - open/create semantics
  - read/write semantics
  - error mapping

Verification:

- `cargo test --workspace`
- live interop tests against Samba
- packet trace diff review when a protocol-facing change lands

Exit criteria:

- Every merged protocol change must pass local packet tests and at least one live Samba interop job.

### Phase 6: Use Samba's Real Test Suite the Right Way

Goal: adopt Samba's own tooling without pretending it is a drop-in fit for the wrong product surface.

For a client/toolkit implementation:

- Use a real Samba server as the interoperability oracle.
- Use `smbtorture` and Samba `selftest` selectively to understand expected server behavior and generate traces, not as the only pass/fail gate.
- Keep the primary automated gates in Rust plus live Samba interop tests.

For a server/fileserver implementation:

- Add a dedicated test harness that exposes Smolder as a fileserver target.
- Use Samba `selftest` with targeted `TESTS=` regexes and `make testenv` workflows to run real `smbtorture` cases against Smolder.
- Start with a narrow allowlist around:
  - negotiate
  - session setup
  - tree connect
  - create/open
  - close
  - read/write
- Expand only after the first subset is stable.

Recommended server-side follow-up:

- Add `xfstests-cifs` later for filesystem semantics once protocol negotiation and handle lifecycle are stable.

Verification:

- Document exact setup commands in `docs/testing/samba.md`.
- Record which Samba tests are expected green, expected red, and intentionally out of scope.

Exit criteria:

- The project has a repeatable external conformance story instead of an ad hoc "works against my server" claim.

### Phase 7: Broaden Features Without Breaking the Core

Goal: add capability only after the base protocol path is trustworthy.

Expansion order:

1. read/write
2. query/set info
3. directory enumeration
4. durable handles and leases
5. encryption
6. compounding
7. Kerberos

Each feature must add:

- wire fixtures
- mock-transport tests
- live Samba interop coverage
- documentation updates to the feature matrix

## Verification Stack

Keep all four layers:

1. `smolder-proto` unit and fixture tests.
2. `smolder-core` state-machine tests with fake transports.
3. Live interop tests against Samba.
4. Samba `selftest` / `smbtorture` and later `xfstests-cifs` where they fit the chosen product surface.

Required routine commands:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- opt-in live Samba integration command, documented in the repo

## Anti-Patterns to Avoid

- Keeping everything in one `smb.rs` file.
- Building new features on top of SMB1 assumptions.
- Mixing packet parsing, socket I/O, and auth logic in one type.
- Adding Kerberos before NTLMv2 plus signing is stable.
- Claiming "spec compliance" based only on unit tests.
- Claiming "Samba compatible" based on one manual happy-path run.

## External References

- Samba selftest overview: https://www.samba.org/~asn/sambaxp-2015-andreas_schneider-selftest.pdf
- Samba `xfstests-cifs` guidance: https://wiki.samba.org/index.php/Xfstesting-cifs
- Microsoft CIFS introduction: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/934c2faa-54af-4526-ac74-6a24d126724e
- Microsoft SMB2 negotiate behavior: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1
