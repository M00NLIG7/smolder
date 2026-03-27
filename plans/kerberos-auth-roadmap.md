# Kerberos Auth Roadmap

## Objective

Add a production-grade Kerberos authentication module to `smolder-core` for SMB
`SESSION_SETUP`, with the quality bar expected of a serious Rust protocol
library.

This track is intentionally broader than "make Kerberos login work once". The
goal is for Smolder's SMB Kerberos story to feel as credible and reusable in
Rust as `russh` does for SSH:

- library-first, not CLI-first
- strong docs and examples
- clean feature boundaries
- real interop coverage against Windows and Samba
- APIs that downstream projects can build on without copying protocol glue

## Product Bar

`russh` is a good comparison point because it is recognized as a reusable Rust
transport/auth library, not just a one-off client. The relevant bar from
`russh` is:

- clear client-facing API boundaries
- explicit feature and backend choices
- real examples for normal use cases
- interop-focused development
- an ecosystem surface that other crates can depend on

Smolder should aim for the SMB equivalent:

- `smolder-proto`: SMB/DCE-RPC wire codecs
- `smolder-core`: NTLM and Kerberos auth/session/transport primitives
- `smolder`: high-level workflows and CLI

Kerberos belongs in `smolder-core`.

## Scope

### In Scope For The First Serious Kerberos Release

1. SPNEGO negotiation for Kerberos in SMB `SESSION_SETUP`
2. AP-REQ / AP-REP processing with mutual authentication
3. Exported session key handling suitable for SMB signing and encryption
4. SMB target SPN construction for `cifs/<hostname>` with override support
5. Credential inputs expected for SMB clients:
   - password-based acquisition
   - existing ticket cache
   - keytab-based acquisition
6. DFS-aware host/SPN handling when referrals cross hosts
7. Interop against:
   - Windows AD-backed SMB
   - Samba joined to an AD realm
8. Library docs and examples for the common Kerberos paths

### Explicitly Out Of Scope For The First Kerberos Track

1. SMB1 compatibility
2. PKINIT / smart card auth
3. S4U / constrained delegation
4. FAST armor
5. PAC inspection as a first-class API
6. Cross-forest optimization work beyond baseline interoperability
7. NegoEx-specific work unless the actual SMB targets require it

Those can follow later, but they should not block a strong SMB Kerberos baseline.

## Why This Scope Fits SMB

For SMB, Kerberos is not just another credential format. The client needs:

- a service ticket for the SMB server SPN
- correct SPNEGO wrapping in `SESSION_SETUP`
- AP-REP validation when the server completes mutual auth
- a session key that feeds SMB signing and SMB3 encryption

That means the minimum credible scope is:

- credential acquisition
- SPN handling
- SPNEGO token exchange
- session-key export
- post-auth signing/sealing integration

Anything smaller would produce a demo, not a library people trust.

Microsoft's SMB/GSS flow makes this explicit: SMB uses SPNEGO for
authentication, and Kerberos service tickets are requested for SMB server SPNs
such as `cifs/servername.domain`.

Sources:

- [MS-SMB2: Handling a New Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c)
- [MS-SMB2: Handling GSS-API Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654)
- [MS-KILE: Naming](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/04033bd5-913c-4c78-a398-b549b09e65d9)
- [Microsoft Learn: SMB SPN validation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852272%28v%3Dws.11%29)

## Architecture Direction

### Core API Shape

The public auth surface in [smolder-core/src/auth/mod.rs](/Users/cmagana/Projects/smolder/smolder-core/src/auth/mod.rs)
already has the right abstraction point:

- `AuthProvider`
- `initial_token(...)`
- `next_token(...)`
- `finish(...)`
- `session_key()`

Kerberos should be another `AuthProvider`, not a special case wired directly
into the client.

### Proposed Modules

- `smolder-core/src/auth/kerberos.rs`
- `smolder-core/src/auth/kerberos_cache.rs`
- `smolder-core/src/auth/kerberos_kdc.rs`
- `smolder-core/src/auth/kerberos_spn.rs`
- `smolder-core/src/auth/spnego.rs` updates for multi-mech support

The likely public entry point is:

- `KerberosAuthenticator`
- `KerberosCredentials`
- `KerberosTarget`

### Backend Strategy

For SMB, reliability matters more than ideological purity. The practical shape
should be backend-oriented:

1. stable public Smolder Kerberos API in `smolder-core`
2. one or more implementation backends behind feature flags

Recommended backend strategy:

- `kerberos`:
  common public API and SPNEGO/session integration
- `kerberos-gssapi`:
  Unix/macOS path using system Kerberos/GSS where available
- `kerberos-sspi`:
  Windows-native path
- optional future:
  `kerberos-pure`

This is closer to the `russh` mindset of clear backend choices than forcing a
single backend too early.

Current status note:

- the current implementation behind `kerberos` is `sspi`-backed and
  password-oriented
- `kerberos-gssapi` now adds a Unix ticket-cache backend behind the same
  public `KerberosCredentials` / `KerberosAuthenticator` surface
- the vendored `sspi` `0.19.2` path used by Smolder requires outbound auth data
  and does not expose a clean ticket-cache/keytab flow through the current
  integration shape
- that means keytab support should still be treated as a backend/credential
  store expansion milestone, not a small extension to `KerberosCredentials`

### Client Integration

The `Connection::authenticate(...)` flow in
[smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
should stay generic. The client changes needed are:

1. multi-mechanism SPNEGO token support
2. session-key export handling that does not assume NTLM
3. signing/encryption derivation that works from a Kerberos session key
4. target-SPN-aware session setup builder inputs

## Milestones

### Milestone 1

Commit title:
`feat(auth): add SPNEGO multi-mechanism support`

Target files:

- [smolder-core/src/auth/mod.rs](/Users/cmagana/Projects/smolder/smolder-core/src/auth/mod.rs)
- [smolder-core/src/auth/spnego.rs](/Users/cmagana/Projects/smolder/smolder-core/src/auth/spnego.rs)
- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)

Tasks:

- Stop hardcoding NTLM as the only advertised SPNEGO mech
- Model mechanism OIDs explicitly
- Make the client auth loop mechanism-agnostic
- Preserve the existing NTLM behavior unchanged

Exit criteria:

- NTLM still passes all current Windows and Samba gates
- Kerberos mech advertisement becomes possible without protocol hacks

### Milestone 2

Commit title:
`feat(auth): add password-backed Kerberos SMB session setup`

Target files:

- `smolder-core/src/auth/kerberos.rs`
- `smolder-core/src/auth/kerberos_spn.rs`
- [smolder-core/src/auth/mod.rs](/Users/cmagana/Projects/smolder/smolder-core/src/auth/mod.rs)

Tasks:

- Add a Kerberos authenticator that can acquire tickets from username/password
- Implement SPN derivation for `cifs/<hostname>`
- Export the Kerberos session key through `AuthProvider::session_key()`
- Allow caller override for SPN / realm / hostname canonicalization
- Produce SPNEGO-wrapped Kerberos tokens for SMB `SESSION_SETUP`

Exit criteria:

- password-backed Kerberos can complete signed SMB `SESSION_SETUP`
- the authenticator exports a session key suitable for SMB signing/encryption

### Milestone 3

Commit title:
`test(auth): validate Kerberos signing and live SMB interop`

Target files:

- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- [smolder-core/src/crypto.rs](/Users/cmagana/Projects/smolder/smolder-core/src/crypto.rs)
- Kerberos auth module files
- Windows and Samba interop tests

Tasks:

- Validate AP-REP / final token handling
- reuse the existing SMB signing/encryption machinery with Kerberos-established keys
- add regression tests ensuring post-auth requests are signed/sealed correctly
- add Windows AD-backed and Samba AD-backed live interop coverage

Exit criteria:

- Kerberos-authenticated sessions can perform signed SMB traffic
- SMB3 encryption also works after Kerberos auth

### Milestone 4

Commit title:
`feat(auth): add ticket-cache and keytab Kerberos providers`

Target files:

- `smolder-core/src/auth/kerberos_cache.rs`
- `smolder-core/src/auth/kerberos_kdc.rs`
- `smolder-core/src/auth/kerberos.rs`
- `smolder-tools/src/main.rs` if CLI wiring is added in the same slice

Tasks:

- Add ticket-cache-backed Kerberos acquisition
- Add keytab-based ticket acquisition
- Expose the right builder inputs in library code first
- Wire CLI flags only after the core flow is stable

Exit criteria:

- callers can use an existing `kinit` cache without re-entering a password
- keytab auth works for service-style automation

### Milestone 5

Commit title:
`feat(auth): carry Kerberos identity across DFS referrals and reconnects`

Target files:

- DFS helpers in `smolder-core`
- reconnect helpers in `smolder`
- Kerberos SPN helper module

Tasks:

- recompute target SPNs across DFS host changes
- ensure reconnect helpers can rebuild Kerberos-authenticated sessions
- keep service identity explicit where host canonicalization matters

Exit criteria:

- cross-host DFS does not silently fall back to broken SPN assumptions
- durable/reconnect flows remain viable with Kerberos-backed sessions

### Milestone 6

Commit title:
`docs(auth): add Kerberos examples and interop matrix`

Target files:

- `smolder-core/examples/kerberos_tree_connect.rs`
- `smolder/examples/kerberos_ls.rs`
- [README.md](/Users/cmagana/Projects/smolder/README.md)
- [docs/testing/interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md)

Tasks:

- add minimal library and CLI examples
- document supported credential sources and target assumptions
- add Kerberos-specific interop lanes to the matrix
- document the known failure modes people actually hit:
  - SPN mismatch
  - clock skew
  - realm resolution
  - DNS canonicalization surprises

Exit criteria:

- users can discover and use Kerberos without reading source first
- the feature looks intentional and mature on docs.rs and GitHub

## Verification Bar

Kerberos should not merge behind "unit tests pass" only.

Required verification bar:

1. unit tests for token construction, SPN handling, and session-key extraction
2. Windows AD-backed live interop
3. Samba AD-member live interop
4. signed post-auth file operations
5. encrypted post-auth file operations
6. DFS host-change/SPN coverage

For credibility, Smolder should also ship examples and at least one public
guide before calling the feature complete.

## Recognition Track

If the goal is "the SMB equivalent of `russh` recognition", implementation alone
is not enough. The track also needs:

1. first-class docs.rs pages
2. examples people can run
3. a stable public auth API
4. interop receipts against real targets
5. follow-on ecosystem surface

That likely means later companion crates such as:

- `smolder-dcerpc` if RPC usage becomes broad enough
- `smolder-fs` or `smolder-share` if the high-level facade needs its own
  package boundary

Those are later decisions, but the Kerberos design should keep that ecosystem
future open.
