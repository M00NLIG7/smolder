# Smolder Library And Security Expansion Roadmap

## Objective

Make Smolder better than `smb-rs` in two dimensions at the same time:

- a stronger general-purpose Rust SMB library
- a stronger Rust SMB/RPC security toolkit

This track keeps `smolder-smb-core` as the reusable engine and `smolder` as the
operator-facing layer. The goal is not to collapse those boundaries. The goal
is to make the core easier to embed while expanding the security surface on top
of it.

## Invariants

1. Keep `smolder-proto`, `smolder-smb-core`, and `smolder` `unsafe`-free.
2. Keep remote-exec orchestration in `smolder`, not in `smolder-smb-core`.
3. Prefer additive public APIs over churn in the published `0.2.x` line.
4. Land protocol-first work in `smolder-proto`, transport/session work in
   `smolder-smb-core`, then adoption in `smolder`.
5. Defer SMB1 until the milestones in this roadmap are complete or clearly
   blocked.

## Why This Track Exists

Right now Smolder already wins the security-operator comparison on:

- `psexec`
- `smbexec`
- named-pipe RPC
- DFS
- durable reconnect
- Windows/Samba/Kerberos interop

But `smb-rs` still has the stronger generic-library story because it exposes a
clear high-level client API, covers more transport/protocol breadth, and feels
easier to embed into non-security applications.

This roadmap closes that gap without giving up Smolder's security advantage.

## Scope

This roadmap covers these milestones, in order:

1. High-level client facade in `smolder-smb-core`
2. SMB compression
3. `SRVSVC` + `SAMR` + `LSARPC`
4. QUIC
5. full Samba `selftest` lane
6. stronger Windows automation

Explicitly deferred:

- SMB1
- RDMA
- multichannel as a top-priority feature

## Dependency Graph

- Steps 1-3 build the new high-level library facade.
- Steps 4-5 add SMB compression wire support and session integration.
- Steps 6-8 add typed RPC interface clients on top of the existing pipe/RPC
  core.
- Step 9 adds QUIC once the facade and session shape are stable enough to reuse
  with another transport.
- Step 10 adds Samba `selftest` / `smbtorture` automation.
- Step 11 strengthens Windows automation after the new library/security surface
  exists.
- SMB1 is a post-roadmap decision, not a hidden dependency.

## Step 1

Commit title:
`feat(core): add high-level client builder and session facade`

Context brief:
`smolder-smb-core` has strong primitives but no first-class embedded client
entry point. New consumers should not need to compose `Connection`,
`SmbSessionConfig`, and DFS/session logic manually for simple file or pipe
workflows.

Target files:

- `smolder-core/src/facade.rs` (new)
- [smolder-core/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-core/src/lib.rs)
- [smolder-core/src/pipe.rs](/Users/cmagana/Projects/smolder/smolder-core/src/pipe.rs)
- [smolder-core/README.md](/Users/cmagana/Projects/smolder/smolder-core/README.md)

Tasks:

- Add a high-level `ClientBuilder` and `Client` facade in core.
- Support NTLM and Kerberos configuration without moving operator behavior into
  the facade.
- Reuse the existing connection/session primitives internally instead of
  rewriting them.
- Keep the facade additive and clearly separate from the low-level typestate
  API.

Verification:

- `cargo test -p smolder-smb-core --lib`
- `cargo build -p smolder-smb-core --examples`

Exit criteria:

- A downstream user can connect and authenticate without manually composing raw
  session setup flow.

## Step 2

Commit title:
`feat(core): add share-level file facade on top of the client`

Context brief:
The first facade step is not enough if consumers still need to manually stitch
`CREATE` / `READ` / `WRITE` / `CLOSE` flows for common file operations.

Target files:

- `smolder-core/src/facade.rs`
- `smolder-core/examples/client_file_roundtrip.rs` (new)
- [docs/reference/smolder-core-api.md](/Users/cmagana/Projects/smolder/docs/reference/smolder-core-api.md)

Tasks:

- Add a share/session wrapper for open/read/write/remove/stat workflows.
- Keep explicit access to low-level handles for expert consumers.
- Reuse existing durable/reconnect support where it fits instead of creating a
  second reconnect model.

Verification:

- `cargo test -p smolder-smb-core --lib`
- `cargo build -p smolder-smb-core --example client_file_roundtrip`

Exit criteria:

- `smolder-smb-core` has a credible embedded-client story for common SMB file
  use cases.

## Step 3

Commit title:
`feat(core): add facade support for named pipes and RPC`

Context brief:
If the high-level client only covers file I/O, `smb-rs` remains the cleaner
general client while Smolder's pipe/RPC power stays hidden behind low-level
types.

Target files:

- `smolder-core/src/facade.rs`
- [smolder-core/src/rpc.rs](/Users/cmagana/Projects/smolder/smolder-core/src/rpc.rs)
- `smolder-core/examples/client_rpc_bind.rs` (new)

Tasks:

- Add high-level `connect_pipe` / `bind_rpc` style facade methods.
- Preserve `NamedPipe` and `PipeRpcClient` as the expert-oriented lower layer.
- Keep the surface additive and avoid remote-exec-specific behavior.

Verification:

- `cargo test -p smolder-smb-core --lib`
- `cargo build -p smolder-smb-core --example client_rpc_bind`

Exit criteria:

- The new client facade covers file and pipe/RPC workflows, not just files.

## Step 4

Commit title:
`feat(proto): add SMB compression wire types and negotiate contexts`

Context brief:
Compression is a real protocol-breadth gap versus `smb-rs`. The wire layer has
to own this first so session code does not guess at packet shapes.

Target files:

- `smolder-proto/src/smb/compression.rs` (new)
- [smolder-proto/src/smb/mod.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/mod.rs)
- [smolder-proto/src/smb/smb2/negotiate.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/negotiate.rs)

Tasks:

- Add SMB compression transform/header types and codecs.
- Add negotiate contexts for compression capabilities.
- Start with decode/encode for the algorithms Windows/Samba actually negotiate.

Verification:

- `cargo test -p smolder-proto`

Exit criteria:

- The wire crate can represent negotiated compression cleanly.

## Step 5

Commit title:
`feat(core): negotiate and apply SMB compression`

Context brief:
Wire support is not enough; the client has to negotiate, compress outbound
traffic when appropriate, and safely decode compressed responses.

Target files:

- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- [smolder-core/src/crypto.rs](/Users/cmagana/Projects/smolder/smolder-core/src/crypto.rs)
- `smolder-core/tests/windows_compression.rs` (new)
- `smolder-core/tests/samba_compression.rs` (new)

Tasks:

- Negotiate compression capabilities.
- Add request/response compression handling in the dispatch path.
- Validate interaction with signing and encryption order.

Verification:

- `cargo test -p smolder-smb-core`
- live Windows/Samba compression tests when fixtures support them

Exit criteria:

- Compression becomes part of the supported core SMB session path.

## Step 6

Commit title:
`feat(rpc): add typed SRVSVC client and share/session enumeration`

Context brief:
`SRVSVC` is the best first interface after raw RPC transport because it is
useful for both general library users and security workflows.

Target files:

- `smolder-proto/src/rpc/srvsvc.rs` (new)
- `smolder-core/src/rpc/srvsvc.rs` (new)
- [smolder-tools/src/remote_exec.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/remote_exec.rs)
- docs/examples for enumeration

Tasks:

- Add typed `SRVSVC` stubs for practical enumeration calls.
- Expose them through reusable core RPC clients.
- Add at least one library example and one operator-facing enumeration command
  or helper.

Verification:

- `cargo test -p smolder-proto`
- `cargo test -p smolder-smb-core`
- live Windows/Samba `srvsvc` interop

Exit criteria:

- Smolder exposes more than SCMR on its typed RPC surface.

## Step 7

Commit title:
`feat(rpc): add typed SAMR client`

Context brief:
`SAMR` is one of the clearest “security toolkit” differentiators and a major
step toward Impacket-class account/domain operations.

Target files:

- `smolder-proto/src/rpc/samr.rs` (new)
- `smolder-core/src/rpc/samr.rs` (new)
- tools docs/examples or commands as needed

Tasks:

- Add typed SAMR request/response models for the first useful enumeration and
  lookup workflows.
- Expose a reusable core client API rather than burying it in CLI code.

Verification:

- `cargo test -p smolder-proto`
- `cargo test -p smolder-smb-core`
- live Windows SAMR interop

Exit criteria:

- Smolder gains a meaningful typed account/domain RPC surface.

## Step 8

Commit title:
`feat(rpc): add typed LSARPC client`

Context brief:
`LSARPC` rounds out the first serious RPC trio and makes the security story much
stronger than “SMB plus remote exec.”

Target files:

- `smolder-proto/src/rpc/lsarpc.rs` (new)
- `smolder-core/src/rpc/lsarpc.rs` (new)
- docs/examples or tools integration as needed

Tasks:

- Add typed LSARPC request/response coverage for practical policy and SID/LSA
  lookup workflows.
- Reuse the same RPC client conventions as `SRVSVC` and `SAMR`.

Verification:

- `cargo test -p smolder-proto`
- `cargo test -p smolder-smb-core`
- live Windows LSARPC interop

Exit criteria:

- The core RPC story expands from transport to a reusable interface suite.

## Step 9

Commit title:
`feat(core): add QUIC transport support`

Context brief:
QUIC is the biggest modern transport gap versus a top-tier SMB library. It
should land only after the facade shape is stable enough to reuse with another
transport backend.

Target files:

- `smolder-core/src/transport/quic.rs` (new)
- [smolder-core/src/transport.rs](/Users/cmagana/Projects/smolder/smolder-core/src/transport.rs)
- [smolder-core/Cargo.toml](/Users/cmagana/Projects/smolder/smolder-core/Cargo.toml)

Tasks:

- Add a feature-gated QUIC transport backend.
- Reuse the existing transport trait rather than forking connection logic.
- Add smoke coverage against a real QUIC-capable target or a documented fixture.

Verification:

- `cargo test -p smolder-smb-core --features quic`
- targeted QUIC interop checks

Exit criteria:

- Smolder supports a modern transport path beyond plain TCP.

## Step 10

Commit title:
`test(samba): add full selftest lane for supported product surface`

Context brief:
Interop today is strong but narrower than Samba's own validation ecosystem.
`selftest` is the right next confidence layer for protocol reputation.

Target files:

- `docker/samba-selftest/` (new, if needed)
- `scripts/run-samba-selftest.sh` (new)
- `.github/workflows/interop-samba.yml`
- docs under `docs/testing/`

Tasks:

- Add a repeatable Samba `selftest` / `smbtorture` lane for the surfaces
  Smolder claims to support.
- Start targeted, not exhaustive: file I/O, encryption, pipes/RPC, reconnect,
  and compression once implemented.

Verification:

- targeted `selftest` jobs pass locally and in CI

Exit criteria:

- Samba parity is backed by Samba's own test tooling, not only custom harnesses.

## Step 11

Commit title:
`ci(windows): strengthen automated Windows interop and Kerberos gates`

Context brief:
The current Windows gate works, but it is still operationally heavier than the
Samba side. That limits confidence and slows releases.

Target files:

- `.github/workflows/interop-windows-self-hosted.yml`
- `scripts/run-windows-release-gate.sh`
- `scripts/run-windows-kerberos-interop.sh`
- docs under `docs/testing/`

Tasks:

- Expand the self-hosted Windows workflow to cover the new facade,
  compression, and RPC interface lanes.
- Reduce manual steps in the Tiny11 path where possible.
- Keep Windows release validation aligned with the public support policy.

Verification:

- self-hosted Windows workflow green for the documented release gate

Exit criteria:

- Windows automation stops being the main credibility gap after core feature
  expansion.

## Deferred Decision: SMB1

Only revisit SMB1 after this roadmap lands or clearly stalls.

Decision criteria:

- whether SMB1 expands real user adoption instead of just maintenance burden
- whether it fits the static-friendly, safe-library direction of the project
- whether it distracts from modern SMB library and RPC/security reputation

Until then, keep SMB1 out of the active implementation queue.

## Mutation Protocol

Allowed plan changes:

- split a step if it becomes too large for one reviewable PR
- insert a prerequisite if a step exposes a missing abstraction
- reorder later milestones if QUIC or `selftest` fixture work proves to be
  operationally blocked

Rules:

- do not pull SMB1 forward without an explicit decision
- do not weaken the `smolder-smb-core` / `smolder` boundary to land security
  features faster
- preserve additive public API bias unless a clearly wrong design forces a
  break
