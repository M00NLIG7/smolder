# Smolder Core Library Roadmap

## Objective

Finish the split implied by the current workspace:

- `smolder-proto` owns SMB/DCE-RPC wire types and codecs.
- `smolder-core` owns reusable transport, session, auth, signing, pipe, and RPC primitives.
- `smolder-tools` owns ergonomic workflows, CLI behavior, remote execution, and other operator-facing flows.

The target end state is a safe Rust SMB/RPC library in `smolder-core` plus a thinner `smolder-tools` layer that composes it.

## Invariants

1. Keep `#![forbid(unsafe_code)]` in `smolder-core`, `smolder-proto`, and `smolder-tools`.
2. Do not move remote execution logic back into `smolder-core`.
3. Do not add SMB1 or Kerberos work on this track.
4. Prefer protocol-first changes in `smolder-proto`, then session/transport work in `smolder-core`, then tool adoption in `smolder-tools`.
5. Keep commits atomic and stage only files owned by the current step.

## Current Gaps

- Boundary leak: [smolder-core/src/fs.rs](/Users/cmagana/Projects/smolder/smolder-core/src/fs.rs) still exports `SmbClientBuilder`, `SmbClient`, `Share`, and `RemoteFile`, which are higher-level facades rather than strict primitives.
- Missing SMB2/3 command families: [smolder-proto/src/smb/smb2/mod.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/mod.rs) has negotiate/session/tree/create/io/info/ioctl, but no first-class `LOCK`, `CHANGE_NOTIFY`, `ECHO`, or `CANCEL`.
- Compound engine gap: [smolder-proto/src/smb/smb2/header.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/header.rs) already exposes `next_command`, but [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs) does not yet expose a real compound request engine.
- RPC auth gap: [smolder-proto/src/rpc/mod.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/rpc/mod.rs) currently supports unauthenticated connection-oriented PDUs only.
- Named-pipe gap: named-pipe behavior is embedded indirectly through remote-exec code in [smolder-tools/src/remote_exec.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/remote_exec.rs) instead of being a clean reusable core API.
- Transport feature gap: signing and SMB 3.1.1 preauth already exist in [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs), but encryption/sealing, durable reconnect, and DFS behavior are still missing.

## Dependency Graph

- Step 1 is the boundary cleanup and should land first.
- Step 2 enables Step 3.
- Step 4 enables Steps 5 and 6.
- Step 5 should land before Step 8.
- Step 6 should land before Step 9.
- Step 7 can start after Step 4, but it is lower priority than Steps 2 through 6.
- Step 8 can start after Steps 4 and 5.
- Step 9 is the final gate and should widen coverage across the earlier steps.

## Step 1

Commit title:
`refactor: move high-level SMB facade into smolder-tools`

Why:
`smolder-core` should expose protocol/session primitives, not the ergonomic builder/share/file facade currently centered in `fs.rs`.

Target files:

- [smolder-core/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-core/src/lib.rs)
- [smolder-core/src/fs.rs](/Users/cmagana/Projects/smolder/smolder-core/src/fs.rs)
- [smolder-tools/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/lib.rs)
- [smolder-tools/src/main.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/main.rs)
- `smolder-tools/src/fs.rs` (new)
- [smolder-core/tests/samba_high_level.rs](/Users/cmagana/Projects/smolder/smolder-core/tests/samba_high_level.rs)
- [smolder-tools/tests/cli_smoke.rs](/Users/cmagana/Projects/smolder/smolder-tools/tests/cli_smoke.rs)

Tasks:

- Move `SmbClientBuilder`, `SmbClient`, `Share`, `RemoteFile`, and the higher-level transfer helpers out of `smolder-core`.
- Leave typestate connection/session primitives in `smolder-core`.
- Keep the CLI on `smolder-tools` APIs only.
- Move high-level Samba tests with the facade.

Verification:

- `cargo build -p smolder-core -p smolder-tools`
- `cargo test -p smolder-core`
- `cargo test -p smolder-tools`

Exit criteria:

- `smolder-core::prelude` no longer exports builder/share/file convenience types.
- `smolder-tools` becomes the home of the ergonomic SMB client facade.

## Step 2

Commit title:
`feat(core): add reusable IPC$ and named-pipe primitives`

Why:
`psexec`/`winexe`-style workflows need a real pipe API in core, not ad hoc file/share behavior hidden behind tools code.

Target files:

- [smolder-core/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-core/src/lib.rs)
- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- `smolder-core/src/pipe.rs` (new)
- [smolder-tools/src/remote_exec.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/remote_exec.rs)

Tasks:

- Add first-class `IPC$` connect helpers in core.
- Add named-pipe open/read/write/close primitives around existing SMB `CREATE`, `READ`, `WRITE`, and `IOCTL`.
- Expose a small reusable pipe session type in `smolder-core`.
- Switch remote execution to consume the new pipe API instead of carrying its own low-level pipe flow.

Verification:

- `cargo build -p smolder-core -p smolder-tools`
- `cargo test -p smolder-core`
- `cargo test -p smolder-tools`
- `target/debug/smolder psexec smb://127.0.0.1 --command whoami --username windowsfixture --password windowsfixture`

Exit criteria:

- Remote exec no longer owns raw named-pipe transport details.
- Another tools-layer feature could use pipes without copying code from `remote_exec.rs`.

## Step 3

Commit title:
`feat(proto,core): add authenticated DCE/RPC transport`

Why:
A safe SMB/RPC library is incomplete if authenticated RPC remains tool-specific or unsupported.

Target files:

- [smolder-proto/src/rpc/mod.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/rpc/mod.rs)
- [smolder-core/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-core/src/lib.rs)
- `smolder-core/src/rpc.rs` (new)
- [smolder-tools/src/remote_exec.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/remote_exec.rs)

Tasks:

- Add auth trailer types and codec support to `smolder-proto`.
- Add a reusable pipe-backed RPC transport in `smolder-core`.
- Support authenticated bind/request/response flows needed for SCMR and future pipe services.
- Move SCMR bind/request plumbing in tools to the new reusable transport.

Verification:

- `cargo build -p smolder-proto -p smolder-core -p smolder-tools`
- `cargo test -p smolder-proto`
- `cargo test -p smolder-core`
- `cargo test -p smolder-tools`
- `target/debug/smolder psexec smb://127.0.0.1 --command hostname --username windowsfixture --password windowsfixture`

Exit criteria:

- `smolder-proto` can encode/decode authenticated DCE/RPC PDUs.
- `smolder-tools` no longer needs bespoke RPC framing logic.

## Step 4

Commit title:
`feat(proto): add missing SMB2 command families and durable create contexts`

Why:
The wire layer still lacks several core SMB2/3 command families and durable-handle context types needed for a serious client library.

Target files:

- [smolder-proto/src/smb/smb2/mod.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/mod.rs)
- `smolder-proto/src/smb/smb2/lock.rs` (new)
- `smolder-proto/src/smb/smb2/notify.rs` (new)
- `smolder-proto/src/smb/smb2/echo.rs` (new)
- `smolder-proto/src/smb/smb2/cancel.rs` (new)
- [smolder-proto/src/smb/smb2/create.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/create.rs)
- [smolder-proto/src/smb/smb2/header.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/header.rs)

Tasks:

- Add typed request/response bodies for `LOCK`, `CHANGE_NOTIFY`, `ECHO`, and `CANCEL`.
- Add create-context types for durable/resilient/persistent handle requests and reconnect flows.
- Extend command enums and packet validation tests accordingly.

Verification:

- `cargo build -p smolder-proto`
- `cargo test -p smolder-proto`

Exit criteria:

- The wire crate can represent the missing command families and handle contexts without raw byte patches in higher layers.

## Step 5

Commit title:
`feat(core): add compound requests and credit-aware dispatch`

Why:
The header already carries `next_command`, but the client still behaves like a single-request transaction engine.

Target files:

- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- `smolder-core/src/dispatcher.rs` (new, optional)
- [smolder-core/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-core/src/lib.rs)

Tasks:

- Add a reusable compound request builder/executor.
- Track credits explicitly and validate server credit grants.
- Handle related operations, async IDs, and interim responses cleanly.
- Keep signing and preauth transcript handling correct across compound chains.

Verification:

- `cargo build -p smolder-core`
- `cargo test -p smolder-core`

Exit criteria:

- Core can issue and parse multi-command chains without tool-specific packet stitching.

## Step 6

Commit title:
`feat(core): add durable and resilient handle reconnect`

Why:
The current client can open handles, but it does not yet provide the reconnect semantics expected from a production SMB2/3 library.

Target files:

- [smolder-proto/src/smb/smb2/create.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/smb2/create.rs)
- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- `smolder-core/tests/durable_handles.rs` (new)
- [smolder-tools/src/fs.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/fs.rs)

Tasks:

- Add durable/resilient reopen flows on reconnect.
- Preserve enough session and file state in core to rebind handles safely.
- Teach the high-level file facade in tools to opt into durable semantics where appropriate.

Verification:

- `cargo build -p smolder-core -p smolder-tools`
- `cargo test -p smolder-core`
- `cargo test -p smolder-tools`

Exit criteria:

- A broken transport no longer implies lost handle state for the supported durable path.

## Step 7

Commit title:
`feat(proto,core): add SMB3 encryption and sealing`

Why:
Signing is implemented, but a modern SMB library also needs message encryption for the SMB 3.x path.

Target files:

- `smolder-proto/src/smb/transform.rs` (new)
- [smolder-proto/src/smb/mod.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/smb/mod.rs)
- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- `smolder-core/src/crypto.rs` (new, optional)

Tasks:

- Add SMB transform-header wire support in `smolder-proto`.
- Derive and manage encryption keys in `smolder-core`.
- Encrypt and decrypt request/response payloads when negotiated and required.

Verification:

- `cargo build -p smolder-proto -p smolder-core`
- `cargo test -p smolder-proto`
- `cargo test -p smolder-core`

Exit criteria:

- Core can run the negotiated encrypted path without exposing crypto details to tools code.

## Step 8

Commit title:
`feat(core): add DFS referrals and UNC resolution behavior`

Why:
The wire layer already understands DFS-related bits, but the library does not yet behave like a DFS-aware SMB client.

Target files:

- [smolder-core/src/client.rs](/Users/cmagana/Projects/smolder/smolder-core/src/client.rs)
- `smolder-core/src/dfs.rs` (new)
- [smolder-tools/src/fs.rs](/Users/cmagana/Projects/smolder/smolder-tools/src/fs.rs)

Tasks:

- Add DFS referral resolution and normalization rules.
- Route UNC paths through DFS-aware share resolution.
- Keep the policy in core and the ergonomic path handling in tools.

Verification:

- `cargo build -p smolder-core -p smolder-tools`
- `cargo test -p smolder-core`
- `cargo test -p smolder-tools`

Exit criteria:

- DFS behavior is implemented as library functionality rather than being left to callers.

## Step 9

Commit title:
`test: establish the smb core interoperability matrix`

Why:
The earlier steps are not complete until they are exercised against real targets and regression fixtures.

Target files:

- [README.md](/Users/cmagana/Projects/smolder/README.md)
- `docs/testing/interop.md` (new)
- [smolder-core/tests/samba_negotiate.rs](/Users/cmagana/Projects/smolder/smolder-core/tests/samba_negotiate.rs)
- `smolder-core/tests/windows_interop.rs` (new)
- `smolder-core/tests/named_pipe_interop.rs` (new)
- `smolder-core/tests/rpc_interop.rs` (new)

Tasks:

- Document the supported interop matrix by feature and target.
- Add opt-in live tests for Samba and Windows covering auth, files, pipes, RPC, reconnect, and execution prerequisites.
- Preserve regression fixtures for packet and transcript-level cases where live tests are too expensive.

Verification:

- `cargo build`
- `cargo test -p smolder-proto`
- `cargo test -p smolder-core`
- `cargo test -p smolder-tools`
- `target/debug/smolder smbexec smb://127.0.0.1 --command whoami --username windowsfixture --password windowsfixture`
- `target/debug/smolder psexec smb://127.0.0.1 --command whoami --username windowsfixture --password windowsfixture`

Exit criteria:

- The project has an explicit compatibility matrix and repeatable live verification commands.

## Suggested Execution Order

1. Step 1
2. Step 2
3. Step 3
4. Step 4
5. Step 5
6. Step 6
7. Step 8
8. Step 7
9. Step 9

Reasoning:

- Steps 1 through 3 make the crate boundary real and unlock the `psexec`/`winexe`-style model.
- Steps 4 through 6 fill the most important missing SMB library semantics.
- Step 8 matters for a serious client surface, but it should not block pipe/RPC fundamentals.
- Step 7 is important, but lower priority than the reconnection and pipe/RPC work needed by current tooling.

## Mutation Protocol

If a step turns out to be too large for one atomic commit:

1. Split only that step into `part 1` and `part 2`.
2. Preserve the same boundary and verification goals.
3. Do not pull later-scope work forward just because the touched files overlap.

If Step 1 reveals that some file APIs truly belong in `smolder-core`:

- Keep only low-level open/read/write/query/close primitives in core.
- Move builder/session/share/file convenience wrappers to tools.
- Update this roadmap before starting Step 2.
