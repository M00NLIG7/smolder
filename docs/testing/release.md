# Release Verification Checklist

Use this checklist before merging high-risk SMB changes or cutting a release.

This document is intentionally operational. The detailed fixture descriptions
live in:

- [support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md)
- [versioning-policy.md](/Users/cmagana/Projects/smolder/docs/reference/versioning-policy.md)
- [CHANGELOG.md](/Users/cmagana/Projects/smolder/CHANGELOG.md)
- [interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md)
- [samba.md](/Users/cmagana/Projects/smolder/docs/testing/samba.md)
- [windows.md](/Users/cmagana/Projects/smolder/docs/testing/windows.md)

## Release Notes Flow

Before tagging a release:

- update [CHANGELOG.md](/Users/cmagana/Projects/smolder/CHANGELOG.md)
- move `Unreleased` notes into a dated version section
- call out any support-policy or MSRV changes explicitly
- summarize the actual validation gates that were run for that release

When cutting the GitHub release:

- use the matching version section from
  [CHANGELOG.md](/Users/cmagana/Projects/smolder/CHANGELOG.md) as the release
  body baseline
- keep the release text user-facing rather than commit-by-commit
- include any known fixture caveats only when they materially affect the
  release scope

After tagging:

- recreate an empty `Unreleased` section in
  [CHANGELOG.md](/Users/cmagana/Projects/smolder/CHANGELOG.md)

## Baseline Rule

If a change touches any of these areas, run the appropriate gates before merge:

- SMB negotiate / session setup / signing / encryption
- named pipes / `IPC$`
- DCE/RPC
- DFS path resolution
- durable handles / reconnect
- `smbexec` / `psexec`
- high-level file facade or CLI file commands
- SMB over QUIC transport or TLS server-name handling

## Required Gates

### For normal PRs touching core or tools behavior

Required:

- GitHub Actions Samba interop workflow passes:
  - [interop-samba.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-samba.yml)

Recommended local replay:

- `scripts/run-interop.sh --samba --core --tools`

### For changes that affect Windows compatibility

Required before release:

- `scripts/run-windows-release-gate.sh`
- or a green [interop-windows-self-hosted.yml](/Users/cmagana/Projects/smolder/.github/workflows/interop-windows-self-hosted.yml) run on the Tiny11 self-hosted runner

Runner bootstrap and secret setup live in
[windows-runner.md](/Users/cmagana/Projects/smolder/docs/testing/windows-runner.md).

This includes:

- Windows `smolder-core` interop tests
- Windows `smolder-tools` interop tests
- Windows encrypted `IPC$` / named-pipe / RPC coverage
- `smbexec whoami`
- `psexec whoami`

### For SMB over QUIC changes

Required when the `quic` feature or QUIC transport logic changed:

- `cargo test -p smolder-smb-core --features quic --lib`
- a manual QUIC replay against a real Windows Server target:
  - [run-windows-quic-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-windows-quic-interop.sh)
  - [windows-quic.md](/Users/cmagana/Projects/smolder/docs/testing/windows-quic.md)
- optional Samba QUIC replay on a Linux host with `quic.ko`:
  - [run-samba-quic-interop.sh](/Users/cmagana/Projects/smolder/scripts/run-samba-quic-interop.sh)
  - [samba-quic.md](/Users/cmagana/Projects/smolder/docs/testing/samba-quic.md)
  - [samba-quic-utm.md](/Users/cmagana/Projects/smolder/docs/testing/samba-quic-utm.md)

### For DFS changes

Required when DFS path resolution or CLI path handling changed:

- Samba interop workflow
- `scripts/run-windows-release-gate.sh --no-remote-exec`
- Windows DFS gate with `SMOLDER_WINDOWS_DFS_ROOT` configured:
  - `scripts/run-interop.sh --windows --tools`

### For remote execution changes

Required:

- `scripts/run-windows-release-gate.sh`

If the service payload changed too:

- rebuild the payload with `cross`
- rerun the full Windows gate

## Change-Type Matrix

| Change area | Minimum gate |
| --- | --- |
| `smolder-proto` packet/codecs only | Samba interop workflow |
| `smolder-core` auth/session/transport | Samba interop workflow + Windows release gate |
| `smolder-core` QUIC transport | `cargo test -p smolder-smb-core --features quic --lib` + Windows QUIC manual lane, plus Samba QUIC when a Linux QUIC host is available |
| `smolder-core` pipes/RPC | Samba interop workflow + Windows release gate |
| `smolder-tools` file facade / CLI | Samba interop workflow + Windows release gate when Windows behavior could differ |
| `smolder-tools` DFS | Samba interop workflow + Windows tools gate with DFS root configured |
| `smolder-tools` remote exec | Windows release gate |
| `smolder-psexecsvc` payload | Windows release gate after rebuilding payload |

## Expected Output

Healthy release validation should end with:

- Samba interop workflow green
- Windows self-hosted interop workflow green, or an equivalent local Windows release-gate run
- Windows release gate printing:
  - `nt authority\system` for `smbexec`
  - `nt authority\system` for `psexec`
- Windows `windows_rpc_encryption` passing

Known fixture caveats that do not block release on their own:

- local Samba may not grant a lease even when a lease-aware open succeeds
- local Samba may reject the resiliency IOCTL
- local Samba may not preserve durable reopen state after transport drop
- Windows DFS is skipped unless `SMOLDER_WINDOWS_DFS_ROOT` is set
- the Windows `ADMIN$` negative encryption probe skips when the Tiny11 fixture is globally encrypted

## Failure Triage

When a gate fails:

1. Reproduce with the narrowest command from [interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md).
2. Decide whether the failure is:
   - a real protocol regression
   - a fixture limitation already documented
   - a harness/doc mismatch
3. Fix the regression or update the documented fixture boundary.
4. Re-run the full gate, not just the narrow repro, before merging.
