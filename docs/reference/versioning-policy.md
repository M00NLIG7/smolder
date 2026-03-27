# Smolder MSRV and Versioning Policy

This document defines the current MSRV and semver rules for the published
workspace crates:

- `smolder-proto`
- `smolder-smb-core`
- `smolder`
- `smolder-psexecsvc`

It is the release-discipline companion to
[support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md).

## Current MSRV

The current minimum supported Rust version is:

- `1.85`

This is now pinned in each published crate manifest through `rust-version =
"1.85"`.

Why `1.85`:

- the workspace currently vendors `kenobi-unix`, which uses Rust 2024 edition
  support
- the workspace has been verified with:
  - `cargo +1.85.0 check -p smolder-proto`
  - `cargo +1.85.0 check -p smolder-smb-core`
  - `cargo +1.85.0 check -p smolder`
  - `cargo +1.85.0 check -p smolder-psexecsvc`

The MSRV is a release promise for the published crates, not a best-effort guess.

## MSRV Rules

- Raising the MSRV is a breaking change in practice and must be treated as one.
- Do not raise the MSRV casually because of style-only standard-library helpers
  or tooling drift.
- Prefer small compatibility fixes over unnecessary MSRV increases when the
  lower floor is still reasonable.
- If a dependency forces a higher floor, document the reason in the changelog
  and this policy file.

For `0.2.x`, the intent is to keep the MSRV stable unless there is a clear
release-quality reason to move it.

## Semver Rules for `0.2.x`

The project is still pre-`1.0`, but published crates should no longer behave as
if every release is unconstrained.

Practical interpretation:

- being pre-`1.0` does not mean "expect random API breakage"
- downstream users should expect small additive releases by default
- when supported public behavior must change, the release should make that
  obvious and give users a clear migration expectation

### Patch releases

Use patch releases for:

- bug fixes
- interop fixes
- test/doc improvements
- additive internal implementation work that does not alter supported public
  behavior
- additive feature-gated behavior that does not change the stable default API
  surface

### Minor releases

Use minor releases for:

- deliberate public API changes
- behavior changes to documented supported flows
- MSRV raises
- feature-surface reshaping that downstream users need to react to
- support-policy changes that narrow or materially redefine guarantees

### What counts as breaking here

For the published `0.2.x` line, treat these as breaking even before `1.0`:

- removing or renaming documented public entry points
- changing the meaning of stable feature flags
- raising the MSRV
- changing CLI behavior in a way that breaks documented workflows
- narrowing the supported target/auth/encryption matrix from
  [support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md)

## Feature-Flag Policy

- `kerberos` is the stable documented feature surface.
- `kerberos-gssapi` is an additive backend path and explicit native-linking
  exception.
- backend expansion should preserve the top-level auth API unless there is a
  strong reason to do otherwise.

New features should default to additive introduction behind feature flags or
new APIs rather than churn on the existing stable path.

## Release Process Hooks

Before release:

- the required gates from
  [release.md](/Users/cmagana/Projects/smolder/docs/testing/release.md) must be
  green
- if the release changes compatibility, update:
  - this file
  - [support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md)
  - release notes / changelog

## Practical Rule

If a change would make a downstream user say "I need to change toolchain,
feature flags, API calls, or operational expectations," then it should be
treated as a minor-release change, not a silent patch bump.
