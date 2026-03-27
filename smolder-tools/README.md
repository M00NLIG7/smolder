# smolder

`smolder` is the CLI and high-level workflow package for the Smolder workspace.

The published package name is `smolder`, while the Rust library crate name
remains `smolder_tools`.

It includes SMB file workflows, DFS-aware path handling, reconnect helpers,
`smbexec`, and `psexec`.

Real-project readiness:

- intended for direct CLI and high-level library use within the documented
  `0.1.x` support policy
- file workflows are the more stable surface; operator workflows are supported
  but have a narrower target matrix
- additive API evolution is preferred over churn, even though the project is
  still pre-`1.0`

Start here:

- examples guide:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md>
- cookbook:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/cookbook.md>
- support policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md>
- versioning policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md>

Standalone binaries:

- `smbexec`
- `psexec`
- `smolder-cat`
- `smolder-ls`
- `smolder-stat`
- `smolder-get`
- `smolder-put`
- `smolder-rm`
- `smolder-mv`

`smolder` remains available as a temporary compatibility wrapper for the old
`smolder <subcommand>` entrypoint. It should be removed after repo callers and
external scripts migrate to the standalone binaries.

Project policy and validation:

- support policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md>
- versioning policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md>
- examples guide:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md>

Repository: <https://github.com/M00NLIG7/smolder>
