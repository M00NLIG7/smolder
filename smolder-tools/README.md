# smolder

`smolder` is the CLI and high-level workflow package for the Smolder workspace.

The published package name is `smolder`, while the Rust library crate name
remains `smolder_tools`.

It includes SMB file workflows, DFS-aware path handling, reconnect helpers,
`smbexec`, and `psexec`.

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

Repository: <https://github.com/M00NLIG7/smolder>
