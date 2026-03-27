# Remote Exec

Remote execution lives in `smolder`, not `smolder-smb-core`.

That boundary is intentional:

- `smolder-smb-core` owns SMB, named pipes, RPC, auth, and reconnect primitives
- `smolder` owns `smbexec`, `psexec`, staging, SCM orchestration, and shell UX

## Stable Paths

Today the stable remote-exec paths are:

- one-shot `smbexec`
- one-shot `psexec`
- interactive `psexec` with the staged `smolder-psexecsvc` payload

The interactive example is documented as:

- stable for direct `cmd.exe`
- stable for direct `powershell.exe`
- not yet a promise of polished nested-shell parity

## Interactive Example

Use the shipped tools example:

- [interactive_psexec.rs](/Users/cmagana/Projects/smolder/smolder-tools/examples/interactive_psexec.rs)

or the direct CLI equivalent from:

- [examples.md](/Users/cmagana/Projects/smolder/docs/guide/examples.md)

## Validation And Policy

The remote-exec validation story lives in:

- [windows.md](/Users/cmagana/Projects/smolder/docs/testing/windows.md)
- [windows-kerberos.md](/Users/cmagana/Projects/smolder/docs/testing/windows-kerberos.md)
- [interop.md](/Users/cmagana/Projects/smolder/docs/testing/interop.md)

If a feature depends on shell behavior, SCM semantics, or execution UX, it
should stay documented and implemented in the tools layer rather than being
backfilled into `smolder-smb-core`.
