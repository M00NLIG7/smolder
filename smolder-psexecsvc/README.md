# smolder-psexecsvc

`smolder-psexecsvc` is the Windows service payload used by Smolder's `psexec`
mode.

It is published as a separate crate because it is a target-side Windows service
artifact rather than part of the host-side CLI.

Most users should not depend on this crate directly. If you want host-side
remote execution or SMB file workflows, use `smolder` instead.

Use this crate when you need:

- the payload-side argument parser used by the staged `psexec` helper
- the pipe-name derivation and payload request model for interactive sessions
- a small auditable Windows service payload surface

Start here:

- crate docs: [smolder-psexecsvc/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-psexecsvc/src/lib.rs)
- Windows fixture docs:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/testing/windows.md>
- interactive `psexec` usage guide:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md>

Repository: <https://github.com/M00NLIG7/smolder>
