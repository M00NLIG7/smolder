# Examples Guide

This guide is the practical entry point for Smolder examples.

It focuses on examples that are:

- compile-checked in the workspace
- aligned with the current `0.1.x` support policy
- backed by real interop where possible

The support contract for these examples lives in
[support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md).

## Core Library Examples

`smolder-smb-core` currently ships these compile-checked examples:

- [ntlm_tree_connect.rs](/Users/cmagana/Projects/smolder/smolder-core/examples/ntlm_tree_connect.rs)
- [named_pipe_rpc_bind.rs](/Users/cmagana/Projects/smolder/smolder-core/examples/named_pipe_rpc_bind.rs)
- [kerberos_tree_connect.rs](/Users/cmagana/Projects/smolder/smolder-core/examples/kerberos_tree_connect.rs)

Build them with:

```bash
cargo build -p smolder-smb-core --examples
```

Build the Kerberos example explicitly:

```bash
cargo build -p smolder-smb-core --features kerberos --example kerberos_tree_connect
```

## Tools Example

`smolder` now ships a compile-checked interactive remote-exec example:

- [interactive_psexec.rs](/Users/cmagana/Projects/smolder/smolder-tools/examples/interactive_psexec.rs)

Build it with:

```bash
cargo build -p smolder --example interactive_psexec
```

### Interactive PsExec Example

This example uses the staged `smolder-psexecsvc.exe` payload and opens a real
interactive shell through a Windows pseudoconsole, so `cmd.exe` and
`powershell.exe` behave like proper console applications instead of plain
redirected pipe processes.

Recommended usage patterns:

- Start directly in the shell you want to use for the whole session.
- Use the default interactive `cmd.exe` shell for the most stable baseline.
- If you want PowerShell, start PowerShell directly with `SMOLDER_PSEXEC_COMMAND=powershell.exe`
  or `--command powershell.exe` instead of entering `cmd.exe` first and then
  launching a nested shell inside it.

Required environment:

```bash
export SMOLDER_WINDOWS_HOST=127.0.0.1
export SMOLDER_WINDOWS_PORT=445
export SMOLDER_WINDOWS_USERNAME='<windows-username>'
export SMOLDER_WINDOWS_PASSWORD='<windows-password>'
export SMOLDER_PSEXEC_SERVICE_BINARY=target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe
```

Optional:

```bash
export SMOLDER_PSEXEC_COMMAND=powershell.exe
```

Run it:

```bash
cargo run -p smolder --example interactive_psexec
```

If `SMOLDER_PSEXEC_COMMAND` is unset or empty, the example starts an
interactive `cmd.exe` shell. If it is set, Smolder starts that command under
the payload's pipe-backed interactive mode.
Type `exit` at the prompt to end the interactive shell cleanly.

### Build the Payload First

For the Tiny11 ARM fixture, build the payload first:

```bash
cross build -p smolder-psexecsvc --target aarch64-pc-windows-gnullvm --release -j 1
```

## CLI Equivalent

The standalone CLI flow for the same interactive path is:

```bash
target/debug/smolder psexec smb://127.0.0.1 \
  --interactive \
  --service-binary target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe \
  --username "$SMOLDER_WINDOWS_USERNAME" \
  --password "$SMOLDER_WINDOWS_PASSWORD"
```

To start `powershell.exe` directly instead of the default `cmd.exe` shell:

```bash
target/debug/smolder psexec smb://127.0.0.1 \
  --interactive \
  --command powershell.exe \
  --service-binary target/aarch64-pc-windows-gnullvm/release/smolder-psexecsvc.exe \
  --username "$SMOLDER_WINDOWS_USERNAME" \
  --password "$SMOLDER_WINDOWS_PASSWORD"
```

## Scope Notes

- The interactive `psexec` example currently depends on the staged
  `smolder-psexecsvc` payload path.
- The example is validated for direct interactive `cmd.exe` and direct
  interactive `powershell.exe` startup. It is not positioned yet as a full
  terminal-emulator replacement with polished nested-shell parity.
- The no-helper `psexec` fallback remains the default one-shot execution path.
- For repeatable validation, prefer the documented Windows gates in
  [windows.md](/Users/cmagana/Projects/smolder/docs/testing/windows.md) and
  [windows-kerberos.md](/Users/cmagana/Projects/smolder/docs/testing/windows-kerberos.md).
