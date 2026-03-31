# Proto Fuzzing

This document describes the current fuzzing entrypoints for `smolder-proto`.

The goal of this layer is narrow:

- hit decode-heavy packet surfaces with libFuzzer
- keep the harness separate from the main workspace
- complement, not replace, the property tests in
  [property_codecs.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-proto/tests/property_codecs.rs)

## Install

```bash
cargo install cargo-fuzz
```

## Targets

The fuzz workspace lives in [fuzz/Cargo.toml](https://github.com/M00NLIG7/smolder/blob/main/fuzz/Cargo.toml).

Current targets:

- `netbios_session_message`
  - exercises RFC1002 session-frame decode
- `rpc_packet`
  - exercises top-level DCE/RPC packet dispatch and decode
- `smb2_decode_surface`
  - exercises the main SMB2 header/body decode surface across negotiate,
    session, tree, create, read, write, ioctl, notify, and lock requests

## Run

From the repo root:

```bash
cargo fuzz run netbios_session_message
cargo fuzz run rpc_packet
cargo fuzz run smb2_decode_surface
```

## Non-fuzz Check

If `cargo-fuzz` is not installed, the harness still compiles as a standalone
crate:

```bash
cargo check --manifest-path fuzz/Cargo.toml --bins
```

## Current Scope

This is intentionally a first fuzzing slice, not a full corpus strategy yet.
The next useful expansions are:

- seed corpora from real SMB/RPC captures
- CI smoke builds for the fuzz targets
- additional encode/decode cross-check targets for create contexts and DFS/RPC
