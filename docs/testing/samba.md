# Samba Interop

Smolder now has two layers of SMB verification:

- packet-level unit tests in `smolder-proto`
- async session-engine tests in `smolder-core`

This document adds the first live interoperability gate against a real Samba server: `NEGOTIATE`.

## Why Start With `NEGOTIATE`

`NEGOTIATE` is the first place where wire compatibility becomes real:

- framing must be valid RFC1002
- the SMB2 header must be encoded correctly
- dialect ordering and capability bits must be accepted by Samba
- the response must parse cleanly back into Smolder's typed wire model

This gate is intentionally narrow. Session setup and authentication are not wired up yet, so the live test stops before `SESSION_SETUP`.

## Running The Live Test

Set the target endpoint:

```bash
export SMOLDER_SAMBA_HOST=127.0.0.1
export SMOLDER_SAMBA_PORT=445
```

Then run:

```bash
cargo test -p smolder-core --test samba_negotiate -- --nocapture
```

If `SMOLDER_SAMBA_HOST` is unset, the test exits early and reports that it was skipped.

## Recommended Local Target

Use a real Samba server, not a mock. The test only needs a TCP listener that speaks SMB2 and accepts `NEGOTIATE`.

For local development, either:

- point to an existing Samba instance
- run a disposable Samba container or VM configured to listen on port `445`

## Current Limits

The live negotiate test currently sends:

- dialects: `SMB 2.1`, `SMB 3.0.2`
- signing mode: enabled
- capabilities: `LARGE_MTU`

`SMB 3.1.1` is intentionally deferred in the live test until negotiate-context handling is hooked up to the rest of the session path, including pre-auth integrity requirements.

## Next External Gates

Once authentication is implemented, add live tests in this order:

1. `SESSION_SETUP`
2. `TREE_CONNECT`
3. `CREATE`
4. `CLOSE`

After those pass consistently, the next step is wiring a repeatable Samba `selftest` / `smbtorture` harness for the product surface Smolder actually exposes.
