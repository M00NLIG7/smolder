# Samba Interop

Smolder now has two layers of SMB verification:

- packet-level unit tests in `smolder-proto`
- async session-engine tests in `smolder-core`
- high-level file API tests in `smolder-core`
- CLI smoke tests in `smolder-tools`

This document now includes live interoperability gates against a real Samba server for:

- `NEGOTIATE`
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT`
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> CREATE -> WRITE -> READ -> CLOSE`
- high-level `write` / `read`
- high-level `put` / `get`
- CLI `cat`
- CLI `get`
- CLI `put`

## Why Start With `NEGOTIATE`

`NEGOTIATE` is the first place where wire compatibility becomes real:

- framing must be valid RFC1002
- the SMB2 header must be encoded correctly
- dialect ordering and capability bits must be accepted by Samba
- the response must parse cleanly back into Smolder's typed wire model

The second gate exercises NTLMv2 session setup and confirms that Smolder can bind to a real share.
The third gate exercises basic file I/O over a real handle and keeps the file ephemeral with `DELETE_ON_CLOSE`.
The newer high-level and CLI gates prove that the ergonomic APIs stay honest against the same Samba endpoint.

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

To run the authenticated tree-connect path, also set:

```bash
export SMOLDER_SAMBA_USERNAME=smolder
export SMOLDER_SAMBA_PASSWORD=smolderpass
export SMOLDER_SAMBA_SHARE=share
export SMOLDER_SAMBA_DOMAIN=WORKGROUP
```

## Recommended Local Target

Use a real Samba server, not a mock.

For local development, either:

- point to an existing Samba instance
- run a disposable Samba container or VM configured to listen on port `445`

The repo now includes a pinned Docker Compose target at [docker/samba/compose.yaml](/Users/cmagana/Projects/smolder/docker/samba/compose.yaml) with config in [docker/samba/data/config.yml](/Users/cmagana/Projects/smolder/docker/samba/data/config.yml). It exposes Samba on `127.0.0.1:1445`.

Bring it up with:

```bash
docker compose -f docker/samba/compose.yaml up -d
```

Then point the tests at it:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_SHARE=share \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo test -p smolder-core --test samba_negotiate -- --nocapture
```

Run the high-level API gates with the same environment:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_SHARE=share \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo test -p smolder-core --test samba_high_level -- --nocapture
```

Run the CLI smoke tests:

```bash
SMOLDER_SAMBA_HOST=127.0.0.1 \
SMOLDER_SAMBA_PORT=1445 \
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_SHARE=share \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo test -p smolder-tools --test cli_smoke -- --nocapture
```

You can also drive the CLI manually:

```bash
SMOLDER_SAMBA_USERNAME=smolder \
SMOLDER_SAMBA_PASSWORD=smolderpass \
SMOLDER_SAMBA_DOMAIN=WORKGROUP \
cargo run -p smolder-tools -- \
  cat smb://127.0.0.1:1445/share/example.txt
```

Shut it down with:

```bash
docker compose -f docker/samba/compose.yaml down -v
```

## Current Limits

The live negotiate test currently sends:

- dialects: `SMB 2.1`, `SMB 3.0.2`
- signing mode: enabled
- capabilities: `LARGE_MTU`

`SMB 3.1.1` is intentionally deferred in the live test until negotiate-context handling is hooked up to the rest of the session path, including pre-auth integrity requirements.

## Next External Gates

The current live coverage now reaches:

1. `NEGOTIATE`
2. `SESSION_SETUP`
3. `TREE_CONNECT`
4. `CREATE`
5. `WRITE`
6. `READ`
7. `CLOSE`
8. high-level `write`
9. high-level `read`
10. high-level `put`
11. high-level `get`
12. CLI `cat`
13. CLI `get`
14. CLI `put`

The next practical interop gates are:

1. `QUERY_INFO` / metadata reads
2. `SET_INFO`
3. `RENAME`
4. `DELETE`
5. directory enumeration

After those pass consistently, the next step is wiring a repeatable Samba `selftest` / `smbtorture` harness for the product surface Smolder actually exposes.
