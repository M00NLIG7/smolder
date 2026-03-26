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
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> CREATE -> WRITE -> FLUSH -> CLOSE -> TREE_DISCONNECT -> LOGOFF`
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> CREATE -> FLUSH -> CLOSE -> TREE_DISCONNECT -> LOGOFF`
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> CREATE(LEASE_V2) -> CLOSE`
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> CREATE -> IOCTL(FSCTL_SRV_REQUEST_RESUME_KEY) -> CLOSE`
- `NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT -> IOCTL(FSCTL_QUERY_NETWORK_INTERFACE_INFO)`
- high-level `open` with lease
- high-level `write` / `read`
- high-level `put` / `get`
- high-level `list` / `stat`
- high-level `rename` / `remove`
- high-level `flush` / `disconnect` / `logoff`
- CLI `cat`
- CLI `get`
- CLI `put`
- CLI `ls`
- CLI `stat`
- CLI `mv`
- CLI `rm`

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
scripts/prepare-samba-fixture.sh
docker compose -f docker/samba/compose.yaml up -d
```

The prep step matters on Linux hosts and GitHub Actions runners: it makes the
bind-mounted share directories writable by the Samba container user so live
`CREATE` tests do not fail with `STATUS_ACCESS_DENIED (0xc0000022)`.

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
cargo test -p smolder-tools --test cli_smoke -- --nocapture --test-threads=1
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

The live negotiate path currently sends:

- dialects: `SMB 2.1`, `SMB 3.0.2`, `SMB 3.1.1`
- signing mode: enabled
- capabilities: `LARGE_MTU`, `LEASING`
- SMB 3.1.1 preauth-integrity negotiate context with `SHA-512`

When Samba selects `SMB 3.1.1`, Smolder now tracks the preauth transcript across `NEGOTIATE` and `SESSION_SETUP`, derives the SMB 3.1.1 signing key from the final session-setup request hash, verifies the final signed `SESSION_SETUP` success response, signs subsequent session and tree/file requests, and verifies signed SMB 3.x responses on the shared post-auth receive path.

The current local Samba fixture accepts lease-aware opens, but it does not consistently grant a lease back under its current policy. The live lease tests therefore verify that lease-aware `CREATE` requests interoperate and only assert the granted lease details when the server actually returns them.

The same local fixture can also reject `FSCTL_LMR_REQUEST_RESILIENCY` and drop durable reopen state after a transport break. The live durable reconnect gate still attempts that flow, but it downgrades those fixture-specific failures to skips instead of treating them as protocol regressions.

## Next External Gates

The current live coverage now reaches:

1. `NEGOTIATE`
2. `SESSION_SETUP`
3. `TREE_CONNECT`
4. `CREATE`
5. `WRITE`
6. `READ`
7. `CLOSE`
8. `FLUSH`
9. `TREE_DISCONNECT`
10. `LOGOFF`
11. `CREATE(LEASE_V2)`
12. high-level `open` with lease
13. `IOCTL(FSCTL_SRV_REQUEST_RESUME_KEY)`
14. `IOCTL(FSCTL_QUERY_NETWORK_INTERFACE_INFO)` when the server advertises multi-channel support
15. high-level `write`
16. high-level `read`
17. high-level `put`
18. high-level `get`
19. high-level `list`
20. high-level `stat`
21. high-level `rename`
22. high-level `remove`
23. high-level `flush`
24. high-level `disconnect`
25. high-level `logoff`
26. CLI `cat`
27. CLI `get`
28. CLI `put`
29. CLI `ls`
30. CLI `stat`
31. CLI `mv`
32. CLI `rm`

The current engine also handles interim async SMB2 responses (`STATUS_PENDING` with `SMB2_FLAGS_ASYNC_COMMAND`) and keeps waiting for the final response on the same message id.

The next practical interop gates are:

1. deeper `QUERY_INFO` coverage beyond basic file metadata
2. stronger SMB 3.x response-signing coverage for more edge cases, including additional async and error paths
3. lease-break handling, lease upgrades/downgrades, and durable-handle create contexts
4. richer `QUERY_INFO` and `SET_INFO` coverage around metadata edge cases
5. broader `IOCTL` coverage beyond `FSCTL_SRV_REQUEST_RESUME_KEY` and `FSCTL_QUERY_NETWORK_INTERFACE_INFO`
6. encryption and negotiate-context expansion beyond preauth integrity

After those pass consistently, the next step is wiring a repeatable Samba `selftest` / `smbtorture` harness for the product surface Smolder actually exposes.
