# Benchmark Harness

This document describes the current microbenchmark harness for Smolder's hot
library paths.

The goal is not to claim absolute throughput numbers across machines. The goal
is to keep a repeatable baseline around the code that is most likely to matter
for real SMB performance:

- `smolder-smb-core` crypto and SMB3 sealing
- `smolder-proto` decode-heavy wire paths

## Current Benches

`smolder-smb-core`:

- `crypto_paths`
  - `derive_encryption_keys`
  - SMB3 encrypt/decrypt for:
    - SMB 3.0.2 `AES-128-CCM`
    - SMB 3.1.1 `AES-128-GCM`
    - SMB 3.1.1 `AES-256-GCM`
  - message sizes:
    - 4 KiB
    - 64 KiB

`smolder-proto`:

- `decode_paths`
  - SMB2 header decode
  - negotiate request decode
  - session setup request decode
  - NetBIOS session frame decode
  - SMB3 transform header decode
  - RPC bind/request packet decode

## Running

Compile the benches:

```bash
cargo check --benches -p smolder-smb-core
cargo check --benches -p smolder-proto
```

Run the core crypto bench:

```bash
cargo bench -p smolder-smb-core --bench crypto_paths
```

Run the proto decode bench:

```bash
cargo bench -p smolder-proto --bench decode_paths
```

Run both:

```bash
cargo bench -p smolder-smb-core --bench crypto_paths
cargo bench -p smolder-proto --bench decode_paths
```

## CI Smoke

The repo now includes a compile-only GitHub Actions smoke workflow at
[bench-smoke.yml](/Users/cmagana/Projects/smolder/.github/workflows/bench-smoke.yml).

It runs:

```bash
cargo check --benches -p smolder-proto
cargo check --benches -p smolder-smb-core
```

This is intentionally a structure/compile gate, not a performance regression
gate. It keeps the benchmark harness healthy without making CI runtime depend on
machine-specific throughput.

## Scope Notes

- These benches intentionally stay on public APIs.
- They are not yet wired into CI as pass/fail performance gates.
- They are a baseline for regression spotting, not a full perf story yet.

The next likely additions are:

- compound-request dispatch throughput in `smolder-smb-core`
- named-pipe / RPC message throughput in `smolder-smb-core`
- larger decode corpora and corpus-driven benchmark inputs in `smolder-proto`
