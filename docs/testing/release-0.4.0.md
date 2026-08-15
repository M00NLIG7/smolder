# Smolder `0.4.0` Release Candidate Record

This record is the operator handoff for the public `0.4.0` crate set. It does
not authorize publishing, tagging, creating a GitHub release, or merging the
release PR.

## Immutable Release Contract

Source destination:

- <https://github.com/M00NLIG7/smolder>
- default branch: `main`
- hardened preparation base: `b400688a772e87d8e7a0c92f4fcdc10c2d052e59`

The public crate set and publication order are exactly:

1. `smolder-proto 0.4.0`
2. `smolder-smb-core 0.4.0`, depending on `smolder-proto = "=0.4.0"`
3. `smolder 0.4.0`, depending on both internal packages at `"=0.4.0"`

`smolder-psexecsvc` is excluded. It remains at `0.3.0`; do not package,
publish, or tag a `0.4.0` version of it.

The release commit must be authored and committed by:

```text
M00NLIG7 <57321738+M00NLIG7@users.noreply.github.com>
```

Verify the effective identity before the release-preparation commit and again
immediately before any later publication:

```bash
test "$(git config user.name)" = M00NLIG7
test "$(git config user.email)" = 57321738+M00NLIG7@users.noreply.github.com
git log -1 --format='%an <%ae>%n%cn <%ce>'
```

## Candidate Archive Gate

Run from a clean tracked checkout with the committed `Cargo.lock` and the
pinned Rust `1.85.0` toolchain:

```bash
cargo +1.85.0 fetch --locked
scripts/test-package-consumer.sh
```

The script prepares packages in publication order. Before crates.io has the new
versions, it installs each lower-level candidate into a Cargo directory source
that replaces crates.io while preserving registry source identity and archive
checksums. This allows every `cargo package` invocation to remain `--locked
--offline` and lets dependent archive lockfiles resolve the exact lower-level
candidate rather than an older registry release or a workspace path.

The gate then:

- accepts only the three expected `.crate` files and rejects a
  `smolder-psexecsvc` archive
- rejects unsafe archive members, credential-like files, high-confidence token
  material, and workstation-local absolute paths
- verifies clean Git provenance against the checked-out commit
- verifies package name/version, Rust version, MIT license declaration, README,
  docs.rs URL, and `https://github.com/M00NLIG7/smolder` repository metadata
- parses normalized manifests and rejects local-path or non-crates.io registry
  dependencies
- verifies exact internal requirements and confirms each dependent archive's
  lockfile selects the preceding candidate archive checksum
- compiles all targets shipped by each exact extracted archive, including the
  top-level `smolder` binaries and examples
- resolves a fresh consumer whose manifest contains only registry-shaped exact
  requirements for `smolder`, `smolder-smb-core`, and `smolder-proto`
- independently checks the default, Kerberos backend, QUIC, and dangerous NTLM
  diagnostics feature shapes where they apply

Generated evidence is intentionally untracked:

```text
target/release-candidate-0.4.0/archives/*.crate
target/release-candidate-0.4.0/SHA256SUMS
target/release-candidate-0.4.0/evidence.json
```

Do not commit a candidate checksum into a file that is itself packaged: another
commit changes `.cargo_vcs_info.json` and therefore changes the archive bytes.
Attach the output for the final PR head to the PR evidence, and regenerate it
from the exact later publication commit before uploading.

## Deterministic and Supply-Chain Gates

The authoritative deterministic matrix is
[verify.yml](https://github.com/M00NLIG7/smolder/blob/main/.github/workflows/verify.yml).
A release candidate must pass:

```bash
cargo +1.85.0 fmt --all -- --check
cargo +1.85.0 check --workspace --all-targets --all-features --locked
cargo +1.85.0 clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.85.0 test --workspace --all-targets --all-features --locked
cargo +1.85.0 test --workspace --lib --all-features --release --locked
PROPTEST_CASES=4096 cargo +1.85.0 test -p smolder-proto --test property_codecs --locked
RUSTDOCFLAGS='-D warnings' cargo +1.85.0 doc --workspace --all-features --no-deps --locked
cargo audit --no-fetch --stale
cargo deny --offline check advisories sources licenses
scripts/test-package-consumer.sh
```

Record the local RustSec advisory database commit and timestamp with the audit
result. `--stale` means the result is bounded by that local snapshot; it is not
evidence that a network refresh occurred.

The GitHub PR must also be green for every check registered by the repository,
including the pinned-MSRV host matrix, all configured cross targets, bench
smoke, package consumer, and Samba interop workflow.

## Live Surface Evidence and Limitations

Ignored tests are not live passes. Use the explicit fixture workflows described
in [interop.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/interop.md)
and record a URL or exact command/result for each lane actually run.

| Surface | Release evidence | What must not be inferred |
| --- | --- | --- |
| Samba SMB/RPC/tools | Green `interop-samba.yml` run for the release PR | Ordinary unit tests do not establish a Samba pass |
| Windows SMB/RPC and remote execution | Green `interop-windows-self-hosted.yml` dispatch for the candidate, or the exact local `scripts/run-windows-release-gate.sh` output including both `whoami` checks | A missing runner, secrets, VM, or ignored test is not a pass |
| QUIC deterministic surface | `cargo test -p smolder-smb-core --features quic --lib --locked` plus the normal all-feature matrix | This is not live Windows or Samba QUIC interoperability |
| Windows QUIC | Explicit `scripts/run-windows-quic-interop.sh` replay against a certificate-configured Windows Server | Unavailable credentials/server must be recorded as unavailable |
| Samba QUIC | Explicit `scripts/run-samba-quic-interop.sh` replay on a Linux host with `quic.ko` | A host without kernel QUIC support is not a pass |
| Samba AD / Windows Kerberos | Explicit Kerberos fixture scripts when credentials and fixtures are configured | Feature compilation alone is not live Kerberos auth |

The release PR is the evidence ledger for exact run URLs, archive SHA-256
values, advisory snapshot age, and unavailable external lanes. Do not replace a
limitation with an unqualified green statement.

## Later Publication Procedure

Only a separately authorized operator may publish. Start from the exact,
reviewed release commit in a clean checkout. Re-run all deterministic,
supply-chain, and archive gates, compare the regenerated SHA-256 values with the
approved PR evidence, and verify identity again. Do not access or print the
registry token during verification.

For each package below, publish only that package with `--locked`, then wait
until the exact version is visible through the public crates.io API and the
registry archive checksum matches the approved candidate **before** proceeding:

```bash
# 1. Publish smolder-proto 0.4.0, then wait and verify.
cargo +1.85.0 publish --locked -p smolder-proto

# 2. Only after proto visibility/checksum verification.
cargo +1.85.0 publish --locked -p smolder-smb-core

# 3. Only after core visibility/checksum verification.
cargo +1.85.0 publish --locked -p smolder
```

For each step, query the public version record and download endpoint (replace
`PACKAGE`):

```bash
curl -fsSL "https://crates.io/api/v1/crates/PACKAGE/0.4.0"
curl -fsSL "https://crates.io/api/v1/crates/PACKAGE/0.4.0/download" \
  -o "/tmp/PACKAGE-0.4.0.crate"
shasum -a 256 "/tmp/PACKAGE-0.4.0.crate"
```

Compare both the API checksum and downloaded archive SHA-256 with
`target/release-candidate-0.4.0/SHA256SUMS`. Stop on a mismatch or while the
version is not yet visible; do not publish the dependent package speculatively.

After all three checksums are confirmed, prove the public consumer shape from a
fresh directory without a path or patch override:

```bash
cargo +1.85.0 new --lib /tmp/smolder-0.4.0-consumer
cd /tmp/smolder-0.4.0-consumer
cargo +1.85.0 add 'smolder@=0.4.0'
cargo +1.85.0 check --locked
cargo +1.85.0 tree --locked
```

Pandora can then declare:

```toml
[dependencies]
smolder = "=0.4.0"
```

No tag or GitHub release should be created until all registry visibility,
checksum, and fresh-consumer checks have succeeded under separate authorization.
