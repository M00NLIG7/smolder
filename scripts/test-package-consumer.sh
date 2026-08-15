#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
release_version="0.4.0"
package_dir="${repo_root}/target/package"
candidate_dir="${repo_root}/target/release-candidate-${release_version}"
archive_dir="${candidate_dir}/archives"
registry_dir="${candidate_dir}/registry"
consumer_dir="${candidate_dir}/downstream-consumer"
source_config="${candidate_dir}/candidate-source.toml"
package_target="${SMOLDER_PACKAGE_TARGET:-$(rustc +1.85.0 -vV | awk '/^host:/ { print $2}')}"
cargo=(cargo +1.85.0)
packages=(smolder-proto smolder-smb-core smolder)

cd "${repo_root}"

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "error: release archives must be built from a clean tracked tree" >&2
  exit 1
fi

rm -rf "${candidate_dir}"
mkdir -p "${archive_dir}" "${registry_dir}" "${consumer_dir}/src"

# Seed a complete, lockfile-pinned directory source. Candidate packages are added in publish
# order below, allowing Cargo to prepare dependent archives before any version is published.
"${cargo[@]}" vendor --quiet --locked --offline --versioned-dirs "${registry_dir}" >/dev/null

python3 - "${registry_dir}" >"${source_config}" <<'PY'
import json
import pathlib
import sys

registry = pathlib.Path(sys.argv[1]).resolve()
print('[source.crates-io]')
print('replace-with = "candidate-archives"')
print()
print('[source.candidate-archives]')
print(f'directory = {json.dumps(str(registry))}')
print()
print('[net]')
print('offline = true')
PY

package_candidate() {
  local package="$1"
  local archive="${package_dir}/${package}-${release_version}.crate"
  local -a source_args=()

  if [[ "${package}" != "smolder-proto" ]]; then
    source_args+=(--config "${source_config}")
  fi

  rm -f "${archive}"
  "${cargo[@]}" package --locked --offline --no-verify -p "${package}" "${source_args[@]}"
  cp "${archive}" "${archive_dir}/"
  python3 scripts/release_archive.py install \
    --archive "${archive_dir}/${package}-${release_version}.crate" \
    --registry "${registry_dir}" >/dev/null
}

# The order is part of the release contract. Each dependent archive lockfile resolves the exact
# lower-level candidate through the registry-shaped directory source, never through a path patch.
for package in "${packages[@]}"; do
  package_candidate "${package}"
done

python3 scripts/release_archive.py verify \
  --repo "${repo_root}" \
  --candidate "${candidate_dir}" \
  --version "${release_version}"

cat >"${consumer_dir}/Cargo.toml" <<EOF
[workspace]

[package]
name = "smolder-registry-consumer"
version = "0.0.0"
edition = "2021"
rust-version = "1.85"
publish = false

[features]
kerberos = ["smolder/kerberos", "smolder-smb-core/kerberos"]
kerberos-sspi = ["smolder-smb-core/kerberos-sspi"]
kerberos-gssapi = ["smolder-smb-core/kerberos-gssapi"]
quic = ["smolder-smb-core/quic"]
dangerous-ntlm-diagnostics = ["smolder-smb-core/dangerous-ntlm-diagnostics"]

[dependencies]
smolder = { version = "=${release_version}", default-features = false }
smolder-smb-core = { version = "=${release_version}", default-features = false }
smolder-proto = "=${release_version}"
EOF

cat >"${consumer_dir}/src/lib.rs" <<'EOF'
use smolder_core::prelude::{Client, ClientBuilder, NtlmCredentials, SecurityPolicy};
use smolder_proto::smb::smb2::Dialect;
use smolder_tools::prelude::SmbClientBuilder;

pub fn strict_boundary_credentials() -> (SecurityPolicy, NtlmCredentials) {
    (
        SecurityPolicy::pandora(),
        NtlmCredentials::new("package-consumer", "not-a-real-password"),
    )
}

pub fn strict_boundary_builder() -> ClientBuilder {
    Client::pandora_builder("package-consumer.invalid").with_ntlm_credentials(
        NtlmCredentials::new("package-consumer", "not-a-real-password"),
    )
}

pub fn top_level_archive_builder() -> (SmbClientBuilder, Dialect) {
    (
        SmbClientBuilder::new()
            .server("package-consumer.invalid")
            .credentials(NtlmCredentials::new(
                "package-consumer",
                "not-a-real-password",
            )),
        Dialect::Smb311,
    )
}

#[cfg(any(
    feature = "kerberos",
    feature = "kerberos-sspi",
    feature = "kerberos-gssapi"
))]
pub fn kerberos_api_is_consumable() -> smolder_core::prelude::KerberosCredentials {
    smolder_core::prelude::KerberosCredentials::new(
        "package-consumer",
        "not-a-real-password",
    )
}
EOF

cp "${source_config}" "${consumer_dir}/candidate-source.toml"
(
  cd "${consumer_dir}"
  "${cargo[@]}" generate-lockfile --offline --config candidate-source.toml
  "${cargo[@]}" metadata --locked --offline --format-version 1 \
    --config candidate-source.toml >metadata.json
)

python3 - "${consumer_dir}" "${release_version}" <<'PY'
import json
import pathlib
import sys
import tomllib

consumer = pathlib.Path(sys.argv[1])
version = sys.argv[2]
manifest = tomllib.loads((consumer / "Cargo.toml").read_text())
expected = {"smolder", "smolder-smb-core", "smolder-proto"}
for name, dependency in manifest["dependencies"].items():
    if name not in expected:
        continue
    if isinstance(dependency, str):
        requirement = dependency
        path = None
    else:
        requirement = dependency["version"]
        path = dependency.get("path")
    if requirement != f"={version}" or path is not None:
        raise SystemExit(f"{name} is not an exact registry-shaped dependency: {dependency!r}")

metadata = json.loads((consumer / "metadata.json").read_text())
resolved = {package["name"]: package for package in metadata["packages"] if package["name"] in expected}
if set(resolved) != expected:
    raise SystemExit(f"candidate graph resolved {sorted(resolved)}, expected {sorted(expected)}")
for name, package in resolved.items():
    if package["version"] != version:
        raise SystemExit(f"candidate graph resolved {name} {package['version']}, expected {version}")
    source = package.get("source") or ""
    if source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"candidate graph resolved {name} from non-registry source {source!r}")
print("registry-shaped candidate graph: smolder = =0.4.0 -> smolder-smb-core/smolder-proto = =0.4.0")
PY

cargo_check() {
  local manifest="$1"
  shift
  local -a command=(
    "${cargo[@]}" check --manifest-path "${manifest}" --locked --offline
    --config "${source_config}"
  )
  if [[ -n "${SMOLDER_PACKAGE_TARGET:-}" ]]; then
    command+=(--target "${SMOLDER_PACKAGE_TARGET}")
  fi
  "${command[@]}" "$@"
}

# Compile every target shipped in each exact archive, including the top-level binaries/examples,
# rather than proving only that the workspace source happens to build.
for package in "${packages[@]}"; do
  cargo_check "${registry_dir}/${package}-${release_version}/Cargo.toml" --all-targets
done

cargo_check "${registry_dir}/smolder-smb-core-${release_version}/Cargo.toml" \
  --all-targets --features kerberos
cargo_check "${registry_dir}/smolder-${release_version}/Cargo.toml" \
  --all-targets --features kerberos

consumer_check() {
  local -a command=(
    "${cargo[@]}" check --manifest-path "${consumer_dir}/Cargo.toml" --locked --offline
    --config "${source_config}" --all-targets
  )
  if [[ -n "${SMOLDER_PACKAGE_TARGET:-}" ]]; then
    command+=(--target "${SMOLDER_PACKAGE_TARGET}")
  fi
  "${command[@]}" "$@"
}

# Prove the featureless default and each applicable advertised feature independently; one
# all-feature build could otherwise hide missing target-specific code behind another backend.
consumer_check
consumer_check --features kerberos

if [[ "${package_target}" == *-windows-* ]]; then
  consumer_check --features kerberos-sspi
elif [[ "${package_target}" == *-linux-* || "${package_target}" == *-darwin ]]; then
  consumer_check --features kerberos-gssapi
fi

if [[ -z "${SMOLDER_PACKAGE_TARGET:-}" ]]; then
  consumer_check --features quic
  consumer_check --features dangerous-ntlm-diagnostics
fi

echo "candidate archive and downstream-consumer gate passed for ${release_version}"
