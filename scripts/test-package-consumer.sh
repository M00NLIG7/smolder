#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
package_dir="${repo_root}/target/package"
consumer_dir="${repo_root}/target/extracted-package-consumer"
package_target="${SMOLDER_PACKAGE_TARGET:-$(rustc -vV | awk '/^host:/ { print $2}')}"

cd "${repo_root}"
rm -rf "${consumer_dir}"
mkdir -p "${consumer_dir}/src" "${consumer_dir}/packages"

# `--no-verify` only creates the archives. The extracted downstream build below is the proof;
# unlike Cargo's workspace-root verification, it cannot inherit local path dependencies.
for package in smolder-proto smolder-smb-core; do
  cargo package --locked --offline --no-verify -p "${package}"
done

for archive in \
  "${package_dir}/smolder-proto-0.3.0.crate" \
  "${package_dir}/smolder-smb-core-0.3.0.crate"; do
  tar -xzf "${archive}" -C "${consumer_dir}/packages"
done

cat >"${consumer_dir}/Cargo.toml" <<EOF
[workspace]

[package]
name = "smolder-extracted-consumer"
version = "0.0.0"
edition = "2021"
rust-version = "1.85"
publish = false

[features]
kerberos = ["smolder-smb-core/kerberos"]
kerberos-sspi = ["smolder-smb-core/kerberos-sspi"]
kerberos-gssapi = ["smolder-smb-core/kerberos-gssapi"]
quic = ["smolder-smb-core/quic"]
dangerous-ntlm-diagnostics = ["smolder-smb-core/dangerous-ntlm-diagnostics"]

[dependencies]
smolder-smb-core = { path = "${consumer_dir}/packages/smolder-smb-core-0.3.0", default-features = false }

[patch.crates-io]
smolder-proto = { path = "${consumer_dir}/packages/smolder-proto-0.3.0" }
smolder-smb-core = { path = "${consumer_dir}/packages/smolder-smb-core-0.3.0" }
EOF

cat >"${consumer_dir}/src/lib.rs" <<'EOF'
use smolder_core::prelude::{Client, ClientBuilder, NtlmCredentials, SecurityPolicy};

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

#[cfg(any(
    feature = "kerberos",
    feature = "kerberos-sspi",
    feature = "kerberos-gssapi"
))]
pub fn kerberos_api_is_consumable() -> smolder_core::prelude::KerberosCredentials {
    smolder_core::prelude::KerberosCredentials::new("package-consumer", "not-a-real-password")
}
EOF

cargo generate-lockfile --manifest-path "${consumer_dir}/Cargo.toml" --offline

consumer_check() {
  local -a command=(
    cargo check --manifest-path "${consumer_dir}/Cargo.toml" --locked --offline --all-targets
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
  cargo check --manifest-path "${consumer_dir}/Cargo.toml" --locked --offline --all-targets \
    --features quic
  cargo check --manifest-path "${consumer_dir}/Cargo.toml" --locked --offline --all-targets \
    --features dangerous-ntlm-diagnostics
fi
