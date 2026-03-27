#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

keytab_dir="${repo_root}/.tmp"
keytab_path="${keytab_dir}/smolder-user.keytab"
krb5_config_path="${keytab_dir}/krb5-smolder.conf"
dc_container="smolder-samba-ad-dc"
dc_config="/var/lib/smolder-ad-dc/etc/smb.conf"

mkdir -p "${keytab_dir}"
trap 'rm -f "${keytab_path}" "${krb5_config_path}"' EXIT

scripts/prepare-samba-ad-fixture.sh
docker compose -f docker/samba-ad/compose.yaml up -d --build --remove-orphans dc1 files1

until nc -vz 127.0.0.1 2445 >/dev/null 2>&1; do
  sleep 2
done

until nc -vz 127.0.0.1 1088 >/dev/null 2>&1; do
  sleep 2
done

until docker compose -f docker/samba-ad/compose.yaml exec -T files1 wbinfo -t >/dev/null 2>&1; do
  sleep 2
done

export SMOLDER_KERBEROS_HOST="${SMOLDER_KERBEROS_HOST:-files1.lab.example}"
export SMOLDER_KERBEROS_PORT="${SMOLDER_KERBEROS_PORT:-2445}"
export SMOLDER_KERBEROS_USERNAME="${SMOLDER_KERBEROS_USERNAME:-smolder@LAB.EXAMPLE}"
export SMOLDER_KERBEROS_PASSWORD="${SMOLDER_KERBEROS_PASSWORD:-Passw0rd!}"
export SMOLDER_KERBEROS_SHARE="${SMOLDER_KERBEROS_SHARE:-share}"
export SMOLDER_KERBEROS_REALM="${SMOLDER_KERBEROS_REALM:-LAB.EXAMPLE}"
export SMOLDER_KERBEROS_TARGET_HOST="${SMOLDER_KERBEROS_TARGET_HOST:-files1.lab.example}"
export SMOLDER_KERBEROS_KDC_URL="${SMOLDER_KERBEROS_KDC_URL:-tcp://dc1.lab.example:1088}"
keytab_target="${SMOLDER_KERBEROS_KEYTAB:-${keytab_path}}"

if ! nc -vz "${SMOLDER_KERBEROS_HOST}" "${SMOLDER_KERBEROS_PORT}" >/dev/null 2>&1; then
  printf 'Kerberos SMB target %s:%s is unreachable from the host.\n' \
    "${SMOLDER_KERBEROS_HOST}" "${SMOLDER_KERBEROS_PORT}" >&2
  printf 'Ensure /etc/hosts maps dc1.lab.example and files1.lab.example to 127.0.0.1 when using the local fixture.\n' >&2
  exit 1
fi

cargo test -p smolder-smb-core --features kerberos --test kerberos_interop -- --nocapture

docker compose -f docker/samba-ad/compose.yaml exec -T dc1 \
  samba-tool domain exportkeytab /tmp/smolder-user.keytab \
    --principal="${SMOLDER_KERBEROS_USERNAME}" \
    --configfile="${dc_config}" >/dev/null
docker cp "${dc_container}:/tmp/smolder-user.keytab" "${keytab_target}" >/dev/null

cat >"${krb5_config_path}" <<EOF
[libdefaults]
    default_realm = ${SMOLDER_KERBEROS_REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    ${SMOLDER_KERBEROS_REALM} = {
        kdc = dc1.lab.example
        admin_server = dc1.lab.example
    }

[domain_realm]
    .lab.example = ${SMOLDER_KERBEROS_REALM}
    lab.example = ${SMOLDER_KERBEROS_REALM}
EOF

unset SMOLDER_KERBEROS_PASSWORD

docker run --rm \
  --network samba-ad_adnet \
  -e KRB5_CONFIG=/tmp/krb5.conf \
  -e SMOLDER_KERBEROS_HOST=files1.lab.example \
  -e SMOLDER_KERBEROS_PORT=445 \
  -e SMOLDER_KERBEROS_USERNAME="${SMOLDER_KERBEROS_USERNAME}" \
  -e SMOLDER_KERBEROS_KEYTAB=/tmp/smolder-user.keytab \
  -e SMOLDER_KERBEROS_SHARE="${SMOLDER_KERBEROS_SHARE}" \
  -e SMOLDER_KERBEROS_TARGET_HOST=files1.lab.example \
  -e SMOLDER_KERBEROS_REALM="${SMOLDER_KERBEROS_REALM}" \
  -e SMOLDER_KERBEROS_KDC_URL=tcp://dc1.lab.example:88 \
  -v "${repo_root}:/work" \
  -v "${HOME}/.cargo/registry:/usr/local/cargo/registry" \
  -v "${HOME}/.cargo/git:/usr/local/cargo/git" \
  -v "${keytab_target}:/tmp/smolder-user.keytab:ro" \
  -v "${krb5_config_path}:/tmp/krb5.conf:ro" \
  -w /work \
  rust:1.94-slim-bookworm \
  bash -lc '
    export PATH="/usr/local/cargo/bin:${PATH}"
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      pkg-config libkrb5-dev clang libclang-dev >/dev/null
    cargo test --offline -p smolder-smb-core --features kerberos-gssapi \
      --test kerberos_interop -- --nocapture
  '
