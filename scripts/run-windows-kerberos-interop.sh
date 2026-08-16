#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

dc_config="/var/lib/smolder-ad-dc/etc/smb.conf"

require_env() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" ]]; then
    printf 'missing required environment variable: %s\n' "${name}" >&2
    exit 1
  fi
  printf '%s' "${value}"
}

scripts/prepare-samba-ad-fixture.sh
docker compose -f docker/samba-ad/compose.yaml up -d dc1 files1

until nc -vz 127.0.0.1 1088 >/dev/null 2>&1; do
  sleep 2
done

until docker compose -f docker/samba-ad/compose.yaml exec -T dc1 \
  samba-tool domain level show --configfile="${dc_config}" >/dev/null 2>&1; do
  sleep 2
done

until docker compose -f docker/samba-ad/compose.yaml exec -T files1 wbinfo -t >/dev/null 2>&1; do
  sleep 2
done

export SMOLDER_KERBEROS_HOST="${SMOLDER_KERBEROS_HOST:-127.0.0.1}"
export SMOLDER_KERBEROS_PORT="${SMOLDER_KERBEROS_PORT:-1445}"
export SMOLDER_KERBEROS_USERNAME="${SMOLDER_KERBEROS_USERNAME:-smolder@LAB.EXAMPLE}"
export SMOLDER_KERBEROS_PASSWORD="${SMOLDER_KERBEROS_PASSWORD:-Passw0rd!}"
export SMOLDER_KERBEROS_SHARE="${SMOLDER_KERBEROS_SHARE:-IPC$}"
export SMOLDER_KERBEROS_REALM="${SMOLDER_KERBEROS_REALM:-LAB.EXAMPLE}"
export SMOLDER_KERBEROS_TARGET_HOST="${SMOLDER_KERBEROS_TARGET_HOST:-DESKTOP-PTNJUS5.lab.example}"
unset SMOLDER_KERBEROS_KDC_URL
export SMOLDER_WINDOWS_USERNAME="$(require_env SMOLDER_WINDOWS_USERNAME)"
export SMOLDER_WINDOWS_PASSWORD="$(require_env SMOLDER_WINDOWS_PASSWORD)"

secret_dir="$(mktemp -d "${TMPDIR:-/tmp}/smolder-windows-kerberos.XXXXXX")"
chmod 700 "${secret_dir}"
trap 'rm -rf -- "${secret_dir}"' EXIT
kerberos_password_file="${secret_dir}/kerberos-password"
windows_password_file="${secret_dir}/windows-password"
krb5_config_path="${secret_dir}/krb5.conf"
: >"${kerberos_password_file}"
: >"${windows_password_file}"
chmod 600 "${kerberos_password_file}" "${windows_password_file}"
printf '%s' "${SMOLDER_KERBEROS_PASSWORD}" >"${kerberos_password_file}"
printf '%s' "${SMOLDER_WINDOWS_PASSWORD}" >"${windows_password_file}"
export SMOLDER_KERBEROS_PASSWORD_FILE="${kerberos_password_file}"
unset SMOLDER_KERBEROS_PASSWORD SMOLDER_WINDOWS_PASSWORD

cat >"${krb5_config_path}" <<EOF
[libdefaults]
    default_realm = ${SMOLDER_KERBEROS_REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    ${SMOLDER_KERBEROS_REALM} = {
        kdc = dc1.lab.example:1088
        admin_server = dc1.lab.example:1088
    }

[domain_realm]
    .lab.example = ${SMOLDER_KERBEROS_REALM}
    lab.example = ${SMOLDER_KERBEROS_REALM}
EOF
export KRB5_CONFIG="${krb5_config_path}"

kerberos_netbios_domain="${SMOLDER_KERBEROS_NETBIOS_DOMAIN:-${SMOLDER_KERBEROS_REALM%%.*}}"
kerberos_user="${SMOLDER_KERBEROS_USERNAME%%@*}"
windows_domain_admin_member="${SMOLDER_WINDOWS_DOMAIN_ADMIN_MEMBER:-${kerberos_netbios_domain}\\${kerberos_user}}"

machine_account="$(printf '%s' "${SMOLDER_KERBEROS_TARGET_HOST%%.*}" | tr '[:lower:]' '[:upper:]')$"

if ! nc -vz "${SMOLDER_KERBEROS_HOST}" "${SMOLDER_KERBEROS_PORT}" >/dev/null 2>&1; then
  printf 'Windows SMB target %s:%s is unreachable from the host.\n' \
    "${SMOLDER_KERBEROS_HOST}" "${SMOLDER_KERBEROS_PORT}" >&2
  exit 1
fi

if ! docker compose -f docker/samba-ad/compose.yaml exec -T dc1 \
  samba-tool spn list "${machine_account}" --configfile="${dc_config}" >/dev/null 2>&1; then
  printf 'Kerberos machine account %s is missing from the Samba AD realm.\n' "${machine_account}" >&2
  printf 'Re-run scripts/join-tiny11-to-samba-ad.sh before this Windows Kerberos gate.\n' >&2
  exit 1
fi

cargo test -p smolder-smb-core --features kerberos --test kerberos_interop -- --ignored --nocapture
cargo build -p smolder --features kerberos --bin smolder-ls --bin smolder >/dev/null

target_url="smb://${SMOLDER_KERBEROS_HOST}"
if [[ "${SMOLDER_KERBEROS_PORT}" != "445" ]]; then
  target_url="${target_url}:${SMOLDER_KERBEROS_PORT}"
fi
target_url="${target_url}/${SMOLDER_KERBEROS_SHARE}"

rpc_target="smb://${SMOLDER_KERBEROS_HOST}"
if [[ "${SMOLDER_KERBEROS_PORT}" != "445" ]]; then
  rpc_target="${rpc_target}:${SMOLDER_KERBEROS_PORT}"
fi

target/debug/smolder-ls "${target_url}" \
  --kerberos \
  --username "${SMOLDER_KERBEROS_USERNAME}" \
  --password-file "${kerberos_password_file}" \
  --target-host "${SMOLDER_KERBEROS_TARGET_HOST}" \
  --realm "${SMOLDER_KERBEROS_REALM}" >/dev/null

if ! target/debug/smolder psexec "${rpc_target}" \
  --command "cmd /c net localgroup Administrators \"${windows_domain_admin_member}\" /add" \
  --username "${SMOLDER_WINDOWS_USERNAME}" \
  --password-file "${windows_password_file}" >/dev/null 2>&1; then
  :
fi

target/debug/smolder smbexec "${rpc_target}" \
  --command whoami \
  --kerberos \
  --username "${SMOLDER_KERBEROS_USERNAME}" \
  --password-file "${kerberos_password_file}" \
  --target-host "${SMOLDER_KERBEROS_TARGET_HOST}" \
  --realm "${SMOLDER_KERBEROS_REALM}" >/dev/null

target/debug/smolder psexec "${rpc_target}" \
  --command whoami \
  --kerberos \
  --username "${SMOLDER_KERBEROS_USERNAME}" \
  --password-file "${kerberos_password_file}" \
  --target-host "${SMOLDER_KERBEROS_TARGET_HOST}" \
  --realm "${SMOLDER_KERBEROS_REALM}" >/dev/null
