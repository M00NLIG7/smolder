#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

compose_file="docker/samba-ad/compose.yaml"
vm_name="${SMOLDER_WINDOWS_VM:-Tiny11}"
windows_host="${SMOLDER_WINDOWS_HOST:-127.0.0.1}"
windows_port="${SMOLDER_WINDOWS_PORT:-445}"
windows_username="${SMOLDER_WINDOWS_USERNAME:-windowsfixture}"
windows_password="${SMOLDER_WINDOWS_PASSWORD:-windowsfixture}"
guest_blob_path="${SMOLDER_WINDOWS_ODJ_GUEST_PATH:-C:\\Windows\\Temp\\tiny11-odj.txt}"
host_blob_path="${SMOLDER_WINDOWS_ODJ_HOST_PATH:-/tmp/tiny11-odj.txt}"
ad_domain="${SMOLDER_AD_DOMAIN:-LAB.EXAMPLE}"
ad_netbios_domain="${SMOLDER_AD_NETBIOS_DOMAIN:-${ad_domain%%.*}}"
ad_admin_user="${SMOLDER_AD_ADMIN_USER:-Administrator}"
ad_admin_password="${SMOLDER_AD_ADMIN_PASSWORD:-Passw0rd!}"
ad_test_user="${SMOLDER_AD_TEST_USER:-smolder}"
windows_domain_admin_member="${SMOLDER_WINDOWS_DOMAIN_ADMIN_MEMBER:-${ad_netbios_domain}\\${ad_test_user}}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd VBoxManage
require_cmd nc

if [[ ! -x target/debug/psexec ]]; then
  cargo build -p smolder --bin psexec >/dev/null
fi

scripts/prepare-samba-ad-fixture.sh
docker compose -f "${compose_file}" up -d --build --remove-orphans dc1 files1

until nc -vz 127.0.0.1 1088 >/dev/null 2>&1; do
  sleep 2
done

until docker compose -f "${compose_file}" exec -T files1 wbinfo -t >/dev/null 2>&1; do
  sleep 2
done

guest_hostname=""
for _attempt in $(seq 1 24); do
  if guest_hostname="$(
    target/debug/psexec "smb://${windows_host}" \
      --command "cmd /c hostname" \
      --username "${windows_username}" \
      --password "${windows_password}" 2>/dev/null | tr -d '\r\n'
  )"; then
    if [[ -n "${guest_hostname}" ]]; then
      break
    fi
  fi
  sleep 5
done

if [[ -z "${guest_hostname}" ]]; then
  printf 'failed to query Tiny11 hostname through SMB execution\n' >&2
  exit 1
fi

blob_basename="$(basename "${host_blob_path}")"

docker compose -f "${compose_file}" exec -T files1 sh -lc \
  "rm -f /tmp/${blob_basename} && net offlinejoin provision \
    domain=${ad_domain} \
    machine_name=${guest_hostname} \
    reuse \
    savefile=/tmp/${blob_basename} \
    -U${ad_admin_user}%${ad_admin_password} \
    --option=\"netbios name=${guest_hostname}\""

member_container_id="$(docker compose -f "${compose_file}" ps -q files1)"
if [[ -z "${member_container_id}" ]]; then
  printf 'failed to resolve Samba AD member container id\n' >&2
  exit 1
fi

docker cp "${member_container_id}:/tmp/${blob_basename}" "${host_blob_path}"

copy_succeeded=0
for _attempt in $(seq 1 24); do
  if VBoxManage guestcontrol "${vm_name}" copyto "${host_blob_path}" "${guest_blob_path}" \
    --username "${windows_username}" \
    --password "${windows_password}" >/dev/null 2>&1; then
    copy_succeeded=1
    break
  fi
  sleep 5
done

if [[ "${copy_succeeded}" -ne 1 ]]; then
  printf 'failed to copy the offline join blob into Tiny11\n' >&2
  exit 1
fi

target/debug/psexec "smb://${windows_host}" \
  --command "cmd /c djoin /requestODJ /loadfile ${guest_blob_path} /windowspath C:\\Windows /localos" \
  --username "${windows_username}" \
  --password "${windows_password}"

target/debug/psexec "smb://${windows_host}" \
  --command "shutdown /r /t 0 /f" \
  --username "${windows_username}" \
  --password "${windows_password}" >/dev/null || true

until nc -vz "${windows_host}" "${windows_port}" >/dev/null 2>&1; do
  sleep 5
done

domain_line=""
for _attempt in $(seq 1 24); do
  if domain_line="$(
    target/debug/psexec "smb://${windows_host}" \
      --command "cmd /c systeminfo | findstr /B /C:\"Domain\"" \
      --username "${windows_username}" \
      --password "${windows_password}" 2>/dev/null | tr -d '\r'
  )"; then
    if [[ -n "${domain_line}" ]]; then
      break
    fi
  fi
  sleep 5
done

if [[ "${domain_line}" != *"lab.example"* ]]; then
  printf 'Tiny11 did not report the expected domain after offline join.\n' >&2
  if [[ -n "${domain_line}" ]]; then
    printf 'systeminfo output: %s\n' "${domain_line}" >&2
  fi
  exit 1
fi

if ! target/debug/psexec "smb://${windows_host}" \
  --command "cmd /c net localgroup Administrators \"${windows_domain_admin_member}\" /add" \
  --username "${windows_username}" \
  --password "${windows_password}" >/dev/null 2>&1; then
  printf 'warning: could not confirm local Administrators membership for %s during join\n' \
    "${windows_domain_admin_member}" >&2
fi

printf 'Tiny11 offline domain join succeeded for %s.\n' "${guest_hostname}"
printf '%s\n' "${domain_line}"
printf 'Ensured local Administrators membership for %s.\n' "${windows_domain_admin_member}"
