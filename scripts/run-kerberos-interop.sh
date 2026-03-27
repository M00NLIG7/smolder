#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

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

if ! nc -vz "${SMOLDER_KERBEROS_HOST}" "${SMOLDER_KERBEROS_PORT}" >/dev/null 2>&1; then
  printf 'Kerberos SMB target %s:%s is unreachable from the host.\n' \
    "${SMOLDER_KERBEROS_HOST}" "${SMOLDER_KERBEROS_PORT}" >&2
  printf 'Ensure /etc/hosts maps dc1.lab.example and files1.lab.example to 127.0.0.1 when using the local fixture.\n' >&2
  exit 1
fi

cargo test -p smolder-smb-core --features kerberos --test kerberos_interop -- --nocapture
