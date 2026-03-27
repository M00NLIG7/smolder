#!/usr/bin/env bash
set -euo pipefail

REALM="${REALM:-LAB.EXAMPLE}"
DOMAIN="${DOMAIN:-LAB}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Passw0rd!}"
TEST_USER="${TEST_USER:-smolder}"
TEST_PASSWORD="${TEST_PASSWORD:-Passw0rd!}"
STATE_DIR=/var/lib/smolder-ad-dc

rm -rf "${STATE_DIR}"
mkdir -p "${STATE_DIR}"

samba-tool domain provision \
  --realm="${REALM}" \
  --domain="${DOMAIN}" \
  --server-role=dc \
  --dns-backend=SAMBA_INTERNAL \
  --use-rfc2307 \
  --adminpass="${ADMIN_PASSWORD}" \
  --option="interfaces=lo eth0" \
  --option="bind interfaces only=yes" \
  --targetdir="${STATE_DIR}"

install -m 0644 "${STATE_DIR}/private/krb5.conf" /etc/krb5.conf

if ! samba-tool user show "${TEST_USER}" --configfile="${STATE_DIR}/etc/smb.conf" >/dev/null 2>&1; then
  samba-tool user create "${TEST_USER}" "${TEST_PASSWORD}" \
    --configfile="${STATE_DIR}/etc/smb.conf"
fi

exec samba -i -M single -s "${STATE_DIR}/etc/smb.conf" --debug-stdout
