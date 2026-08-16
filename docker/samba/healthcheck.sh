#!/usr/bin/env bash
set -euo pipefail

readonly auth_file="/run/samba/fixture.auth"
readonly port="${SMOLDER_SMB_PORTS:-445}"
readonly protection="${SMOLDER_CLIENT_PROTECTION:-sign}"

wbinfo -p >/dev/null
smbclient -A "${auth_file}" -p "${port}" --client-protection="${protection}" \
  -m SMB3 //localhost/share -c quit >/dev/null
rpcclient -A "${auth_file}" -p "${port}" --client-protection="${protection}" \
  localhost -c 'enumalsgroups builtin' 2>/dev/null | \
  grep -Fqi 'group:[Administrators] rid:[0x220]'
