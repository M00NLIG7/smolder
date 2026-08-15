#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SMOLDER_SAMBA_HOST="${SMOLDER_SAMBA_HOST:-127.0.0.1}"
export SMOLDER_SAMBA_PORT="${SMOLDER_SAMBA_PORT:-1445}"
export SMOLDER_SAMBA_USERNAME="${SMOLDER_SAMBA_USERNAME:-smolder}"
export SMOLDER_SAMBA_PASSWORD="${SMOLDER_SAMBA_PASSWORD:-smolderpass}"
export SMOLDER_SAMBA_DOMAIN="${SMOLDER_SAMBA_DOMAIN:-WORKGROUP}"

cd "${REPO_ROOT}"

scripts/prepare-samba-fixture.sh
scripts/start-samba-fixture.sh samba

docker exec smolder-samba \
  rpcclient -A /run/samba/fixture.auth localhost -c lsaquery
docker exec smolder-samba \
  rpcclient -A /run/samba/fixture.auth localhost -c enumdomusers
docker exec smolder-samba \
  rpcclient -A /run/samba/fixture.auth localhost -c 'enumalsgroups builtin' | \
  grep -Fqi 'group:[Administrators] rid:[0x220]'

password_file="$(mktemp "${TMPDIR:-/tmp}/smolder-samba-password.XXXXXX")"
trap 'rm -f -- "${password_file}"' EXIT
chmod 600 "${password_file}"
printf '%s' "${SMOLDER_SAMBA_PASSWORD}" >"${password_file}"
export SMOLDER_SAMBA_PASSWORD_FILE="${password_file}"
unset SMOLDER_SAMBA_PASSWORD

cargo test -p smolder-smb-core --test samba_lsarpc_interop -- --ignored --nocapture
cargo test -p smolder-smb-core --test samba_samr_standalone_interop -- --ignored --nocapture
