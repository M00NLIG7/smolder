#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker/samba/compose.yaml"

export SMOLDER_SAMBA_HOST="${SMOLDER_SAMBA_HOST:-127.0.0.1}"
export SMOLDER_SAMBA_PORT="${SMOLDER_SAMBA_PORT:-1445}"
export SMOLDER_SAMBA_USERNAME="${SMOLDER_SAMBA_USERNAME:-smolder}"
export SMOLDER_SAMBA_PASSWORD="${SMOLDER_SAMBA_PASSWORD:-smolderpass}"
export SMOLDER_SAMBA_DOMAIN="${SMOLDER_SAMBA_DOMAIN:-WORKGROUP}"

cd "${REPO_ROOT}"

docker compose -f "${COMPOSE_FILE}" up -d samba

docker exec smolder-samba sh -lc \
  "rpcclient -U '${SMOLDER_SAMBA_USERNAME}%${SMOLDER_SAMBA_PASSWORD}' localhost -c lsaquery"
docker exec smolder-samba sh -lc \
  "rpcclient -U '${SMOLDER_SAMBA_USERNAME}%${SMOLDER_SAMBA_PASSWORD}' localhost -c enumdomusers"

cargo test -p smolder-smb-core --test samba_lsarpc_interop -- --nocapture
