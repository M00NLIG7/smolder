#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'missing required environment variable: %s\n' "$name" >&2
    exit 1
  fi
}

require_env SMOLDER_WINDOWS_QUIC_SERVER
require_env SMOLDER_WINDOWS_QUIC_USERNAME
require_env SMOLDER_WINDOWS_QUIC_PASSWORD
require_env SMOLDER_WINDOWS_QUIC_SHARE

printf '\n==> SMB over QUIC target: server=%s connect_host=%s tls_server_name=%s port=%s share=%s\n' \
  "${SMOLDER_WINDOWS_QUIC_SERVER}" \
  "${SMOLDER_WINDOWS_QUIC_CONNECT_HOST:-${SMOLDER_WINDOWS_QUIC_SERVER}}" \
  "${SMOLDER_WINDOWS_QUIC_TLS_SERVER_NAME:-${SMOLDER_WINDOWS_QUIC_SERVER}}" \
  "${SMOLDER_WINDOWS_QUIC_PORT:-443}" \
  "${SMOLDER_WINDOWS_QUIC_SHARE}"

cargo test -p smolder-smb-core --features quic --test windows_quic -- --nocapture
