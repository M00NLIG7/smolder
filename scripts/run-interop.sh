#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_windows=0
run_samba=0
run_core=0
run_tools=0
run_remote_exec=0

usage() {
  cat <<'EOF'
Usage: scripts/run-interop.sh [options]

Runs the live SMB interoperability matrix described in docs/testing/interop.md.

Options:
  --windows       Run Windows-backed gates.
  --samba         Run Samba-backed gates.
  --core          Run smolder-smb-core package gates.
  --tools         Run smolder package gates.
  --remote-exec   Run smbexec/psexec smoke commands after tools gates.
  -h, --help      Show this help text.

Defaults:
  If no target flags are passed, the script runs every available target with the
  required environment configured.
  If no layer flags are passed, the script runs both core and tools gates.
  Remote execution is opt-in and only runs when --remote-exec is passed.
EOF
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'missing required environment variable: %s\n' "$name" >&2
    exit 1
  fi
}

have_windows_env() {
  [[ -n "${SMOLDER_WINDOWS_HOST:-}" ]] &&
    [[ -n "${SMOLDER_WINDOWS_USERNAME:-}" ]] &&
    [[ -n "${SMOLDER_WINDOWS_PASSWORD:-}" ]]
}

have_samba_env() {
  [[ -n "${SMOLDER_SAMBA_HOST:-}" ]] &&
    [[ -n "${SMOLDER_SAMBA_USERNAME:-}" ]] &&
    [[ -n "${SMOLDER_SAMBA_PASSWORD:-}" ]]
}

run_cmd() {
  printf '\n==> %s\n' "$*"
  "$@"
}

run_env_cmd() {
  local -a env_args=()
  while [[ $# -gt 0 && "$1" == *=* ]]; do
    env_args+=("$1")
    shift
  done
  printf '\n==> '
  printf '%s ' "${env_args[@]}"
  printf '%s ' "$@"
  printf '\n'
  env "${env_args[@]}" "$@"
}

run_windows_core() {
  require_env SMOLDER_WINDOWS_HOST
  require_env SMOLDER_WINDOWS_USERNAME
  require_env SMOLDER_WINDOWS_PASSWORD

  local encrypted_share="${SMOLDER_WINDOWS_ENCRYPTED_SHARE:-SMOLDERENC}"

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test windows_interop -- --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test windows_reconnect -- --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    "SMOLDER_WINDOWS_ENCRYPTED_SHARE=${encrypted_share}" \
    cargo test -p smolder-smb-core --test windows_encryption -- --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test named_pipe_interop \
      exchanges_srvsvc_bind_over_windows_named_pipe_when_configured -- --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test rpc_interop -- --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test windows_rpc_encryption -- --nocapture
}

run_windows_tools() {
  require_env SMOLDER_WINDOWS_HOST
  require_env SMOLDER_WINDOWS_USERNAME
  require_env SMOLDER_WINDOWS_PASSWORD

  local encrypted_share="${SMOLDER_WINDOWS_ENCRYPTED_SHARE:-SMOLDERENC}"

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder --test windows_reconnect -- --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    "SMOLDER_WINDOWS_ENCRYPTED_SHARE=${encrypted_share}" \
    cargo test -p smolder --test windows_encryption -- --nocapture

  if [[ -n "${SMOLDER_WINDOWS_DFS_ROOT:-}" ]]; then
    run_env_cmd \
      "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
      "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
      "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
      "SMOLDER_WINDOWS_DFS_ROOT=${SMOLDER_WINDOWS_DFS_ROOT}" \
      cargo test -p smolder --test windows_dfs -- --nocapture
  else
    printf '\n==> skipping windows_dfs: SMOLDER_WINDOWS_DFS_ROOT is not set\n'
  fi
}

run_windows_remote_exec() {
  require_env SMOLDER_WINDOWS_HOST
  require_env SMOLDER_WINDOWS_USERNAME
  require_env SMOLDER_WINDOWS_PASSWORD

  run_cmd cargo build -p smolder --bin smbexec --bin psexec
  run_cmd target/debug/smbexec \
    "smb://${SMOLDER_WINDOWS_HOST}" \
    --command whoami \
    --username "${SMOLDER_WINDOWS_USERNAME}" \
    --password "${SMOLDER_WINDOWS_PASSWORD}"
  run_cmd target/debug/psexec \
    "smb://${SMOLDER_WINDOWS_HOST}" \
    --command whoami \
    --username "${SMOLDER_WINDOWS_USERNAME}" \
    --password "${SMOLDER_WINDOWS_PASSWORD}"
}

run_samba_core() {
  require_env SMOLDER_SAMBA_HOST
  require_env SMOLDER_SAMBA_USERNAME
  require_env SMOLDER_SAMBA_PASSWORD

  local plain_port="${SMOLDER_SAMBA_PORT:-1445}"
  local rpc_port="${SMOLDER_SAMBA_RPC_PORT:-1446}"
  local share="${SMOLDER_SAMBA_SHARE:-share}"
  local domain="${SMOLDER_SAMBA_DOMAIN:-WORKGROUP}"
  local encrypted_share="${SMOLDER_SAMBA_ENCRYPTED_SHARE:-SMOLDERENC}"

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder-smb-core --test samba_negotiate -- --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_ENCRYPTED_SHARE=${encrypted_share}" \
    cargo test -p smolder-smb-core --test samba_encryption -- --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${rpc_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    cargo test -p smolder-smb-core --test named_pipe_interop \
      exchanges_srvsvc_bind_over_samba_named_pipe_when_configured -- --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${rpc_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    cargo test -p smolder-smb-core --test samba_rpc_encryption -- --nocapture
}

run_samba_tools() {
  require_env SMOLDER_SAMBA_HOST
  require_env SMOLDER_SAMBA_USERNAME
  require_env SMOLDER_SAMBA_PASSWORD

  local plain_port="${SMOLDER_SAMBA_PORT:-1445}"
  local share="${SMOLDER_SAMBA_SHARE:-share}"
  local domain="${SMOLDER_SAMBA_DOMAIN:-WORKGROUP}"

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder --test samba_high_level -- --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder --test cli_smoke -- --nocapture --test-threads=1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --windows)
      run_windows=1
      ;;
    --samba)
      run_samba=1
      ;;
    --core)
      run_core=1
      ;;
    --tools)
      run_tools=1
      ;;
    --remote-exec)
      run_remote_exec=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "$run_windows" -eq 0 && "$run_samba" -eq 0 ]]; then
  if have_windows_env; then
    run_windows=1
  fi
  if have_samba_env; then
    run_samba=1
  fi
fi

if [[ "$run_core" -eq 0 && "$run_tools" -eq 0 ]]; then
  run_core=1
  run_tools=1
fi

if [[ "$run_windows" -eq 0 && "$run_samba" -eq 0 ]]; then
  printf 'no enabled interop targets found; configure Windows and/or Samba env first\n' >&2
  exit 1
fi

if [[ "$run_windows" -eq 1 ]]; then
  if [[ "$run_core" -eq 1 ]]; then
    run_windows_core
  fi
  if [[ "$run_tools" -eq 1 ]]; then
    run_windows_tools
  fi
  if [[ "$run_remote_exec" -eq 1 ]]; then
    run_windows_remote_exec
  fi
fi

if [[ "$run_samba" -eq 1 ]]; then
  if [[ "$run_core" -eq 1 ]]; then
    run_samba_core
  fi
  if [[ "$run_tools" -eq 1 ]]; then
    run_samba_tools
  fi
fi

printf '\ninterop matrix completed successfully\n'
