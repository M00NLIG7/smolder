#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_windows=0
run_samba=0
run_core=0
run_tools=0
run_remote_exec=0
secret_files=()

cleanup_secret_files() {
  if ((${#secret_files[@]})); then
    rm -f -- "${secret_files[@]}"
  fi
}
trap cleanup_secret_files EXIT

create_password_file() {
  local output_name="$1"
  local password="$2"
  local path
  path="$(mktemp "${TMPDIR:-/tmp}/smolder-password.XXXXXX")"
  chmod 600 "$path"
  printf '%s' "$password" >"$path"
  secret_files+=("$path")
  printf -v "$output_name" '%s' "$path"
}

load_password_provider() {
  local name="$1"
  local file_name="${name}_FILE"
  local file_path="${!file_name:-}"
  local value="${!name:-}"
  if [[ -n "${file_path}" ]]; then
    if [[ ! -f "${file_path}" || -L "${file_path}" ]]; then
      printf '%s must identify a regular, non-symlink password file\n' "${file_name}" >&2
      exit 1
    fi
    value="$(<"${file_path}")"
  fi
  if [[ -n "${value}" ]]; then
    printf -v "${name}" '%s' "${value}"
    # Keep the compatibility value only in this shell; child processes receive protected files.
    export -n "${name}" 2>/dev/null || true
  fi
}

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
  local -a environment=()
  printf '\n==> '
  local env_arg env_name secret_file
  while [[ $# -gt 0 && "$1" == *=* ]]; do
    env_arg="$1"
    env_name="${env_arg%%=*}"
    case "$env_name" in
      *_PASSWORD)
        create_password_file secret_file "${env_arg#*=}"
        environment+=("${env_name}_FILE=${secret_file}")
        printf '%s_FILE=%s ' "$env_name" "$secret_file"
        ;;
      *_TOKEN|*_SECRET|*_KEY)
        environment+=("$env_arg")
        printf '%s=<redacted> ' "$env_name"
        ;;
      *)
        environment+=("$env_arg")
        printf '%s ' "$env_arg"
        ;;
    esac
    shift
  done
  printf '%s ' "$@"
  printf '\n'
  (
    for env_arg in "${environment[@]}"; do
      # `export` is a shell builtin, and `exec` replaces this private subshell. Secret values are
      # therefore never placed in an intermediate process argument list or retained by the caller.
      export "$env_arg"
    done
    exec "$@"
  )
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
    cargo test -p smolder-smb-core --test windows_interop -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test windows_reconnect -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    "SMOLDER_WINDOWS_ENCRYPTED_SHARE=${encrypted_share}" \
    cargo test -p smolder-smb-core --test windows_encryption -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test named_pipe_interop \
      exchanges_srvsvc_bind_over_windows_named_pipe_when_configured -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test rpc_interop -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    cargo test -p smolder-smb-core --test windows_rpc_encryption -- --ignored --nocapture
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
    cargo test -p smolder --test windows_reconnect -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
    "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
    "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
    "SMOLDER_WINDOWS_ENCRYPTED_SHARE=${encrypted_share}" \
    cargo test -p smolder --test windows_encryption -- --ignored --nocapture

  if [[ -n "${SMOLDER_WINDOWS_DFS_ROOT:-}" ]]; then
    run_env_cmd \
      "SMOLDER_WINDOWS_HOST=${SMOLDER_WINDOWS_HOST}" \
      "SMOLDER_WINDOWS_USERNAME=${SMOLDER_WINDOWS_USERNAME}" \
      "SMOLDER_WINDOWS_PASSWORD=${SMOLDER_WINDOWS_PASSWORD}" \
      "SMOLDER_WINDOWS_DFS_ROOT=${SMOLDER_WINDOWS_DFS_ROOT}" \
      cargo test -p smolder --test windows_dfs -- --ignored --nocapture
  else
    printf '\n==> skipping windows_dfs: SMOLDER_WINDOWS_DFS_ROOT is not set\n'
  fi
}

run_windows_remote_exec() {
  require_env SMOLDER_WINDOWS_HOST
  require_env SMOLDER_WINDOWS_USERNAME
  require_env SMOLDER_WINDOWS_PASSWORD

  local windows_port="${SMOLDER_WINDOWS_PORT:-445}"
  local windows_target="smb://${SMOLDER_WINDOWS_HOST}:${windows_port}"
  local password_file
  create_password_file password_file "${SMOLDER_WINDOWS_PASSWORD}"

  run_cmd cargo build -p smolder --bin smbexec --bin psexec
  run_cmd target/debug/smbexec \
    "${windows_target}" \
    --command whoami \
    --username "${SMOLDER_WINDOWS_USERNAME}" \
    --password-file "${password_file}"
  run_cmd target/debug/psexec \
    "${windows_target}" \
    --command whoami \
    --username "${SMOLDER_WINDOWS_USERNAME}" \
    --password-file "${password_file}"
}

run_samba_core() {
  require_env SMOLDER_SAMBA_HOST
  require_env SMOLDER_SAMBA_USERNAME
  require_env SMOLDER_SAMBA_PASSWORD

  local plain_port="${SMOLDER_SAMBA_PORT:-1445}"
  local netbios_port="${SMOLDER_SAMBA_NETBIOS_PORT:-1139}"
  local rpc_port="${SMOLDER_SAMBA_RPC_PORT:-1446}"
  local share="${SMOLDER_SAMBA_SHARE:-share}"
  local domain="${SMOLDER_SAMBA_DOMAIN:-WORKGROUP}"
  local encrypted_share="${SMOLDER_SAMBA_ENCRYPTED_SHARE:-SMOLDERENC}"

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_NETBIOS_PORT=${netbios_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder-smb-core --test samba_netbios -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder-smb-core --test samba_negotiate -- --ignored --nocapture --test-threads=1

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_ENCRYPTED_SHARE=${encrypted_share}" \
    cargo test -p smolder-smb-core --test samba_encryption -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder-smb-core --test samba_compression -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder-smb-core --test samba_lsarpc_interop -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder-smb-core --test samba_samr_standalone_interop -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${rpc_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    cargo test -p smolder-smb-core --test named_pipe_interop \
      exchanges_srvsvc_bind_over_samba_named_pipe_when_configured -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${rpc_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    cargo test -p smolder-smb-core --test samba_rpc_encryption -- --ignored --nocapture
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
    cargo test -p smolder --test samba_high_level -- --ignored --nocapture

  run_env_cmd \
    "SMOLDER_SAMBA_HOST=${SMOLDER_SAMBA_HOST}" \
    "SMOLDER_SAMBA_PORT=${plain_port}" \
    "SMOLDER_SAMBA_USERNAME=${SMOLDER_SAMBA_USERNAME}" \
    "SMOLDER_SAMBA_PASSWORD=${SMOLDER_SAMBA_PASSWORD}" \
    "SMOLDER_SAMBA_SHARE=${share}" \
    "SMOLDER_SAMBA_DOMAIN=${domain}" \
    cargo test -p smolder --test cli_smoke -- --ignored --nocapture --test-threads=1
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

load_password_provider SMOLDER_WINDOWS_PASSWORD
load_password_provider SMOLDER_SAMBA_PASSWORD

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
