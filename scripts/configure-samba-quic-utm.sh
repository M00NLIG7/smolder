#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${SMOLDER_SAMBA_QUIC_UTM_DIR:-/tmp/smolder-samba-quic-utm}"

SSH_KEY_PATH="${SMOLDER_SAMBA_QUIC_SSH_KEY_PATH:-${ARTIFACT_DIR}/id_ed25519}"
SSH_PORT="${SMOLDER_SAMBA_QUIC_SSH_PORT:-2422}"
GUEST_USER="${SMOLDER_SAMBA_QUIC_GUEST_USER:-smolder}"
SERVER_NAME="${SMOLDER_SAMBA_QUIC_SERVER_NAME:-files.lab.example}"
USERNAME="${SMOLDER_SAMBA_QUIC_USERNAME:-smolder}"
PASSWORD="${SMOLDER_SAMBA_QUIC_PASSWORD:-smolderpass}"
SHARE_NAME="${SMOLDER_SAMBA_QUIC_SHARE_NAME:-share}"

SSH_HOST="127.0.0.1"
REMOTE_WORK_DIR="/opt/smolder-samba-quic"
LOCAL_CA_PATH="${ARTIFACT_DIR}/samba-quic-ca.pem"
QUIC_SOURCE_URL="${SMOLDER_SAMBA_QUIC_SOURCE_URL:-https://codeload.github.com/lxin/quic/tar.gz/refs/heads/main}"

SSH_OPTS=(
  -i "$SSH_KEY_PATH"
  -p "$SSH_PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=24
)

SCP_OPTS=(
  -i "$SSH_KEY_PATH"
  -P "$SSH_PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 1
  fi
}

wait_for_ssh() {
  local deadline
  deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    if ssh "${SSH_OPTS[@]}" "${GUEST_USER}@${SSH_HOST}" true >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done

  printf 'timed out waiting for guest ssh connectivity\n' >&2
  exit 1
}

push_fixture() {
  local archive quic_archive
  archive="$(mktemp "${ARTIFACT_DIR}/samba-quic.XXXXXX")"
  tar -C "${ROOT_DIR}/docker" -czf "$archive" samba-quic
  scp "${SCP_OPTS[@]}" "$archive" "${GUEST_USER}@${SSH_HOST}:/tmp/samba-quic.tar.gz" >/dev/null
  rm -f "$archive"

  scp "${SCP_OPTS[@]}" "${ROOT_DIR}/scripts/setup-samba-quic-guest.sh" \
    "${GUEST_USER}@${SSH_HOST}:/tmp/setup-samba-quic-guest.sh" >/dev/null

  quic_archive="$(mktemp "${ARTIFACT_DIR}/quic-src.XXXXXX")"
  curl -fsSL "$QUIC_SOURCE_URL" -o "$quic_archive"
  scp "${SCP_OPTS[@]}" "$quic_archive" "${GUEST_USER}@${SSH_HOST}:/tmp/quic-src.tar.gz" >/dev/null
  rm -f "$quic_archive"

  ssh "${SSH_OPTS[@]}" "${GUEST_USER}@${SSH_HOST}" "
    sudo mkdir -p '${REMOTE_WORK_DIR}' &&
    sudo tar -xzf /tmp/samba-quic.tar.gz --strip-components=1 -C '${REMOTE_WORK_DIR}' &&
    sudo chmod +x /tmp/setup-samba-quic-guest.sh
  "
}

run_guest_setup() {
  ssh "${SSH_OPTS[@]}" "${GUEST_USER}@${SSH_HOST}" "
    export SMOLDER_SAMBA_QUIC_SERVER_NAME='${SERVER_NAME}' &&
    export SMOLDER_SAMBA_QUIC_USERNAME='${USERNAME}' &&
    export SMOLDER_SAMBA_QUIC_PASSWORD='${PASSWORD}' &&
    export SMOLDER_SAMBA_QUIC_SHARE_NAME='${SHARE_NAME}' &&
    sudo -E /tmp/setup-samba-quic-guest.sh '${REMOTE_WORK_DIR}'
  "
}

pull_cert() {
  mkdir -p "$ARTIFACT_DIR"
  scp "${SCP_OPTS[@]}" \
    "${GUEST_USER}@${SSH_HOST}:${REMOTE_WORK_DIR}/certs/ca.pem" \
    "$LOCAL_CA_PATH" >/dev/null
}

require_tool ssh
require_tool scp
require_tool tar

if [[ ! -f "$SSH_KEY_PATH" ]]; then
  printf 'missing ssh key: %s\n' "$SSH_KEY_PATH" >&2
  exit 1
fi

wait_for_ssh
push_fixture
run_guest_setup
pull_cert

printf '\nUTM guest configured.\n'
printf '  ssh: ssh -i %s -p %s %s@127.0.0.1\n' "$SSH_KEY_PATH" "$SSH_PORT" "$GUEST_USER"
printf '  ca: %s\n' "$LOCAL_CA_PATH"
printf '  trust on macOS:\n'
printf '    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n' "$LOCAL_CA_PATH"
printf '  test env:\n'
printf '    export SMOLDER_SAMBA_QUIC_SERVER=%q\n' "$SERVER_NAME"
printf '    export SMOLDER_SAMBA_QUIC_CONNECT_HOST=127.0.0.1\n'
printf '    export SMOLDER_SAMBA_QUIC_TLS_SERVER_NAME=%q\n' "$SERVER_NAME"
printf '    export SMOLDER_SAMBA_QUIC_PORT=2443\n'
printf '    export SMOLDER_SAMBA_QUIC_USERNAME=%q\n' "$USERNAME"
printf '    export SMOLDER_SAMBA_QUIC_PASSWORD=%q\n' "$PASSWORD"
printf '    export SMOLDER_SAMBA_QUIC_SHARE=%q\n' "$SHARE_NAME"
printf '    scripts/run-samba-quic-interop.sh\n'
