#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

include_remote_exec=1
forward_args=()

usage() {
  cat <<'EOF'
Usage: scripts/run-windows-release-gate.sh [options]

Runs the full Tiny11 / Windows release-style verification pass:
  - smolder-smb-core package Windows interop gates
  - smolder package Windows interop gates
  - smbexec/psexec smoke commands by default

Options:
  --no-remote-exec  Skip smbexec/psexec smoke commands.
  -h, --help        Show this help text.

Any other arguments are forwarded to scripts/run-interop.sh after the default:
  --windows --core --tools
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-remote-exec)
      include_remote_exec=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      forward_args+=("$1")
      ;;
  esac
  shift
done

cmd=(scripts/run-interop.sh --windows --core --tools)
if [[ "$include_remote_exec" -eq 1 ]]; then
  cmd+=(--remote-exec)
fi
if [[ "${#forward_args[@]}" -gt 0 ]]; then
  cmd+=("${forward_args[@]}")
fi

printf '==> %s\n' "${cmd[*]}"
exec "${cmd[@]}"
