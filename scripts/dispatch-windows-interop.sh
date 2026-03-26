#!/usr/bin/env bash
set -euo pipefail

workflow_file="${SMOLDER_WINDOWS_WORKFLOW:-interop-windows-self-hosted.yml}"
ref_name="${SMOLDER_WINDOWS_WORKFLOW_REF:-main}"

usage() {
  cat <<'EOF'
Usage: scripts/dispatch-windows-interop.sh [--no-watch]

Triggers the self-hosted Tiny11 Windows workflow_dispatch run and, by default,
watches the newest run until completion.

Environment:
  SMOLDER_WINDOWS_WORKFLOW      Workflow filename (default: interop-windows-self-hosted.yml)
  SMOLDER_WINDOWS_WORKFLOW_REF  Git ref to dispatch (default: main)
EOF
}

watch_run=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-watch)
      watch_run=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if ! command -v gh >/dev/null 2>&1; then
  printf 'gh is required to dispatch the workflow\n' >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  printf 'gh is not authenticated. Run: gh auth login -h github.com\n' >&2
  exit 1
fi

printf 'Dispatching %s on ref %s\n' "$workflow_file" "$ref_name"
gh workflow run "$workflow_file" --ref "$ref_name"

if [[ "$watch_run" -eq 0 ]]; then
  exit 0
fi

run_id="$(
  gh run list \
    --workflow "$workflow_file" \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId'
)"

if [[ -z "$run_id" || "$run_id" == "null" ]]; then
  printf 'could not determine the newly dispatched run id\n' >&2
  exit 1
fi

gh run watch "$run_id" --exit-status
