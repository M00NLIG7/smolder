#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

runner_root="${SMOLDER_RUNNER_ROOT:-$ROOT_DIR/.tmp/github-runner/windows-gate}"
runner_labels="${SMOLDER_RUNNER_LABELS:-smolder-windows-gate}"
runner_name="${SMOLDER_RUNNER_NAME:-$(hostname)-smolder-windows-gate}"
repo_slug="${GITHUB_REPOSITORY:-}"

usage() {
  cat <<'EOF'
Usage: scripts/setup-windows-self-hosted-runner.sh

Bootstraps a GitHub Actions self-hosted runner for this repository and configures
it with the label expected by .github/workflows/interop-windows-self-hosted.yml.

Environment:
  GITHUB_REPOSITORY                Optional explicit owner/repo slug.
  SMOLDER_RUNNER_ROOT             Install directory (default: .tmp/github-runner/windows-gate)
  SMOLDER_RUNNER_LABELS           Comma-separated runner labels (default: smolder-windows-gate)
  SMOLDER_RUNNER_NAME             Runner name (default: <hostname>-smolder-windows-gate)
  ACTIONS_RUNNER_VERSION          Optional pinned runner version. When unset, the latest public release is used.
  GITHUB_RUNNER_REGISTRATION_TOKEN Optional pre-fetched registration token. When unset, gh api is used.

Prerequisites:
  - gh must be authenticated against github.com
  - curl and tar must be installed

This script configures the runner but does not install it as a launchd/system service.
After configuration, start it with:

  cd "$SMOLDER_RUNNER_ROOT"
  ./run.sh

Or install the service manually with:

  ./svc.sh install
  ./svc.sh start
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

require_cmd gh
require_cmd curl
require_cmd tar
require_cmd ruby
require_cmd git

if ! gh auth status >/dev/null 2>&1; then
  printf 'gh is not authenticated. Run: gh auth login -h github.com\n' >&2
  exit 1
fi

if [[ -z "$repo_slug" ]]; then
  origin_url="$(git remote get-url origin)"
  repo_slug="$(printf '%s\n' "$origin_url" | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##')"
fi

case "$(uname -s)" in
  Darwin) os_label="osx" ;;
  Linux) os_label="linux" ;;
  *)
    printf 'unsupported runner host OS: %s\n' "$(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64|aarch64) arch_label="arm64" ;;
  x86_64|amd64) arch_label="x64" ;;
  *)
    printf 'unsupported runner host architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

runner_version="${ACTIONS_RUNNER_VERSION:-}"
if [[ -z "$runner_version" ]]; then
  runner_version="$(
    curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | \
      ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("tag_name").sub(/^v/, "")'
  )"
fi

asset_name="actions-runner-${os_label}-${arch_label}-${runner_version}.tar.gz"
download_url="https://github.com/actions/runner/releases/download/v${runner_version}/${asset_name}"

mkdir -p "$runner_root"
cd "$runner_root"

if [[ ! -x ./config.sh ]]; then
  archive_path="$runner_root/$asset_name"
  printf 'Downloading GitHub Actions runner %s\n' "$runner_version"
  curl -fsSL -o "$archive_path" "$download_url"
  tar xzf "$archive_path"
  rm -f "$archive_path"
fi

if [[ -f .runner ]]; then
  printf 'Runner is already configured in %s\n' "$runner_root"
  exit 0
fi

registration_token="${GITHUB_RUNNER_REGISTRATION_TOKEN:-}"
if [[ -z "$registration_token" ]]; then
  registration_token="$(
    gh api -X POST "repos/${repo_slug}/actions/runners/registration-token" --jq .token
  )"
fi

printf 'Configuring self-hosted runner %s for %s with labels %s\n' \
  "$runner_name" "$repo_slug" "$runner_labels"
./config.sh \
  --url "https://github.com/${repo_slug}" \
  --token "$registration_token" \
  --name "$runner_name" \
  --labels "$runner_labels" \
  --work "_work" \
  --unattended \
  --replace

printf '\nRunner configured in %s\n' "$runner_root"
printf 'Start it with: cd %s && ./run.sh\n' "$runner_root"
