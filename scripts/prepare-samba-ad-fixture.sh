#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
share_dir="${repo_root}/docker/samba-ad/member/share"

mkdir -p "${share_dir}"
chmod 0777 "${share_dir}" || true

printf 'prepared Samba AD fixture directory: %s\n' "${share_dir}"
