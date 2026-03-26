#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

share_dirs=(
  "docker/samba/share"
  "docker/samba/share-encrypted"
)

for dir in "${share_dirs[@]}"; do
  mkdir -p "$dir"
  chmod 0777 "$dir"
  printf 'prepared Samba share directory: %s\n' "$dir"
done
