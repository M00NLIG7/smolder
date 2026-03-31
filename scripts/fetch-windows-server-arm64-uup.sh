#!/usr/bin/env bash
set -euo pipefail

uup_id="${1:-}"
pack="${SMOLDER_WINDOWS_QUIC_UUP_PACK:-en-us}"
edition="${SMOLDER_WINDOWS_QUIC_UUP_EDITION:-serverturbine}"
out_dir="${SMOLDER_WINDOWS_QUIC_UUP_OUTDIR:-$HOME/Downloads}"

if [[ -z "$uup_id" ]]; then
  printf 'usage: %s <uup-build-id>\n' "${0##*/}" >&2
  printf 'example: %s 32833df7-ff91-424f-8087-9895b395a1b0\n' "${0##*/}" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  printf 'curl is required\n' >&2
  exit 1
fi

mkdir -p "$out_dir"

url="https://uupdump.net/get.php?id=${uup_id}&pack=${pack}&edition=${edition}"
body_file="$(mktemp)"
header_file="$(mktemp)"
aria2_file="$(mktemp)"
trap 'rm -f "$body_file" "$header_file" "$aria2_file"' EXIT

curl -fsSL \
  --retry 3 \
  --retry-delay 2 \
  "${url}&aria2=2" \
  -o "$aria2_file"

if rg -q '^#UUPDUMP_ERROR:' "$aria2_file"; then
  printf 'uupdump reported no live Windows Update file list for build %s\n' "$uup_id" >&2
  sed -n '1,5p' "$aria2_file" >&2
  printf '\nPick a newer ARM64 Windows Server build from https://uupdump.net/known.php?q=Windows+Server and retry.\n' >&2
  exit 1
fi

curl -fsSL \
  --retry 3 \
  --retry-delay 2 \
  --data 'autodl=2' \
  -D "$header_file" \
  -o "$body_file" \
  "$url"

magic="$(hexdump -n 2 -e '2/1 "%02x"' "$body_file" 2>/dev/null || true)"
if [[ "$magic" != "504b" ]]; then
  printf 'uupdump did not return a zip archive for build %s\n' "$uup_id" >&2
  if rg -q '^#UUPDUMP_ERROR:' "$body_file"; then
    sed -n '1,5p' "$body_file" >&2
  else
    sed -n '1,20p' "$body_file" >&2
  fi
  printf '\nPick a newer ARM64 Windows Server build from https://uupdump.net/known.php?q=Windows+Server and retry.\n' >&2
  exit 1
fi

filename="$(sed -n 's/.*filename=\"\([^\"]*\)\".*/\1/p' "$header_file" | tail -n 1)"
if [[ -z "$filename" ]]; then
  filename="${uup_id}_${pack}_${edition}_convert.zip"
fi

dest="${out_dir%/}/${filename}"
mv "$body_file" "$dest"

printf 'Saved UUP package: %s\n' "$dest"
printf 'Next steps:\n'
printf '1. Unzip the package.\n'
printf '2. Run uup_download_windows.cmd inside Tiny11 or another Windows machine, or use uup_download_macos.sh on a host with the required conversion tools.\n'
printf '3. Boot the generated ARM64 ISO in UTM.\n'
printf '4. Run scripts/configure-windows-quic-server.ps1 in the Windows Server guest.\n'
printf '5. Trust the exported certificate on the host and run scripts/run-windows-quic-interop.sh.\n'
