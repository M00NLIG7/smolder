#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker/samba/compose.yaml"
WAIT_TIMEOUT="${SMOLDER_SAMBA_START_TIMEOUT:-120}"

if [[ ! "${WAIT_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'SMOLDER_SAMBA_START_TIMEOUT must be a positive integer\n' >&2
  exit 1
fi

if [[ "$#" -eq 0 ]]; then
  services=(samba samba-netbios samba-global-encryption)
else
  services=("$@")
fi

containers=()
for service in "${services[@]}"; do
  case "${service}" in
    samba)
      containers+=(smolder-samba)
      ;;
    samba-netbios)
      containers+=(smolder-samba-netbios)
      ;;
    samba-global-encryption)
      containers+=(smolder-samba-global-encryption)
      ;;
    *)
      printf 'unknown Samba fixture service: %s\n' "${service}" >&2
      exit 1
      ;;
  esac
done

docker compose -f "${COMPOSE_FILE}" build samba
if ! docker compose -f "${COMPOSE_FILE}" up -d --no-build --wait \
  --wait-timeout "${WAIT_TIMEOUT}" "${services[@]}"; then
  docker compose -f "${COMPOSE_FILE}" ps >&2 || true
  docker compose -f "${COMPOSE_FILE}" logs --no-color --tail 200 "${services[@]}" >&2 || true
  exit 1
fi

for container in "${containers[@]}"; do
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "${container}")"
  if [[ "${health}" != "healthy" ]]; then
    printf '%s did not reach deterministic fixture readiness (health=%s)\n' \
      "${container}" "${health}" >&2
    exit 1
  fi
done

docker compose -f "${COMPOSE_FILE}" ps
