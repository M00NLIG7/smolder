#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/smolder-samba-readiness.XXXXXX")"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT

cat >"${TEMP_DIR}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_LOG}"
if [[ "${1:-}" == "inspect" ]]; then
  container="${!#}"
  if [[ "${container}" == "${FAKE_UNHEALTHY_CONTAINER:-}" ]]; then
    printf 'starting\n'
  else
    printf 'healthy\n'
  fi
fi
EOF
chmod 0755 "${TEMP_DIR}/docker"

export FAKE_DOCKER_LOG="${TEMP_DIR}/docker.log"
PATH="${TEMP_DIR}:${PATH}"
export PATH

: >"${FAKE_DOCKER_LOG}"
"${ROOT_DIR}/scripts/start-samba-fixture.sh" >/dev/null
if ! grep -Eq 'compose -f .+ build samba' "${FAKE_DOCKER_LOG}"; then
  printf 'fixture startup did not build the pinned fixture image once\n' >&2
  exit 1
fi
if ! grep -Eq 'compose -f .+ up -d --no-build --wait --wait-timeout 120 samba samba-netbios samba-global-encryption' \
  "${FAKE_DOCKER_LOG}"; then
  printf 'fixture startup did not require Compose health readiness\n' >&2
  exit 1
fi
if [[ "$(grep -c '^inspect ' "${FAKE_DOCKER_LOG}")" -ne 3 ]]; then
  printf 'fixture startup did not verify every expected container health state\n' >&2
  exit 1
fi

: >"${FAKE_DOCKER_LOG}"
export FAKE_UNHEALTHY_CONTAINER=smolder-samba-netbios
if "${ROOT_DIR}/scripts/start-samba-fixture.sh" >"${TEMP_DIR}/unhealthy.out" 2>&1; then
  printf 'fixture startup accepted a non-healthy container\n' >&2
  exit 1
fi
if ! grep -Fq 'smolder-samba-netbios did not reach deterministic fixture readiness (health=starting)' \
  "${TEMP_DIR}/unhealthy.out"; then
  printf 'fixture startup did not identify the non-ready container\n' >&2
  exit 1
fi
unset FAKE_UNHEALTHY_CONTAINER

if SMOLDER_SAMBA_START_TIMEOUT=0 "${ROOT_DIR}/scripts/start-samba-fixture.sh" \
  >"${TEMP_DIR}/timeout.out" 2>&1; then
  printf 'fixture startup accepted an invalid readiness timeout\n' >&2
  exit 1
fi

echo 'Samba fixture readiness regression checks passed'
