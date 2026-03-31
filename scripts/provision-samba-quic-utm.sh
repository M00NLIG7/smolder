#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ARTIFACT_DIR="${SMOLDER_SAMBA_QUIC_UTM_DIR:-/tmp/smolder-samba-quic-utm}"
VM_NAME="${SMOLDER_SAMBA_QUIC_VM:-SmolderSambaQuic}"
IMAGE_URL="${SMOLDER_SAMBA_QUIC_IMAGE_URL:-https://cloud-images.ubuntu.com/releases/plucky/release/ubuntu-25.04-server-cloudimg-arm64.img}"
IMAGE_NAME="$(basename "$IMAGE_URL")"
IMAGE_PATH="${SMOLDER_SAMBA_QUIC_IMAGE_PATH:-${ARTIFACT_DIR}/${IMAGE_NAME}}"
SEED_DIR="${ARTIFACT_DIR}/seed"
SEED_ISO="${ARTIFACT_DIR}/smolder-samba-quic-seed.iso"
SSH_KEY_PATH="${ARTIFACT_DIR}/id_ed25519"

VM_MEMORY_MIB="${SMOLDER_SAMBA_QUIC_VM_MEMORY_MIB:-4096}"
VM_CPU_CORES="${SMOLDER_SAMBA_QUIC_VM_CPU_CORES:-2}"
DISK_SIZE_GIB="${SMOLDER_SAMBA_QUIC_DISK_SIZE_GIB:-40}"

SSH_PORT="${SMOLDER_SAMBA_QUIC_SSH_PORT:-2422}"
SMB_PORT="${SMOLDER_SAMBA_QUIC_HOST_PORT:-2445}"
QUIC_PORT="${SMOLDER_SAMBA_QUIC_QUIC_PORT:-2443}"

GUEST_HOSTNAME="${SMOLDER_SAMBA_QUIC_GUEST_HOSTNAME:-smolder-samba-quic}"
GUEST_USER="${SMOLDER_SAMBA_QUIC_GUEST_USER:-smolder}"
GUEST_PASSWORD="${SMOLDER_SAMBA_QUIC_GUEST_PASSWORD:-smolderpass}"

REPLACE_VM="${SMOLDER_SAMBA_QUIC_REPLACE_VM:-0}"
START_VM="${SMOLDER_SAMBA_QUIC_START_VM:-1}"
WAIT_FOR_SSH="${SMOLDER_SAMBA_QUIC_WAIT_FOR_SSH:-1}"

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 1
  fi
}

escape_applescript_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

download_image() {
  mkdir -p "$ARTIFACT_DIR"
  if [[ -f "$IMAGE_PATH" ]]; then
    printf 'using existing image: %s\n' "$IMAGE_PATH"
    return
  fi

  printf 'downloading cloud image: %s\n' "$IMAGE_URL"
  if command -v aria2c >/dev/null 2>&1; then
    aria2c -x 8 -d "$ARTIFACT_DIR" -o "$IMAGE_NAME" "$IMAGE_URL"
  else
    curl -fL --continue-at - -o "$IMAGE_PATH" "$IMAGE_URL"
  fi
}

ensure_ssh_key() {
  if [[ -f "$SSH_KEY_PATH" && -f "${SSH_KEY_PATH}.pub" ]]; then
    return
  fi
  ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY_PATH"
}

write_cloud_init_seed() {
  local public_key
  public_key="$(tr -d '\n' < "${SSH_KEY_PATH}.pub")"

  rm -rf "$SEED_DIR"
  mkdir -p "$SEED_DIR"

  cat > "${SEED_DIR}/meta-data" <<EOF
instance-id: ${VM_NAME}
local-hostname: ${GUEST_HOSTNAME}
EOF

  cat > "${SEED_DIR}/user-data" <<EOF
#cloud-config
hostname: ${GUEST_HOSTNAME}
manage_etc_hosts: true
ssh_pwauth: true
users:
  - default
  - name: ${GUEST_USER}
    gecos: Smolder QUIC
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: ${GUEST_PASSWORD}
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${public_key}
package_update: true
packages:
  - openssh-server
  - qemu-guest-agent
runcmd:
  - systemctl enable --now ssh
  - systemctl enable --now qemu-guest-agent
EOF

  rm -f "$SEED_ISO"
  hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata \
    -o "$SEED_ISO" "$SEED_DIR"
}

create_or_replace_vm() {
  local vm_name image_path seed_iso
  vm_name="$(escape_applescript_string "$VM_NAME")"
  image_path="$(escape_applescript_string "$IMAGE_PATH")"
  seed_iso="$(escape_applescript_string "$SEED_ISO")"

  osascript <<EOF
tell application "UTM"
    try
        set existingVm to virtual machine named "${vm_name}"
        if "${REPLACE_VM}" is "1" then
            try
                stop existingVm by kill
            end try
            delete existingVm
        else
            error "virtual machine already exists: ${vm_name}"
        end if
    end try

    set imageFile to POSIX file "${image_path}"
    set seedFile to POSIX file "${seed_iso}"
    set vm to make new virtual machine with properties {backend:qemu, configuration:{name:"${vm_name}", architecture:"aarch64", drives:{{source:imageFile}, {removable:true, source:seedFile}}}}
end tell
EOF
}

vm_bundle_path() {
  printf '%s/Library/Containers/com.utmapp.UTM/Data/Documents/%s.utm' "$HOME" "$VM_NAME"
}

patch_vm_bundle() {
  local bundle plist data_dir seed_name
  bundle="$(vm_bundle_path)"
  plist="${bundle}/config.plist"
  data_dir="${bundle}/Data"
  seed_name="$(basename "$SEED_ISO")"

  if [[ ! -f "$plist" ]]; then
    printf 'missing UTM config bundle: %s\n' "$plist" >&2
    exit 1
  fi

  mkdir -p "$data_dir"
  cp -f "$SEED_ISO" "${data_dir}/${seed_name}"

  /usr/libexec/PlistBuddy -c "Set :System:MemorySize ${VM_MEMORY_MIB}" "$plist"
  /usr/libexec/PlistBuddy -c "Set :QEMU:Hypervisor true" "$plist"
  /usr/libexec/PlistBuddy -c "Set :QEMU:UEFIBoot true" "$plist"
  if ! /usr/libexec/PlistBuddy -c "Set :Drive:1:ImageName ${seed_name}" "$plist" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Add :Drive:1:ImageName string ${seed_name}" "$plist"
  fi
  /usr/libexec/PlistBuddy -c "Set :Network:0:Mode Emulated" "$plist"
  /usr/libexec/PlistBuddy -c "Delete :Network:0:PortForward" "$plist" || true
  /usr/libexec/PlistBuddy -c "Add :Network:0:PortForward array" "$plist"

  add_port_forward "$plist" 0 TCP "$SSH_PORT" 22
  add_port_forward "$plist" 1 TCP "$SMB_PORT" 445
  add_port_forward "$plist" 2 UDP "$QUIC_PORT" 443
}

resize_guest_disk() {
  local bundle qcow_path data_dir
  bundle="$(vm_bundle_path)"
  data_dir="${bundle}/Data"
  qcow_path="$(find "${data_dir}" -maxdepth 1 -type f -name '*.qcow2' | head -n 1)"

  if [[ -z "$qcow_path" ]]; then
    printf 'missing guest qcow2 in %s\n' "$data_dir" >&2
    exit 1
  fi

  docker run --rm -v "${data_dir}:/data" debian:sid-slim sh -lc "\
    apt-get update >/dev/null && \
    apt-get install -y qemu-utils >/dev/null && \
    qemu-img resize /data/$(basename "$qcow_path") ${DISK_SIZE_GIB}G >/dev/null"
}

add_port_forward() {
  local plist="$1"
  local index="$2"
  local protocol="$3"
  local host_port="$4"
  local guest_port="$5"

  /usr/libexec/PlistBuddy -c "Add :Network:0:PortForward:${index} dict" "$plist"
  /usr/libexec/PlistBuddy -c "Add :Network:0:PortForward:${index}:Protocol string ${protocol}" "$plist"
  /usr/libexec/PlistBuddy -c "Add :Network:0:PortForward:${index}:HostAddress string 127.0.0.1" "$plist"
  /usr/libexec/PlistBuddy -c "Add :Network:0:PortForward:${index}:HostPort integer ${host_port}" "$plist"
  /usr/libexec/PlistBuddy -c "Add :Network:0:PortForward:${index}:GuestPort integer ${guest_port}" "$plist"
}

start_vm() {
  local vm_name
  vm_name="$(escape_applescript_string "$VM_NAME")"

  osascript <<EOF
tell application "UTM"
    start virtual machine named "${vm_name}"
end tell
EOF
}

reload_utm() {
  osascript <<EOF >/dev/null 2>&1 || true
tell application "UTM"
    quit
end tell
EOF

  local deadline
  deadline=$((SECONDS + 30))
  while pgrep -x UTM >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      break
    fi
    sleep 1
  done
}

wait_for_ssh() {
  local deadline now
  deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    if nc -vz 127.0.0.1 "$SSH_PORT" >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done

  printf 'timed out waiting for guest ssh on 127.0.0.1:%s\n' "$SSH_PORT" >&2
  exit 1
}

require_tool osascript
require_tool hdiutil
require_tool nc
require_tool ssh-keygen
require_tool /usr/libexec/PlistBuddy
require_tool docker

download_image
ensure_ssh_key
write_cloud_init_seed
create_or_replace_vm
patch_vm_bundle
resize_guest_disk
reload_utm

if [[ "$START_VM" == "1" ]]; then
  start_vm
fi

if [[ "$START_VM" == "1" && "$WAIT_FOR_SSH" == "1" ]]; then
  wait_for_ssh
fi

printf '\nUTM guest prepared.\n'
printf '  VM: %s\n' "$VM_NAME"
printf '  image: %s\n' "$IMAGE_PATH"
printf '  display: headless Ubuntu server; a black UTM window is expected\n'
printf '  ssh: ssh -i %s -p %s %s@127.0.0.1\n' "$SSH_KEY_PATH" "$SSH_PORT" "$GUEST_USER"
printf '  next: %s\n' "scripts/configure-samba-quic-utm.sh"
