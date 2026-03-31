#!/usr/bin/env bash
set -euo pipefail

vm_name="${SMOLDER_WINDOWS_QUIC_VM:-SmolderServer2025}"
iso_path="${SMOLDER_WINDOWS_QUIC_ISO:-${1:-}}"
ostype="${SMOLDER_WINDOWS_QUIC_OSTYPE:-Windows2025_64}"
cpus="${SMOLDER_WINDOWS_QUIC_CPUS:-4}"
memory_mb="${SMOLDER_WINDOWS_QUIC_MEMORY_MB:-8192}"
disk_mb="${SMOLDER_WINDOWS_QUIC_DISK_MB:-131072}"
quic_host_port="${SMOLDER_WINDOWS_QUIC_HOST_PORT:-443}"
rdp_host_port="${SMOLDER_WINDOWS_QUIC_RDP_PORT:-3389}"
disk_path="${SMOLDER_WINDOWS_QUIC_DISK:-$HOME/VirtualBox VMs/${vm_name}/${vm_name}.vdi}"
server_name="${SMOLDER_WINDOWS_QUIC_SERVER_NAME:-files.lab.example}"

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    printf '%s is required\n' "$name" >&2
    exit 1
  fi
}

require_cmd VBoxManage

host_arch="$(uname -m)"
if [[ "$host_arch" == "arm64" ]]; then
  printf 'VirtualBox on this ARM host cannot run the x64 Windows Server evaluation ISO.\n' >&2
  printf 'Use an x86_64 host, or provide a separate emulation/virtualization path outside this script.\n' >&2
  exit 1
fi

if [[ -z "$iso_path" ]]; then
  printf 'usage: %s /path/to/windows-server-2025.iso\n' "${0##*/}" >&2
  printf 'or set SMOLDER_WINDOWS_QUIC_ISO\n' >&2
  exit 1
fi

if [[ ! -f "$iso_path" ]]; then
  printf 'windows server iso not found: %s\n' "$iso_path" >&2
  exit 1
fi

if VBoxManage showvminfo "$vm_name" >/dev/null 2>&1; then
  printf 'vm %s already exists\n' "$vm_name" >&2
  printf 'inspect it with: VBoxManage showvminfo "%s"\n' "$vm_name"
  exit 1
fi

mkdir -p "$(dirname "$disk_path")"

VBoxManage createvm --name "$vm_name" --ostype "$ostype" --register
VBoxManage modifyvm "$vm_name" \
  --cpus "$cpus" \
  --memory "$memory_mb" \
  --vram 32 \
  --firmware efi \
  --chipset ich9 \
  --ioapic on \
  --audio-enabled off \
  --clipboard-mode disabled \
  --drag-and-drop disabled \
  --nic1 nat

VBoxManage storagectl "$vm_name" --name "SATA" --add sata --controller IntelAhci
VBoxManage createmedium disk --filename "$disk_path" --size "$disk_mb" --format VDI
VBoxManage storageattach "$vm_name" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$disk_path"
VBoxManage storageattach "$vm_name" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium "$iso_path"

VBoxManage modifyvm "$vm_name" --boot1 dvd --boot2 disk --boot3 none --boot4 none

VBoxManage modifyvm "$vm_name" --natpf1 delete "quic443udp" >/dev/null 2>&1 || true
VBoxManage modifyvm "$vm_name" --natpf1 delete "rdp3389" >/dev/null 2>&1 || true
VBoxManage modifyvm "$vm_name" --natpf1 "quic443udp,udp,,${quic_host_port},,443"
VBoxManage modifyvm "$vm_name" --natpf1 "rdp3389,tcp,,${rdp_host_port},,3389"

printf 'Created VM %s\n' "$vm_name"
printf '  ISO: %s\n' "$iso_path"
printf '  Disk: %s\n' "$disk_path"
printf '  QUIC NAT: udp 127.0.0.1:%s -> guest:443\n' "$quic_host_port"
printf '  RDP NAT:  tcp 127.0.0.1:%s -> guest:3389\n' "$rdp_host_port"
printf '\nNext steps:\n'
printf '1. Start the installer:\n'
printf '   VBoxManage startvm "%s" --type gui\n' "$vm_name"
printf '2. Install Windows Server 2025 with Desktop Experience.\n'
printf '3. In the guest, run scripts/configure-windows-quic-server.ps1 with:\n'
printf "   -ServerName '%s' -ShareName 'smolder' -LocalUsername 'smolder'\n" "$server_name"
printf '4. Copy the exported certificate from the guest to the host and trust it.\n'
printf '5. Add a hosts entry for %s -> 127.0.0.1 if needed.\n' "$server_name"
printf '6. Export SMOLDER_WINDOWS_QUIC_* and run scripts/run-windows-quic-interop.sh\n'
