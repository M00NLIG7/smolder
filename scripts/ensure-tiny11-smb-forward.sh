#!/usr/bin/env bash
set -euo pipefail

vm_name="${SMOLDER_WINDOWS_VM:-Tiny11}"
nat_adapter="${SMOLDER_WINDOWS_NAT_ADAPTER:-natpf1}"
nat_rule="${SMOLDER_WINDOWS_NATPF_RULE:-smb445}"
host_port="${SMOLDER_WINDOWS_HOST_PORT:-445}"
guest_port="${SMOLDER_WINDOWS_GUEST_PORT:-445}"

if ! command -v VBoxManage >/dev/null 2>&1; then
  printf 'VBoxManage is required to manage the Tiny11 fixture\n' >&2
  exit 1
fi

vm_info="$(VBoxManage showvminfo "$vm_name" --machinereadable)"
vm_state="$(printf '%s\n' "$vm_info" | sed -n 's/^VMState=\"\([^\"]*\)\"$/\1/p')"
forward_pattern=",tcp,,${host_port},,${guest_port}\""

if [[ "$vm_state" != "running" ]]; then
  printf 'fixture VM %s must be running, current state is %s\n' "$vm_name" "${vm_state:-unknown}" >&2
  exit 1
fi

if printf '%s\n' "$vm_info" | grep -Fq "$forward_pattern"; then
  printf 'Tiny11 NAT forward already maps host %s to guest %s\n' "$host_port" "$guest_port"
  exit 0
fi

printf 'Adding Tiny11 NAT forward %s on %s (%s -> %s)\n' "$nat_rule" "$nat_adapter" "$host_port" "$guest_port"
VBoxManage controlvm "$vm_name" "$nat_adapter" "${nat_rule},tcp,,${host_port},,${guest_port}"
