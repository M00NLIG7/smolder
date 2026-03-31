#!/usr/bin/env bash
set -euo pipefail

vm_name="${SMOLDER_WINDOWS_VM:-Tiny11}"
nat_adapter="${SMOLDER_WINDOWS_NAT_ADAPTER:-natpf1}"
nat_rule="${SMOLDER_WINDOWS_NATPF_RULE:-smb445}"
windows_host="${SMOLDER_WINDOWS_HOST:-127.0.0.1}"
host_port="${SMOLDER_WINDOWS_HOST_PORT:-${SMOLDER_WINDOWS_PORT:-445}}"
guest_port="${SMOLDER_WINDOWS_GUEST_PORT:-445}"
smb_wait_seconds="${SMOLDER_WINDOWS_SMB_WAIT_SECONDS:-45}"
initial_smb_wait_seconds="${SMOLDER_WINDOWS_SMB_INITIAL_WAIT_SECONDS:-30}"
windows_username="${SMOLDER_WINDOWS_USERNAME:-}"
windows_password="${SMOLDER_WINDOWS_PASSWORD:-}"

if ! command -v VBoxManage >/dev/null 2>&1; then
  printf 'VBoxManage is required to manage the Tiny11 fixture\n' >&2
  exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
  printf 'nc is required to probe the Tiny11 SMB endpoint\n' >&2
  exit 1
fi

vm_info="$(VBoxManage showvminfo "$vm_name" --machinereadable)"
vm_state="$(printf '%s\n' "$vm_info" | sed -n 's/^VMState=\"\([^\"]*\)\"$/\1/p')"
named_rule_pattern="^Forwarding\\([0-9]+\\)=\"${nat_rule},tcp,([^,]*),${host_port},([^,]*),${guest_port}\"$"
equivalent_rule_pattern="^Forwarding\\([0-9]+\\)=\"[^\"]+,tcp,(|127\\.0\\.0\\.1),${host_port},,${guest_port}\"$"

if [[ "$vm_state" != "running" ]]; then
  printf 'fixture VM %s must be running, current state is %s\n' "$vm_name" "${vm_state:-unknown}" >&2
  exit 1
fi

if printf '%s\n' "$vm_info" | grep -Eq "$named_rule_pattern"; then
  printf 'Tiny11 NAT rule %s already maps host %s to guest %s\n' "$nat_rule" "$host_port" "$guest_port"
elif printf '%s\n' "$vm_info" | grep -Eq "$equivalent_rule_pattern"; then
  printf 'Tiny11 NAT forward already maps host %s to guest %s\n' "$host_port" "$guest_port"
else
  printf 'Adding Tiny11 NAT forward %s on %s (%s -> %s)\n' "$nat_rule" "$nat_adapter" "$host_port" "$guest_port"
  VBoxManage controlvm "$vm_name" "$nat_adapter" "${nat_rule},tcp,,${host_port},,${guest_port}"
fi

if nc -vz "$windows_host" "$host_port" >/dev/null 2>&1; then
  printf 'Tiny11 SMB endpoint %s:%s is reachable\n' "$windows_host" "$host_port"
  exit 0
fi

initial_attempts=$(((initial_smb_wait_seconds + 2) / 3))
for _attempt in $(seq 1 "$initial_attempts"); do
  sleep 3
  if nc -vz "$windows_host" "$host_port" >/dev/null 2>&1; then
    printf 'Tiny11 SMB endpoint %s:%s became reachable during initial wait\n' "$windows_host" "$host_port"
    exit 0
  fi
done

if [[ -z "$windows_username" || -z "$windows_password" ]]; then
  printf 'Tiny11 SMB endpoint %s:%s is unreachable and SMOLDER_WINDOWS_USERNAME / SMOLDER_WINDOWS_PASSWORD are not set\n' \
    "$windows_host" "$host_port" >&2
  exit 1
fi

powershell_exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
powershell_cmd="\$ErrorActionPreference = 'Continue'; try { Set-Service -Name LanmanServer -StartupType Automatic } catch { Write-Warning ('Set-Service LanmanServer failed: ' + \$_.Exception.Message) }; try { if ((Get-Service -Name LanmanServer).Status -ne 'Running') { Start-Service -Name LanmanServer } } catch { Write-Warning ('Start-Service LanmanServer failed: ' + \$_.Exception.Message) }; try { Set-SmbServerConfiguration -EncryptData \$true -Force | Out-Null } catch { Write-Warning ('Set-SmbServerConfiguration failed: ' + \$_.Exception.Message) }; try { Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Out-Null } catch { Write-Warning ('Enable-NetFirewallRule failed: ' + \$_.Exception.Message) }; Write-Output ((Get-Service -Name LanmanServer).Status)"

printf 'Configuring Tiny11 SMB service and firewall rules via guestcontrol\n'
if ! VBoxManage guestcontrol "$vm_name" run \
  --exe "$powershell_exe" \
  --username "$windows_username" \
  --password "$windows_password" \
  --wait-stdout \
  --wait-stderr \
  -- -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$powershell_cmd"; then
  printf 'Tiny11 guestcontrol recovery did not complete cleanly; continuing to wait for SMB readiness\n' >&2
fi

attempts=$(((smb_wait_seconds + 2) / 3))
for _attempt in $(seq 1 "$attempts"); do
  if nc -vz "$windows_host" "$host_port" >/dev/null 2>&1; then
    printf 'Tiny11 SMB endpoint %s:%s is reachable\n' "$windows_host" "$host_port"
    exit 0
  fi
  sleep 3
done

printf 'Tiny11 SMB endpoint %s:%s is still unreachable after guest configuration\n' \
  "$windows_host" "$host_port" >&2
exit 1
