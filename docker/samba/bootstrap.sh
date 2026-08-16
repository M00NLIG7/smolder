#!/usr/bin/env bash
set -euo pipefail

readonly fixture_user="smolder"
readonly fixture_group="smolder"
readonly fixture_password="smolderpass"
readonly fixture_domain="WORKGROUP"
readonly builtin_administrators_sid="S-1-5-32-544"

mkdir -p /run/samba /var/cache/samba /var/lib/samba/private /samba/share /samba/share-encrypted
getent group "${fixture_group}" >/dev/null || groupadd --gid 1000 "${fixture_group}"
id "${fixture_user}" >/dev/null 2>&1 || \
  useradd --uid 1000 --gid "${fixture_group}" --no-create-home \
    --shell /usr/sbin/nologin "${fixture_user}"

cat >/etc/samba/smb.conf <<EOF
[global]
    workgroup = ${fixture_domain}
    server string = Smolder Samba Test Fixture
    server role = standalone server
    security = user
    map to guest = never
    server min protocol = SMB2_10
    server signing = default
    server multi channel support = yes
    disable spoolss = yes
    printing = bsd
    printcap name = /dev/null
    load printers = no
    create mask = 0666
    force create mode = 0666
    directory mask = 0777
    force directory mode = 0777
    log level = 1
    log file = /dev/stdout
    max log size = 0
    disable netbios = ${SMOLDER_DISABLE_NETBIOS:-yes}
    smb ports = ${SMOLDER_SMB_PORTS:-445}
    server smb encrypt = ${SMOLDER_GLOBAL_ENCRYPTION:-default}
    passdb backend = tdbsam
    idmap config * : backend = tdb
    idmap config * : range = 10000-19999
    winbind enum users = yes
    winbind enum groups = yes

[share]
    path = /samba/share
    browsable = yes
    read only = no
    guest ok = no
    valid users = ${fixture_user}
    write list = ${fixture_user}
EOF

if [[ "${SMOLDER_INCLUDE_ENCRYPTED_SHARE:-0}" == "1" ]]; then
  cat >>/etc/samba/smb.conf <<EOF

[SMOLDERENC]
    path = /samba/share-encrypted
    browsable = yes
    read only = no
    guest ok = no
    valid users = ${fixture_user}
    write list = ${fixture_user}
    smb encrypt = required
EOF
fi

printf '%s\n%s\n' "${fixture_password}" "${fixture_password}" | \
  smbpasswd -a -s "${fixture_user}"
cat >/run/samba/fixture.auth <<EOF
username = ${fixture_user}
password = ${fixture_password}
domain = ${fixture_domain}
EOF
chmod 0600 /run/samba/fixture.auth
testparm -s >/dev/null

winbindd --foreground --no-process-group --debug-stdout &
winbind_pid=$!
smbd_pid=""
cleanup() {
  if [[ -n "${smbd_pid}" ]]; then
    kill -TERM "${smbd_pid}" 2>/dev/null || true
  fi
  kill -TERM "${winbind_pid}" 2>/dev/null || true
  if [[ -n "${smbd_pid}" ]]; then
    wait "${smbd_pid}" 2>/dev/null || true
  fi
  wait "${winbind_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

winbind_ready=0
for _ in $(seq 1 30); do
  if wbinfo -p >/dev/null 2>&1; then
    winbind_ready=1
    break
  fi
  if ! kill -0 "${winbind_pid}" 2>/dev/null; then
    echo "winbindd exited before fixture provisioning" >&2
    exit 1
  fi
  sleep 1
done
if [[ "${winbind_ready}" != "1" ]]; then
  echo "winbindd did not become ready for fixture provisioning" >&2
  exit 1
fi

if ! net groupmap list | grep -Fq "Administrators (${builtin_administrators_sid})"; then
  net sam createbuiltingroup Administrators
fi
if ! net sam addmem Administrators "${fixture_user}"; then
  net sam listmem Administrators | grep -Fq "${fixture_user}"
fi

smbd --foreground --no-process-group --debug-stdout &
smbd_pid=$!
wait -n "${smbd_pid}" "${winbind_pid}"
