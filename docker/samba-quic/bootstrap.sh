#!/usr/bin/env bash
set -euo pipefail

SERVER_NAME="${SERVER_NAME:-files.lab.example}"
WORKGROUP="${WORKGROUP:-WORKGROUP}"
USERNAME="${USERNAME:-smolder}"
PASSWORD="${PASSWORD:-smolderpass}"
SHARE_NAME="${SHARE_NAME:-share}"
SHARE_DIR="${SHARE_DIR:-/srv/share}"
TLS_DIR="${TLS_DIR:-/var/lib/samba/private/tls}"

mkdir -p /run/samba /var/log/samba "${SHARE_DIR}" "${TLS_DIR}"
chmod 0777 "${SHARE_DIR}"

if ! id -u "${USERNAME}" >/dev/null 2>&1; then
  useradd -M -s /usr/sbin/nologin "${USERNAME}"
fi
printf '%s:%s\n' "${USERNAME}" "${PASSWORD}" | chpasswd

if ! pdbedit -L -u "${USERNAME}" >/dev/null 2>&1; then
  (printf '%s\n%s\n' "${PASSWORD}" "${PASSWORD}") | smbpasswd -s -a "${USERNAME}"
else
  (printf '%s\n%s\n' "${PASSWORD}" "${PASSWORD}") | smbpasswd -s "${USERNAME}"
fi

if [[ ! -f "${TLS_DIR}/key.pem" || ! -f "${TLS_DIR}/cert.pem" ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${TLS_DIR}/key.pem" \
    -out "${TLS_DIR}/cert.pem" \
    -days 3650 \
    -subj "/CN=${SERVER_NAME}"
fi

cat >/etc/samba/smb.conf <<EOF
[global]
    workgroup = ${WORKGROUP}
    security = user
    map to guest = never
    disable netbios = yes
    smb ports = 445
    server smb transports = +quic
    server min protocol = SMB2_02
    tls enabled = yes
    tls keyfile = ${TLS_DIR}/key.pem
    tls certfile = ${TLS_DIR}/cert.pem

[${SHARE_NAME}]
    path = ${SHARE_DIR}
    read only = no
    guest ok = no
    browsable = yes
    valid users = ${USERNAME}
    create mask = 0777
    directory mask = 0777
EOF

testparm -s /etc/samba/smb.conf >/dev/null
exec smbd -F --debug-stdout --no-process-group -d 3
