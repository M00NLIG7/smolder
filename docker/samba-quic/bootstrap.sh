#!/usr/bin/env bash
set -euo pipefail

SERVER_NAME="${SERVER_NAME:-files.lab.example}"
WORKGROUP="${WORKGROUP:-WORKGROUP}"
USERNAME="${USERNAME:-smolder}"
PASSWORD="${PASSWORD:-smolderpass}"
SHARE_NAME="${SHARE_NAME:-share}"
SHARE_DIR="${SHARE_DIR:-/srv/share}"
TLS_DIR="${TLS_DIR:-/var/lib/samba/private/tls}"
TLS_SOURCE_DIR="${TLS_SOURCE_DIR:-/tls-input}"
SERVER_CA_SUBJECT="${SERVER_CA_SUBJECT:-/CN=Smolder Samba QUIC Root CA}"

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

if [[ -f "${TLS_SOURCE_DIR}/key.pem" && -f "${TLS_SOURCE_DIR}/cert.pem" ]]; then
  install -m 0600 -o root -g root "${TLS_SOURCE_DIR}/key.pem" "${TLS_DIR}/key.pem"
  install -m 0644 -o root -g root "${TLS_SOURCE_DIR}/cert.pem" "${TLS_DIR}/cert.pem"
  if [[ -f "${TLS_SOURCE_DIR}/ca.pem" ]]; then
    install -m 0644 -o root -g root "${TLS_SOURCE_DIR}/ca.pem" "${TLS_DIR}/ca.pem"
  fi
elif [[ ! -f "${TLS_DIR}/key.pem" || ! -f "${TLS_DIR}/cert.pem" ]]; then
  EXT_FILE="${TLS_DIR}/server-ext.cnf"
  CSR_FILE="${TLS_DIR}/server.csr"
  SERIAL_FILE="${TLS_DIR}/ca.srl"

  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${TLS_DIR}/ca-key.pem" \
    -out "${TLS_DIR}/ca.pem" \
    -days 3650 \
    -subj "${SERVER_CA_SUBJECT}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

  openssl req -nodes -newkey rsa:2048 \
    -keyout "${TLS_DIR}/key.pem" \
    -out "${CSR_FILE}" \
    -subj "/CN=${SERVER_NAME}" \
    -addext "subjectAltName=DNS:${SERVER_NAME}"

  cat > "${EXT_FILE}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_NAME}
EOF

  openssl x509 -req -days 3650 \
    -in "${CSR_FILE}" \
    -CA "${TLS_DIR}/ca.pem" \
    -CAkey "${TLS_DIR}/ca-key.pem" \
    -CAcreateserial \
    -CAserial "${SERIAL_FILE}" \
    -out "${TLS_DIR}/cert.pem" \
    -extfile "${EXT_FILE}"

  rm -f "${CSR_FILE}" "${EXT_FILE}" "${SERIAL_FILE}"
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
