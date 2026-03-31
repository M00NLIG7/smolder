#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${1:-/opt/smolder-samba-quic}"
SERVER_NAME="${SMOLDER_SAMBA_QUIC_SERVER_NAME:-files.lab.example}"
USERNAME="${SMOLDER_SAMBA_QUIC_USERNAME:-smolder}"
PASSWORD="${SMOLDER_SAMBA_QUIC_PASSWORD:-smolderpass}"
WORKGROUP="${SMOLDER_SAMBA_QUIC_WORKGROUP:-WORKGROUP}"
SHARE_NAME="${SMOLDER_SAMBA_QUIC_SHARE_NAME:-share}"

CERT_DIR="${WORK_DIR}/certs"
SHARE_DIR="${WORK_DIR}/share"
QUIC_SRC_DIR="/opt/quic"
SERVER_CA_SUBJECT="${SMOLDER_SAMBA_QUIC_CA_SUBJECT:-/CN=Smolder Samba QUIC Root CA}"

export DEBIAN_FRONTEND=noninteractive

dpkg --configure -a || true
apt-get -f install -y || true
apt-get update
apt-get install -y \
  autoconf \
  automake \
  build-essential \
  ca-certificates \
  curl \
  docker-compose-v2 \
  docker.io \
  git \
  htop \
  ktls-utils \
  libgnutls28-dev \
  libtool \
  linux-headers-$(uname -r) \
  openssl \
  pkg-config

systemctl enable --now docker

mkdir -p "$CERT_DIR" "$SHARE_DIR"
if [[ ! -f "${CERT_DIR}/ca.pem" || ! -f "${CERT_DIR}/ca-key.pem" || ! -f "${CERT_DIR}/key.pem" || ! -f "${CERT_DIR}/cert.pem" ]]; then
  EXT_FILE="${CERT_DIR}/server-ext.cnf"
  CSR_FILE="${CERT_DIR}/server.csr"
  SERIAL_FILE="${CERT_DIR}/ca.srl"

  openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
    -subj "${SERVER_CA_SUBJECT}" \
    -keyout "${CERT_DIR}/ca-key.pem" \
    -out "${CERT_DIR}/ca.pem" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

  openssl req -nodes -newkey rsa:4096 \
    -subj "/CN=${SERVER_NAME}" \
    -keyout "${CERT_DIR}/key.pem" \
    -out "${CSR_FILE}" \
    -addext "subjectAltName=DNS:${SERVER_NAME}"

  cat > "${EXT_FILE}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_NAME}
EOF

  openssl x509 -req -days 365 \
    -in "${CSR_FILE}" \
    -CA "${CERT_DIR}/ca.pem" \
    -CAkey "${CERT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -CAserial "${SERIAL_FILE}" \
    -out "${CERT_DIR}/cert.pem" \
    -extfile "${EXT_FILE}"

  rm -f "${CSR_FILE}" "${EXT_FILE}" "${SERIAL_FILE}"
fi

install -m 0644 "${CERT_DIR}/ca.pem" /usr/local/share/ca-certificates/smolder-samba-quic-ca.crt
update-ca-certificates

mkdir -p /etc/tlshd
cat > /etc/tlshd/config <<EOF
[debug]
loglevel=0
tls=0
nl=0

[authenticate]
keyrings=quic

[authenticate.server]
x509.truststore=${CERT_DIR}/ca.pem
x509.certificate=${CERT_DIR}/cert.pem
x509.private_key=${CERT_DIR}/key.pem
EOF

if [[ ! -f /tmp/quic-src.tar.gz ]]; then
  printf 'missing /tmp/quic-src.tar.gz\n' >&2
  exit 1
fi

rm -rf "$QUIC_SRC_DIR"
mkdir -p "$QUIC_SRC_DIR"
tar -xzf /tmp/quic-src.tar.gz --strip-components=1 -C "$QUIC_SRC_DIR"

pushd "$QUIC_SRC_DIR" >/dev/null
./autogen.sh
./configure --prefix=/usr
make -j"$(nproc)"
make install
depmod -a
popd >/dev/null

modprobe quic
systemctl enable --now tlshd

SMOLDER_SAMBA_QUIC_HOST_SMB_PORT=445 \
SMOLDER_SAMBA_QUIC_HOST_QUIC_PORT=443 \
SERVER_NAME="${SERVER_NAME}" \
WORKGROUP="${WORKGROUP}" \
USERNAME="${USERNAME}" \
PASSWORD="${PASSWORD}" \
SHARE_NAME="${SHARE_NAME}" \
docker compose -f "${WORK_DIR}/compose.yaml" up -d --build

printf '\nGuest setup complete.\n'
printf '  server name: %s\n' "$SERVER_NAME"
printf '  cert: %s\n' "${CERT_DIR}/cert.pem"
printf '  quic module: '
lsmod | awk '$1 == "quic" {print $1}'
