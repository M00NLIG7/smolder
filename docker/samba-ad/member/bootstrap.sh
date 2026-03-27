#!/usr/bin/env bash
set -euo pipefail

REALM="${REALM:-LAB.EXAMPLE}"
DOMAIN="${DOMAIN:-LAB}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Passw0rd!}"
DC_FQDN="${DC_FQDN:-dc1.lab.example}"
TEST_SHARE="${TEST_SHARE:-share}"
TEST_USER="${TEST_USER:-smolder}"

mkdir -p /run/samba /var/log/samba "/srv/share"
chmod 0777 "/srv/share"

cat >/etc/krb5.conf <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false

[realms]
    ${REALM} = {
        kdc = ${DC_FQDN}
        admin_server = ${DC_FQDN}
    }

[domain_realm]
    .lab.example = ${REALM}
    lab.example = ${REALM}
EOF

cat >/etc/samba/smb.conf <<EOF
[global]
    workgroup = ${DOMAIN}
    realm = ${REALM}
    security = ADS
    kerberos method = secrets and keytab
    dedicated keytab file = /etc/krb5.keytab
    server role = member server
    map to guest = Never
    winbind refresh tickets = yes
    winbind use default domain = yes
    idmap config * : backend = tdb
    idmap config * : range = 3000-7999
    idmap config ${DOMAIN} : backend = rid
    idmap config ${DOMAIN} : range = 10000-999999
    template shell = /bin/bash
    template homedir = /home/%D/%U

[${TEST_SHARE}]
    path = /srv/share
    read only = no
    guest ok = no
    browsable = yes
    force user = root
    create mask = 0777
    directory mask = 0777
EOF

until host -t SRV _ldap._tcp.lab.example "${DC_FQDN}" >/dev/null 2>&1; do
    sleep 2
done

net ads join -U "Administrator%${ADMIN_PASSWORD}"

winbindd -D
until wbinfo -t >/dev/null 2>&1; do
    sleep 1
done

exec smbd -F --debug-stdout --no-process-group -d 3
