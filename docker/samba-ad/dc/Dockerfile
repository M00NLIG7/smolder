FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dnsutils \
        iproute2 \
        krb5-user \
        procps \
        samba \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        tini \
        winbind \
    && rm -rf /var/lib/apt/lists/*

COPY bootstrap.sh /bootstrap.sh
RUN chmod +x /bootstrap.sh

ENTRYPOINT ["/usr/bin/tini", "--", "/bootstrap.sh"]
