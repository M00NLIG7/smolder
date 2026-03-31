FROM debian:sid-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssl \
        procps \
        samba \
        smbclient \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY bootstrap.sh /bootstrap.sh
RUN chmod +x /bootstrap.sh

ENTRYPOINT ["/usr/bin/tini", "--", "/bootstrap.sh"]
