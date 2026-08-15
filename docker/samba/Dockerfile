FROM debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

ARG DEBIAN_FRONTEND=noninteractive
ARG SAMBA_VERSION=2:4.22.10+dfsg-0+deb13u2
ARG TINI_VERSION=0.19.0-3+b7

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        "samba=${SAMBA_VERSION}" \
        "smbclient=${SAMBA_VERSION}" \
        "tini=${TINI_VERSION}" \
        "winbind=${SAMBA_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

COPY bootstrap.sh healthcheck.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/bootstrap.sh /usr/local/bin/healthcheck.sh

EXPOSE 139 445
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/bootstrap.sh"]
