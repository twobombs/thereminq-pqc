# syntax=docker/dockerfile:1.7
# pqc-web/edge-apache: dual certificate stack TLS edge (classical + ML-DSA) on Apache httpd 2.4 and OpenSSL 3.5.
# Build from web-ingress/:  docker build -f docker/apache/Dockerfile -t pqc-web/edge-apache .
# Pin the base by digest for production: --build-arg DEBIAN_IMAGE=debian:trixie-slim@sha256:...
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 openssl ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
RUN a2dissite -q 000-default \
 && for m in status autoindex cgid; do a2dismod -q -f "$m" >/dev/null 2>&1 || true; done \
 && a2enmod -q ssl proxy proxy_http proxy_wstunnel headers rewrite remoteip http2 socache_shmcb \
 && rm -f /etc/apache2/conf-enabled/other-vhosts-access-log.conf

# Refuse to build without OpenSSL >= 3.5 (mod_ssl links the system libssl), ML-DSA TLS sigalgs and ML-KEM.
RUN set -eu; \
    v="$(openssl version | awk '{print $2}')"; major="${v%%.*}"; rest="${v#*.}"; minor="${rest%%.*}"; \
    { [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 5 ]; }; } || { echo "OpenSSL $v < 3.5" >&2; exit 1; }; \
    openssl list -tls-signature-algorithms | grep -q mldsa65; \
    openssl list -kem-algorithms | grep -q ML-KEM-768; \
    ldd /usr/lib/apache2/modules/mod_ssl.so | grep -q 'libssl.so.3'; \
    echo "edge-apache: OpenSSL $v, $(apache2 -v | head -n 1)"

COPY lib/profile.sh lib/edge-common.sh profiles/profiles.env /usr/local/share/pqc-web/
COPY docker/apache/pqc-edge-apache /usr/local/bin/pqc-edge-apache
RUN chmod 0755 /usr/local/bin/pqc-edge-apache \
 && install -d -o www-data -g www-data -m 0750 /tmp/pqc-edge /etc/pqc/sites

ENV PQC_PROFILE=compat \
    PQC_SITES_DIR=/etc/pqc/sites \
    PQC_LISTEN_TLS=8443 \
    PQC_LISTEN_HTTP=8080 \
    PQC_RUN=/tmp/pqc-edge

USER www-data
EXPOSE 8443 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/pqc-edge-apache"]
CMD ["run"]
