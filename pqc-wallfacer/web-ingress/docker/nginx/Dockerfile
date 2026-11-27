# syntax=docker/dockerfile:1.7
# pqc-web/edge-nginx: dual certificate stack TLS edge (classical + ML-DSA) on nginx and OpenSSL 3.5.
# Build from web-ingress/:  docker build -f docker/nginx/Dockerfile -t pqc-web/edge-nginx .
# Pin the base by digest for production: --build-arg DEBIAN_IMAGE=debian:trixie-slim@sha256:...
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx openssl ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*

# Refuse to build without OpenSSL >= 3.5, ML-DSA TLS signature algorithms and ML-KEM hybrid groups.
RUN set -eu; \
    v="$(openssl version | awk '{print $2}')"; major="${v%%.*}"; rest="${v#*.}"; minor="${rest%%.*}"; \
    { [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 5 ]; }; } || { echo "OpenSSL $v < 3.5" >&2; exit 1; }; \
    openssl list -tls-signature-algorithms | grep -q mldsa65; \
    openssl list -kem-algorithms | grep -q ML-KEM-768; \
    nginx -V 2>&1 | grep -E 'OpenSSL 3\.([5-9]|[1-9][0-9])'; \
    echo "edge-nginx: OpenSSL $v, $(nginx -v 2>&1)"

COPY lib/profile.sh lib/edge-common.sh profiles/profiles.env /usr/local/share/pqc-web/
COPY docker/nginx/pqc-edge-nginx /usr/local/bin/pqc-edge-nginx
RUN chmod 0755 /usr/local/bin/pqc-edge-nginx \
 && install -d -o www-data -g www-data -m 0750 /tmp/pqc-edge /etc/pqc/sites

ENV PQC_PROFILE=compat \
    PQC_SITES_DIR=/etc/pqc/sites \
    PQC_LISTEN_TLS=8443 \
    PQC_LISTEN_HTTP=8080 \
    PQC_RUN=/tmp/pqc-edge

# Unprivileged: ports above 1024, writable state only under /tmp (an emptyDir in Kubernetes).
USER www-data
EXPOSE 8443 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/pqc-edge-nginx"]
CMD ["run"]
