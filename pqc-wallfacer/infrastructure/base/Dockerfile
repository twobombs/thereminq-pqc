# syntax=docker/dockerfile:1.7
# wallfacer/base — shared root for every Wallfacer image.
# Debian 13 (trixie) ships OpenSSL 3.5, which carries ML-KEM, ML-DSA and SLH-DSA natively (PKI-01).
# Pin the base by digest in .env (DEBIAN_IMAGE=debian:trixie-slim@sha256:...) before production builds.
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssl ca-certificates coreutils findutils tini \
 && rm -rf /var/lib/apt/lists/*

# PKI-01: refuse to build on anything older than OpenSSL 3.5, or without native ML-DSA-87 / ML-KEM-1024.
RUN set -eu; \
    v="$(openssl version | awk '{print $2}')"; \
    major="${v%%.*}"; rest="${v#*.}"; minor="${rest%%.*}"; \
    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 5 ]; }; then \
      echo "wallfacer/base: OpenSSL $v is older than 3.5" >&2; exit 1; \
    fi; \
    openssl list -signature-algorithms | grep -q 'ML-DSA-87'; \
    openssl list -kem-algorithms | grep -q 'ML-KEM-1024'; \
    echo "wallfacer/base: OpenSSL $v with ML-DSA-87 and ML-KEM-1024"

# PKI-05: TLS 1.3 only, hybrid PQC groups only. No classical-only key exchange.
COPY openssl-wallfacer.cnf /etc/ssl/openssl-wallfacer.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-wallfacer.cnf

# PRV-05: fail-closed verifier used by every loader.
COPY wf-verify /usr/local/bin/wf-verify

RUN chmod 0755 /usr/local/bin/wf-verify \
 && groupadd -g 10001 wf \
 && useradd -u 10001 -g wf -M -d /nonexistent -s /usr/sbin/nologin wf

USER wf
ENTRYPOINT ["/usr/bin/tini", "--"]
