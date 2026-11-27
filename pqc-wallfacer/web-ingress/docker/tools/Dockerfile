# syntax=docker/dockerfile:1.7
# pqc-web/tools: OpenSSL 3.5 client side for pqc-eval, pqc-ca, pqc-webconf and pqc-k8s.
# Use it wherever the host OpenSSL is older than 3.5 (Ubuntu 24.04 ships 3.0).
# Build from web-ingress/:  docker build -f docker/tools/Dockerfile -t pqc-web/tools .
#   optional: --build-arg KUBECTL_VERSION=v1.34.2 --build-arg KUBECTL_SHA256=<sha256 of the linux/amd64 binary>
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}

ARG KUBECTL_VERSION=""
ARG KUBECTL_SHA256=""
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates bash curl python3 coreutils tini \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    if [ -n "$KUBECTL_VERSION" ]; then \
      [ -n "$KUBECTL_SHA256" ] || { echo "KUBECTL_SHA256 required with KUBECTL_VERSION" >&2; exit 1; }; \
      curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"; \
      echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum -c -; \
      chmod 0755 /usr/local/bin/kubectl; \
    fi

RUN set -eu; \
    v="$(openssl version | awk '{print $2}')"; major="${v%%.*}"; rest="${v#*.}"; minor="${rest%%.*}"; \
    { [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 5 ]; }; } || { echo "OpenSSL $v < 3.5" >&2; exit 1; }

COPY bin/ /opt/pqc-web/bin/
COPY lib/ /opt/pqc-web/lib/
COPY profiles/ /opt/pqc-web/profiles/
RUN chmod 0755 /opt/pqc-web/bin/* \
 && groupadd -g 10001 pqc && useradd -u 10001 -g pqc -m -d /work -s /bin/bash pqc
ENV PATH=/opt/pqc-web/bin:$PATH
USER pqc
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]
