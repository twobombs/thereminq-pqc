# syntax=docker/dockerfile:1.7
# wallfacer/gateway — dark perimeter: WireGuard + Rosenpass, nftables default drop (NET-01..NET-08, MSH-01..MSH-06).
#
# Runtime needs: host network, CAP_NET_ADMIN, and the wireguard kernel module on the host.
ARG BASE_IMAGE=wallfacer/base:latest
ARG RUST_IMAGE=rust:slim-trixie

# ---------- build Rosenpass from a pinned tag (NET-09) ----------
FROM ${RUST_IMAGE} AS build
ARG ROSENPASS_VERSION
RUN test -n "${ROSENPASS_VERSION}" || { echo "set ROSENPASS_VERSION (e.g. v0.2.2)" >&2; exit 1; }
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates cmake clang libclang-dev pkg-config libsodium-dev make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${ROSENPASS_VERSION}" https://github.com/rosenpass/rosenpass.git . \
 && cargo build --release --locked \
 && mkdir -p /out \
 && cp target/release/rosenpass /out/ \
 && if [ -x target/release/rp ]; then cp target/release/rp /out/; else cp rp /out/rp; fi \
 && /out/rosenpass --help >/dev/null

# ---------- runtime ----------
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      wireguard-tools nftables iproute2 libsodium23 bash procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/rosenpass /out/rp /usr/local/bin/
COPY gateway-entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
RUN chmod 0755 /usr/local/bin/gateway-entrypoint.sh /usr/local/bin/rp /usr/local/bin/rosenpass \
 && install -d -m 0700 /var/lib/wallfacer

# Root is required: rp creates the WireGuard interface and the entrypoint owns the nftables ruleset.
# Compose drops every capability except NET_ADMIN.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/gateway-entrypoint.sh"]
