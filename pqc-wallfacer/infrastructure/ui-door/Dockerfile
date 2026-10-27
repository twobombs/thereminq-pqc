# syntax=docker/dockerfile:1.7
# wallfacer/ui-door — two TCP relays from the WireGuard-facing publish address to the UI.
# The UI itself stays on an internal network with no route out; only this small,
# code-free relay sits on a publishable bridge, and the gateway's forward policy stops
# that bridge from reaching anything but the tunnel.
ARG BASE_IMAGE=wallfacer/base:latest
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat \
 && rm -rf /var/lib/apt/lists/*
COPY ui-door.sh /usr/local/bin/ui-door.sh
RUN chmod 0755 /usr/local/bin/ui-door.sh
USER wf
EXPOSE 6080 8888
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ui-door.sh"]
