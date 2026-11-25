# syntax=docker/dockerfile:1.7
# wallfacer/keyroll — offline paper QR key-roll encoder/decoder (air-gapped alternative
# to radio/IP relay for PQC private keys, Rosenpass static keys, and PSKs).
#
# Built with context = pqc-wallfacer/ (see build.sh). Runs with network_mode: none.
ARG BASE_IMAGE=wallfacer/base:latest

FROM ${BASE_IMAGE} AS build
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir \
      segno reportlab pillow zxing-cpp cryptography

FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 poppler-utils \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/venv /opt/venv
COPY wallfacer_paper_keyroll.py /usr/local/bin/wf-keyroll
RUN chmod 0755 /usr/local/bin/wf-keyroll \
 && install -d -o wf -g wf -m 0700 /keyroll

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER wf
WORKDIR /keyroll
VOLUME ["/keyroll"]
CMD ["wf-keyroll", "--help"]
