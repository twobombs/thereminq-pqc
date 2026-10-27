# syntax=docker/dockerfile:1.7
# wallfacer/gatekeeper — LLM firewall + Merlin tool-call scoring on CPU (GATE-01..GATE-08, FW-01..FW-04).
# No GPU stack: Merlin is a 70.8M-parameter DeBERTa encoder and runs on CPU.
ARG BASE_IMAGE=wallfacer/base:latest

# ---------- build: venv, CPU torch, Merlin reference package, pinned checkpoint ----------
FROM ${BASE_IMAGE} AS build
ARG MERLIN_REF
ARG TORCH_VERSION=2.9.0
ARG MERLIN_HF_REVISION=21b6f2cc381dd036160bf237877780bca72ceea5
ARG MERLIN_SAFETENSORS_SHA256=075d68f8bb4c1b4b98e2d2b2c0d5b013056b202172b080b34e7364b698844c86
USER root
RUN test -n "${MERLIN_REF}" || { echo "set MERLIN_REF to a kontext-security/merlin commit" >&2; exit 1; }
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv git \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir "torch==${TORCH_VERSION}" --index-url https://download.pytorch.org/whl/cpu \
 && /opt/venv/bin/pip install --no-cache-dir "git+https://github.com/kontext-security/merlin@${MERLIN_REF}" huggingface_hub
RUN /opt/venv/bin/python -c "from huggingface_hub import snapshot_download; \
snapshot_download('kontext-security/Merlin', revision='${MERLIN_HF_REVISION}', local_dir='/opt/merlin-model')" \
 && rm -rf /opt/merlin-model/.cache \
 && echo "${MERLIN_SAFETENSORS_SHA256}  /opt/merlin-model/model.safetensors" | sha256sum -c - \
 && echo "${MERLIN_SAFETENSORS_SHA256}  model.safetensors" > /opt/merlin-model/EXPECTED.sha256

# ---------- runtime ----------
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 libgomp1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/merlin-model /opt/merlin-model
COPY firewall.py gatekeeper.py /opt/gatekeeper/
COPY policy.example.json /etc/wallfacer/policy.json
COPY gatekeeper-entrypoint.sh /usr/local/bin/gatekeeper-entrypoint.sh
RUN chmod 0755 /usr/local/bin/gatekeeper-entrypoint.sh

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    WF_MERLIN_DIR=/opt/merlin-model

USER wf
WORKDIR /opt/gatekeeper
EXPOSE 8443
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/gatekeeper-entrypoint.sh"]
