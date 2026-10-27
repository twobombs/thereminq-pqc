# syntax=docker/dockerfile:1.7
# wallfacer/ui — ThereminQ Jupyter desktop (twobombs/thereminq-tensors:jupyter) as the enclave UI.
#
# The upstream image is used as-is; only its boot script is replaced:
#   - Jupyter token and VNC password come from secrets (upstream: empty token, VNC 00000000)
#   - no xrdp, no PulseAudio, no model download at boot (upstream GITS-SAC.sh pulls GGUF
#     shards from Hugging Face and serves them unsigned on :9931; that breaks PRV-05/CMP-02)
#   - Ai clients (openai package, VS Code) point at the gatekeeper, which forwards to the
#     signed model in wallfacer/inference
#
# THEREMINQ_JUPYTER_IMAGE must be pinned by digest and imported via the quarantine host (PRV-07).
ARG THEREMINQ_JUPYTER_IMAGE
FROM ${THEREMINQ_JUPYTER_IMAGE}

COPY wf-run-ui /root/wf-run-ui
COPY vscode-settings.json /root/.config/Code/User/settings.json

# Remove the shipped default VNC password so nothing can start with it.
RUN chmod 0755 /root/wf-run-ui && rm -f /root/.vnc/passwd

ENV OPENAI_BASE_URL=http://gatekeeper:8443/v1 \
    OPENAI_API_BASE=http://gatekeeper:8443/v1 \
    OPENAI_API_KEY=wallfacer-local \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    DO_NOT_TRACK=1 \
    QRACK_LIB_PATH=/usr/local/lib/qrack/libqrack_pinvoke.so

EXPOSE 6080 8888
ENTRYPOINT ["/root/wf-run-ui"]
