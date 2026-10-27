#!/bin/sh
# Fail-closed model loader (PRV-05, CMP-02, WF-02).
#
# WF_MODEL_DIR (read-only mount) must be a wf-sign'ed directory holding exactly:
#   one .gguf file, model.meta, optionally chat_template.jinja, MANIFEST.sha384(.sig)
# The template is reviewed and signed with the weights; when present it replaces the
# template embedded in the GGUF, so an unreviewed template never runs.
set -eu

WF_MODEL_DIR=${WF_MODEL_DIR:-/models/current}
WF_ARTIFACT_PUB=${WF_ARTIFACT_PUB:-/trust/artifact.pub.pem}
WF_PORT=${WF_PORT:-8080}
WF_CTX=${WF_CTX:-8192}
WF_GPU_LAYERS=${WF_GPU_LAYERS:-999}       # CMP-09: keep weights VRAM-resident

wf-verify "$WF_MODEL_DIR" "$WF_ARTIFACT_PUB" || { echo "inference: model refused" >&2; exit 1; }

[ -f "$WF_MODEL_DIR/model.meta" ] || { echo "inference: model.meta missing (WF-01)" >&2; exit 1; }
n=$(find "$WF_MODEL_DIR" -maxdepth 1 -name '*.gguf' | wc -l)
[ "$n" -eq 1 ] || { echo "inference: expected exactly one .gguf, found $n" >&2; exit 1; }
MODEL=$(find "$WF_MODEL_DIR" -maxdepth 1 -name '*.gguf')

set -- --model "$MODEL" --host 0.0.0.0 --port "$WF_PORT" \
       --ctx-size "$WF_CTX" --n-gpu-layers "$WF_GPU_LAYERS"
if [ -f "$WF_MODEL_DIR/chat_template.jinja" ]; then
    set -- "$@" --jinja --chat-template-file "$WF_MODEL_DIR/chat_template.jinja"
fi

echo "inference: serving $(basename "$MODEL") ($(grep -E '^name=' "$WF_MODEL_DIR/model.meta" | cut -d= -f2-))"
exec llama-server "$@" ${WF_EXTRA_ARGS:-}
