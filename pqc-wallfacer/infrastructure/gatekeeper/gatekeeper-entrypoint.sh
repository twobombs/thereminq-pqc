#!/bin/sh
# Re-check the baked Merlin checkpoint against its pinned SHA-256 on every start (GATE-02),
# then run the gatekeeper. A mismatch stops the container; nothing runs unchecked.
set -eu
cd "$WF_MERLIN_DIR"
sha256sum --strict --quiet -c EXPECTED.sha256 \
    || { echo "gatekeeper: Merlin checkpoint hash mismatch, refusing to start" >&2; exit 1; }
cd /opt/gatekeeper
exec python3 -s gatekeeper.py
