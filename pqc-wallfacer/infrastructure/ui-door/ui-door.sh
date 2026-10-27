#!/bin/sh
# Relay 6080 (noVNC) and 8888 (Jupyter) to the UI container. Exits if either relay dies.
set -eu
UI_HOST=${WF_UI_HOST:-ui}
socat TCP-LISTEN:6080,fork,reuseaddr,max-children=32 "TCP:$UI_HOST:6080" &
P1=$!
socat TCP-LISTEN:8888,fork,reuseaddr,max-children=32 "TCP:$UI_HOST:8888" &
P2=$!
echo "ui-door: relaying :6080 and :8888 to $UI_HOST"
while kill -0 "$P1" 2>/dev/null && kill -0 "$P2" 2>/dev/null; do sleep 5; done
echo "ui-door: a relay exited" >&2
kill "$P1" "$P2" 2>/dev/null || true
exit 1
