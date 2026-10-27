#!/bin/sh
# Build every Wallfacer image in dependency order. Local only: nothing is pushed.
# Prints each image ID at the end; those IDs are what the offline signer signs (PRV-02).
set -eu
cd "$(dirname "$0")"

[ -f .env ] || { echo "build.sh: copy .env.example to .env and fill in the pins" >&2; exit 1; }
set -a; . ./.env; set +a

: "${LLAMA_CPP_REF:?set LLAMA_CPP_REF in .env}"
: "${MERLIN_REF:?set MERLIN_REF in .env}"
: "${ROSENPASS_VERSION:?set ROSENPASS_VERSION in .env}"

docker build --pull -t wallfacer/base:latest \
    --build-arg DEBIAN_IMAGE="$DEBIAN_IMAGE" base

docker build -t wallfacer/pki:latest pki

docker build -t wallfacer/gateway:latest \
    --build-arg RUST_IMAGE="$RUST_IMAGE" \
    --build-arg ROSENPASS_VERSION="$ROSENPASS_VERSION" gateway

docker build -t wallfacer/gatekeeper:latest \
    --build-arg MERLIN_REF="$MERLIN_REF" \
    --build-arg TORCH_VERSION="$TORCH_VERSION" gatekeeper

docker build -t wallfacer/inference:latest \
    --build-arg DEBIAN_IMAGE="$DEBIAN_IMAGE" \
    --build-arg LLAMA_CPP_REF="$LLAMA_CPP_REF" inference

docker build -t wallfacer/ui-door:latest ui-door

: "${THEREMINQ_JUPYTER_IMAGE:?set THEREMINQ_JUPYTER_IMAGE in .env}"
case "$THEREMINQ_JUPYTER_IMAGE" in
    *@sha256:*) ;;
    *) echo "build.sh: THEREMINQ_JUPYTER_IMAGE must be pinned by @sha256 digest (PRV-07)" >&2; exit 1 ;;
esac
docker build -t wallfacer/ui:latest \
    --build-arg THEREMINQ_JUPYTER_IMAGE="$THEREMINQ_JUPYTER_IMAGE" ui

echo
printf '%-26s %s\n' IMAGE ID
for i in base pki gateway gatekeeper inference ui-door ui; do
    printf '%-26s %s\n' "wallfacer/$i" "$(docker image inspect --format '{{.Id}}' "wallfacer/$i:latest")"
done
