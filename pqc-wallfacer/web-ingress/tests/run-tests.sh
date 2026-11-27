#!/usr/bin/env bash
# run-tests.sh: builds the three images and runs every test suite. Needs Docker; nothing is pushed.
#   tests/run-tests.sh            all suites
#   tests/run-tests.sh webconf    one suite: webconf | edge | chromium | k8s
set -uo pipefail
KIT=$(cd "$(dirname "$0")/.." && pwd)
cd "$KIT"
DEBIAN_IMAGE=${DEBIAN_IMAGE:-debian:trixie-slim}
only=${1:-all}
rc=0

echo "== build"
for i in nginx apache tools; do
    tag=pqc-web/edge-$i; [ $i = tools ] && tag=pqc-web/tools
    docker build -q --build-arg DEBIAN_IMAGE="$DEBIAN_IMAGE" -f docker/$i/Dockerfile -t $tag . >/dev/null \
        && echo "  ok   $tag" || { echo "  FAIL build $tag"; exit 1; }
done
docker build -q -t pqc-web/chromium -f tests/Dockerfile.chromium tests >/dev/null \
    && echo "  ok   pqc-web/chromium" || { echo "  FAIL build chromium"; exit 1; }
docker build -q --build-arg DEBIAN_IMAGE="$DEBIAN_IMAGE" -t pqc-web/testbed -f tests/Dockerfile.testbed tests >/dev/null \
    && echo "  ok   pqc-web/testbed" || { echo "  FAIL build testbed"; exit 1; }

if [ "$only" = all ] || [ "$only" = webconf ]; then
    echo "== pqc-ca, pqc-eval, pqc-webconf on nginx and Apache hosts"
    docker run --rm -v "$KIT:/k:ro" pqc-web/testbed bash /k/tests/webconf-e2e.sh || rc=1
fi
if [ "$only" = all ] || [ "$only" = edge ]; then
    echo "== edge images"
    bash tests/edge-e2e.sh || rc=1
fi
if [ "$only" = all ] || [ "$only" = chromium ]; then
    echo "== Chromium against the edge images"
    bash tests/chromium-e2e.sh || rc=1
fi
if [ "$only" = all ] || [ "$only" = k8s ]; then
    echo "== pqc-k8s (stub kubectl) and manifests"
    W=$(mktemp -d); chmod 0777 "$W"
    docker run --rm -v "$W:/w" -v "$KIT/tests:/t:ro" pqc-web/tools bash /t/k8s-offline.sh || rc=1
    if python3 -c 'import yaml' 2>/dev/null; then
        python3 tests/validate_k8s.py k8s "$W/k8s-out" || rc=1
    else
        echo "  skip manifest validation (python3 PyYAML not installed)"
    fi
    rm -rf "$W"
fi
echo
[ $rc -eq 0 ] && echo "run-tests: all suites passed" || echo "run-tests: FAILURES"
exit $rc
