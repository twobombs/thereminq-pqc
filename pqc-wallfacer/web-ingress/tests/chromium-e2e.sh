#!/usr/bin/env bash
# chromium-e2e.sh: real Chromium (Debian 13 package) against both edge images in every profile, with the
# classical root, the PQC root, or both delivered through the CACertificates enterprise policy.
# Needs pqc-web/tools, pqc-web/edge-*, pqc-web/chromium (tests/run-tests.sh builds them).
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
NET=pqc-chr-$$; W=$(mktemp -d); chmod 777 $W
PASS=0; FAILS=0
expect() {   # profile trust -> LOADS|FAILS
    case "$1:$2" in
        compat:classic|compat:both) echo LOADS ;; compat:pqc) echo FAILS ;;
        pqc-first:classic|pqc-only:classic) echo FAILS ;; *) echo LOADS ;;
    esac
}
docker network create $NET >/dev/null 2>&1
docker run --rm -v $W:/w -e PQC_CA_DIR=/w/ca pqc-web/tools bash -c '
cd /w
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout cca.key -out cca.crt -subj /CN=Classic-CA -days 30 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
mkdir -p sites/site/classic sites/site/pqc
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout sites/site/classic/tls.key -subj /CN=site.test -out c.csr 2>/dev/null
printf "subjectAltName=DNS:site.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" > c.ext
openssl x509 -req -in c.csr -CA cca.crt -CAkey cca.key -set_serial 7 -days 30 -extfile c.ext -out sites/site/classic/tls.crt 2>/dev/null
pqc-ca init-root "Chr PQC Root" >/dev/null 2>&1; pqc-ca init-int "Chr PQC Int" --permit-dns site.test >/dev/null 2>&1
pqc-ca issue site site.test --out l >/dev/null 2>&1
cp l/site/fullchain.pem sites/site/pqc/tls.crt; cp l/site/privkey.pem sites/site/pqc/tls.key
chmod -R a+rX sites; chmod a+r sites/site/*/tls.key'
docker run -d --name pqc-chrup-$$ --network $NET --network-alias upstream -v $KIT/tests:/t:ro pqc-web/tools python3 /t/upstream_echo.py 8000 >/dev/null
for server in nginx apache; do for prof in compat pqc-first pqc-only; do
  docker rm -f pqc-chredge-$$ >/dev/null 2>&1
  docker run -d --name pqc-chredge-$$ --network $NET --network-alias edge -e PQC_PROFILE=$prof -e PQC_UPSTREAM=http://upstream:8000 -v $W/sites:/etc/pqc/sites:ro pqc-web/edge-$server >/dev/null
  sleep 3
  for trust in classic both pqc; do
    r=$(docker run --rm --network $NET -v $W:/w pqc-web/chromium bash -c "
      mkdir -p /etc/chromium/policies/managed; certs=''
      der(){ openssl x509 -in \$1 -outform DER | base64 -w0; }
      case $trust in classic) certs=\"\\\"\$(der /w/cca.crt)\\\"\" ;; pqc) certs=\"\\\"\$(der /w/ca/trust/pqc-web-root.pem)\\\"\" ;; both) certs=\"\\\"\$(der /w/cca.crt)\\\",\\\"\$(der /w/ca/trust/pqc-web-root.pem)\\\"\" ;; esac
      echo \"{\\\"CACertificates\\\": [\$certs]}\" > /etc/chromium/policies/managed/ca.json
      ip=\$(getent hosts edge | cut -d' ' -f1)
      timeout 25 chromium --headless=new --no-sandbox --disable-gpu --host-resolver-rules=\"MAP site.test \$ip\" --dump-dom https://site.test:8443/ok 2>/dev/null | grep -q '\"path\": \"/ok\"' && echo LOADS || echo FAILS")
    g=""; [ $server = nginx ] && g=$(docker logs pqc-chredge-$$ 2>&1 | grep -E 'Mozilla' | tail -1 | grep -oE 'TLSv1\.[23] [^ ]+' | head -1)
    want=$(expect $prof $trust)
    if [ "$r" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $server $prof roots=$trust: $r ${g:+($g)}"
    else FAILS=$((FAILS+1)); echo "  FAIL $server $prof roots=$trust: $r, want $want"; fi
  done
done; done
docker rm -f pqc-chredge-$$ pqc-chrup-$$ >/dev/null; docker network rm $NET >/dev/null
echo
echo "chromium-e2e: $PASS passed, $FAILS failed ($(docker run --rm pqc-web/chromium chromium --version))"
[ "$FAILS" -eq 0 ]
