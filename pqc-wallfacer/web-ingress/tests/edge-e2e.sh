#!/usr/bin/env bash
# edge-e2e.sh: runs on a Docker host. Builds nothing; expects pqc-web/tools, pqc-web/edge-nginx and
# pqc-web/edge-apache (tests/run-tests.sh builds them). For both edges and every profile: start the edge in
# front of an echo upstream with a read-only root filesystem and no capabilities, then check
# pqc-eval readiness, proxying, headers, unknown SNI, HTTP redirect and certificate hot reload.
set -uo pipefail

KIT=$(cd "$(dirname "$0")/.." && pwd)
NET=pqc-e2e-$$
WORK=$(mktemp -d)
chmod 0777 "$WORK"
PASS=0; FAILS=0
ok()  { PASS=$((PASS+1)); echo "  ok   $*"; }
bad() { FAILS=$((FAILS+1)); echo "  FAIL $*"; }
cleanup() { docker rm -f pqc-edge-$$ pqc-up-$$ >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

tools() { docker run --rm --network $NET -v "$WORK:/w" -v "$KIT/tests:/t:ro" -v "$KIT/profiles:/k/profiles:ro" -e PQC_CA_DIR=/w/ca pqc-web/tools bash -c "$1"; }

docker network create $NET >/dev/null
echo "== PKI"
tools '
set -e
cd /w
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout cca.key -out cca.crt -subj /CN=Classic-CA -days 30 \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
classic() { # site names...
  s=$1; shift; san=$(printf "DNS:%s," "$@"); san=${san%,}; mkdir -p sites/$s/classic
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout sites/$s/classic/tls.key -subj /CN=$1 -out c.csr 2>/dev/null
  printf "subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" "$san" > c.ext
  openssl x509 -req -in c.csr -CA cca.crt -CAkey cca.key -set_serial 0x$(openssl rand -hex 8) -days 30 -extfile c.ext -out sites/$s/classic/tls.crt 2>/dev/null
}
classic site site.test www.site.test
classic api api.site.test
pqc-ca init-root "E2E PQC Root" >/dev/null 2>&1
pqc-ca init-int "E2E PQC Issuing" --permit-dns site.test >/dev/null 2>&1
for s in "site site.test www.site.test" "api api.site.test"; do
  set -- $s; pqc-ca issue $s --out leaves >/dev/null 2>&1
  mkdir -p sites/$1/pqc; cp leaves/$1/fullchain.pem sites/$1/pqc/tls.crt; cp leaves/$1/privkey.pem sites/$1/pqc/tls.key
done
cat ca/trust/pqc-web-root.pem cca.crt > bundle.pem
chmod -R a+rX sites; chmod a+r sites/*/*/tls.key
' && ok "classical + ML-DSA certificates for site.test and api.site.test" || bad "PKI setup"

docker run -d --name pqc-up-$$ --network $NET --network-alias upstream -v "$KIT/tests:/t:ro" pqc-web/tools \
    python3 /t/upstream_echo.py 8000 >/dev/null

expect_for() {
    case "$1" in
        compat)    echo "level=L2* profile=compat default_client_gets=EC* pqc_verify=ok legacy_verify=ok" ;;
        pqc-first) echo "level=L2* profile=pqc-first default_client_gets=ML-DSA-65 pqc_verify=ok legacy_verify=ok" ;;
        pqc-only)  echo "level=L3* profile=pqc-only legacy_auth=none classical_kex_accepted=no tls12_accepted=no pqc_verify=ok" ;;
    esac
}

for server in nginx apache; do
  for prof in compat pqc-first pqc-only; do
    echo "== edge-$server $prof"
    docker rm -f pqc-edge-$$ >/dev/null 2>&1
    docker run -d --name pqc-edge-$$ --network $NET --network-alias edge \
        --read-only --tmpfs /tmp:uid=33,gid=33,mode=0750 --cap-drop ALL --security-opt no-new-privileges \
        -e PQC_PROFILE=$prof -e PQC_UPSTREAM=http://upstream:8000 -e PQC_RELOAD_INTERVAL=2 \
        -v "$WORK/sites:/etc/pqc/sites:ro" pqc-web/edge-$server >/dev/null
    up=no
    for _ in $(seq 1 30); do
        tools 'curl -fsS -o /dev/null http://edge:8080/healthz' 2>/dev/null && { up=yes; break; }
        sleep 1
    done
    if [ $up = no ]; then bad "edge-$server $prof did not become healthy"; docker logs pqc-edge-$$ 2>&1 | tail -20; continue; fi
    ok "edge-$server $prof healthy (read-only rootfs, no capabilities, uid 33)"

    # shellcheck disable=SC2046
    tools "pqc-eval --format json --timeout 5 --ca /w/ca/trust/pqc-web-root.pem --classic-ca /w/cca.crt --sni site.test edge:8443 > /w/e1.json
           pqc-eval --format json --timeout 5 --ca /w/ca/trust/pqc-web-root.pem --classic-ca /w/cca.crt --sni api.site.test edge:8443 > /w/e2.json
           python3 /t/assert_eval.py /w/e1.json $(expect_for $prof) && python3 /t/assert_eval.py /w/e2.json $(expect_for $prof)" \
        && ok "pqc-eval site.test + api.site.test match $prof" || bad "pqc-eval $server $prof"

    sigalg_flag=""; [ $prof = pqc-only ] && sigalg_flag="--sigalgs mldsa65"
    tools "ip=\$(getent hosts edge | cut -d' ' -f1)
           curl -fsS --cacert /w/bundle.pem --resolve site.test:8443:\$ip --resolve api.site.test:8443:\$ip https://site.test:8443/hello > /w/r1.json
           curl -fsS --cacert /w/bundle.pem --resolve api.site.test:8443:\$ip https://api.site.test:8443/v1 > /w/r2.json
           python3 -c 'import json,sys
r1=json.load(open(\"/w/r1.json\")); r2=json.load(open(\"/w/r2.json\"))
assert r1[\"headers\"][\"host\"].split(\":\")[0]==\"site.test\", r1
assert r1[\"path\"]==\"/hello\", r1
assert r1[\"headers\"][\"x-forwarded-proto\"]==\"https\", r1
assert r1[\"headers\"][\"x-pqc-tls-protocol\"]==\"TLSv1.3\", r1
assert r1[\"headers\"][\"x-forwarded-port\"]==\"443\", r1
assert r2[\"headers\"][\"host\"].split(\":\")[0]==\"api.site.test\", r2
g=r1[\"headers\"].get(\"x-pqc-tls-group\")
assert g is None or \"MLKEM\" in g.upper() or g in (\"0x11eb\", \"0x11ec\", \"0x11ed\"), r1
print(\"group header:\", g)'" \
        && ok "proxying, Host, X-Forwarded-Proto, TLS headers" || bad "proxy checks $server $prof"

    tools "ip=\$(getent hosts edge | cut -d' ' -f1)
           c=\$(curl -sk -o /dev/null -w '%{http_code}' --resolve unknown.test:8443:\$ip https://unknown.test:8443/)
           r=\$(curl -s -o /dev/null -w '%{http_code}' http://edge:8080/x)
           [ \"\$c\" = 421 ] && [ \"\$r\" = 301 ]" \
        && ok "unknown SNI gets 421, plain HTTP gets 301" || bad "421/301 $server $prof"

    tools "ip=\$(getent hosts edge | cut -d' ' -f1)
           OPENSSL_CONF=/k/profiles/client-pqc-strict.cnf curl -fsS -o /dev/null --cacert /w/ca/trust/pqc-web-root.pem \
               --resolve site.test:8443:\$ip https://site.test:8443/ &&
           { [ $prof != compat ] ||
             ! curl -fsS -o /dev/null --cacert /w/ca/trust/pqc-web-root.pem --resolve site.test:8443:\$ip https://site.test:8443/ 2>/dev/null; }" \
        && ok "strict client profile gets the ML-DSA chain (compat: default curl with PQC root only fails)" || bad "strict client $server $prof"

    if [ $prof = compat ]; then
        old=$(tools "openssl s_client -connect edge:8443 -servername site.test -sigalgs mldsa65 </dev/null 2>/dev/null | openssl x509 -noout -serial")
        tools 'cd /w && rm -rf leaves/site && pqc-ca issue site site.test www.site.test --out leaves >/dev/null 2>&1 &&
               cp leaves/site/fullchain.pem sites/site/pqc/tls.crt.new && cp leaves/site/privkey.pem sites/site/pqc/tls.key.new &&
               chmod a+r sites/site/pqc/*.new && mv sites/site/pqc/tls.key.new sites/site/pqc/tls.key && mv sites/site/pqc/tls.crt.new sites/site/pqc/tls.crt'
        sleep 7
        new=$(tools "openssl s_client -connect edge:8443 -servername site.test -sigalgs mldsa65 </dev/null 2>/dev/null | openssl x509 -noout -serial")
        [ -n "$old" ] && [ -n "$new" ] && [ "$old" != "$new" ] && ok "ML-DSA certificate rotation picked up without restart" \
            || { bad "rotation ($old -> $new)"; docker logs pqc-edge-$$ 2>&1 | tail -5; }
    fi
  done
done

echo
echo "edge-e2e: $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
