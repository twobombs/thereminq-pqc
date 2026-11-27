#!/usr/bin/env bash
# webconf-e2e.sh: runs INSIDE the testbed container (Debian trixie with nginx, apache2, openssl 3.5, python3).
# Installs the fixtures into /etc/nginx and /etc/apache2, issues classical and ML-DSA certificates,
# then for each server and each profile: pqc-webconf migrate --apply, start the server, pqc-eval, assert.
# Also covers: idempotent re-run, profile switch, remove, byte-exact rollback, skipped vhosts.
set -uo pipefail

K=${K:-/k}
B=$K/bin
F=$K/tests/fixtures
W=/tmp/w
PASS=0; FAILS=0
ok()   { PASS=$((PASS+1)); echo "  ok   $*"; }
bad()  { FAILS=$((FAILS+1)); echo "  FAIL $*"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

mkdir -p $W /etc/ssl/fixture /etc/pqc/certs
export PQC_CA_DIR=$W/ca PQC_BACKUP_ROOT=$W/backups

echo "== certificates"
# classical CA + leaves (stand-in for the existing, presumed-forgeable WebPKI chain)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $W/cca.key -out $W/cca.crt \
    -subj /CN=Classic-Test-CA -days 30 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
leaf() {   # name sans...
    local n=$1; shift; local san; san=$(printf 'DNS:%s,' "$@"); san=${san%,}
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /etc/ssl/fixture/$n.key \
        -subj /CN=$1 -out $W/$n.csr 2>/dev/null
    printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$san" > $W/$n.ext
    openssl x509 -req -in $W/$n.csr -CA $W/cca.crt -CAkey $W/cca.key -set_serial 0x$(openssl rand -hex 8) -days 30 \
        -extfile $W/$n.ext -out /etc/ssl/fixture/$n.crt 2>/dev/null
}
leaf a a.test www.a.test; leaf b b.test; leaf c c.test; leaf d d.test; leaf e e.test
openssl req -x509 -newkey rsa:2048 -nodes -keyout $W/e-rsa.key -out $W/e-rsa.crt -subj /CN=e.test \
    -addext subjectAltName=DNS:e.test -days 30 2>/dev/null
cat $W/e-rsa.crt $W/e-rsa.key > /etc/ssl/fixture/e-rsa-combined.pem
chmod 0644 /etc/ssl/fixture/*

$B/pqc-ca init-root "Test PQC Web Root" >/dev/null 2>&1
$B/pqc-ca init-int "Test PQC Web Issuing" --permit-dns test >/dev/null 2>&1
for s in "a.test a.test www.a.test" "b.test b.test" "c.test c.test" "d.test d.test"; do
    # shellcheck disable=SC2086
    $B/pqc-ca issue $s --out /etc/pqc/certs >/dev/null 2>&1 || bad "issue $s"
done
chmod 0644 /etc/pqc/certs/*/privkey.pem   # test only: nginx workers read keys as root here anyway
ROOT=$W/ca/trust/pqc-web-root.pem
check "pqc-ca issued 4 ML-DSA leaves" test "$(ls /etc/pqc/certs/*/fullchain.pem | wc -l)" = 4

eval_json() {   # out target sni
    $B/pqc-eval --format json --timeout 5 --ca "$ROOT" --classic-ca $W/cca.crt --sni "$3" "$2" > "$1" 2>/dev/null
}
expect() {   # label json key=val...
    local label=$1 j=$2; shift 2
    if python3 $K/tests/assert_eval.py "$j" "$@"; then ok "$label"; else bad "$label"; fi
}
profile_expect() {   # profile -> assertions
    case "$1" in
        compat)    echo "level=L2* profile=compat default_client_gets=EC* pqc_auth=ML-DSA-65 pqc_verify=ok legacy_verify=ok hybrid_groups=X25519MLKEM768*" ;;
        pqc-first) echo "level=L2* profile=pqc-first default_client_gets=ML-DSA-65 pqc_verify=ok legacy_verify=ok" ;;
        pqc-only)  echo "level=L3* profile=pqc-only legacy_auth=none classical_kex_accepted=no tls12_accepted=no pqc_verify=ok" ;;
    esac
}

# --------------------------------------------------------------------------- nginx
echo "== nginx"
rm -f /etc/nginx/sites-enabled/default
cp -r $F/nginx/. /etc/nginx/
[ -s /proc/net/if_inet6 ] || sed -i '/listen \[::\]/d' /etc/nginx/sites-enabled/*.conf   # host without IPv6
nginx -t -q || bad "fixture nginx config invalid"
nginx
sleep 1
eval_json $W/n0.json 127.0.0.1:443 a.test
expect "nginx a.test before: L0 (classical groups pinned)" $W/n0.json "level=L0*"

$B/pqc-webconf inventory --server nginx > $W/inv-nginx.txt 2>&1
check "inventory lists 4 TLS servers" test "$(grep -c 'http server | .* | yes |' $W/inv-nginx.txt)" = 4
check "inventory flags pinned classical groups" grep -q "groups pinned without hybrid" $W/inv-nginx.txt
check "inventory reports linked OpenSSL 3.5" grep -q "| 3\.5\.[0-9]* | yes |" $W/inv-nginx.txt
$B/pqc-webconf inventory --server nginx --emit-csr /tmp/csr > $W/csr.txt
check "inventory emits CSR command for a.test" grep -q "pqc-ca key-csr a.test a.test www.a.test" $W/csr.txt

mkdir -p $W/pristine-nginx; cp -r /etc/nginx/. $W/pristine-nginx/
$B/pqc-webconf migrate --server nginx --profile compat > $W/dry.txt 2>&1
check "dry run changes nothing on disk" diff -rq /etc/nginx $W/pristine-nginx
check "dry run shows the managed block" grep -q "+    # >>> pqc-webconf profile=compat site=a.test >>>" $W/dry.txt
check "shared listen note for 443 not needed when all migrate" bash -c "! grep -q 'is shared by' $W/dry.txt"

for prof in compat pqc-first pqc-only; do
    $B/pqc-webconf migrate --server nginx --profile $prof --apply --reload > $W/m-$prof.txt 2>&1
    check "nginx migrate $prof applied" grep -q "config test passed" $W/m-$prof.txt
    sleep 1
    for t in "127.0.0.1:443 a.test" "127.0.0.1:443 d.test" "127.0.0.1:4431 b.test" "127.0.0.1:4432 c.test"; do
        set -- $t
        eval_json $W/e.json "$1" "$2"
        # shellcheck disable=SC2046
        expect "nginx $prof $2" $W/e.json $(profile_expect $prof)
    done
done
c_block=$(sed -n '/site=c.test/,/<<< pqc-webconf/p' /etc/nginx/sites-enabled/c.conf)
check "inherited ssl_conf_command copied (pqc-only keeps non-owned commands)" grep -q "PrioritizeChaCha" <<< "$c_block"
check "pqc-only disabled classical cert in multi-line directive (d)" grep -q "#pqc-webconf# ssl_certificate" /etc/nginx/sites-enabled/d.conf

$B/pqc-webconf migrate --server nginx --profile pqc-only --apply > $W/idem.txt 2>&1
check "re-running the same profile is a no-op" grep -q "nothing to change" $W/idem.txt

$B/pqc-webconf migrate --server nginx --profile compat --apply --reload > /dev/null 2>&1
sleep 2   # let workers of the previous generation drain
eval_json $W/e.json 127.0.0.1:4431 b.test
expect "profile switch pqc-only -> compat restores classical chain (b one-liner)" $W/e.json $(profile_expect compat)
nginx -s reload; sleep 1

# rollback to pristine: walk the backups newest first
for bdir in $(ls -1dr $W/backups/nginx-*); do $B/pqc-webconf rollback "$bdir" --force > /dev/null 2>&1; done
check "rollback chain restores files byte-exact" diff -r /etc/nginx $W/pristine-nginx
$B/pqc-webconf migrate --server nginx --profile compat --apply > /dev/null 2>&1
$B/pqc-webconf remove --server nginx --apply --reload > $W/rm.txt 2>&1
check "remove passes config test" grep -q "config test passed" $W/rm.txt
check "remove leaves no managed lines" bash -c "! grep -rq 'pqc-webconf' /etc/nginx"
sleep 1
eval_json $W/e.json 127.0.0.1:443 a.test
expect "after remove a.test is back to L0" $W/e.json "level=L0*"

# failing config test must restore automatically
cp -r $W/pristine-nginx/. /etc/nginx/
$B/pqc-webconf migrate --server nginx --profile compat --apply --test-cmd false > $W/fail.txt 2>&1
check "failed config test restores backup" diff -r /etc/nginx $W/pristine-nginx
nginx -s stop; sleep 1

# --------------------------------------------------------------------------- apache
echo "== apache"
a2enmod -q ssl >/dev/null
cp -r $F/apache/. /etc/apache2/
apache2ctl -t > /dev/null 2>&1 || { bad "fixture apache config invalid"; apache2ctl -t; }
apache2ctl start; sleep 2
eval_json $W/a0.json 127.0.0.1:4431 b.test
expect "apache b.test before: L0 (Groups X25519 pinned)" $W/a0.json "level=L0*"

$B/pqc-webconf inventory --server apache > $W/inv-apache.txt 2>&1
check "apache inventory sees 4 TLS vhosts" test "$(grep -c 'VirtualHost | .* | yes |' $W/inv-apache.txt)" = 4
check "apache inventory flags key-in-cert vhost e.test" grep -q "e.test.*count mismatch" $W/inv-apache.txt

mkdir -p $W/pristine-apache; cp -r /etc/apache2/. $W/pristine-apache/
for prof in compat pqc-first pqc-only; do
    $B/pqc-webconf migrate --server apache --profile $prof --apply --reload > $W/am-$prof.txt 2>&1
    check "apache migrate $prof applied" grep -q "config test passed" $W/am-$prof.txt
    check "apache e.test skipped" grep -q "| e.test .* skip | certificate/key directive count differs" $W/am-$prof.txt
    sleep 2
    for t in "127.0.0.1:443 a.test" "127.0.0.1:4431 b.test" "127.0.0.1:4432 c.test"; do
        set -- $t
        eval_json $W/e.json "$1" "$2"
        # shellcheck disable=SC2046
        expect "apache $prof $2" $W/e.json $(profile_expect $prof)
    done
done
check "continuation-line SSLCertificateFile disabled on both lines" \
    bash -c "grep -c '#pqc-webconf#' /etc/apache2/sites-enabled/b-ssl.conf | grep -qx 3"
$B/pqc-webconf migrate --server apache --profile pqc-only --apply > $W/aidem.txt 2>&1
check "apache re-run is a no-op" grep -q "nothing to change" $W/aidem.txt
for bdir in $(ls -1dr $W/backups/apache-*); do $B/pqc-webconf rollback "$bdir" --force > /dev/null 2>&1; done
check "apache rollback chain byte-exact" diff -r /etc/apache2 $W/pristine-apache
apache2ctl stop

echo
echo "webconf-e2e: $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
