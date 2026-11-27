#!/usr/bin/env bash
# k8s-offline.sh: tests pqc-k8s against a stub kubectl (no cluster needed). Runs inside pqc-web/tools.
# Writes generated YAML to $OUTDIR (default /w/k8s-out) for tests/validate_k8s.py on the host.
set -uo pipefail
OUTDIR=${OUTDIR:-/w/k8s-out}
T=$(mktemp -d)
mkdir -p "$OUTDIR" "$T/bin"
PASS=0; FAILS=0
ok()  { PASS=$((PASS+1)); echo "  ok   $*"; }
bad() { FAILS=$((FAILS+1)); echo "  FAIL $*"; }

# classical "existing" certificate for the stubbed Ingress secrets
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/c.key" -out "$T/c.crt" \
    -subj /CN=shop.example.org -addext "subjectAltName=DNS:shop.example.org,DNS:www.shop.example.org" -days 60 2>/dev/null

cat > "$T/deploy.json" <<'EOF'
{"items": [
 {"kind": "Deployment", "metadata": {"namespace": "ingress-nginx", "name": "ingress-nginx-controller"},
  "spec": {"template": {"spec": {"containers": [{"image": "registry.k8s.io/ingress-nginx/controller:v1.12.1"}]}}}},
 {"kind": "Deployment", "metadata": {"namespace": "shop", "name": "web"},
  "spec": {"template": {"spec": {"containers": [{"image": "example/shop:3"}]}}}}
]}
EOF
cat > "$T/ingress.json" <<'EOF'
{"items": [
 {"metadata": {"namespace": "shop", "name": "shop"},
  "spec": {"ingressClassName": "nginx",
           "tls": [{"hosts": ["shop.example.org", "www.shop.example.org"], "secretName": "shop-tls"}],
           "rules": [{"host": "shop.example.org"}, {"host": "www.shop.example.org"}]}},
 {"metadata": {"namespace": "api", "name": "api", "annotations": {"kubernetes.io/ingress.class": "nginx"}},
  "spec": {"tls": [{"hosts": ["api.example.org"], "secretName": "api-tls"}], "rules": [{"host": "api.example.org"}]}},
 {"metadata": {"namespace": "intranet", "name": "plain"}, "spec": {"rules": [{"host": "intranet.example.org"}]}}
]}
EOF
cat > "$T/bin/kubectl" <<EOF
#!/bin/sh
case "\$*" in
  "get deploy,daemonset -A -o json") cat $T/deploy.json ;;
  "get ingress -A -o json") cat $T/ingress.json ;;
  *"get secret -n shop shop-tls -o jsonpath={.data.tls\\\\.crt}"*) base64 -w0 < $T/c.crt ;;
  *"get secret -n shop shop-tls -o jsonpath={.data.tls\\\\.key}"*) base64 -w0 < $T/c.key ;;
  *"get secret -n api api-tls"*) echo 'Error from server (Forbidden)' >&2; exit 1 ;;
  "get crd gateways.gateway.networking.k8s.io") exit 1 ;;
  *) echo "stub kubectl: unhandled: \$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$T/bin/kubectl"
export PATH="$T/bin:$PATH"

pqc-k8s inventory > "$T/inv.md" 2>&1
grep -q "retired upstream" "$T/inv.md" && ok "inventory flags the retired ingress-nginx controller" || { bad "inventory controller"; cat "$T/inv.md"; }
grep -qE '^\| shop \| shop \| nginx \| shop\.example\.org www\.shop\.example\.org \| shop-tls \| EC-prime256v1 [56][0-9]d \|$' "$T/inv.md" \
    && ok "inventory decodes the TLS secret algorithm and lifetime" || { bad "inventory secret"; cat "$T/inv.md"; }

pqc-k8s plan -o "$OUTDIR/plan.tsv" 2>/dev/null
grep -qP '^shop.example.org\tshop/shop-tls\tshop.example.org www.shop.example.org$' "$OUTDIR/plan.tsv" \
    && grep -qP '^api.example.org\tapi/api-tls\tapi.example.org$' "$OUTDIR/plan.tsv" \
    && ! grep -q intranet "$OUTDIR/plan.tsv" \
    && ok "plan lists TLS sites only" || { bad "plan"; cat "$OUTDIR/plan.tsv"; }

pqc-k8s csr "$OUTDIR/plan.tsv" /w/csr > "$T/csr.sh"
grep -q "pqc-ca key-csr shop.example.org shop.example.org www.shop.example.org --out /w/csr" "$T/csr.sh" \
    && ok "csr emits key-csr commands" || bad "csr"

export PQC_CA_DIR=$T/ca
pqc-ca init-root R >/dev/null 2>&1 && pqc-ca init-int I --permit-dns example.org >/dev/null 2>&1
pqc-ca issue shop.example.org shop.example.org www.shop.example.org --out "$T/pqc" >/dev/null 2>&1
pqc-ca issue api.example.org api.example.org --out "$T/pqc" >/dev/null 2>&1
pqc-k8s secrets "$OUTDIR/plan.tsv" "$T/pqc" > "$OUTDIR/secrets.yaml" 2> "$T/sec.err"
[ "$(grep -c '^kind: Secret' "$OUTDIR/secrets.yaml")" = 3 ] && ok "secrets: 2 ML-DSA + 1 classic copy" || { bad "secrets count"; cat "$T/sec.err"; }
grep -q "classic secret api/api-tls not readable" "$T/sec.err" && ok "unreadable classic secret reported" || bad "classic warning"
python3 - "$OUTDIR/secrets.yaml" "$T/pqc/shop.example.org/fullchain.pem" <<'PY' && ok "ML-DSA secret round-trips byte-exact" || bad "secret content"
import base64, re, sys
y = open(sys.argv[1]).read()
m = re.search(r"name: shop.example.org-pqc.*?tls.crt: (\S+)", y, re.S)
assert m and base64.b64decode(m.group(1)) == open(sys.argv[2], "rb").read()
PY
pqc-k8s sites-patch "$OUTDIR/plan.tsv" > "$OUTDIR/sites-patch.yaml"
grep -q "path: api.example.org/pqc/tls.key" "$OUTDIR/sites-patch.yaml" && ok "sites-patch maps secrets to the edge layout" || bad "sites-patch"

echo
echo "k8s-offline: $PASS passed, $FAILS failed"
rm -rf "$T"
[ "$FAILS" -eq 0 ]
