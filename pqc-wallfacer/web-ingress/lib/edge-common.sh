#!/bin/sh
# lib/edge-common.sh: shared by the nginx and Apache edge entrypoints.
#
# Sites directory ($PQC_SITES_DIR, default /etc/pqc/sites), one directory per site:
#   <site>/pqc/tls.crt       ML-DSA leaf + intermediate (pqc-ca fullchain.pem)      required
#   <site>/pqc/tls.key       ML-DSA private key                                     required
#   <site>/classic/tls.crt   existing RSA/ECDSA chain (cert-manager / ACME secret)  compat, pqc-first
#   <site>/classic/tls.key
#   <site>/upstream          optional per-site upstream URL, overrides PQC_UPSTREAM
# Server names come from the subjectAltName DNS entries of both certificates.
# The layout matches Kubernetes TLS secrets (tls.crt / tls.key) mounted with a projected volume.

PQC_SHARE=${PQC_SHARE:-/usr/local/share/pqc-web}
export PQC_PROFILES_FILE=${PQC_PROFILES_FILE:-$PQC_SHARE/profiles.env}
# shellcheck source=profile.sh
. "$PQC_SHARE/profile.sh"

PQC_PROFILE=${PQC_PROFILE:-compat}
PQC_SITES_DIR=${PQC_SITES_DIR:-/etc/pqc/sites}
PQC_UPSTREAM=${PQC_UPSTREAM:-}
PQC_UPSTREAM_CA=${PQC_UPSTREAM_CA:-}
PQC_LISTEN_TLS=${PQC_LISTEN_TLS:-8443}
PQC_LISTEN_HTTP=${PQC_LISTEN_HTTP:-8080}
PQC_FORWARDED_PORT=${PQC_FORWARDED_PORT:-443}   # public port clients use (Service / -p mapping), sent as X-Forwarded-Port
PQC_HTTP_REDIRECT=${PQC_HTTP_REDIRECT:-yes}
PQC_PROXY_PROTOCOL=${PQC_PROXY_PROTOCOL:-no}
PQC_IPV6=${PQC_IPV6:-auto}
PQC_HSTS=${PQC_HSTS:-}
PQC_RELOAD_INTERVAL=${PQC_RELOAD_INTERVAL:-60}
PQC_RUN=${PQC_RUN:-/tmp/pqc-edge}

log() { echo "pqc-edge: $*" >&2; }
fail() { log "FATAL: $*"; exit 1; }

edge_preflight() {
    pqc_openssl_ok || fail "OpenSSL $(openssl version) lacks ML-DSA TLS signatures or ML-KEM (need >= 3.5)"
    pqc_profile "$PQC_PROFILE" || fail "PQC_PROFILE must be compat, pqc-first or pqc-only"
    [ -d "$PQC_SITES_DIR" ] || fail "PQC_SITES_DIR $PQC_SITES_DIR missing"
    case "$PQC_IPV6" in
        auto) if [ -s /proc/net/if_inet6 ]; then PQC_IPV6=yes; else PQC_IPV6=no; fi ;;
        yes|no) ;;
        *) fail "PQC_IPV6 must be auto, yes or no" ;;
    esac
    mkdir -p "$PQC_RUN"
}

cert_alg() {   # cert -> ML-DSA-65 | RSA | EC | ...
    openssl x509 -in "$1" -noout -text 2>/dev/null | sed -n 's/^ *Public Key Algorithm: *//p' | head -n 1
}

cert_dns() {   # cert -> names, one per line
    openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p'
}

cert_days() {
    end=$(openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2)
    [ -n "$end" ] || { echo 0; return; }
    echo $(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
}

pair_ok() {   # cert key
    a=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null)
    b=$(openssl pkey -in "$2" -pubout 2>/dev/null)
    [ -n "$a" ] && [ "$a" = "$b" ]
}

# Prints "site|names|pqc_crt|pqc_key|classic_crt|classic_key|upstream" for every valid site.
edge_sites() {
    for d in "$PQC_SITES_DIR"/*/; do
        [ -d "$d" ] || continue
        site=$(basename "$d")
        pc="$d/pqc/tls.crt"; pk="$d/pqc/tls.key"; cc="$d/classic/tls.crt"; ck="$d/classic/tls.key"
        if [ ! -f "$pc" ] || [ ! -f "$pk" ]; then log "site $site: no pqc/tls.crt + tls.key, skipped"; continue; fi
        case "$(cert_alg "$pc")" in ML-DSA-*) ;; *) log "site $site: pqc/tls.crt is not ML-DSA, skipped"; continue ;; esac
        pair_ok "$pc" "$pk" || { log "site $site: pqc key does not match certificate, skipped"; continue; }
        days=$(cert_days "$pc"); [ "$days" -lt 7 ] && log "site $site: ML-DSA certificate expires in $days days"
        if [ "$PROFILE_CLASSIC_CERT" = yes ] && [ -f "$cc" ] && [ -f "$ck" ]; then
            if ! pair_ok "$cc" "$ck"; then log "site $site: classic key does not match certificate, classic chain dropped"; cc=""; ck=""; fi
        else
            [ "$PROFILE_CLASSIC_CERT" = yes ] && log "site $site: no classic chain; clients without the PQC root will fail"
            cc=""; ck=""
        fi
        names=$( { cert_dns "$pc"; [ -n "$cc" ] && cert_dns "$cc"; } | tr 'A-Z' 'a-z' | sort -u | tr '\n' ' ')
        [ -n "$names" ] || { log "site $site: no DNS names in certificates, skipped"; continue; }
        up=$PQC_UPSTREAM
        [ -f "$d/upstream" ] && up=$(head -n 1 "$d/upstream" | tr -d ' \r')
        [ -n "$up" ] || { log "site $site: no upstream (PQC_UPSTREAM or $d/upstream), skipped"; continue; }
        case "$up" in http://*|https://*) ;; *) log "site $site: upstream '$up' must start with http:// or https://, skipped"; continue ;; esac
        echo "$site|$names|$pc|$pk|$cc|$ck|$up"
    done
}

sites_checksum() {
    find -L "$PQC_SITES_DIR" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do sha256sum "$f"; done | sha256sum | cut -d' ' -f1
}

# watch_loop <render_fn> <test_fn> <reload_fn>: re-render when certificates or sites change.
watch_loop() {
    last=$(sites_checksum)
    while sleep "$PQC_RELOAD_INTERVAL"; do
        now=$(sites_checksum)
        [ "$now" = "$last" ] && continue
        log "sites changed, re-rendering"
        if "$1" "$PQC_RUN/next" && "$2" "$PQC_RUN/next"; then
            rm -rf "$PQC_RUN/prev"; mv "$PQC_RUN/live" "$PQC_RUN/prev"; mv "$PQC_RUN/next" "$PQC_RUN/live"
            "$3" && log "reloaded" || log "reload failed"
            last=$now
        else
            log "new configuration rejected, keeping the running one"
            rm -rf "$PQC_RUN/next"
            last=$now
        fi
    done
}
