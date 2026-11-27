#!/bin/sh
# lib/profile.sh: resolve a TLS profile from profiles/profiles.env.
#
#   . lib/profile.sh
#   pqc_profile compat            # sets the variables below, returns 1 on unknown profile
#
#   PROFILE_NAME          compat | pqc-first | pqc-only
#   PROFILE_PROTOCOLS     space separated, e.g. "TLSv1.2 TLSv1.3"
#   PROFILE_GROUPS        colon separated OpenSSL group list
#   PROFILE_SIGALGS       colon separated OpenSSL TLS sigalg list, in server preference order
#   PROFILE_CLASSIC_CERT  yes | no

PQC_PROFILES_FILE=${PQC_PROFILES_FILE:-$(dirname "$0")/../profiles/profiles.env}

_pqc_get() {   # key
    sed -n "s/^$1=\"\(.*\)\"\$/\1/p" "$PQC_PROFILES_FILE" | head -n 1
}

_pqc_expand() {   # "HYBRID:CLASSIC" prefix(PQC_GROUPS|PQC_SIGALGS)
    out=""
    old_ifs=$IFS; IFS=:
    for part in $1; do
        val=$(_pqc_get "$2_$part")
        [ -n "$val" ] || { IFS=$old_ifs; return 1; }
        out="${out:+$out:}$val"
    done
    IFS=$old_ifs
    printf '%s' "$out"
}

pqc_profile() {   # name
    [ -f "$PQC_PROFILES_FILE" ] || { echo "profile.sh: $PQC_PROFILES_FILE not found" >&2; return 1; }
    case "$1" in compat|pqc-first|pqc-only) ;; *) echo "profile.sh: unknown profile '$1'" >&2; return 1 ;; esac
    PROFILE_NAME=$1
    PROFILE_PROTOCOLS=$(_pqc_get "$1_PROTOCOLS")
    PROFILE_GROUPS=$(_pqc_expand "$(_pqc_get "$1_GROUPS")" PQC_GROUPS) || return 1
    PROFILE_SIGALGS=$(_pqc_expand "$(_pqc_get "$1_SIGALGS")" PQC_SIGALGS) || return 1
    PROFILE_CLASSIC_CERT=$(_pqc_get "$1_CLASSIC_CERT")
    export PROFILE_NAME PROFILE_PROTOCOLS PROFILE_GROUPS PROFILE_SIGALGS PROFILE_CLASSIC_CERT
}

pqc_openssl_ok() {   # exit 0 when the openssl in PATH is >= 3.5 with ML-DSA TLS sigalgs and ML-KEM groups
    v=$(openssl version 2>/dev/null | awk '{print $2}')
    major=${v%%.*}; rest=${v#*.}; minor=${rest%%.*}
    [ -n "$major" ] || return 1
    { [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 5 ]; }; } || return 1
    openssl list -tls-signature-algorithms 2>/dev/null | grep -q mldsa65 || return 1
    openssl list -kem-algorithms 2>/dev/null | grep -q 'ML-KEM-768' || return 1
}
