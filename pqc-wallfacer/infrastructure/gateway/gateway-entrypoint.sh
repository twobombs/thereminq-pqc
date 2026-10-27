#!/usr/bin/env bash
# Wallfacer gateway entrypoint.
#
#   1. verify the signed peer bundle and refuse rollback          MSH-02, MSH-05
#   2. install the dark-perimeter nftables ruleset                 NET-01, NET-02, NET-06
#   3. start Rosenpass + WireGuard from the bundle                 NET-03, MSH-01
#   4. hold all tunnel traffic until every peer has had a PSK
#      for WF_PSK_SETTLE seconds, and re-engage when a PSK goes
#      stale or missing                                            NET-05, MSH-06, MSH-12
#
# Bundle layout (signed with wf-sign using the overlay key):
#   SERIAL                    strictly increasing integer
#   peers.conf                one peer per line: <name> <endpoint|-> <allowed-ips>
#   peers/<name>/             rp pubkey output for that peer (pqpk, wgpk)

set -euo pipefail

: "${WF_PUBLIC_IF:?set WF_PUBLIC_IF to the internet-facing interface}"
: "${WF_WG_ADDR:?set WF_WG_ADDR, e.g. 10.77.0.1/24}"
WF_LISTEN_ADDR=${WF_LISTEN_ADDR:-0.0.0.0}
WF_RP_PORT=${WF_RP_PORT:-9999}
WF_WG_PORT=$((WF_RP_PORT + 1))            # rp always uses rosenpass port + 1 for WireGuard
WF_WG_DEV=${WF_WG_DEV:-rosenpass0}
WF_BUNDLE=${WF_BUNDLE:-/bundle}
WF_OVERLAY_PUB=${WF_OVERLAY_PUB:-/trust/overlay.pub.pem}
WF_SECRET=${WF_SECRET:-/secret}
WF_STATE=${WF_STATE:-/var/lib/wallfacer}
WF_FORWARD_IF=${WF_FORWARD_IF:-}          # optional enclave-side interface the tunnel may forward into
WF_PSK_SETTLE=${WF_PSK_SETTLE:-180}       # >= WireGuard REJECT_AFTER_TIME, so no pre-PSK session survives
WF_PSK_STALE=${WF_PSK_STALE:-300}         # Rosenpass rotates about every 120 s
WF_POLL=${WF_POLL:-5}

log() { printf '%s gateway %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "FATAL $*"; exit 1; }

# ---------- 1. bundle ----------
wf-verify "$WF_BUNDLE" "$WF_OVERLAY_PUB" || die "peer bundle failed verification"
serial=$(tr -cd '0-9' < "$WF_BUNDLE/SERIAL")
[ -n "$serial" ] || die "bundle SERIAL empty"
last=0
[ -f "$WF_STATE/serial" ] && last=$(tr -cd '0-9' < "$WF_STATE/serial")
[ "$serial" -ge "${last:-0}" ] || die "bundle serial $serial older than accepted $last (rollback refused)"
echo "$serial" > "$WF_STATE/serial"
[ -d "$WF_SECRET" ] || die "Rosenpass secret dir $WF_SECRET missing (generate on this node: rp genkey)"

# ---------- 2. nftables ----------
apply_ruleset() {
    local fwd=""
    if [ -n "$WF_FORWARD_IF" ]; then
        fwd="iifname \"$WF_WG_DEV\" oifname \"$WF_FORWARD_IF\" accept
        iifname \"$WF_FORWARD_IF\" oifname \"$WF_WG_DEV\" ct state established,related accept"
    fi
    nft -f - <<EOF
table inet wallfacer
delete table inet wallfacer
table inet wallfacer {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        iifname "$WF_PUBLIC_IF" meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
        iifname "$WF_PUBLIC_IF" udp dport { $WF_RP_PORT, $WF_WG_PORT } accept
        iifname "$WF_WG_DEV" accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        # Docker enables br_netfilter, so container-to-container traffic on one bridge passes
        # here too. Bridge ports are veth*; routed egress (veth -> public NIC) still drops.
        iifname "veth*" oifname "veth*" accept
        $fwd
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
    chain holddown_in {
        type filter hook input priority filter - 10; policy accept;
    }
    chain holddown_fwd {
        type filter hook forward priority filter - 10; policy accept;
    }
    chain holddown_out {
        type filter hook output priority filter - 10; policy accept;
    }
}
EOF
}

HOLD=""
hold_on() {
    [ "$HOLD" = on ] && return 0
    nft add rule inet wallfacer holddown_in iifname "$WF_WG_DEV" drop
    nft add rule inet wallfacer holddown_fwd iifname "$WF_WG_DEV" drop
    nft add rule inet wallfacer holddown_fwd oifname "$WF_WG_DEV" drop
    nft add rule inet wallfacer holddown_out oifname "$WF_WG_DEV" drop
    HOLD=on
    log "holddown ON ($1)"
}
hold_off() {
    [ "$HOLD" = off ] && return 0
    nft flush chain inet wallfacer holddown_in
    nft flush chain inet wallfacer holddown_fwd
    nft flush chain inet wallfacer holddown_out
    HOLD=off
    log "holddown OFF (all peers on Rosenpass PSK for >= ${WF_PSK_SETTLE}s)"
}

apply_ruleset
hold_on "startup"

# ---------- 3. Rosenpass + WireGuard ----------
args=(exchange "$WF_SECRET" dev "$WF_WG_DEV" listen "$WF_LISTEN_ADDR:$WF_RP_PORT")
npeers=0
while read -r name endpoint allowed _rest; do
    case "$name" in ''|'#'*) continue ;; esac
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad peer name: $name"
    [ -d "$WF_BUNDLE/peers/$name" ] || die "peer $name has no public key dir in bundle"
    args+=(peer "$WF_BUNDLE/peers/$name")
    [ "$endpoint" != "-" ] && args+=(endpoint "$endpoint")
    args+=(allowed-ips "$allowed")
    npeers=$((npeers + 1))
done < "$WF_BUNDLE/peers.conf"
[ "$npeers" -gt 0 ] || die "no peers in bundle"
log "bundle serial=$serial peers=$npeers"

rp "${args[@]}" &
RP_PID=$!
trap 'kill "$RP_PID" 2>/dev/null || true; exit 0' TERM INT

for _ in $(seq 1 30); do ip link show "$WF_WG_DEV" >/dev/null 2>&1 && break; sleep 1; done
ip link show "$WF_WG_DEV" >/dev/null 2>&1 || die "$WF_WG_DEV did not appear"
ip address replace "$WF_WG_ADDR" dev "$WF_WG_DEV"
ip link set "$WF_WG_DEV" up

# ---------- 4. PSK watchdog ----------
psk_since=0              # time all peers first had a PSK in the current unbroken run
declare -A psk_hash=()   # per peer: short hash of its current PSK (key material is never logged)
declare -A psk_change=() # per peer: when that PSK last changed

while kill -0 "$RP_PID" 2>/dev/null; do
    now=$(date +%s)
    have=0
    oldest=0
    while read -r peer psk; do
        [ -n "$peer" ] && [ -n "$psk" ] && [ "$psk" != "(none)" ] || continue
        have=$((have + 1))
        h=$(printf '%s' "$psk" | sha256sum | cut -c1-16)
        if [ "${psk_hash[$peer]:-}" != "$h" ]; then psk_hash[$peer]=$h; psk_change[$peer]=$now; fi
        age=$((now - psk_change[$peer]))
        [ "$age" -gt "$oldest" ] && oldest=$age
    done < <(wg show "$WF_WG_DEV" preshared-keys 2>/dev/null || true)

    if [ "$have" -lt "$npeers" ]; then
        psk_since=0
        hold_on "$have/$npeers peers have a Rosenpass PSK"
    elif [ "$oldest" -gt "$WF_PSK_STALE" ]; then
        psk_since=0
        hold_on "a peer PSK is unchanged for ${oldest}s (stale Rosenpass)"
    else
        [ "$psk_since" -eq 0 ] && psk_since=$now
        if [ $((now - psk_since)) -ge "$WF_PSK_SETTLE" ]; then hold_off; fi
    fi
    sleep "$WF_POLL"
done

die "rp exited; restart policy brings the gateway back with holddown on"
