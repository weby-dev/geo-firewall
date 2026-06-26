#!/usr/bin/env bash
#
# Installs the nftables ruleset that feeds the WebUp C++ firewall daemon.
#
# Design:
#   OUTPUT  policy ACCEPT  -> your server downloads anything it wants.
#   INPUT   policy DROP    -> fail CLOSED. Client-initiated traffic is judged.
#     - invalid .......................... DROP
#     - loopback ......................... ACCEPT
#     - ct mark $APPROVED ................ ACCEPT  (daemon already cleared flow)
#     - ct mark $REJECTED ................ DROP    (daemon already blocked flow)
#     - established HTTP/80, undecided ... QUEUE   (waiting to read User-Agent)
#     - established/related .............. ACCEPT  (replies to YOUR downloads)
#     - SSH from $ADMIN_IPS .............. ACCEPT  (ANTI-LOCKOUT, before geo drop)
#     - NEW connections .................. QUEUE   (daemon: geo + UA rules)
#
# Flows are fanned out across QUEUE_BASE..QUEUE_BASE+NUM_QUEUES-1 by flow hash,
# so every packet of a connection reaches the same daemon worker thread.
#
# If the daemon is NOT running, NEW connections hit policy DROP (fail closed) but
# admin SSH still works via the allowlist, so you can recover.
#
# Counters are attached to every verdict so `nft list table inet webup` shows
# live hit counts. Re-running this script atomically replaces the ruleset.
#
# Run as root.

set -euo pipefail

# === EDIT THESE (must match config/firewall.conf) ============================
QUEUE_BASE=0
NUM_QUEUES=4
MARK_APPROVED=1
MARK_REJECTED=2
HTTP_PORT=80
HTTPS_PORT=443
SSH_PORT=22
# Admin IPs/CIDRs that may ALWAYS reach SSH, regardless of geo, even if the
# daemon is down. Put your own admin IP(s) here or you risk lockout.
ADMIN_IPS_V4=( "203.0.113.10" )                 # <-- CHANGE
ADMIN_IPS_V6=( )                                 # e.g. ( "2001:db8::1" )

# Anti-bot auto-ban on web ports. A single source IP exceeding WEB_RATE (after a
# WEB_BURST allowance) of NEW web connections is banned for BAN_TTL.
# NOTE: Indian mobile carriers use CARRIER-GRADE NAT -- thousands of real users
# share one public IPv4 -- so keep these GENEROUS to avoid banning whole pools.
# The per-request L7 checks (daemon + nginx) are the precise filter; this is just
# a volumetric backstop against floods.
WEB_RATE="600/minute"
WEB_BURST=300
BAN_TTL="30m"
# =============================================================================

if [[ $EUID -ne 0 ]]; then echo "must run as root" >&2; exit 1; fi
command -v nft >/dev/null || { echo "nftables (nft) not installed" >&2; exit 1; }

LAST_QUEUE=$(( QUEUE_BASE + NUM_QUEUES - 1 ))
if (( NUM_QUEUES > 1 )); then
    QEXPR="counter queue num ${QUEUE_BASE}-${LAST_QUEUE} fanout"
else
    QEXPR="counter queue num ${QUEUE_BASE}"
fi

join() { local IFS=,; echo "${*:-}"; }
ADMIN4_SET=""; ADMIN6_SET=""
[[ ${#ADMIN_IPS_V4[@]} -gt 0 ]] && ADMIN4_SET="elements = { $(join "${ADMIN_IPS_V4[@]}") }"
[[ ${#ADMIN_IPS_V6[@]} -gt 0 ]] && ADMIN6_SET="elements = { $(join "${ADMIN_IPS_V6[@]}") }"

# add+delete+define => atomic replace whether or not the table already exists.
nft -f - <<EOF
add table inet webup
delete table inet webup
table inet webup {
    set admin4 { type ipv4_addr; flags interval; ${ADMIN4_SET} }
    set admin6 { type ipv6_addr; flags interval; ${ADMIN6_SET} }

    # Auto-ban lists: a source is added here when it floods the web ports, and
    # is dropped (for new web connections) until the timeout expires.
    set bots4 { type ipv4_addr; flags dynamic, timeout; timeout ${BAN_TTL}; }
    set bots6 { type ipv6_addr; flags dynamic, timeout; timeout ${BAN_TTL}; }

    chain input {
        type filter hook input priority filter; policy drop;

        ct state invalid counter drop
        iif "lo" accept

        # Flows the daemon already ruled on -> no userspace round-trip.
        ct mark ${MARK_APPROVED} counter accept
        ct mark ${MARK_REJECTED} counter drop

        # Undecided HTTP/80 mid-flow: keep feeding the daemon until it has read
        # the request line + User-Agent and stamped a ct mark.
        ct state established,related ct mark 0 tcp dport ${HTTP_PORT} ${QEXPR}

        # All other return traffic (replies to your downloads, approved 443...).
        ct state established,related counter accept

        # ANTI-LOCKOUT: admin SSH allowed regardless of geo / daemon state.
        tcp dport ${SSH_PORT} ip  saddr @admin4 counter accept
        tcp dport ${SSH_PORT} ip6 saddr @admin6 counter accept

        # --- anti-bot volumetric backstop (web ports only) ------------------
        # Drop new web connections from already-banned sources.
        ct state new tcp dport { ${HTTP_PORT}, ${HTTPS_PORT} } ip  saddr @bots4 counter drop
        ct state new tcp dport { ${HTTP_PORT}, ${HTTPS_PORT} } ip6 saddr @bots6 counter drop
        # Per-source rate meter: over the limit -> ban + drop.
        ct state new tcp dport { ${HTTP_PORT}, ${HTTPS_PORT} } \
            meter webrate4 { ip  saddr limit rate over ${WEB_RATE} burst ${WEB_BURST} packets } \
            add @bots4 { ip saddr } counter drop
        ct state new tcp dport { ${HTTP_PORT}, ${HTTPS_PORT} } \
            meter webrate6 { ip6 saddr limit rate over ${WEB_RATE} burst ${WEB_BURST} packets } \
            add @bots6 { ip6 saddr } counter drop

        # Every new client-initiated connection -> daemon decides (geo + UA).
        # No 'bypass': if the daemon is dead, packets fall through to policy DROP.
        ct state new ${QEXPR}
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
        # Server can initiate and download anything it wants.
    }
}
EOF

echo "webup nftables ruleset installed: queues ${QUEUE_BASE}-${LAST_QUEUE}."
echo "Admin SSH allowlist v4: ${ADMIN_IPS_V4[*]:-<none>}  v6: ${ADMIN_IPS_V6[*]:-<none>}"
if [[ ${#ADMIN_IPS_V4[@]} -eq 0 && ${#ADMIN_IPS_V6[@]} -eq 0 ]]; then
    echo "WARNING: no admin IPs set -- if the daemon dies you may be locked out!"
fi

# Explicit success: never let the exit status be poisoned by a preceding test
# (e.g. the admin-IP check above) -- systemd treats any non-zero as a failure.
exit 0
