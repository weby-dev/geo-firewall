#!/usr/bin/env bash
#
# WebUp firewall installer.
#
# Linux only (the daemon is built on netfilter/NFQUEUE). Supports the major
# package managers: apt (Debian/Ubuntu), dnf/yum (RHEL/Fedora/Rocky/Alma),
# pacman (Arch), zypper (openSUSE).
#
# Run from the repo root:   sudo ./install.sh
#
# Collects everything you'd otherwise set by hand (admin SSH IP, home country,
# queues, secret token, MaxMind credentials), builds, installs, and starts the
# service. Runs interactively, or fully unattended via env vars + --yes.
#
# Unattended example:
#   sudo WEBUP_ADMIN_IPS="1.2.3.4" WEBUP_HOME_COUNTRY=IN \
#        WEBUP_MM_ACCOUNT=123456 WEBUP_MM_KEY=xxxxx ./install.sh --yes
#
# Flags:
#   -y, --yes         non-interactive; use env vars / defaults, never prompt
#       --no-start    install + enable but do NOT start (review before going live)
#       --reconfigure re-run the questions and regenerate config, even if already
#                     installed (default on re-run: keep existing settings, just
#                     rebuild the binary + refresh GeoIP + restart)
#   -h, --help        show this help
#
# Re-running on an already-configured host UPDATES in place: it rebuilds and
# reinstalls the daemon/scripts/service and restarts, WITHOUT touching your
# existing firewall.conf / nftables.env / GeoIP credentials. So the documented
# upgrade flow just works:
#
#   git clone https://github.com/weby-dev/geo-firewall.git
#   cd geo-firewall && sudo ./install.sh

set -euo pipefail

log()  { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

[[ "$(id -u)" -eq 0 ]] || die "run as root:  sudo ./install.sh"
[[ "$(uname -s)" == "Linux" ]] || die "Linux only -- the daemon needs netfilter/NFQUEUE."

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
[[ -f CMakeLists.txt && -d src ]] || die "run this from the repo root (CMakeLists.txt/src not found)"

# ---------------------------------------------------------------- flags --------
ASSUME_YES=0
DO_START=1
RECONFIGURE=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes|--non-interactive) ASSUME_YES=1 ;;
        --no-start) DO_START=0 ;;
        --reconfigure|--reconfig) RECONFIGURE=1 ;;
        -h|--help) usage ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done

# ------------------------------------------------------- install vs update -----
# An existing firewall.conf means this host is already configured. On a plain
# re-run we then UPDATE in place: rebuild + reinstall + restart, but PRESERVE the
# existing config/nftables.env/GeoIP creds. --reconfigure forces the full Q&A.
CONF_DIR=/etc/webup-firewall
CONF_FILE="$CONF_DIR/firewall.conf"
NFT_ENV="$CONF_DIR/nftables.env"
MODE=install
PRESERVE=0
if [[ -f "$CONF_FILE" ]]; then
    MODE=update
    [[ "$RECONFIGURE" -eq 1 ]] || PRESERVE=1
fi

# conf_get KEY FILE -> value of `KEY = value` (last match; trims surrounding ws)
conf_get() {
    [[ -r "$2" ]] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | tail -n1 \
        | sed 's/[[:space:]]*$//'
}
# admin IPs currently in nftables.env (v4 + v6), space-separated
read_existing_admin_ips() {
    ( set +u; . "$NFT_ENV" 2>/dev/null
      echo "${ADMIN_IPS_V4[*]:-} ${ADMIN_IPS_V6[*]:-}" ) | xargs 2>/dev/null || true
}

# ask VAR "prompt" "default" [silent]
# Precedence: env WEBUP_<VAR>  >  interactive answer  >  default.
ask() {
    local __var="$1" __prompt="$2" __def="${3-}" __silent="${4-}" __val="" __env="WEBUP_$1"
    if [[ -n "${!__env-}" ]]; then printf -v "$__var" '%s' "${!__env}"; return; fi
    if [[ "$ASSUME_YES" -eq 1 ]]; then printf -v "$__var" '%s' "$__def"; return; fi
    if [[ "$__silent" == "silent" ]]; then
        read -r -s -p "$__prompt${__def:+ [default: keep blank]}: " __val; echo
    else
        read -r -p "$__prompt [${__def}]: " __val
    fi
    printf -v "$__var" '%s' "${__val:-$__def}"
}

yesno_to_bool() { case "${1,,}" in y|yes|true|1|on) echo true ;; *) echo false ;; esac; }

# ---------------------------------------------------- gather inputs ------------
# Safe defaults so `set -u` never trips on these later, even in preserve mode
# where the interactive Q&A is skipped entirely.
ADMIN_IPS=""; HOME_COUNTRY=""; NUM_QUEUES=""; BLOCK_DC_BOOL=""
UA_TOKEN=""; MM_ACCOUNT=""; MM_KEY=""; ALLOWED_UAS=""; ALLOWED_UA_FILE=""
ADMIN_V4=(); ADMIN_V6=()

if [[ "$PRESERVE" -eq 1 ]]; then
    log "Existing installation detected ($CONF_FILE)."
    log "UPDATING in place: rebuild + reinstall + restart, keeping your current"
    log "settings. Run with --reconfigure to change them."
else
    # Defaults: seed from the existing config when reconfiguring an install,
    # else from the environment / sensible fallbacks on a fresh install.
    DEF_ADMIN="$(awk '{print $1}' <<<"${SSH_CONNECTION:-}")"
    [[ -z "$DEF_ADMIN" ]] && DEF_ADMIN="$(awk '{print $1}' <<<"${SSH_CLIENT:-}")"
    DEF_HOME="IN"
    DEF_QUEUES="$(nproc 2>/dev/null || echo 4)"
    DEF_BLOCK="yes"
    if [[ "$MODE" == update ]]; then
        log "Reconfiguring existing install -- current values shown as defaults."
        cur_admin="$(read_existing_admin_ips)";              [[ -n "$cur_admin" ]] && DEF_ADMIN="$cur_admin"
        cur_home="$(conf_get home_country "$CONF_FILE")";    [[ -n "$cur_home" ]]  && DEF_HOME="$cur_home"
        cur_q="$(conf_get num_queues "$CONF_FILE")";         [[ -n "$cur_q" ]]     && DEF_QUEUES="$cur_q"
        [[ "$(conf_get block_datacenter "$CONF_FILE")" == false ]] && DEF_BLOCK="no"
    fi

    echo "=== WebUp firewall installer ==="
    ask ADMIN_IPS  "Admin IP(s) allowed to SSH regardless of geo (space-separated)" "$DEF_ADMIN"
    ask HOME_COUNTRY "Home country -- allowed inbound (ISO 3166 alpha-2)" "$DEF_HOME"
    ask NUM_QUEUES "Worker threads / NFQUEUEs (≈ CPU count)" "$DEF_QUEUES"
    ask BLOCK_DC   "Block datacenter/cloud/VPN networks on web ports? (yes/no)" "$DEF_BLOCK"

    # Custom User-Agent allowlist (allowlist mode). When you provide one or more
    # entries, ONLY requests whose User-Agent contains one of them are allowed on
    # web ports -- the mobile/bot heuristics are bypassed. Leave empty to instead
    # allow all mobile browsers.
    if [[ -n "${WEBUP_ALLOWED_UAS-}" ]]; then
        ALLOWED_UAS="$WEBUP_ALLOWED_UAS"                 # newline-separated
    elif [[ "$ASSUME_YES" -eq 0 ]]; then
        echo "Allowed custom User-Agents (one per line, blank line to finish)."
        echo "  -> ONLY these will be accepted. Leave empty to allow all mobile browsers."
        while true; do
            read -r -p "  custom UA> " __ua || break
            [[ -z "$__ua" ]] && break
            ALLOWED_UAS+="${__ua}"$'\n'
        done
    fi

    # Secret token only applies in open-mobile mode (ignored when an allowlist is set).
    if [[ -z "$ALLOWED_UAS" ]]; then
        ask UA_TOKEN "Secret User-Agent token (blank = open to all mobile browsers)" "" silent
    else
        UA_TOKEN=""
    fi

    # MaxMind License Key is shown as you type/paste it (plain text, not masked).
    ask MM_ACCOUNT "MaxMind Account ID (blank to skip GeoIP auto-download)" ""
    ask MM_KEY     "MaxMind License Key (shown as you type)" ""

    if [[ -z "$ADMIN_IPS" ]]; then
        if [[ "$ASSUME_YES" -eq 1 ]]; then
            die "No admin IP. Set WEBUP_ADMIN_IPS to avoid locking yourself out (fail-closed firewall)."
        fi
        warn "No admin IP set -- if the daemon ever stops you may lose SSH. Continuing anyway."
    fi
    [[ "$HOME_COUNTRY" =~ ^[A-Za-z]{2}$ ]] || die "home country must be a 2-letter code (got '$HOME_COUNTRY')"
    HOME_COUNTRY="${HOME_COUNTRY^^}"
    BLOCK_DC_BOOL="$(yesno_to_bool "$BLOCK_DC")"

    # Split admin IPs into v4 / v6 by presence of ':'.
    for ip in $ADMIN_IPS; do
        case "$ip" in *:*) ADMIN_V6+=("$ip") ;; *) ADMIN_V4+=("$ip") ;; esac
    done
fi

# ---------------------------------------------------- dependencies -------------
install_deps() {
    log "Installing build dependencies..."
    if   command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            build-essential cmake pkg-config git nftables \
            libnetfilter-queue-dev libmnl-dev libmaxminddb-dev libsystemd-dev geoipupdate
    elif command -v dnf >/dev/null; then
        dnf install -y gcc-c++ cmake pkgconf-pkg-config git nftables \
            libnetfilter_queue-devel libmnl-devel libmaxminddb-devel systemd-devel
        dnf install -y geoipupdate || warn "geoipupdate not in repos (try EPEL); GeoIP step may be skipped."
    elif command -v yum >/dev/null; then
        yum install -y gcc-c++ cmake pkgconfig git nftables \
            libnetfilter_queue-devel libmnl-devel libmaxminddb-devel systemd-devel
        yum install -y geoipupdate || warn "geoipupdate not in repos (try EPEL); GeoIP step may be skipped."
    elif command -v pacman >/dev/null; then
        pacman -Sy --needed --noconfirm base-devel cmake pkgconf git nftables \
            libnetfilter_queue libmnl libmaxminddb geoipupdate
    elif command -v zypper >/dev/null; then
        zypper --non-interactive install -y gcc-c++ cmake pkgconf git nftables \
            libnetfilter_queue-devel libmnl-devel libmaxminddb-devel systemd-devel geoipupdate
    else
        die "no supported package manager (apt/dnf/yum/pacman/zypper). Install deps manually, then re-run."
    fi
}
install_deps

# ---------------------------------------------------- build --------------------
log "Building webup-firewall..."
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"
[[ -x build/webup-firewall ]] || die "build failed -- no build/webup-firewall"
ctest --test-dir build --output-on-failure || warn "unit tests reported issues (continuing)"

# ---------------------------------------------------- install files ------------
GEO_DIR=/usr/share/GeoIP
log "Installing files..."
id webup-fw >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin webup-fw
install -d /opt/webup-firewall /etc/webup-firewall /usr/local/sbin "$GEO_DIR"
cp -r scripts /opt/webup-firewall/
chmod +x /opt/webup-firewall/scripts/*.sh
# Atomic replace via same-dir rename so an UPDATE works even while the old
# daemon is still running (writing the in-use binary in place can fail with
# ETXTBSY; the running process keeps the old inode until the restart below).
install -m 0755 build/webup-firewall /usr/local/sbin/webup-firewall.new
mv -f /usr/local/sbin/webup-firewall.new /usr/local/sbin/webup-firewall
install -m 0644 systemd/webup-firewall.service /etc/systemd/system/webup-firewall.service

if [[ "$PRESERVE" -eq 1 ]]; then
    log "Keeping existing config: $CONF_FILE, $NFT_ENV"
else

# back up an existing config before overwriting
if [[ -f /etc/webup-firewall/firewall.conf ]]; then
    cp /etc/webup-firewall/firewall.conf "/etc/webup-firewall/firewall.conf.bak.$(date +%s)"
fi

# custom User-Agent allowlist file (one UA substring per line), if provided
if [[ -n "$ALLOWED_UAS" ]]; then
    ALLOWED_UA_FILE=/etc/webup-firewall/allowed_uas.txt
    printf '%s' "$ALLOWED_UAS" > "$ALLOWED_UA_FILE"
    chmod 0644 "$ALLOWED_UA_FILE"
    log "Allowlist mode: $(grep -cve '^[[:space:]]*$' "$ALLOWED_UA_FILE") custom User-Agent(s) -> $ALLOWED_UA_FILE"
fi

# daemon config -- values on their own clean lines (no inline comments)
cat > /etc/webup-firewall/firewall.conf <<EOF
# Generated by install.sh $(date -u +%FT%TZ)
base_queue = 0
num_queues = ${NUM_QUEUES}
mark_approved = 1
mark_rejected = 2
queue_maxlen = 8192
recv_buffer_bytes = 8388608
geoip_db = ${GEO_DIR}/GeoLite2-Country.mmdb
home_country = ${HOME_COUNTRY}
treat_unknown_as_home = false
http_port = 80
https_port = 443
require_mobile = true
mobile_regex = (Mobile|Android|iPhone|iPod|Windows Phone|webOS|BlackBerry|Opera Mini|IEMobile)
ua_token = ${UA_TOKEN}
allowed_ua_file = ${ALLOWED_UA_FILE}
allowed_ua_regex =
asn_db = ${GEO_DIR}/GeoLite2-ASN.mmdb
block_datacenter = ${BLOCK_DC_BOOL}
blocked_asn_file =
datacenter_org_regex = (amazon|aws|google|cloud|azure|microsoft|ovh|hetzner|digitalocean|linode|akamai|fastly|cloudflare|vultr|scaleway|leaseweb|contabo|alibaba|aliyun|tencent|oracle|choopa|m247|datacamp|colo|hosting|datacenter|data center|dedicated|vpn|proxy)
required_headers = accept,accept-encoding
bot_ua_regex = (bot|crawl|spider|scrap|slurp|curl|wget|python-?requests|python-?urllib|libwww|http[-_]?client|go-http-client|java/|headless|phantom|selenium|puppeteer|playwright|axios|node-fetch|okhttp|httpie|aiohttp|guzzle|postman)
inapp_allow_regex = (Instagram|FBAN|FBAV|FB_IAB|FBIOS|Line/|Snapchat|musical_ly|CriOS|FxiOS|EdgiOS|GSA/)
max_inspect_bytes = 8192
http_idle_timeout_s = 15
max_http_conns = 65536
verbose = false
log_rate_per_sec = 50
stats_interval_s = 300
EOF

# nftables overrides (sourced by setup-nftables.sh)
v4_lit=""; ((${#ADMIN_V4[@]})) && v4_lit="$(printf '"%s" ' "${ADMIN_V4[@]}")"
v6_lit=""; ((${#ADMIN_V6[@]})) && v6_lit="$(printf '"%s" ' "${ADMIN_V6[@]}")"
cat > /etc/webup-firewall/nftables.env <<EOF
# Generated by install.sh $(date -u +%FT%TZ) -- sourced by setup-nftables.sh
QUEUE_BASE=0
NUM_QUEUES=${NUM_QUEUES}
MARK_APPROVED=1
MARK_REJECTED=2
HTTP_PORT=80
HTTPS_PORT=443
SSH_PORT=22
ADMIN_IPS_V4=( ${v4_lit})
ADMIN_IPS_V6=( ${v6_lit})
WEB_RATE="600/minute"
WEB_BURST=300
BAN_TTL="30m"
EOF
chmod 600 /etc/webup-firewall/nftables.env

fi   # end: PRESERVE==0 config generation

# ---------------------------------------------------- GeoIP --------------------
if [[ "$PRESERVE" -eq 1 ]]; then
    # Update mode: refresh existing databases if MaxMind creds are already stored.
    if [[ -f /etc/GeoIP.conf ]] && command -v geoipupdate >/dev/null; then
        log "Refreshing GeoIP databases (stored MaxMind credentials)..."
        geoipupdate -v || warn "geoipupdate failed -- keeping existing databases."
    elif [[ -f "${GEO_DIR}/GeoLite2-Country.mmdb" ]]; then
        log "Keeping existing GeoIP databases (no stored MaxMind credentials)."
    else
        warn "No ${GEO_DIR}/GeoLite2-Country.mmdb and no stored creds -- daemon may not start."
        DO_START=0
    fi
elif [[ -n "$MM_ACCOUNT" && -n "$MM_KEY" ]] && command -v geoipupdate >/dev/null; then
    log "Configuring + downloading GeoIP databases..."
    cat > /etc/GeoIP.conf <<EOF
AccountID ${MM_ACCOUNT}
LicenseKey ${MM_KEY}
EditionIDs GeoLite2-Country GeoLite2-ASN
DatabaseDirectory ${GEO_DIR}
EOF
    chmod 600 /etc/GeoIP.conf
    geoipupdate -v || warn "geoipupdate failed -- add ${GEO_DIR}/GeoLite2-Country.mmdb manually."
elif [[ -f "${GEO_DIR}/GeoLite2-Country.mmdb" ]]; then
    log "GeoIP database already present -- skipping download."
else
    warn "No MaxMind creds and no ${GEO_DIR}/GeoLite2-Country.mmdb."
    warn "The daemon will not start until that file exists. Get a free key at"
    warn "  https://www.maxmind.com/en/geolite2/signup  then run: geoipupdate"
    DO_START=0
fi

# optional: auto-reload the daemon after weekly GeoIP refresh
if systemctl list-unit-files 2>/dev/null | grep -q '^geoipupdate\.timer'; then
    systemctl enable --now geoipupdate.timer 2>/dev/null || true
    install -d /etc/systemd/system/geoipupdate.service.d
    cat > /etc/systemd/system/geoipupdate.service.d/reload-webup.conf <<'EOF'
[Service]
ExecStartPost=/bin/systemctl reload-or-restart webup-firewall
EOF
fi

# ---------------------------------------------------- enable / start -----------
systemctl daemon-reload
systemctl enable webup-firewall >/dev/null 2>&1 || true
systemctl reset-failed webup-firewall 2>/dev/null || true

if [[ "$DO_START" -eq 1 ]]; then
    log "$([[ "$MODE" == update ]] && echo "Restarting" || echo "Starting") webup-firewall..."
    systemctl restart webup-firewall
    sleep 1
    systemctl --no-pager --full status webup-firewall | sed -n '1,12p' || true
else
    warn "Service enabled but NOT started. Start it with:  systemctl start webup-firewall"
fi

# In preserve mode the summary vars were never gathered -- read them back from
# the on-disk config so the summary reflects the live settings.
if [[ "$PRESERVE" -eq 1 ]]; then
    HOME_COUNTRY="$(conf_get home_country "$CONF_FILE")"
    NUM_QUEUES="$(conf_get num_queues "$CONF_FILE")"
    [[ "$(conf_get block_datacenter "$CONF_FILE")" == false ]] && BLOCK_DC_BOOL=false || BLOCK_DC_BOOL=true
    ADMIN_IPS="$(read_existing_admin_ips)"
    ALLOWED_UA_FILE="$(conf_get allowed_ua_file "$CONF_FILE")"
    UA_TOKEN="$(conf_get ua_token "$CONF_FILE")"
fi

cat <<EOF

==================================================================
 WebUp firewall $([[ "$MODE" == update ]] && echo "updated" || echo "installed").
   home country : ${HOME_COUNTRY}     queues: ${NUM_QUEUES}     datacenter-block: ${BLOCK_DC_BOOL}
   admin SSH    : ${ADMIN_IPS:-<none>}
   access mode  : $([[ -n "$ALLOWED_UA_FILE" ]] && echo "custom UA allowlist ($ALLOWED_UA_FILE)" || { [[ -n "$UA_TOKEN" ]] && echo "app-only (token set)" || echo "open to all mobile browsers"; })
   config       : /etc/webup-firewall/firewall.conf
   nft settings : /etc/webup-firewall/nftables.env

 Useful commands:
   systemctl status webup-firewall
   journalctl -u webup-firewall -f          # live (set verbose=true in the config)
   nft list table inet webup                # live ruleset + counters
   systemctl reload webup-firewall          # apply config/GeoIP changes
   nft delete table inet webup              # EMERGENCY: drop all firewall rules

 NOTE: web ports are now ${HOME_COUNTRY}-only + mobile-only; non-mobile, foreign,
 and datacenter clients are dropped (silently -- they see a timeout). Keep your
 admin IP current so you never lose SSH.
==================================================================
EOF
