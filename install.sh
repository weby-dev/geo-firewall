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
#   -h, --help        show this help

set -euo pipefail

log()  { printf '\033[1;32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

[[ "$(id -u)" -eq 0 ]] || die "run as root:  sudo ./install.sh"
[[ "$(uname -s)" == "Linux" ]] || die "Linux only -- the daemon needs netfilter/NFQUEUE."

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
[[ -f CMakeLists.txt && -d src ]] || die "run this from the repo root (CMakeLists.txt/src not found)"

# ---------------------------------------------------------------- flags --------
ASSUME_YES=0
DO_START=1
for arg in "$@"; do
    case "$arg" in
        -y|--yes|--non-interactive) ASSUME_YES=1 ;;
        --no-start) DO_START=0 ;;
        -h|--help) usage ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done

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
DEF_ADMIN="$(awk '{print $1}' <<<"${SSH_CONNECTION:-}")"
[[ -z "$DEF_ADMIN" ]] && DEF_ADMIN="$(awk '{print $1}' <<<"${SSH_CLIENT:-}")"
DEF_QUEUES="$(nproc 2>/dev/null || echo 4)"

echo "=== WebUp firewall installer ==="
ask ADMIN_IPS  "Admin IP(s) allowed to SSH regardless of geo (space-separated)" "$DEF_ADMIN"
ask HOME_COUNTRY "Home country -- allowed inbound (ISO 3166 alpha-2)" "IN"
ask NUM_QUEUES "Worker threads / NFQUEUEs (≈ CPU count)" "$DEF_QUEUES"
ask UA_TOKEN   "Secret User-Agent token (blank = open to all mobile browsers)" "" silent
ask BLOCK_DC   "Block datacenter/cloud/VPN networks on web ports? (yes/no)" "yes"
ask MM_ACCOUNT "MaxMind Account ID (blank to skip GeoIP auto-download)" ""
ask MM_KEY     "MaxMind License Key" "" silent

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
ADMIN_V4=(); ADMIN_V6=()
for ip in $ADMIN_IPS; do
    case "$ip" in *:*) ADMIN_V6+=("$ip") ;; *) ADMIN_V4+=("$ip") ;; esac
done

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
install -m 0755 build/webup-firewall /usr/local/sbin/webup-firewall
install -m 0644 systemd/webup-firewall.service /etc/systemd/system/webup-firewall.service

# back up an existing config before overwriting
if [[ -f /etc/webup-firewall/firewall.conf ]]; then
    cp /etc/webup-firewall/firewall.conf "/etc/webup-firewall/firewall.conf.bak.$(date +%s)"
fi

# daemon config -- values on their own clean lines (no inline comments)
cat > /etc/webup-firewall/firewall.conf <<EOF
# Generated by install.sh $(date -u +%FT%TZ)
base_queue = 0
num_queues = ${NUM_QUEUES}
mark_approved = 1
mark_rejected = 2
geoip_db = ${GEO_DIR}/GeoLite2-Country.mmdb
home_country = ${HOME_COUNTRY}
treat_unknown_as_home = false
http_port = 80
https_port = 443
require_mobile = true
mobile_regex = (Mobile|Android|iPhone|iPod|Windows Phone|webOS|BlackBerry|Opera Mini|IEMobile)
ua_token = ${UA_TOKEN}
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

# ---------------------------------------------------- GeoIP --------------------
if [[ -n "$MM_ACCOUNT" && -n "$MM_KEY" ]] && command -v geoipupdate >/dev/null; then
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
    log "Starting webup-firewall..."
    systemctl restart webup-firewall
    sleep 1
    systemctl --no-pager --full status webup-firewall | sed -n '1,12p' || true
else
    warn "Service enabled but NOT started. Start it with:  systemctl start webup-firewall"
fi

cat <<EOF

==================================================================
 WebUp firewall installed.
   home country : ${HOME_COUNTRY}     queues: ${NUM_QUEUES}     datacenter-block: ${BLOCK_DC_BOOL}
   admin SSH    : ${ADMIN_IPS:-<none>}
   token mode   : $([[ -n "$UA_TOKEN" ]] && echo "app-only (token set)" || echo "open to all mobile browsers")
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
