# WebUp Firewall

A multi-threaded C++ firewall daemon for Linux that enforces these rules on your
server:

1. **Your server can download anything**, but **no client outside your home
   country (India) can download from you** — all outsider-initiated inbound
   connections are dropped.
2. **Your website (ports 80/443) is open to genuine mobile browsers only** —
   including the in-app browsers of Telegram, Instagram and Facebook — **with no
   token and no challenge for real users.** Bots are filtered out by a layered
   stack: device (mobile UA) + behaviour (required browser headers, bot-UA
   denylist) + **network (datacenter/cloud/VPN ASN blocking)** + per-IP
   rate-limit/auto-ban.
3. **Everything else inside India works normally.**

GeoIP + ASN + connection-direction + plaintext-HTTP inspection happen in a C++
NFQUEUE daemon; the encrypted HTTPS checks are mirrored in nginx.

> **Honest scope.** "No bot can *ever* touch it" is not achievable by any
> firewall. With **no token and no challenge** (your choice, for zero user
> friction), the strongest remaining signal is the *network*: this blocks
> essentially all desktop bots, cloud/scraper bots and floods, but a determined
> bot running a spoofed mobile User-Agent from a **real residential/mobile IP**
> can still get through. To close that last gap you'd need a JS proof-of-work
> challenge or a signed-request/app-attestation client — both available as
> drop-in upgrades (see *Hardening further*).

---

## How it works

```
                 ┌─────────── OUTPUT hook (policy ACCEPT) ───────────┐
 your server ───▶│  your downloads go out & their replies come back   │──▶ internet
                 └───────────────────────────────────────────────────┘
                 ┌─────────── INPUT hook (policy DROP) ──────────────────────────┐
  clients   ────▶│ established/related ............ ACCEPT  (replies to you)       │
                 │ ct mark 1 / ct mark 2 .......... ACCEPT / DROP  (cached verdict)│
                 │ NEW conn → [nft auto-ban: banned? rate>limit? → DROP] →         │
                 │ NFQUEUE(fanout) ─▶ C++ worker:                                  │
                 │     geo(src) ≠ IN ........................... DROP   (Rule 1)    │
                 │     IN, port ∉ {80,443} ..................... ACCEPT (normal)    │
                 │     IN, web port, datacenter/VPN ASN ........ DROP   (bot)       │
                 │     IN, port 443 ............................ ACCEPT (nginx L7)  │
                 │     IN, port 80: not mobile / bot-UA / no    ─┐                 │
                 │       browser headers ........................ DROP   (bot)      │
                 │       genuine mobile browser ................ ACCEPT             │
                 └────────────────────────────────────────────────────────────────┘
```

- **Direction is free:** packets your server *sends* go through `OUTPUT` (open);
  replies return as conntrack `ESTABLISHED`. Only client-initiated packets reach
  `INPUT`, where the rules live.
- **Anti-bot layers** (cheap → expensive): nftables drops banned IPs and
  rate-limits floods in-kernel; the daemon drops datacenter/cloud/VPN ASNs and,
  on HTTP/80, anything that isn't a genuine mobile browser (UA + required
  headers + bot denylist, with Telegram/IG/FB in-app browsers explicitly
  allowed).
- **HTTPS L7 in nginx:** on 443 the UA and headers are TLS-encrypted — unreadable
  at the packet layer — so nginx mirrors the mobile/bot/header checks
  (`nginx/webup-ua-geo.conf`). The firewall still does the geo + ASN gate for 443.
- **Conntrack-mark fast path:** the daemon decides once per connection and stamps
  a conntrack mark (1=approved, 2=rejected). The rest of the flow matches the
  `ct mark` rules in nftables and never re-enters userspace.

### Production characteristics

| Concern | How it's handled |
|---------|------------------|
| Bot mitigation | Layered: datacenter/cloud/VPN **ASN block**, mobile-UA + required-header + bot-UA checks, in-kernel **rate-limit/auto-ban**. In-app browsers (TG/IG/FB) explicitly allowed. |
| Throughput / resilience | **N worker threads, one per NFQUEUE**, flows fanned out by hash. A stall on one flow can't block others. Set `num_queues ≈ nproc`. |
| Per-packet hot path | **No shared locks, no per-packet allocation.** GeoIP/ASN are looked up straight from the raw address bytes via `MMDB_lookup_sockaddr` (no `getaddrinfo` per packet); hot-swappable state is snapshotted once per batch (no `atomic<shared_ptr>` lock per packet); stats are **per-worker, cache-line aligned** (no cross-core counter bouncing); IP→text is computed only when actually logged. Built with LTO + `-O3`. |
| Burst headroom | `queue_maxlen` (kernel packets buffered per queue, default 8192 vs the kernel's 1024) and `recv_buffer_bytes` (netlink socket buffer) absorb spikes before fail-closed drops; `NFQNL_COPY_PACKET` copies only the bytes actually inspected. |
| GeoIP DB updates | **`SIGHUP` hot-reload** of DB + config + policy with zero dropped flows (`systemctl reload`). A bad reload is rejected and the old state kept. |
| DoS / memory | Per-worker cap on pending HTTP flows (`max_http_conns`) + idle sweep; excess is shed. Bounded header inspection (`max_inspect_bytes`). |
| Observability | Per-worker atomic counters summed and dumped every `stats_interval_s` and on `SIGUSR1`; per-rule `counter`s visible via `nft list table inet webup`. |
| Liveness | Optional **systemd watchdog** (`Type=notify`, `WatchdogSec=30`) + `Restart=always`. |
| Fail mode | **Fail-closed** (policy DROP) with an admin-SSH allowlist so you can always recover. |
| Privilege | Runs as a **dedicated unprivileged user** with only `CAP_NET_ADMIN`, plus a strict systemd sandbox. |
| Correctness | IPv4 + IPv6 (incl. extension-header chains); unit-tested parser/policy. |

---

## Components

| Path | Purpose |
|------|---------|
| `src/main.cpp` | Worker threads, signals/reload/stats, NFQUEUE verdicts |
| `src/packet.cpp` | Portable IPv4/IPv6 parser (ext-header walk) — unit-tested |
| `src/policy.cpp` | Compiled anti-bot policy (mobile/bot/header/ASN) — unit-tested |
| `src/geoip.cpp` | MaxMind GeoLite2-Country wrapper |
| `src/asn.cpp` | MaxMind GeoLite2-ASN wrapper (datacenter detection) |
| `src/stats.cpp` | Lock-free counters |
| `scripts/setup-nftables.sh` | Ruleset + auto-ban sets (**edit admin IPs + queues!**) |
| `config/firewall.conf` | Runtime config |
| `nginx/webup-ua-geo.conf` | HTTPS/443 geo + ASN + anti-bot enforcement |
| `systemd/webup-firewall.service` | Hardened service unit |
| `tests/test_parser.cpp` | Portable unit tests |

---

## Quick install (recommended)

`install.sh` detects your package manager (apt / dnf / yum / pacman / zypper),
installs deps, builds, configures, and starts the service. Run it from the repo
root on the **Linux server**:

```bash
git clone https://github.com/weby-dev/geo-firewall.git
cd geo-firewall
sudo ./install.sh
```

It prompts for everything (admin SSH IP — auto-detected from your session, home
country, queues, optional secret token, MaxMind Account ID + License Key) with
sensible defaults. Settings land in `/etc/webup-firewall/firewall.conf` and
`/etc/webup-firewall/nftables.env`.

Fully unattended (e.g. for config management):

```bash
sudo WEBUP_ADMIN_IPS="1.2.3.4" WEBUP_HOME_COUNTRY=IN WEBUP_NUM_QUEUES=4 \
     WEBUP_MM_ACCOUNT=123456 WEBUP_MM_KEY=xxxxxxxx ./install.sh --yes
```

Flags: `--yes` (non-interactive; requires `WEBUP_ADMIN_IPS` so you can't lock
yourself out), `--no-start` (install but don't activate the ruleset yet),
`--reconfigure` (re-run the questions on an already-configured host).

### Updating

Re-running the installer on a host that's already configured **updates in
place** — it rebuilds and reinstalls the daemon, scripts and service unit, then
restarts, **without touching your existing `firewall.conf`, `nftables.env` or
MaxMind credentials** (and it refreshes the GeoIP databases if creds are
stored). So upgrading to a newer version is just:

```bash
git clone https://github.com/weby-dev/geo-firewall.git
cd geo-firewall
sudo ./install.sh          # detects the existing install → update, keeps settings
```

The binary is swapped atomically (temp + rename), so the update is safe while
the old daemon is still serving traffic. Pass `--reconfigure` if you want to
change settings instead of keeping them (current values are offered as
defaults).

The manual steps below remain valid if you'd rather do it by hand or understand
each piece.

---

## Build (on the Linux server)

> The daemon is Linux-only (netfilter). Build on the server, or cross-compile.

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y build-essential cmake pkg-config nftables \
     libnetfilter-queue-dev libmnl-dev libmaxminddb-dev libsystemd-dev

# RHEL/Fedora
# sudo dnf install -y gcc-c++ cmake pkgconf-pkg-config nftables \
#      libnetfilter_queue-devel libmnl-devel libmaxminddb-devel systemd-devel

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure     # run unit tests
# -> build/webup-firewall
```

> `libsystemd-dev` enables the readiness/watchdog notifications the unit's
> `Type=notify` expects. If you build **without** it, edit the unit:
> set `Type=exec` and remove `WatchdogSec=30`.

### GeoIP databases

Create a free MaxMind account and download **both** databases:

- **GeoLite2-Country.mmdb** → `geoip_db` (default `/usr/share/GeoIP/GeoLite2-Country.mmdb`) — the India gate.
- **GeoLite2-ASN.mmdb** → `asn_db` (default `/usr/share/GeoIP/GeoLite2-ASN.mmdb`) — datacenter/cloud/VPN detection.

If the ASN DB is missing, the daemon logs a warning and **continues with
datacenter blocking disabled** (it won't fail to start). Use the `geoipupdate`
package to keep both fresh, then reload after each update (see "Operations").

---

## Configure

1. **`config/firewall.conf`** — confirm `home_country = IN`, the two GeoIP paths,
   and `num_queues` (≈ CPU count). Leave `ua_token` **empty** for open mobile
   access (no challenge); set it only for app-only mode. Tune
   `datacenter_org_regex` / `bot_ua_regex` / `inapp_allow_regex` if needed. For
   high traffic, set `num_queues ≈ nproc` and raise `queue_maxlen` /
   `recv_buffer_bytes` for more burst headroom before fail-closed drops.
2. **`scripts/setup-nftables.sh`** — set `ADMIN_IPS_V4` to your admin IP(s), and
   make `QUEUE_BASE` / `NUM_QUEUES` match the config. **Set admin IPs or you risk
   locking yourself out.**
3. **`nginx/webup-ua-geo.conf`** — set the token in `$webup_ua_token` to the
   *same* value as `ua_token`; include the maps + per-server guard.

---

## Install & run

```bash
# dedicated unprivileged user for the daemon
sudo useradd --system --no-create-home --shell /usr/sbin/nologin webup-fw

sudo install -d /opt/webup-firewall /etc/webup-firewall /usr/local/sbin
sudo cp -r scripts /opt/webup-firewall/
sudo cp build/webup-firewall /usr/local/sbin/
sudo cp config/firewall.conf /etc/webup-firewall/
sudo cp systemd/webup-firewall.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now webup-firewall
```

---

## Operations

```bash
# live counters
sudo systemctl kill -s SIGUSR1 webup-firewall && journalctl -u webup-firewall -n1
# per-rule hit counts
sudo nft list table inet webup
# hot-reload after a GeoIP/config change (no dropped flows)
sudo systemctl reload webup-firewall
# follow decisions (set verbose=true first)
journalctl -u webup-firewall -f
```

**Auto-reload after GeoIP updates** — drop in
`/etc/systemd/system/geoipupdate.service.d/reload-webup.conf`:

```ini
[Service]
ExecStartPost=/bin/systemctl reload-or-restart webup-firewall
```

**Kernel tuning** (the rules depend on conntrack — size it for your load):

```bash
# /etc/sysctl.d/99-webup.conf
net.netfilter.nf_conntrack_max = 1048576
net.core.rmem_max = 16777216
```

---

## Testing the rules

 Use a real mobile device on mobile data for the "allowed" cases (curl can't
 fake the *network* — it'll be on your test host's ASN — but it's fine for the
 device/header checks):

```bash
# From INSIDE India:
#  genuine-looking mobile browser request with browser headers -> allowed
curl -H 'Accept: text/html' -H 'Accept-Encoding: gzip' \
     -A 'Mozilla/5.0 (Linux; Android 13; Pixel) AppleWebKit/537.36 Chrome/120 Mobile' \
     http://your-server/                                              # 200
curl -A 'curl/8.4' http://your-server/                               # blocked (bot UA)
curl -A 'Mozilla/5.0 (Windows NT 10.0) Chrome/120' http://your-server/  # blocked (desktop)
curl -H 'Accept: text/html' -A 'Mozilla/5.0 (iPhone) Mobile' http://your-server/  # blocked (no Accept-Encoding)
ssh user@your-server                                                 # works (non-web port)

#  from a cloud host (AWS/GCP/...) inside India: blocked by ASN even with a
#  perfect mobile UA -> this is the core anti-bot win
curl -A 'Mozilla/5.0 (Linux; Android 13) Mobile' http://your-server/ # blocked (datacenter ASN)

# From OUTSIDE India:
curl http://your-server/                                             # blocked (Rule 1)
ssh user@your-server                                                 # blocked UNLESS in admin allowlist

# From the server itself, outbound is unaffected:
curl -O https://example.com/bigfile.iso                              # works
```

HTTPS/443 behaves the same; the device/header/bot checks happen in nginx (403).
Watch `sudo nft list table inet webup` and `SIGUSR1` stats to see which layer
caught each request (`drop_asn`, `drop_botua`, `drop_headers`, `drop_ua`, ...).

---

## Important caveats & limits

- **No firewall blocks *all* bots.** With no token/challenge, a bot with a
  spoofed mobile UA + browser headers from a **real residential/mobile IP**
  passes. This stack stops desktop bots, cloud/datacenter bots, naive scrapers
  and floods — the overwhelming majority — but not that last category.
- **CARRIER-GRADE NAT (critical for India):** Jio/Airtel put thousands of real
  mobile users behind one public IPv4. So per-IP rate limits are deliberately
  **generous** (`WEB_RATE`/`WEB_BURST` in the nft script) and the precise
  filtering is per-*request* (daemon + nginx), not per-IP. If you tighten the
  rate limits, you risk banning whole carrier pools — test carefully.
- **ASN data is approximate** and updated weekly; a brand-new hosting range may
  be missed until the next `geoipupdate`. VPN/proxy detection via org-name is
  best-effort. Both are coarse filters, not identity.
- **In-app vs. crawler:** the in-app *browsers* of TG/IG/FB (a user tapping a
  link) are allowed; their *link-preview crawlers* (`facebookexternalhit`,
  `TelegramBot`, from datacenter IPs) are blocked — so link previews won't render
  when your URLs are shared. Allowlist them explicitly if you want previews.
- **Keep-alive:** on HTTP/80 only the *first* request of a connection is checked.
- **No TCP reassembly:** the request is inspected as bytes arrive; headers must
  fit in `max_inspect_bytes` and complete within `http_idle_timeout_s`.
- **Fail-closed:** if the daemon dies, new inbound is dropped; admin SSH stays
  open via the allowlist so you can recover.
- **Defence in depth, not a replacement for application authentication.**

## Hardening further (closing the residual gap)

If you later want to stop the "spoofed mobile UA from a real IP" bots:

1. **App-only mode** — set `ua_token` (and the nginx token map). Your app injects
   the secret; normal browsers are then blocked. Strong if you control the app
   and ship the token only inside it (ideally via signed requests, not a static
   string).
2. **JS proof-of-work challenge** — front the site with a challenge (e.g. Anubis)
   so only clients that execute JavaScript get a cookie. Defeats non-JS scrapers
   with near-zero friction for real browsers.
3. **Signed requests / app attestation** — HMAC each request with a per-install
   key, or use Play Integrity / App Attest. The gold standard; bots can't forge
   it without breaking the attestation.
```
