#pragma once
#include <string>
#include <cstdint>
#include <cstddef>

// Runtime configuration for the firewall daemon.
// Loaded from a simple key=value file (see config/firewall.conf).
struct Config {
    // --- NFQUEUE / kernel glue ---
    // Base queue id. With num_queues > 1 the daemon binds base_queue ..
    // base_queue+num_queues-1 and nftables fans flows out across that range.
    uint16_t base_queue      = 0;
    unsigned num_queues      = 4;        // worker threads = queues; must match nft script

    // ct marks the daemon writes back so nftables can fast-path the rest of a
    // connection without bouncing every packet to userspace. Must match the
    // values used in setup-nftables.sh.
    uint32_t mark_approved   = 1;
    uint32_t mark_rejected   = 2;

    // --- GeoIP ---
    std::string geoip_db     = "/usr/share/GeoIP/GeoLite2-Country.mmdb";
    std::string home_country = "IN";     // "inside" = this; everything else = "outside"
    // If the source IP cannot be resolved to a country (private ranges, missing
    // from the DB, etc.) should we treat it as the home country? Default: no,
    // i.e. unknown is treated as "outside" and blocked. LAN/admin access should
    // be handled via the SSH allowlist in setup-nftables.sh instead.
    bool treat_unknown_as_home = false;

    // --- Web ports ---
    uint16_t http_port       = 80;       // plaintext: User-Agent enforced HERE, in C++
    uint16_t https_port      = 443;      // TLS: User-Agent enforced in nginx (see nginx/)

    // --- User-Agent policy (applied to HTTP/80; nginx mirrors it for 443) ---
    bool require_mobile      = true;     // UA must look like a mobile browser
    // Case-insensitive regex deciding "is this a mobile device".
    std::string mobile_regex =
        "(Mobile|Android|iPhone|iPad|iPod|Windows Phone|webOS|BlackBerry|Opera Mini|IEMobile)";
    // The secret token YOU define that must appear verbatim in the User-Agent.
    // Empty => token check skipped (NOT recommended).
    std::string ua_token     = "";

    // Stop accumulating / reading request headers after this many bytes. A
    // request whose headers exceed this without a verdict is rejected (anti
    // slow-loris / oversized-header abuse).
    size_t max_inspect_bytes = 8192;

    // Drop a half-open HTTP/80 connection that never sends a parseable request
    // within this many seconds (slow-loris guard).
    int http_idle_timeout_s  = 15;

    // Hard cap on pending (undecided) HTTP/80 connections tracked PER WORKER.
    // Protects memory under a SYN+data flood; excess new flows are dropped.
    size_t max_http_conns    = 65536;

    // --- Anti-bot: ASN / datacenter blocking (applied to web ports only) ----
    // Real mobile users come from carrier ASNs; bots overwhelmingly come from
    // hosting/cloud/VPN ASNs. We DENY those on 80/443 (your site stays open to
    // residential + mobile networks, incl. phones on home Wi-Fi).
    std::string asn_db        = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";
    bool block_datacenter     = true;
    // Optional file of ASNs (one per line, "AS123" or "123", '#' comments) to
    // always block, in addition to the org-name regex below.
    std::string blocked_asn_file = "";
    // Case-insensitive regex matched against the ASN organisation name.
    std::string datacenter_org_regex =
        "(amazon|aws|google|cloud|azure|microsoft|ovh|hetzner|digitalocean|"
        "linode|akamai|fastly|cloudflare|vultr|scaleway|leaseweb|contabo|"
        "alibaba|aliyun|tencent|oracle|choopa|m247|datacamp|colo|hosting|"
        "datacenter|data center|dedicated|vpn|proxy)";

    // --- Anti-bot: HTTP heuristics (HTTP/80; nginx mirrors these for 443) ----
    // Header names that a real browser always sends; comma-separated, lowercase.
    // Requests missing any of these are treated as bots.
    std::string required_headers = "accept,accept-encoding";
    // Case-insensitive UA denylist (non-browser HTTP clients & headless tools).
    std::string bot_ua_regex =
        "(bot|crawl|spider|scrap|slurp|curl|wget|python-?requests|python-?urllib|"
        "libwww|http[-_]?client|go-http-client|java/|headless|phantom|selenium|"
        "puppeteer|playwright|axios|node-fetch|okhttp|httpie|aiohttp|guzzle|postman)";
    // In-app browser markers (Telegram/IG/FB/etc.) that must ALWAYS be allowed:
    // counts as a mobile browser and is exempt from the bot denylist. It still
    // must pass geo + ASN checks.
    std::string inapp_allow_regex =
        "(Instagram|FBAN|FBAV|FB_IAB|FBIOS|Line/|Snapchat|musical_ly|"
        "CriOS|FxiOS|EdgiOS|GSA/)";

    // --- Observability ---
    bool   verbose           = false;    // log every decision (rate-limited)
    int    log_rate_per_sec  = 50;       // max decision log lines/sec/worker (0 = unlimited)
    int    stats_interval_s  = 300;      // periodic stats dump to stderr (0 = off; also SIGUSR1)

    // Loads from `path`. Lines: key=value, '#' comments, blank lines ignored.
    // Throws std::runtime_error on unreadable file. Unknown keys warn to stderr.
    static Config load(const std::string& path);

    // Validates ranges/consistency; throws std::runtime_error on bad values.
    void validate() const;
};
