// WebUp C++ geo / direction / User-Agent firewall daemon (production build).
//
// Multi-threaded: one worker thread per NFQUEUE id. nftables fans new flows out
// across base_queue .. base_queue+num_queues-1 by flow hash, so every packet of
// a given connection lands on the same worker -- letting each worker keep its
// pending-HTTP map lock-free.
//
// Decision table (all packets here are client-initiated INBOUND; the server's
// own outbound downloads never reach this queue -- see setup-nftables.sh):
//
//   GeoIP(src) != home_country          -> DROP   (Rule 1: outsiders can't pull from us)
//   home & dport not a web port         -> ACCEPT (rest works normally)
//   home & dport == https_port (443)    -> ACCEPT (UA is encrypted -> nginx enforces it)
//   home & dport == http_port  (80)     -> read the HTTP request:
//        mobile UA + token              -> ACCEPT
//        anything else / not HTTP       -> DROP
//
// Operational signals (handled in the main thread):
//   SIGHUP  -> reload config file, GeoIP DB and UA policy (no dropped flows)
//   SIGUSR1 -> dump counters to stderr/journal
//   SIGTERM/SIGINT -> graceful shutdown
//
// Build deps: libnetfilter_queue, libmnl, libmaxminddb (+ optional libsystemd).

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "config.hpp"
#include "geoip.hpp"
#include "asn.hpp"
#include "policy.hpp"
#include "packet.hpp"
#include "stats.hpp"

namespace {

// ---- shared, hot-swappable state -------------------------------------------
// Read in workers via std::atomic_load; replaced in the main thread on SIGHUP.
std::shared_ptr<const GeoIP>  g_geo;
std::shared_ptr<const ASNDB>  g_asn;     // may be null (datacenter blocking off)
std::shared_ptr<const Policy> g_policy;
Stats                         g_stats;
std::atomic<bool>             g_stop{false};

// ---- per-connection state for half-decided HTTP/80 flows -------------------
struct ConnState {
    std::string buf;
    std::chrono::steady_clock::time_point first_seen;
};

// ---- one worker bound to one queue id --------------------------------------
struct Worker {
    struct mnl_socket* nl = nullptr;
    unsigned int       portid = 0;
    uint16_t           queue_num = 0;
    std::unordered_map<std::string, ConnState> http_conns;

    // rate-limited decision logging
    time_t  log_second = 0;
    int     log_count  = 0;
};

void verdict_put_ctmark(struct nlmsghdr* nlh, uint32_t mark) {
    struct nlattr* nest = mnl_attr_nest_start(nlh, NFQA_CT);
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(mark));
    mnl_attr_nest_end(nlh, nest);
}

void send_verdict(Worker& w, uint32_t id, int verdict, bool set_mark, uint32_t mark) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, w.queue_num);
    nfq_nlmsg_verdict_put(nlh, id, verdict);
    if (set_mark) verdict_put_ctmark(nlh, mark);
    if (mnl_socket_sendto(w.nl, nlh, nlh->nlmsg_len) < 0)
        perror("mnl_socket_sendto(verdict)");
}

bool should_log(Worker& w, const Policy& pol) {
    if (!pol.cfg().verbose) return false;
    int rate = pol.cfg().log_rate_per_sec;
    if (rate <= 0) return true;
    time_t now = time(nullptr);
    if (now != w.log_second) { w.log_second = now; w.log_count = 0; }
    if (w.log_count >= rate) return false;
    ++w.log_count;
    return true;
}

void log_decision(Worker& w, const Policy& pol, const PktInfo& pi,
                  const std::string& country, const char* action,
                  const std::string& extra = "") {
    if (!should_log(w, pol)) return;
    std::cerr << "[q" << w.queue_num << "] " << action << "  "
              << pi.src_ip << ":" << pi.src_port << " -> :" << pi.dst_port
              << "  geo=" << (country.empty() ? "??" : country);
    if (!extra.empty()) std::cerr << "  " << extra;
    std::cerr << "\n";
}

std::string conn_key(const PktInfo& pi) {
    return pi.src_ip + "/" + std::to_string(pi.src_port) + ">" +
           pi.dst_ip + "/" + std::to_string(pi.dst_port);
}

void sweep_http_conns(Worker& w, int idle_timeout_s) {
    auto now = std::chrono::steady_clock::now();
    for (auto it = w.http_conns.begin(); it != w.http_conns.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
                       now - it->second.first_seen).count();
        if (age > idle_timeout_s) it = w.http_conns.erase(it);
        else ++it;
    }
}

// ---- per-packet decision ----------------------------------------------------
int queue_cb(const struct nlmsghdr* nlh, void* data) {
    Worker& w = *static_cast<Worker*>(data);

    struct nlattr* attr[NFQA_MAX + 1] = {};
    if (nfq_nlmsg_parse(nlh, attr) < 0) return MNL_CB_OK;
    if (!attr[NFQA_PACKET_HDR]) return MNL_CB_OK;

    auto* ph = static_cast<nfqnl_msg_packet_hdr*>(
        mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));
    uint32_t id = ntohl(ph->packet_id);

    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (attr[NFQA_PAYLOAD]) {
        payload = static_cast<const uint8_t*>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
        payload_len = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    }

    auto geo = std::atomic_load(&g_geo);
    auto pol = std::atomic_load(&g_policy);
    const Config& cfg = pol->cfg();

    g_stats.bump(g_stats.pkts);

    PktInfo pi = parse_packet(payload, payload_len);
    if (!pi.ok || pi.src_ip.empty()) {           // can't parse -> fail closed
        g_stats.bump(g_stats.drop_parse);
        send_verdict(w, id, NF_DROP, false, 0);
        return MNL_CB_OK;
    }

    std::string country = geo->country(pi.src_ip);
    bool is_home = country.empty() ? cfg.treat_unknown_as_home
                                   : (country == cfg.home_country);

    // ---- Rule 1: anything not from the home country is dropped --------------
    if (!is_home) {
        g_stats.bump(g_stats.drop_geo);
        log_decision(w, *pol, pi, country, "DROP-geo");
        send_verdict(w, id, NF_DROP, true, cfg.mark_rejected);
        return MNL_CB_OK;
    }

    bool is_http  = pi.is_tcp && pi.dst_port == cfg.http_port;
    bool is_https = pi.is_tcp && pi.dst_port == cfg.https_port;

    // ---- Home, non-web port -> normal --------------------------------------
    if (!is_http && !is_https) {
        g_stats.bump(g_stats.accept_normal);
        log_decision(w, *pol, pi, country, "ACCEPT-normal");
        send_verdict(w, id, NF_ACCEPT, true, cfg.mark_approved);
        return MNL_CB_OK;
    }

    // ---- Web port: block hosting/cloud/VPN networks (bots) ------------------
    // Real users are on mobile/residential ISPs; datacenter ASNs are bots.
    if (cfg.block_datacenter) {
        auto asn = std::atomic_load(&g_asn);
        if (asn) {
            uint32_t num = 0; std::string org;
            if (asn->lookup(pi.src_ip, num, org) && pol->is_blocked_asn(num, org)) {
                g_stats.bump(g_stats.drop_asn);
                log_decision(w, *pol, pi, country, "DROP-asn",
                             "AS" + std::to_string(num) + " \"" + org + "\"");
                send_verdict(w, id, NF_DROP, true, cfg.mark_rejected);
                return MNL_CB_OK;
            }
        }
    }

    // ---- Home, HTTPS/443 -> let it in; nginx enforces the UA ----------------
    if (is_https) {
        g_stats.bump(g_stats.accept_https);
        log_decision(w, *pol, pi, country, "ACCEPT-https(nginx-UA)");
        send_verdict(w, id, NF_ACCEPT, true, cfg.mark_approved);
        return MNL_CB_OK;
    }

    // ---- Home, HTTP/80 -> inspect the User-Agent ---------------------------
    // SYN / pure-ACK with no data: accept but stay UNDECIDED (ct mark 0) so the
    // request packet comes back for inspection.
    if (pi.l4_payload == nullptr || pi.l4_payload_len == 0) {
        g_stats.bump(g_stats.needmore);
        send_verdict(w, id, NF_ACCEPT, false, 0);
        return MNL_CB_OK;
    }

    std::string key = conn_key(pi);
    auto it = w.http_conns.find(key);
    if (it == w.http_conns.end()) {
        // New pending flow. Enforce the per-worker cap (DoS guard).
        if (w.http_conns.size() >= cfg.max_http_conns) {
            sweep_http_conns(w, cfg.http_idle_timeout_s);
            if (w.http_conns.size() >= cfg.max_http_conns) {
                g_stats.bump(g_stats.conns_shed);
                send_verdict(w, id, NF_DROP, true, cfg.mark_rejected);
                return MNL_CB_OK;
            }
        }
        it = w.http_conns.emplace(key, ConnState{}).first;
        it->second.first_seen = std::chrono::steady_clock::now();
    }
    ConnState& st = it->second;
    if (st.buf.size() < cfg.max_inspect_bytes) {
        size_t room = cfg.max_inspect_bytes - st.buf.size();
        st.buf.append(reinterpret_cast<const char*>(pi.l4_payload),
                      std::min(room, pi.l4_payload_len));
    }

    std::string ua;
    DenyReason reason = DenyReason::None;
    HttpVerdict hv = pol->evaluate_http(st.buf, ua, reason);
    if (hv == HttpVerdict::NeedMore) {
        g_stats.bump(g_stats.needmore);
        send_verdict(w, id, NF_ACCEPT, false, 0);
        return MNL_CB_OK;
    }

    w.http_conns.erase(it);
    if (hv == HttpVerdict::Allow) {
        g_stats.bump(g_stats.accept_http);
        log_decision(w, *pol, pi, country, "ACCEPT-http", "ua=\"" + ua + "\"");
        send_verdict(w, id, NF_ACCEPT, true, cfg.mark_approved);
    } else {
        const char* why = "bot";
        switch (reason) {
            case DenyReason::MissingHeaders: g_stats.bump(g_stats.drop_headers); why = "missing-headers"; break;
            case DenyReason::BotUa:          g_stats.bump(g_stats.drop_botua);   why = "bot-ua"; break;
            case DenyReason::NotMobile:      g_stats.bump(g_stats.drop_ua);      why = "not-mobile"; break;
            case DenyReason::NoUa:           g_stats.bump(g_stats.drop_ua);      why = "no-ua"; break;
            case DenyReason::NoToken:        g_stats.bump(g_stats.drop_ua);      why = "no-token"; break;
            case DenyReason::TooLarge:       g_stats.bump(g_stats.drop_nothttp); why = "headers-too-large"; break;
            case DenyReason::NotHttp:        g_stats.bump(g_stats.drop_nothttp); why = "not-http"; break;
            default:                         g_stats.bump(g_stats.drop_nothttp); break;
        }
        log_decision(w, *pol, pi, country, "DROP-http",
                     std::string(why) + (ua.empty() ? "" : " ua=\"" + ua + "\""));
        send_verdict(w, id, NF_DROP, true, cfg.mark_rejected);
    }
    return MNL_CB_OK;
}

bool nfq_bind_queue(Worker& w) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, w.queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(w.nl, nlh, nlh->nlmsg_len) < 0) { perror("nfq bind"); return false; }

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, w.queue_num);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK,  htonl(NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_GSO));
    if (mnl_socket_sendto(w.nl, nlh, nlh->nlmsg_len) < 0) { perror("nfq params"); return false; }
    return true;
}

void worker_loop(uint16_t queue_num) {
    Worker w;
    w.queue_num = queue_num;
    w.nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!w.nl) { perror("mnl_socket_open"); g_stop = true; return; }
    if (mnl_socket_bind(w.nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind"); g_stop = true; return;
    }
    w.portid = mnl_socket_get_portid(w.nl);
    if (!nfq_bind_queue(w)) { g_stop = true; return; }

    int one = 1;
    mnl_socket_setsockopt(w.nl, NETLINK_NO_ENOBUFS, &one, sizeof(one));
    int fd = mnl_socket_get_fd(w.nl);
    // Grow socket buffers so bursts don't ENOBUFS immediately.
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    const size_t rxsize = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    std::vector<char> rx(rxsize);
    uint64_t pkt_counter = 0;

    while (!g_stop.load(std::memory_order_relaxed)) {
        struct pollfd pfd { fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, 500);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }
        if (pr == 0) {                       // idle tick: sweep stale flows
            int idle = std::atomic_load(&g_policy)->cfg().http_idle_timeout_s;
            sweep_http_conns(w, idle);
            continue;
        }
        ssize_t n = mnl_socket_recvfrom(w.nl, rx.data(), rx.size());
        if (n == -1) {
            if (errno == ENOBUFS) { g_stats.bump(g_stats.enobufs); continue; }
            if (errno == EINTR || errno == EAGAIN) continue;
            perror("mnl_socket_recvfrom");
            break;
        }
        if (mnl_cb_run(rx.data(), n, 0, w.portid, queue_cb, &w) < 0)
            perror("mnl_cb_run");
        if ((++pkt_counter & 0x3ff) == 0) {
            int idle = std::atomic_load(&g_policy)->cfg().http_idle_timeout_s;
            sweep_http_conns(w, idle);
        }
    }
    mnl_socket_close(w.nl);
}

// Build fresh shared state from the config file; returns false (and leaves the
// old state in place) on any error so a bad reload never takes the daemon down.
bool load_state(const std::string& cfg_path, bool initial) {
    try {
        Config cfg = Config::load(cfg_path);
        auto geo = std::make_shared<const GeoIP>(cfg.geoip_db);
        auto pol = std::make_shared<const Policy>(cfg);

        // ASN DB is optional: a load failure disables datacenter blocking but
        // must never take the daemon down.
        std::shared_ptr<const ASNDB> asn;
        if (cfg.block_datacenter && !cfg.asn_db.empty()) {
            try {
                asn = std::make_shared<const ASNDB>(cfg.asn_db);
            } catch (const std::exception& e) {
                std::cerr << "warning: ASN DB load failed (" << e.what()
                          << ") -- datacenter blocking DISABLED\n";
            }
        }

        std::atomic_store(&g_geo, std::shared_ptr<const GeoIP>(geo));
        std::atomic_store(&g_policy, std::shared_ptr<const Policy>(pol));
        std::atomic_store(&g_asn, asn);          // may be null
        return true;
    } catch (const std::exception& e) {
        std::cerr << (initial ? "fatal" : "reload failed (keeping old config)")
                  << ": " << e.what() << "\n";
        return false;
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string cfg_path = (argc > 1) ? argv[1]
                                      : "/etc/webup-firewall/firewall.conf";

    if (!load_state(cfg_path, /*initial=*/true)) return 1;
    Config cfg = std::atomic_load(&g_policy)->cfg();

    // Block the signals we manage; worker threads inherit the block, so they
    // are delivered only to the main thread via sigtimedwait().
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);

    std::vector<std::thread> workers;
    for (unsigned i = 0; i < cfg.num_queues; ++i)
        workers.emplace_back(worker_loop, (uint16_t)(cfg.base_queue + i));

    std::cerr << "webup-firewall: queues " << cfg.base_queue << ".."
              << (cfg.base_queue + cfg.num_queues - 1)
              << ", home=" << cfg.home_country
              << ", http=" << cfg.http_port << " https=" << cfg.https_port
              << (cfg.verbose ? " [verbose]" : "") << "\n";

#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1\nSTATUS=running");
#endif

    time_t last_stats = time(nullptr);
    const int loop_timeout_s = 5;        // also the systemd watchdog ping cadence
    while (!g_stop.load()) {
        struct timespec ts { loop_timeout_s, 0 };
        siginfo_t si;
        int s = sigtimedwait(&set, &si, &ts);
        if (s == SIGINT || s == SIGTERM) {
            std::cerr << "webup-firewall: shutting down\n";
            g_stop = true;
            break;
        } else if (s == SIGHUP) {
            std::cerr << "webup-firewall: reloading\n";
            load_state(cfg_path, /*initial=*/false);
        } else if (s == SIGUSR1) {
            std::cerr << g_stats.format() << "\n";
        } // else: timeout (EAGAIN) or SIGPIPE -> fall through

#ifdef HAVE_SYSTEMD
        sd_notify(0, "WATCHDOG=1");
#endif
        time_t now = time(nullptr);
        Config cur = std::atomic_load(&g_policy)->cfg();
        if (cur.stats_interval_s > 0 && now - last_stats >= cur.stats_interval_s) {
            std::cerr << g_stats.format() << "\n";
            last_stats = now;
        }
    }

#ifdef HAVE_SYSTEMD
    sd_notify(0, "STOPPING=1");
#endif
    for (auto& t : workers) if (t.joinable()) t.join();
    std::cerr << g_stats.format() << "\n";
    return 0;
}
