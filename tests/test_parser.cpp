// Portable unit tests for the packet parser and the User-Agent policy.
// No netfilter/GeoIP deps -> runs on any platform (CI, dev laptop, server).
//
//   c++ -std=c++17 -I src tests/test_parser.cpp src/packet.cpp
//       src/policy.cpp src/config.cpp -o webup-tests && ./webup-tests

#include "packet.hpp"
#include "policy.hpp"
#include "config.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <iostream>

static int g_fail = 0;
#define CHECK(cond) do { \
    if (!(cond)) { std::cerr << "FAIL " << __LINE__ << ": " #cond "\n"; ++g_fail; } \
} while (0)

// ---- packet builders --------------------------------------------------------
static void put16(std::vector<uint8_t>& v, size_t off, uint16_t x) {
    v[off] = x >> 8; v[off + 1] = x & 0xff;
}

static std::vector<uint8_t> ipv4_tcp(const char* src, uint16_t sport,
                                     uint16_t dport, const std::string& payload,
                                     uint16_t frag_field = 0) {
    std::vector<uint8_t> p(20 + 20 + payload.size(), 0);
    p[0] = 0x45;
    put16(p, 2, (uint16_t)p.size());
    put16(p, 6, frag_field);
    p[8] = 64;
    p[9] = IPPROTO_TCP;
    inet_pton(AF_INET, src, &p[12]);
    inet_pton(AF_INET, "10.0.0.1", &p[16]);
    put16(p, 20, sport);
    put16(p, 22, dport);
    p[32] = 0x50; // data offset = 5 words (20 bytes)
    std::memcpy(&p[40], payload.data(), payload.size());
    return p;
}

static std::vector<uint8_t> ipv4_udp(const char* src, uint16_t dport) {
    std::vector<uint8_t> p(20 + 8, 0);
    p[0] = 0x45;
    put16(p, 2, (uint16_t)p.size());
    p[8] = 64;
    p[9] = IPPROTO_UDP;
    inet_pton(AF_INET, src, &p[12]);
    inet_pton(AF_INET, "10.0.0.1", &p[16]);
    put16(p, 20, 1234);
    put16(p, 22, dport);
    return p;
}

// IPv6 with an optional single Hop-by-Hop (8-byte) extension header.
static std::vector<uint8_t> ipv6_tcp(const char* src, uint16_t dport,
                                     bool with_ext) {
    size_t ext = with_ext ? 8 : 0;
    std::vector<uint8_t> p(40 + ext + 20, 0);
    p[0] = 0x60;
    put16(p, 4, (uint16_t)(ext + 20));
    p[6] = with_ext ? 0 /*Hop-by-Hop*/ : IPPROTO_TCP;
    p[7] = 64;
    inet_pton(AF_INET6, src, &p[8]);
    inet_pton(AF_INET6, "fd00::1", &p[24]);
    size_t off = 40;
    if (with_ext) {
        p[40] = IPPROTO_TCP; // next header
        p[41] = 0;           // hdr ext len: (0+1)*8 = 8 bytes total
        off = 48;
    }
    put16(p, off, 5555);
    put16(p, off + 2, dport);
    p[off + 12] = 0x50;
    return p;
}

// ---- tests ------------------------------------------------------------------
static void test_packet() {
    {
        auto pkt = ipv4_tcp("8.8.8.8", 4444, 80, "GET / HTTP/1.1\r\n");
        PktInfo pi = parse_packet(pkt.data(), pkt.size());
        CHECK(pi.ok);
        CHECK(pi.af == AF_INET);
        CHECK(pi.is_tcp);
        CHECK(pi.src_text() == "8.8.8.8");
        CHECK(pi.src_port == 4444);
        CHECK(pi.dst_port == 80);
        CHECK(pi.l4_payload_len == 16);
        CHECK(pi.l4_payload && std::memcmp(pi.l4_payload, "GET ", 4) == 0);
    }
    {
        auto pkt = ipv4_udp("1.1.1.1", 53);
        PktInfo pi = parse_packet(pkt.data(), pkt.size());
        CHECK(pi.ok && !pi.is_tcp && pi.dst_port == 53);
    }
    {   // non-first fragment: offset 1 (in 8-byte units) -> no L4
        auto pkt = ipv4_tcp("8.8.8.8", 4444, 80, "x", /*frag_field=*/0x0001);
        PktInfo pi = parse_packet(pkt.data(), pkt.size());
        CHECK(pi.ok && pi.is_fragment && pi.dst_port == 0);
    }
    {   // truncated below an IPv4 header
        std::vector<uint8_t> pkt(10, 0); pkt[0] = 0x45;
        PktInfo pi = parse_packet(pkt.data(), pkt.size());
        CHECK(!pi.ok);
    }
    {
        auto pkt = ipv6_tcp("2001:db8::5", 443, /*with_ext=*/false);
        PktInfo pi = parse_packet(pkt.data(), pkt.size());
        CHECK(pi.ok && pi.af == AF_INET6 && pi.is_tcp && pi.dst_port == 443);
        CHECK(pi.src_text() == "2001:db8::5");
    }
    {   // IPv6 with a hop-by-hop ext header before TCP
        auto pkt = ipv6_tcp("2001:db8::5", 80, /*with_ext=*/true);
        PktInfo pi = parse_packet(pkt.data(), pkt.size());
        CHECK(pi.ok && pi.is_tcp && pi.dst_port == 80);
    }
}

// Builds a request with the two browser headers required by default.
static std::string req(const std::string& ua, bool accept = true,
                       bool accept_enc = true) {
    std::string s = "GET / HTTP/1.1\r\nHost: x\r\n";
    if (accept)     s += "Accept: text/html\r\n";
    if (accept_enc) s += "Accept-Encoding: gzip\r\n";
    if (!ua.empty()) s += "User-Agent: " + ua + "\r\n";
    s += "\r\n";
    return s;
}

static void test_policy() {
    Config c;                          // open-mobile defaults; no token
    Policy pol(c);
    std::string ua; DenyReason r;
    auto eval = [&](const std::string& s) { ua.clear(); return pol.evaluate_http(s, ua, r); };

    // genuine mobile browser -> allowed
    CHECK(eval(req("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) Mobile/15E148")) == HttpVerdict::Allow);
    CHECK(eval(req("Mozilla/5.0 (Linux; Android 13; Pixel) Chrome/120 Mobile")) == HttpVerdict::Allow);

    // in-app browsers (Telegram opens a mobile WebView; IG/FB carry markers)
    CHECK(eval(req("Mozilla/5.0 (Linux; Android 13) Chrome/120 Mobile Instagram 250.0")) == HttpVerdict::Allow);
    CHECK(eval(req("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) Mobile [FBAN/FBIOS;FBAV/400]")) == HttpVerdict::Allow);

    // desktop browser -> blocked (mobile only)
    CHECK(eval(req("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537")) == HttpVerdict::Deny);
    CHECK(r == DenyReason::NotMobile);

    // bots
    CHECK(eval(req("curl/8.4.0")) == HttpVerdict::Deny);             CHECK(r == DenyReason::BotUa);
    CHECK(eval(req("python-requests/2.31")) == HttpVerdict::Deny);   CHECK(r == DenyReason::BotUa);
    CHECK(eval(req("Mozilla/5.0 (compatible; SomeBot/1.0)")) == HttpVerdict::Deny); CHECK(r == DenyReason::BotUa);

    // missing browser headers -> bot
    CHECK(eval(req("Mozilla/5.0 (iPhone) Mobile", /*accept=*/true, /*accept_enc=*/false)) == HttpVerdict::Deny);
    CHECK(r == DenyReason::MissingHeaders);

    // no UA
    CHECK(eval(req("")) == HttpVerdict::Deny);                       CHECK(r == DenyReason::NoUa);

    // not HTTP / partial
    CHECK(eval("\x16\x03\x01 garbage") == HttpVerdict::Deny);        CHECK(r == DenyReason::NotHttp);
    CHECK(eval("GET / HTTP/1.1\r\nUser-Agent: Android Mobile\r\n") == HttpVerdict::NeedMore);
    CHECK(eval("GE") == HttpVerdict::NeedMore);
}

static void test_token() {
    Config c;
    c.ua_token = "S3CRET";             // opt-in app-only mode
    Policy pol(c);
    std::string ua; DenyReason r;
    CHECK(pol.evaluate_http(req("Mozilla/5.0 (iPhone) Mobile S3CRET"), ua, r) == HttpVerdict::Allow);
    CHECK(pol.evaluate_http(req("Mozilla/5.0 (iPhone) Mobile"), ua, r) == HttpVerdict::Deny);
    CHECK(r == DenyReason::NoToken);
}

static void test_ua_allowlist() {
    // Allowlist mode via inline regex: only the two custom UAs pass; mobile/bot
    // heuristics and required headers are bypassed.
    Config c;
    c.allowed_ua_regex = "(MyApp/[0-9.]+|SecretAgent-X)";
    Policy pol(c);
    std::string ua; DenyReason r;

    // matches -> allowed even though it's not "mobile" and sends no headers
    CHECK(pol.evaluate_http("GET / HTTP/1.1\r\nUser-Agent: MyApp/2.5 (any device)\r\n\r\n", ua, r)
          == HttpVerdict::Allow);
    CHECK(pol.evaluate_http("GET / HTTP/1.1\r\nUser-Agent: SecretAgent-X\r\n\r\n", ua, r)
          == HttpVerdict::Allow);

    // a normal mobile browser is NOT on the allowlist -> blocked
    CHECK(pol.evaluate_http(req("Mozilla/5.0 (iPhone) Mobile"), ua, r) == HttpVerdict::Deny);
    CHECK(r == DenyReason::NotAllowlisted);

    // no UA -> NoUa
    CHECK(pol.evaluate_http("GET / HTTP/1.1\r\nHost: x\r\n\r\n", ua, r) == HttpVerdict::Deny);
    CHECK(r == DenyReason::NoUa);
}

static void test_asn() {
    Config c;
    Policy pol(c);                     // default datacenter regex, block_datacenter=true
    CHECK(pol.is_blocked_asn(16509, "Amazon.com, Inc."));
    CHECK(pol.is_blocked_asn(14061, "DigitalOcean, LLC"));
    CHECK(pol.is_blocked_asn(0, "M247 Europe SRL"));
    CHECK(!pol.is_blocked_asn(55836, "Reliance Jio Infocomm Limited"));
    CHECK(!pol.is_blocked_asn(24560, "Bharti Airtel Ltd."));
}

static void test_config_inline_comments() {
    const char* path = "/tmp/webup_test_cfg.conf";
    { std::ofstream f(path);
      f << "home_country = IN   # inside country (ISO alpha-2)\n";
      f << "num_queues   = 8    # one per core\n";
      f << "bot_ua_regex = (bot|crawl#weird)\n";   // '#' not after space -> kept
      f << "ua_token     =\n"; }
    Config c = Config::load(path);
    CHECK(c.home_country == "IN");                  // inline comment stripped
    CHECK(c.num_queues == 8);
    CHECK(c.bot_ua_regex == "(bot|crawl#weird)");   // embedded '#' preserved
    CHECK(c.ua_token.empty());
    std::remove(path);
}

int main() {
    test_packet();
    test_policy();
    test_token();
    test_ua_allowlist();
    test_asn();
    test_config_inline_comments();
    if (g_fail == 0) std::cout << "all tests passed\n";
    else             std::cout << g_fail << " test(s) FAILED\n";
    return g_fail ? 1 : 0;
}
