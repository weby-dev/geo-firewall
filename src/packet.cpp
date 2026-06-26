#include "packet.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

namespace {

std::string ip_to_text(int af, const void* addr) {
    char b[INET6_ADDRSTRLEN] = {0};
    inet_ntop(af, addr, b, sizeof(b));
    return std::string(b);
}

// Alignment-safe big-endian 16-bit read (packet buffers aren't word-aligned).
uint16_t rd16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

bool is_ipv6_ext(uint8_t nh) {
    switch (nh) {
        case 0:   // Hop-by-Hop Options
        case 43:  // Routing
        case 44:  // Fragment
        case 51:  // Authentication Header
        case 60:  // Destination Options
        case 135: // Mobility
            return true;
        default:
            return false;
    }
}

// Parses the TCP/UDP port pair and (for TCP) the data offset at `l4_off`.
void parse_l4(const uint8_t* p, size_t len, size_t l4_off, uint8_t proto,
              PktInfo& pi) {
    if (len < l4_off + 4) { pi.ok = true; return; }  // ports unknown
    pi.src_port = rd16(p + l4_off);
    pi.dst_port = rd16(p + l4_off + 2);
    if (proto == IPPROTO_TCP) {
        pi.is_tcp = true;
        if (len < l4_off + 13) { pi.ok = true; return; }
        size_t thl = ((p[l4_off + 12] >> 4) & 0x0f) * 4u;
        size_t data_off = l4_off + thl;
        if (thl >= 20 && len > data_off) {
            pi.l4_payload = p + data_off;
            pi.l4_payload_len = len - data_off;
        }
    }
    pi.ok = true;
}

} // namespace

PktInfo parse_packet(const uint8_t* p, size_t len) {
    PktInfo pi;
    if (len < 1) return pi;
    uint8_t version = p[0] >> 4;

    if (version == 4) {
        if (len < 20) return pi;
        size_t ihl = (p[0] & 0x0f) * 4u;
        if (ihl < 20 || len < ihl) return pi;
        uint8_t proto = p[9];
        pi.af = AF_INET;
        pi.src_ip = ip_to_text(AF_INET, p + 12);
        pi.dst_ip = ip_to_text(AF_INET, p + 16);
        // Fragment? MF bit or non-zero offset => only the first fragment has L4.
        uint16_t frag = rd16(p + 6);
        bool first_frag = (frag & 0x1fff) == 0;
        pi.is_fragment = !first_frag;
        if (first_frag && (proto == IPPROTO_TCP || proto == IPPROTO_UDP))
            parse_l4(p, len, ihl, proto, pi);
        else
            pi.ok = true;
        return pi;
    }

    if (version == 6) {
        if (len < 40) return pi;
        pi.af = AF_INET6;
        pi.src_ip = ip_to_text(AF_INET6, p + 8);
        pi.dst_ip = ip_to_text(AF_INET6, p + 24);

        uint8_t nh = p[6];
        size_t off = 40;
        int guard = 0;
        while (is_ipv6_ext(nh) && guard++ < 16) {
            if (off + 2 > len) { pi.ok = true; return pi; }
            uint8_t next = p[off];
            size_t hlen;
            if (nh == 44) {            // Fragment header: fixed 8 bytes
                uint16_t fo = rd16(p + off + 2);
                if ((fo & 0xfff8) != 0) pi.is_fragment = true; // not first fragment
                hlen = 8;
            } else if (nh == 51) {     // Authentication Header
                hlen = (static_cast<size_t>(p[off + 1]) + 2) * 4u;
            } else {                   // Hop/Routing/Dest/Mobility
                hlen = (static_cast<size_t>(p[off + 1]) + 1) * 8u;
            }
            if (hlen == 0 || off + hlen > len) { pi.ok = true; return pi; }
            off += hlen;
            nh = next;
            if (pi.is_fragment) { pi.ok = true; return pi; }
        }

        if (nh == IPPROTO_TCP || nh == IPPROTO_UDP)
            parse_l4(p, len, off, nh, pi);
        else
            pi.ok = true;
        return pi;
    }

    return pi; // unknown L3
}
