#pragma once
#include <string>
#include <cstdint>
#include <cstddef>

// A parsed, protocol-agnostic view of one captured packet. Portable: depends
// only on the C library, so it is unit-tested on any platform (see tests/).
struct PktInfo {
    bool        ok       = false;  // L3 header parsed (addresses valid)
    bool        is_tcp   = false;
    bool        is_fragment = false; // non-first IP fragment (no usable L4 header)
    int         af       = 0;      // AF_INET / AF_INET6 / 0
    std::string src_ip;            // textual source address
    std::string dst_ip;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    const uint8_t* l4_payload = nullptr;  // TCP payload (HTTP bytes), if any
    size_t      l4_payload_len = 0;
};

// Parse an IPv4 or IPv6 packet. IPv6 extension-header chains are walked to reach
// the transport header. Returns pi.ok=false only when the L3 header itself is
// unparseable.
PktInfo parse_packet(const uint8_t* p, size_t len);
