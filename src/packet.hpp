#pragma once
#include <string>
#include <cstdint>
#include <cstddef>

// A parsed, protocol-agnostic view of one captured packet. Portable: depends
// only on the C library, so it is unit-tested on any platform (see tests/).
//
// Addresses are kept as RAW network-order bytes (4 for IPv4, 16 for IPv6) so the
// hot path can feed them straight to MMDB_lookup_sockaddr() -- no per-packet
// inet_ntop() + getaddrinfo() round-trip. The textual form is computed lazily
// via src_text()/dst_text(), only where it is actually needed (logging, the
// HTTP/80 connection key).
struct PktInfo {
    bool        ok       = false;  // L3 header parsed (addresses valid)
    bool        is_tcp   = false;
    bool        is_fragment = false; // non-first IP fragment (no usable L4 header)
    int         af       = 0;      // AF_INET / AF_INET6 / 0
    uint8_t     src_addr[16] = {}; // raw network-order source address bytes
    uint8_t     dst_addr[16] = {}; // raw network-order destination address bytes
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    const uint8_t* l4_payload = nullptr;  // TCP payload (HTTP bytes), if any
    size_t      l4_payload_len = 0;

    // Textual address forms, computed on demand (allocates). Return "" if af==0.
    std::string src_text() const;
    std::string dst_text() const;
};

// Parse an IPv4 or IPv6 packet. IPv6 extension-header chains are walked to reach
// the transport header. Returns pi.ok=false only when the L3 header itself is
// unparseable.
PktInfo parse_packet(const uint8_t* p, size_t len);
