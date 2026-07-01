#pragma once
#include <string>
#include <cstdint>
#include <maxminddb.h>

// RAII wrapper over a MaxMind GeoLite2-ASN database. Resolves a source IP to its
// Autonomous System number + organisation, used to tell mobile/residential
// networks (allowed) from hosting/cloud/VPN networks (bots, blocked).
class ASNDB {
public:
    explicit ASNDB(const std::string& db_path);   // throws std::runtime_error
    ~ASNDB();
    ASNDB(const ASNDB&) = delete;
    ASNDB& operator=(const ASNDB&) = delete;

    // Returns true and fills asn/org if the address is found. Takes the raw
    // address bytes (af = AF_INET/AF_INET6) and looks up via
    // MMDB_lookup_sockaddr() -- no getaddrinfo() on the per-packet hot path.
    bool lookup(int af, const void* addr, uint32_t& asn, std::string& org) const;

private:
    mutable MMDB_s mmdb_{};
    bool   open_ = false;
};
