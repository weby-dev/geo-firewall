#pragma once
#include <string>
#include <maxminddb.h>

// Thin RAII wrapper over a MaxMind GeoLite2-Country database.
class GeoIP {
public:
    explicit GeoIP(const std::string& db_path);   // throws std::runtime_error on failure
    ~GeoIP();

    GeoIP(const GeoIP&) = delete;
    GeoIP& operator=(const GeoIP&) = delete;

    // Returns the ISO 3166-1 alpha-2 country code (e.g. "IN", "US") for a raw
    // address (af = AF_INET with 4 bytes, or AF_INET6 with 16 bytes), or "" if
    // the address is unknown / private / not in the database.
    //
    // Takes the binary address directly (not text): this looks up via
    // MMDB_lookup_sockaddr() and avoids the getaddrinfo() call that
    // MMDB_lookup_string() makes on every single lookup -- a major saving on the
    // per-packet hot path.
    std::string country(int af, const void* addr) const;

private:
    // mutable so country() can stay const even if the linked libmaxminddb
    // exposes MMDB_lookup_string with a non-const MMDB_s* (varies by version).
    mutable MMDB_s mmdb_{};
    bool   open_ = false;
};
