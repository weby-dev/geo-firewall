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

    // Returns the ISO 3166-1 alpha-2 country code (e.g. "IN", "US") for a
    // textual IPv4/IPv6 address, or "" if the address is unknown / private /
    // not in the database.
    std::string country(const std::string& ip_text) const;

private:
    // mutable so country() can stay const even if the linked libmaxminddb
    // exposes MMDB_lookup_string with a non-const MMDB_s* (varies by version).
    mutable MMDB_s mmdb_{};
    bool   open_ = false;
};
