#include "geoip.hpp"
#include <stdexcept>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

GeoIP::GeoIP(const std::string& db_path) {
    int status = MMDB_open(db_path.c_str(), MMDB_MODE_MMAP, &mmdb_);
    if (status != MMDB_SUCCESS)
        throw std::runtime_error("MMDB_open(" + db_path + "): " +
                                 MMDB_strerror(status));
    open_ = true;
}

GeoIP::~GeoIP() {
    if (open_) MMDB_close(&mmdb_);
}

std::string GeoIP::country(int af, const void* addr) const {
    // Build a sockaddr from the raw bytes and look it up directly -- no
    // text conversion, no getaddrinfo().
    struct sockaddr_storage ss{};
    ss.ss_family = static_cast<sa_family_t>(af);
    if (af == AF_INET) {
        auto* s = reinterpret_cast<struct sockaddr_in*>(&ss);
        std::memcpy(&s->sin_addr, addr, 4);
    } else if (af == AF_INET6) {
        auto* s = reinterpret_cast<struct sockaddr_in6*>(&ss);
        std::memcpy(&s->sin6_addr, addr, 16);
    } else {
        return "";
    }

    int mmdb_err = 0;
    MMDB_lookup_result_s res = MMDB_lookup_sockaddr(
        &mmdb_, reinterpret_cast<const struct sockaddr*>(&ss), &mmdb_err);

    if (mmdb_err != MMDB_SUCCESS || !res.found_entry)
        return "";

    MMDB_entry_data_s entry{};
    int status = MMDB_get_value(&res.entry, &entry, "country", "iso_code", NULL);
    if (status != MMDB_SUCCESS || !entry.has_data ||
        entry.type != MMDB_DATA_TYPE_UTF8_STRING)
        return "";

    return std::string(entry.utf8_string, entry.data_size);
}
