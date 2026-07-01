#include "asn.hpp"
#include <stdexcept>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

ASNDB::ASNDB(const std::string& db_path) {
    int status = MMDB_open(db_path.c_str(), MMDB_MODE_MMAP, &mmdb_);
    if (status != MMDB_SUCCESS)
        throw std::runtime_error("MMDB_open(" + db_path + "): " +
                                 MMDB_strerror(status));
    open_ = true;
}

ASNDB::~ASNDB() {
    if (open_) MMDB_close(&mmdb_);
}

bool ASNDB::lookup(int af, const void* addr, uint32_t& asn,
                   std::string& org) const {
    struct sockaddr_storage ss{};
    ss.ss_family = static_cast<sa_family_t>(af);
    if (af == AF_INET) {
        auto* s = reinterpret_cast<struct sockaddr_in*>(&ss);
        std::memcpy(&s->sin_addr, addr, 4);
    } else if (af == AF_INET6) {
        auto* s = reinterpret_cast<struct sockaddr_in6*>(&ss);
        std::memcpy(&s->sin6_addr, addr, 16);
    } else {
        return false;
    }

    int mmdb_err = 0;
    MMDB_lookup_result_s res = MMDB_lookup_sockaddr(
        &mmdb_, reinterpret_cast<const struct sockaddr*>(&ss), &mmdb_err);
    if (mmdb_err != MMDB_SUCCESS || !res.found_entry)
        return false;

    asn = 0;
    org.clear();

    MMDB_entry_data_s ed{};
    if (MMDB_get_value(&res.entry, &ed, "autonomous_system_number", NULL) ==
            MMDB_SUCCESS && ed.has_data && ed.type == MMDB_DATA_TYPE_UINT32)
        asn = ed.uint32;

    MMDB_entry_data_s eo{};
    if (MMDB_get_value(&res.entry, &eo, "autonomous_system_organization", NULL) ==
            MMDB_SUCCESS && eo.has_data && eo.type == MMDB_DATA_TYPE_UTF8_STRING)
        org.assign(eo.utf8_string, eo.data_size);

    return asn != 0 || !org.empty();
}
