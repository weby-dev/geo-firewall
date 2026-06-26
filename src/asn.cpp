#include "asn.hpp"
#include <stdexcept>

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

bool ASNDB::lookup(const std::string& ip_text, uint32_t& asn,
                   std::string& org) const {
    int gai_err = 0, mmdb_err = 0;
    MMDB_lookup_result_s res =
        MMDB_lookup_string(&mmdb_, ip_text.c_str(), &gai_err, &mmdb_err);
    if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !res.found_entry)
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
