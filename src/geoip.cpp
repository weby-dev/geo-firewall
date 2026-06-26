#include "geoip.hpp"
#include <stdexcept>

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

std::string GeoIP::country(const std::string& ip_text) const {
    int gai_err = 0, mmdb_err = 0;
    MMDB_lookup_result_s res =
        MMDB_lookup_string(&mmdb_, ip_text.c_str(), &gai_err, &mmdb_err);

    if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !res.found_entry)
        return "";

    MMDB_entry_data_s entry{};
    int status = MMDB_get_value(&res.entry, &entry, "country", "iso_code", NULL);
    if (status != MMDB_SUCCESS || !entry.has_data ||
        entry.type != MMDB_DATA_TYPE_UTF8_STRING)
        return "";

    return std::string(entry.utf8_string, entry.data_size);
}
