#include "stats.hpp"
#include <sstream>

std::string Stats::format() const {
    auto l = [](const std::atomic<uint64_t>& c) {
        return c.load(std::memory_order_relaxed);
    };
    std::ostringstream os;
    os << "stats"
       << " pkts="          << l(pkts)
       << " accept_normal=" << l(accept_normal)
       << " accept_https="  << l(accept_https)
       << " accept_http="   << l(accept_http)
       << " drop_geo="      << l(drop_geo)
       << " drop_asn="      << l(drop_asn)
       << " drop_ua="       << l(drop_ua)
       << " drop_botua="    << l(drop_botua)
       << " drop_headers="  << l(drop_headers)
       << " drop_nothttp="  << l(drop_nothttp)
       << " drop_parse="    << l(drop_parse)
       << " needmore="      << l(needmore)
       << " conns_shed="    << l(conns_shed)
       << " enobufs="       << l(enobufs);
    return os.str();
}
