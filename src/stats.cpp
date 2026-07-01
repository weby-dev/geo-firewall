#include "stats.hpp"
#include <sstream>

std::string Stats::format(const std::vector<Stats>& all) {
    // Sum one field across all workers.
    auto sum = [&all](std::atomic<uint64_t> Stats::* field) {
        uint64_t t = 0;
        for (const auto& s : all)
            t += (s.*field).load(std::memory_order_relaxed);
        return t;
    };
    std::ostringstream os;
    os << "stats"
       << " pkts="          << sum(&Stats::pkts)
       << " accept_normal=" << sum(&Stats::accept_normal)
       << " accept_https="  << sum(&Stats::accept_https)
       << " accept_http="   << sum(&Stats::accept_http)
       << " drop_geo="      << sum(&Stats::drop_geo)
       << " drop_asn="      << sum(&Stats::drop_asn)
       << " drop_ua="       << sum(&Stats::drop_ua)
       << " drop_botua="    << sum(&Stats::drop_botua)
       << " drop_headers="  << sum(&Stats::drop_headers)
       << " drop_nothttp="  << sum(&Stats::drop_nothttp)
       << " drop_parse="    << sum(&Stats::drop_parse)
       << " needmore="      << sum(&Stats::needmore)
       << " conns_shed="    << sum(&Stats::conns_shed)
       << " enobufs="       << sum(&Stats::enobufs);
    return os.str();
}
