#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

// Per-worker counters. Each worker thread owns ONE Stats instance and is its
// only writer, so increments never contend across cores. The struct is
// cache-line aligned (and padded to a multiple of the line size) so two
// workers' counters can never share a cache line -- eliminating the false
// sharing that a single global counter table would cause under high load.
//
// The main thread reads all workers' counters to print an aggregate snapshot;
// the fields stay atomic (relaxed) so those cross-thread reads are well-defined.
struct alignas(64) Stats {
    std::atomic<uint64_t> pkts{0};            // packets handed to userspace
    std::atomic<uint64_t> accept_normal{0};   // home, non-web port
    std::atomic<uint64_t> accept_https{0};    // home, 443 (nginx checks UA)
    std::atomic<uint64_t> accept_http{0};     // home, 80, UA passed
    std::atomic<uint64_t> drop_geo{0};        // Rule 1: outside home country
    std::atomic<uint64_t> drop_asn{0};        // web port, hosting/cloud/VPN ASN
    std::atomic<uint64_t> drop_ua{0};         // home, 80, not a mobile browser
    std::atomic<uint64_t> drop_botua{0};      // home, 80, bot User-Agent
    std::atomic<uint64_t> drop_headers{0};    // home, 80, missing browser headers
    std::atomic<uint64_t> drop_nothttp{0};    // home, 80, not HTTP
    std::atomic<uint64_t> drop_parse{0};      // unparseable packet (fail closed)
    std::atomic<uint64_t> needmore{0};        // accepted-but-undecided (HTTP/80)
    std::atomic<uint64_t> conns_shed{0};      // dropped due to pending-conn cap
    std::atomic<uint64_t> enobufs{0};         // kernel->us queue overflow events

    inline void bump(std::atomic<uint64_t>& c) {
        c.fetch_add(1, std::memory_order_relaxed);
    }

    // One-line human-readable snapshot, summed across every worker's counters.
    static std::string format(const std::vector<Stats>& all);
};
