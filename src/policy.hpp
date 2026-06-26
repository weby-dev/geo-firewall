#pragma once
#include <string>
#include <regex>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include "config.hpp"

enum class HttpVerdict {
    NeedMore,  // not enough bytes yet; accept this packet, keep watching
    Allow,     // genuine mobile-browser request
    Deny       // bot / not allowed
};

// Why a request was denied (for metrics + logging).
enum class DenyReason {
    None, NotHttp, MissingHeaders, BotUa, NotMobile, NoUa, NoToken, TooLarge,
    NotAllowlisted
};

// Immutable, thread-safe compiled view of the anti-bot policy. Built once from a
// Config and shared read-only across workers; swapped atomically on reload.
class Policy {
public:
    explicit Policy(const Config& c);   // throws std::regex_error on bad regex

    // Evaluate accumulated HTTP/80 request bytes. out_ua gets the parsed UA;
    // reason explains a Deny.
    HttpVerdict evaluate_http(const std::string& buf, std::string& out_ua,
                              DenyReason& reason) const;

    // Should a connection from this ASN/org be blocked as a hosting/cloud/VPN
    // network? (Applied to web ports only.)
    bool is_blocked_asn(uint32_t asn, const std::string& org) const;

    // True when a custom User-Agent allowlist is configured (allowlist mode).
    bool allowlist_mode() const { return have_allow_; }

    const Config& cfg() const { return cfg_; }

private:
    bool ua_allowlisted(const std::string& ua) const;

    Config cfg_;
    bool       have_mobile_ = false; std::regex mobile_;
    bool       have_bot_    = false; std::regex bot_;
    bool       have_inapp_  = false; std::regex inapp_;
    bool       have_dc_     = false; std::regex dc_;
    std::vector<std::string>      required_headers_;  // lowercased
    std::unordered_set<uint32_t>  blocked_asns_;

    // Custom UA allowlist
    bool                     have_allow_       = false;
    bool                     have_allow_regex_ = false;
    std::regex               allow_re_;
    std::vector<std::string> allowed_uas_;   // case-sensitive substring matches
};
