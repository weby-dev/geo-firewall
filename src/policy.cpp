#include "policy.hpp"
#include <algorithm>
#include <cctype>
#include <array>
#include <fstream>
#include <sstream>
#include <iostream>

namespace {
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
bool looks_like_method(const std::string& word) {
    static const std::array<const char*, 9> methods = {
        "GET","POST","HEAD","PUT","DELETE","OPTIONS","PATCH","CONNECT","TRACE"};
    for (auto m : methods) if (word == m) return true;
    return false;
}
std::vector<std::string> split_csv_lower(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::string t = lower(trim(item));
        if (!t.empty()) out.push_back(t);
    }
    return out;
}
} // namespace

Policy::Policy(const Config& c) : cfg_(c) {
    auto mk = [](const std::string& pat) {
        return std::regex(pat, std::regex::icase | std::regex::optimize);
    };
    if (cfg_.require_mobile && !cfg_.mobile_regex.empty()) { mobile_ = mk(cfg_.mobile_regex); have_mobile_ = true; }
    if (!cfg_.bot_ua_regex.empty())                        { bot_    = mk(cfg_.bot_ua_regex); have_bot_ = true; }
    if (!cfg_.inapp_allow_regex.empty())                   { inapp_  = mk(cfg_.inapp_allow_regex); have_inapp_ = true; }
    if (cfg_.block_datacenter && !cfg_.datacenter_org_regex.empty()) {
        dc_ = mk(cfg_.datacenter_org_regex); have_dc_ = true;
    }
    required_headers_ = split_csv_lower(cfg_.required_headers);

    if (!cfg_.blocked_asn_file.empty()) {
        std::ifstream in(cfg_.blocked_asn_file);
        if (!in) {
            std::cerr << "policy: WARNING cannot read blocked_asn_file '"
                      << cfg_.blocked_asn_file << "' -- ignoring\n";
        } else {
            std::string line;
            while (std::getline(in, line)) {
                std::string t = trim(line);
                if (t.empty() || t[0] == '#') continue;
                if (t.size() > 2 && (t[0]=='A'||t[0]=='a') && (t[1]=='S'||t[1]=='s'))
                    t = t.substr(2);
                try { blocked_asns_.insert((uint32_t)std::stoul(t)); }
                catch (...) { /* skip malformed */ }
            }
        }
    }
}

bool Policy::is_blocked_asn(uint32_t asn, const std::string& org) const {
    if (asn != 0 && blocked_asns_.count(asn)) return true;
    if (have_dc_ && !org.empty() && std::regex_search(org, dc_)) return true;
    return false;
}

HttpVerdict Policy::evaluate_http(const std::string& buf, std::string& out_ua,
                                  DenyReason& reason) const {
    reason = DenyReason::None;

    // 1) First token must be a known HTTP method.
    {
        size_t sp = buf.find_first_of(" \r\n");
        if (sp == std::string::npos) {
            if (buf.size() > 8) { reason = DenyReason::NotHttp; return HttpVerdict::Deny; }
            return HttpVerdict::NeedMore;
        }
        if (!looks_like_method(buf.substr(0, sp))) {
            reason = DenyReason::NotHttp; return HttpVerdict::Deny;
        }
    }

    // 2) Need the full header block.
    size_t hdr_end = buf.find("\r\n\r\n");
    if (hdr_end == std::string::npos) {
        if (buf.size() >= cfg_.max_inspect_bytes) { reason = DenyReason::TooLarge; return HttpVerdict::Deny; }
        return HttpVerdict::NeedMore;
    }

    // 3) Walk headers: collect names present + grab User-Agent.
    std::string headers = buf.substr(0, hdr_end + 2);
    std::string lc = lower(headers);
    std::unordered_set<std::string> present;
    std::string ua;
    size_t pos = lc.find("\r\n");          // skip the request line
    if (pos != std::string::npos) pos += 2;
    else pos = lc.size();
    while (pos < lc.size()) {
        size_t eol = lc.find("\r\n", pos);
        if (eol == std::string::npos) break;
        size_t colon = lc.find(':', pos);
        if (colon != std::string::npos && colon < eol) {
            std::string name = trim(lc.substr(pos, colon - pos));
            if (!name.empty()) present.insert(name);
            if (name == "user-agent") {
                std::string val = headers.substr(colon + 1, eol - (colon + 1));
                ua = trim(val);
            }
        }
        pos = eol + 2;
    }
    out_ua = ua;

    // 4) Required browser headers.
    for (const auto& h : required_headers_) {
        if (!present.count(h)) { reason = DenyReason::MissingHeaders; return HttpVerdict::Deny; }
    }

    // 5) User-Agent checks.
    if (ua.empty()) { reason = DenyReason::NoUa; return HttpVerdict::Deny; }

    bool inapp = have_inapp_ && std::regex_search(ua, inapp_);

    // In-app browsers (Telegram/IG/FB...) are exempt from the bot denylist and
    // count as mobile; they still went through geo + ASN gates upstream.
    if (!inapp) {
        if (have_bot_ && std::regex_search(ua, bot_)) { reason = DenyReason::BotUa; return HttpVerdict::Deny; }
        if (have_mobile_ && !std::regex_search(ua, mobile_)) { reason = DenyReason::NotMobile; return HttpVerdict::Deny; }
    }

    // 6) Optional secret token (disabled by default for open mobile access).
    if (!cfg_.ua_token.empty() && ua.find(cfg_.ua_token) == std::string::npos) {
        reason = DenyReason::NoToken; return HttpVerdict::Deny;
    }

    return HttpVerdict::Allow;
}
