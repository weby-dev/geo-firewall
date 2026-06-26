#include "config.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <cctype>

namespace {
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
bool to_bool(const std::string& v) {
    std::string s = v;
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s == "1" || s == "true" || s == "yes" || s == "on";
}
} // namespace

Config Config::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open config file: " + path);

    Config c;
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        std::string s = trim(line);
        if (s.empty() || s[0] == '#') continue;
        auto eq = s.find('=');
        if (eq == std::string::npos) {
            std::cerr << "config: ignoring malformed line " << lineno << "\n";
            continue;
        }
        std::string key = trim(s.substr(0, eq));
        std::string val = s.substr(eq + 1);
        // Strip an inline comment: a '#' at the start of the value, or one
        // preceded by whitespace, begins a comment. (A '#' embedded in a token,
        // e.g. a regex, is kept.) This lets "key = value   # note" work.
        for (size_t i = 0; i < val.size(); ++i) {
            if (val[i] == '#' && (i == 0 || val[i-1] == ' ' || val[i-1] == '\t')) {
                val.erase(i);
                break;
            }
        }
        val = trim(val);

        try {
            if      (key == "base_queue")            c.base_queue = (uint16_t)std::stoul(val);
            else if (key == "num_queues")            c.num_queues = (unsigned)std::stoul(val);
            else if (key == "mark_approved")         c.mark_approved = (uint32_t)std::stoul(val);
            else if (key == "mark_rejected")         c.mark_rejected = (uint32_t)std::stoul(val);
            else if (key == "geoip_db")              c.geoip_db = val;
            else if (key == "home_country")          c.home_country = val;
            else if (key == "treat_unknown_as_home") c.treat_unknown_as_home = to_bool(val);
            else if (key == "http_port")             c.http_port = (uint16_t)std::stoul(val);
            else if (key == "https_port")            c.https_port = (uint16_t)std::stoul(val);
            else if (key == "require_mobile")        c.require_mobile = to_bool(val);
            else if (key == "mobile_regex")          c.mobile_regex = val;
            else if (key == "ua_token")              c.ua_token = val;
            else if (key == "max_inspect_bytes")     c.max_inspect_bytes = (size_t)std::stoul(val);
            else if (key == "http_idle_timeout_s")   c.http_idle_timeout_s = std::stoi(val);
            else if (key == "max_http_conns")        c.max_http_conns = (size_t)std::stoul(val);
            else if (key == "asn_db")                c.asn_db = val;
            else if (key == "block_datacenter")      c.block_datacenter = to_bool(val);
            else if (key == "blocked_asn_file")      c.blocked_asn_file = val;
            else if (key == "datacenter_org_regex")  c.datacenter_org_regex = val;
            else if (key == "required_headers")      c.required_headers = val;
            else if (key == "bot_ua_regex")          c.bot_ua_regex = val;
            else if (key == "inapp_allow_regex")     c.inapp_allow_regex = val;
            else if (key == "verbose")               c.verbose = to_bool(val);
            else if (key == "log_rate_per_sec")      c.log_rate_per_sec = std::stoi(val);
            else if (key == "stats_interval_s")      c.stats_interval_s = std::stoi(val);
            else std::cerr << "config: unknown key '" << key << "' (line " << lineno << ")\n";
        } catch (const std::exception&) {
            throw std::runtime_error("config: bad value for '" + key +
                                     "' on line " + std::to_string(lineno));
        }
    }

    if (c.ua_token.empty())
        std::cerr << "config: WARNING ua_token is empty -- any mobile UA will be "
                     "allowed on web ports. Set ua_token for real protection.\n";
    c.validate();
    return c;
}

void Config::validate() const {
    if (num_queues < 1 || num_queues > 64)
        throw std::runtime_error("num_queues must be 1..64");
    if (base_queue + num_queues - 1 > 0xffff)
        throw std::runtime_error("queue range exceeds 65535");
    if (home_country.size() != 2)
        throw std::runtime_error("home_country must be a 2-letter ISO code");
    if (mark_approved == 0 || mark_rejected == 0 || mark_approved == mark_rejected)
        throw std::runtime_error("mark_approved/mark_rejected must be nonzero and distinct");
    if (http_port == 0 || https_port == 0)
        throw std::runtime_error("http_port/https_port must be nonzero");
    if (max_inspect_bytes < 64 || max_inspect_bytes > (1u << 20))
        throw std::runtime_error("max_inspect_bytes out of range (64..1048576)");
    if (max_http_conns < 1)
        throw std::runtime_error("max_http_conns must be >= 1");
}
