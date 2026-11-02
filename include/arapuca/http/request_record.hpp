// Turning an HTTP request into an event.
//
// Pure, so it is testable and fuzzable without a server. Everything an
// attacker controls arrives here: the method, the path, every header name and
// value, and the body. All of it is sanitized and bounded before it becomes
// part of an event, which is safety invariant S2 for the HTTP surface.
//
// Bodies are the interesting case. A scanner posting a ten megabyte payload
// must not cost ten megabytes of event, and a body that is cut has to say so,
// because an analyst reading a truncated payload needs to know it was cut.
#pragma once

#include <arapuca/core/event.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace arapuca::http {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct RawRequest {
    std::string method;
    std::string path;
    std::string query;
    std::string body;
    std::string remote_address;
    std::uint16_t remote_port = 0;
    Headers headers;
};

struct RequestSummary {
    nlohmann::json detail;
    /// User agent, pulled out because it is wanted on its own in dashboards.
    std::string user_agent;
    bool body_truncated = false;
    std::size_t headers_dropped = 0;
};

/// Build the event detail for one request, bounded and sanitized.
[[nodiscard]] RequestSummary summarize(const RawRequest& request, std::size_t max_body_recorded);

/// Headers whose value is replaced rather than recorded. A honeypot wants the
/// credentials an attacker types into a login form, which are the product. It
/// does not want to accumulate bearer tokens and cookies belonging to third
/// parties, which a scanner may be replaying from somewhere else entirely.
[[nodiscard]] bool is_sensitive_header(std::string_view name);

}  // namespace arapuca::http
