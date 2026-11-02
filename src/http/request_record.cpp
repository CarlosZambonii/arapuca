#include <arapuca/core/limits.hpp>
#include <arapuca/http/request_record.hpp>
#include <arapuca/util/redaction.hpp>

#include <algorithm>
#include <cctype>

namespace arapuca::http {
namespace {

std::string lower(std::string_view input) {
    std::string out(input);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

}  // namespace

bool is_sensitive_header(std::string_view name) {
    const std::string lowered = lower(name);
    return lowered == "authorization" || lowered == "proxy-authorization" || lowered == "cookie" ||
           lowered == "set-cookie";
}

RequestSummary summarize(const RawRequest& request, std::size_t max_body_recorded) {
    RequestSummary summary;
    summary.detail = nlohmann::json::object();

    summary.detail["method"] = util::sanitize(request.method, 16).text;
    summary.detail["path"] = util::sanitize(request.path, limits::kMaxHttpUrl).text;
    if (!request.query.empty()) {
        summary.detail["query"] = util::sanitize(request.query, limits::kMaxHttpUrl).text;
    }

    nlohmann::json headers = nlohmann::json::object();
    std::size_t kept = 0;
    for (const auto& [name, value] : request.headers) {
        if (kept >= limits::kMaxHttpHeaders) {
            ++summary.headers_dropped;
            continue;
        }

        const std::string clean_name = util::sanitize(name, limits::kMaxHttpHeaderName).text;
        if (clean_name.empty()) {
            continue;
        }

        if (is_sensitive_header(clean_name)) {
            // Present but not stored. That an Authorization header was sent is
            // signal; its contents belong to someone else.
            headers[clean_name] = "[redacted]";
        } else {
            headers[clean_name] = util::sanitize(value, limits::kMaxHttpHeaderValue).text;
        }

        if (lower(clean_name) == "user-agent") {
            summary.user_agent = headers[clean_name].get<std::string>();
        }
        ++kept;
    }
    summary.detail["headers"] = std::move(headers);
    if (summary.headers_dropped > 0) {
        summary.detail["headers_dropped"] = summary.headers_dropped;
    }

    summary.detail["user_agent"] = summary.user_agent;
    summary.detail["body_bytes"] = request.body.size();

    if (!request.body.empty()) {
        const auto body = util::sanitize(request.body, max_body_recorded);
        summary.detail["body"] = body.text;
        summary.body_truncated = body.truncated || request.body.size() > max_body_recorded;
        summary.detail["body_truncated"] = summary.body_truncated;
    }

    return summary;
}

}  // namespace arapuca::http
