#include <arapuca/capture/virustotal.hpp>
#include <arapuca/core/logging.hpp>

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <memory>
#include <utility>

namespace arapuca::capture {
namespace {

constexpr std::int64_t kMinuteMs = std::int64_t{60} * 1000;
constexpr std::int64_t kDayMs = std::int64_t{24} * 60 * 60 * 1000;

bool is_hex_sha256(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
               return std::isxdigit(static_cast<unsigned char>(c)) != 0;
           });
}

struct CurlDeleter {
    void operator()(CURL* handle) const noexcept {
        if (handle != nullptr) {
            curl_easy_cleanup(handle);
        }
    }
};

struct ListDeleter {
    void operator()(curl_slist* list) const noexcept {
        if (list != nullptr) {
            curl_slist_free_all(list);
        }
    }
};

std::size_t append_callback(char* data, std::size_t size, std::size_t count, void* user) {
    auto* out = static_cast<std::string*>(user);
    const std::size_t incoming = size * count;
    // A report is a few kilobytes. Anything far larger is not a report.
    if (out->size() + incoming > 1024UL * 1024) {
        return 0;
    }
    out->append(data, incoming);
    return incoming;
}

}  // namespace

std::string_view to_string(VtStatus status) {
    // clang-format off
    switch (status) {
        case VtStatus::Ok:          return "ok";
        case VtStatus::NotFound:    return "not_found";
        case VtStatus::Disabled:    return "disabled";
        case VtStatus::RateLimited: return "rate_limited";
        case VtStatus::Error:       return "error";
    }
    // clang-format on
    return "error";
}

// --- RateLimiter ----------------------------------------------------------

RateLimiter::RateLimiter(std::size_t per_minute,
                         std::size_t per_day,
                         std::filesystem::path state_file)
    : per_minute_(per_minute), per_day_(per_day), state_file_(std::move(state_file)) {
    load();
}

void RateLimiter::roll_windows_locked(core::TimePoint now) {
    const std::int64_t millis = core::to_unix_millis(now);
    const std::int64_t minute = millis / kMinuteMs;
    const std::int64_t day = millis / kDayMs;

    if (minute != minute_epoch_) {
        minute_epoch_ = minute;
        minute_count_ = 0;
    }
    if (day != day_epoch_) {
        day_epoch_ = day;
        day_count_ = 0;
    }
}

bool RateLimiter::try_acquire(core::TimePoint now) {
    const std::lock_guard<std::mutex> lock(mutex_);
    roll_windows_locked(now);

    if (minute_count_ >= per_minute_ || day_count_ >= per_day_) {
        return false;
    }
    ++minute_count_;
    ++day_count_;

    if (!state_file_.empty()) {
        const nlohmann::json state = {{"minute_epoch", minute_epoch_},
                                      {"minute_count", minute_count_},
                                      {"day_epoch", day_epoch_},
                                      {"day_count", day_count_}};
        std::ofstream out(state_file_);
        if (out) {
            out << state.dump() << "\n";
        }
    }
    return true;
}

void RateLimiter::persist() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (state_file_.empty()) {
        return;
    }
    const nlohmann::json state = {{"minute_epoch", minute_epoch_},
                                  {"minute_count", minute_count_},
                                  {"day_epoch", day_epoch_},
                                  {"day_count", day_count_}};
    std::ofstream out(state_file_);
    if (out) {
        out << state.dump() << "\n";
    }
}

void RateLimiter::load() {
    if (state_file_.empty()) {
        return;
    }
    std::ifstream in(state_file_);
    if (!in) {
        return;
    }

    try {
        nlohmann::json state;
        in >> state;
        minute_epoch_ = state.value("minute_epoch", std::int64_t{0});
        minute_count_ = state.value("minute_count", std::size_t{0});
        day_epoch_ = state.value("day_epoch", std::int64_t{0});
        day_count_ = state.value("day_count", std::size_t{0});
    } catch (const nlohmann::json::exception& error) {
        // A corrupt state file must not stop the honeypot. Starting from zero
        // risks one burst against the quota, which is recoverable; refusing to
        // start is not.
        core::log().warn("rate limiter state unreadable, starting fresh: {}", error.what());
    }
}

std::size_t RateLimiter::used_this_minute() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return minute_count_;
}

std::size_t RateLimiter::used_today() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return day_count_;
}

// --- report parsing -------------------------------------------------------

VtReport parse_file_report(const nlohmann::json& body) {
    VtReport report;

    if (!body.is_object() || !body.contains("data")) {
        report.status = VtStatus::NotFound;
        return report;
    }

    const auto& data = body.at("data");
    if (!data.is_object() || !data.contains("attributes")) {
        report.status = VtStatus::NotFound;
        return report;
    }

    const auto& attributes = data.at("attributes");
    if (attributes.contains("last_analysis_stats")) {
        const auto& stats = attributes.at("last_analysis_stats");
        const int malicious = stats.value("malicious", 0);
        const int suspicious = stats.value("suspicious", 0);
        report.detections = malicious + suspicious;
        report.total_engines = report.detections + stats.value("undetected", 0) +
                               stats.value("harmless", 0) + stats.value("timeout", 0) +
                               stats.value("type-unsupported", 0) + stats.value("failure", 0);
    }

    if (attributes.contains("popular_threat_classification")) {
        const auto& classification = attributes.at("popular_threat_classification");
        report.popular_label = classification.value("suggested_threat_label", "");
    }

    if (attributes.contains("first_submission_date")) {
        const auto seconds = attributes.value("first_submission_date", std::int64_t{0});
        if (seconds > 0) {
            report.first_seen =
                core::to_rfc3339_millis(core::TimePoint{} + std::chrono::seconds{seconds});
        }
    }

    report.status = VtStatus::Ok;
    return report;
}

// --- client ---------------------------------------------------------------

VirusTotalClient::VirusTotalClient(VirusTotalConfig config)
    : config_(std::move(config)),
      limiter_(config_.requests_per_minute, config_.requests_per_day, config_.state_file) {}

VtReport VirusTotalClient::lookup(const std::string& sha256) {
    VtReport report;

    if (!enabled()) {
        report.status = VtStatus::Disabled;
        return report;
    }
    if (!is_hex_sha256(sha256)) {
        report.status = VtStatus::Error;
        report.error = "not a sha256 digest";
        return report;
    }
    if (!limiter_.try_acquire(core::Clock::now())) {
        // Refused locally, so no request is made. Burning through the free
        // tier gets the key throttled for everyone using it.
        report.status = VtStatus::RateLimited;
        return report;
    }

    const std::unique_ptr<CURL, CurlDeleter> handle(curl_easy_init());
    if (!handle) {
        report.error = "cannot create a curl handle";
        return report;
    }

    // The URL carries the hash and nothing else. There is no request body on
    // this code path, which is what makes an accidental upload impossible.
    const std::string url = config_.base_url + "/files/" + sha256;
    std::string body;

    const std::unique_ptr<curl_slist, ListDeleter> headers(
        curl_slist_append(nullptr, ("x-apikey: " + config_.api_key).c_str()));

    CURL* curl = handle.get();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config_.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "arapuca-honeypot");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

    const CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        report.status = VtStatus::Error;
        report.error = curl_easy_strerror(code);
        return report;
    }

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    if (status == 404) {
        // Unknown to VirusTotal. For a honeypot that is the interesting
        // answer: a sample nobody has seen is a sample worth keeping.
        report.status = VtStatus::NotFound;
        return report;
    }
    if (status == 429) {
        report.status = VtStatus::RateLimited;
        report.error = "VirusTotal returned 429";
        return report;
    }
    if (status != 200) {
        report.status = VtStatus::Error;
        report.error = "VirusTotal returned " + std::to_string(status);
        return report;
    }

    try {
        return parse_file_report(nlohmann::json::parse(body));
    } catch (const nlohmann::json::exception& error) {
        report.status = VtStatus::Error;
        report.error = std::string("unparseable response: ") + error.what();
        return report;
    }
}

}  // namespace arapuca::capture
