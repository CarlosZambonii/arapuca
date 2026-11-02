// VirusTotal enrichment, by hash only.
//
// Safety invariant S4: this client has no upload path. It is not that
// uploading is disabled by a flag, it is that no function here sends a file,
// and none can be added without changing the interface. Submitting a captured
// sample would publish it, and a sample may contain data belonging to whoever
// the attacker took it from.
//
// The free tier allows four requests a minute and five hundred a day.
// Exceeding either gets the key throttled, so the budget is tracked and
// persisted: a honeypot restarts, and a limiter that forgot its history would
// burn the daily allowance in the first minute after a crash loop.
#pragma once

#include <arapuca/core/clock.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace arapuca::capture {

/// Request budget over two windows, persisted across restarts.
class RateLimiter {
public:
    RateLimiter(std::size_t per_minute, std::size_t per_day, std::filesystem::path state_file = {});

    /// Take one slot if the budget allows. `now` is a parameter so the tests
    /// can move time without sleeping.
    bool try_acquire(core::TimePoint now);

    [[nodiscard]] std::size_t used_this_minute() const;
    [[nodiscard]] std::size_t used_today() const;

    /// Write the counters out. Called after every acquisition, because the
    /// interesting failure is a crash, and a crash gives no chance to flush.
    void persist() const;
    void load();

private:
    void roll_windows_locked(core::TimePoint now);

    mutable std::mutex mutex_;
    std::size_t per_minute_;
    std::size_t per_day_;
    std::filesystem::path state_file_;

    std::size_t minute_count_ = 0;
    std::size_t day_count_ = 0;
    std::int64_t minute_epoch_ = 0;
    std::int64_t day_epoch_ = 0;
};

enum class VtStatus : std::uint8_t {
    Ok,           ///< the hash is known to VirusTotal
    NotFound,     ///< a clean lookup that returned nothing, which is itself useful
    Disabled,     ///< no API key configured
    RateLimited,  ///< the local budget refused, no request was made
    Error,
};

[[nodiscard]] std::string_view to_string(VtStatus status);

struct VtReport {
    VtStatus status = VtStatus::Error;
    int detections = 0;
    int total_engines = 0;
    std::string popular_label;
    std::string first_seen;
    std::string error;
};

/// Parse a VirusTotal v3 file report. Separated from the HTTP call so the
/// shape of a real response can be tested without a network or a key.
[[nodiscard]] VtReport parse_file_report(const nlohmann::json& body);

struct VirusTotalConfig {
    std::string api_key;
    std::size_t requests_per_minute = 4;
    std::size_t requests_per_day = 500;
    std::filesystem::path state_file;
    std::string base_url = "https://www.virustotal.com/api/v3";
    long timeout_seconds = 15;
};

class VirusTotalClient {
public:
    explicit VirusTotalClient(VirusTotalConfig config);

    /// Look up one hash. Never throws, and never sends anything but the hash.
    [[nodiscard]] VtReport lookup(const std::string& sha256);

    [[nodiscard]] bool enabled() const {
        return !config_.api_key.empty();
    }

    [[nodiscard]] const RateLimiter& limiter() const {
        return limiter_;
    }

private:
    VirusTotalConfig config_;
    RateLimiter limiter_;
};

}  // namespace arapuca::capture
