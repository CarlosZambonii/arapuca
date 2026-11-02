// Fetching what an attacker asked the fake shell to download.
//
// This is the only place in the honeypot that makes an outbound connection on
// attacker instruction, so it is the most dangerous code in the project and
// the most heavily constrained:
//
//   * Only http and https. No file, no ftp, no gopher, no dict.
//   * The RESOLVED address is checked immediately before every connect, and
//     again on every redirect hop. See capture/address_policy.
//   * A hard byte cap enforced during transfer, so an endless stream is
//     aborted rather than read and then discarded.
//   * A wall clock budget and a connect budget.
//   * No cookies, no credentials, no proxy, no custom headers from the
//     attacker. The request carries nothing of ours.
//
// The bytes come back in memory. Nothing is written to disk here; quarantine
// is a separate step with its own rules.
#pragma once

#include <arapuca/capture/address_policy.hpp>

#include <cstddef>
#include <string>

namespace arapuca::capture {

struct DownloadLimits {
    std::size_t max_bytes = 32UL * 1024 * 1024;
    long total_timeout_seconds = 30;
    long connect_timeout_seconds = 10;
    long max_redirects = 3;
};

enum class DownloadOutcome : std::uint8_t {
    Ok,
    BadScheme,
    BlockedAddress,  ///< the resolved address failed the policy
    TooLarge,
    Timeout,
    ConnectFailed,
    HttpError,
    Empty,
    InternalError,
};

[[nodiscard]] std::string_view to_string(DownloadOutcome outcome);

struct DownloadResult {
    DownloadOutcome outcome = DownloadOutcome::InternalError;
    std::string body;
    long http_status = 0;
    std::string content_type;
    std::string final_url;
    /// Set when the outcome is BlockedAddress, so the event can say which
    /// range the attacker was aiming at.
    AddressVerdict blocked = AddressVerdict::Allowed;
    std::string error;

    [[nodiscard]] bool ok() const {
        return outcome == DownloadOutcome::Ok;
    }
};

class Downloader {
public:
    explicit Downloader(DownloadLimits limits = {});

    /// Fetch a URL. Never throws: a failure is a result, not an exception,
    /// because every failure here is an event worth recording.
    [[nodiscard]] DownloadResult fetch(const std::string& url) const;

    /// Check a URL's scheme without connecting. Exposed for the tests and for
    /// refusing obvious nonsense before a worker thread is woken.
    [[nodiscard]] static bool scheme_allowed(const std::string& url);

private:
    DownloadLimits limits_;
};

}  // namespace arapuca::capture
