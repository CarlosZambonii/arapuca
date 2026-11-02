#include <arapuca/capture/downloader.hpp>
#include <arapuca/core/logging.hpp>

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>

namespace arapuca::capture {
namespace {

/// Per transfer state the libcurl callbacks write into.
struct Transfer {
    std::string body;
    std::size_t max_bytes = 0;
    bool exceeded = false;
    AddressVerdict blocked = AddressVerdict::Allowed;
    bool address_refused = false;
};

std::size_t write_callback(char* data, std::size_t size, std::size_t count, void* user) {
    auto* transfer = static_cast<Transfer*>(user);
    const std::size_t incoming = size * count;

    if (transfer->body.size() + incoming > transfer->max_bytes) {
        // Returning something other than the incoming size aborts the
        // transfer. The cap is enforced here rather than afterwards so an
        // endless stream costs the cap and not a byte more.
        transfer->exceeded = true;
        return 0;
    }

    transfer->body.append(data, incoming);
    return incoming;
}

/// Called by libcurl immediately before it connects, once per attempt and
/// therefore once per redirect hop. This is safety invariant S9 at the only
/// point where the real destination is known.
curl_socket_t open_socket_callback(void* user,
                                   curlsocktype purpose,
                                   struct curl_sockaddr* address) {
    auto* transfer = static_cast<Transfer*>(user);

    if (purpose != CURLSOCKTYPE_IPCXN || address == nullptr) {
        return CURL_SOCKET_BAD;
    }

    const AddressVerdict verdict = classify(&address->addr);
    if (!is_allowed(verdict)) {
        transfer->address_refused = true;
        transfer->blocked = verdict;
        return CURL_SOCKET_BAD;
    }

    return ::socket(address->family, address->socktype, address->protocol);
}

void initialize_curl_once() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            core::log().error("curl_global_init failed, downloads will not work");
        }
    });
}

struct CurlDeleter {
    void operator()(CURL* handle) const noexcept {
        if (handle != nullptr) {
            curl_easy_cleanup(handle);
        }
    }
};

std::string lower(std::string_view input) {
    std::string out(input);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

}  // namespace

std::string_view to_string(DownloadOutcome outcome) {
    // clang-format off
    switch (outcome) {
        case DownloadOutcome::Ok:             return "ok";
        case DownloadOutcome::BadScheme:      return "bad_scheme";
        case DownloadOutcome::BlockedAddress: return "blocked_address";
        case DownloadOutcome::TooLarge:       return "too_large";
        case DownloadOutcome::Timeout:        return "timeout";
        case DownloadOutcome::ConnectFailed:  return "connect_failed";
        case DownloadOutcome::HttpError:      return "http_error";
        case DownloadOutcome::Empty:          return "empty";
        case DownloadOutcome::InternalError:  return "internal_error";
    }
    // clang-format on
    return "internal_error";
}

Downloader::Downloader(DownloadLimits limits) : limits_(limits) {
    initialize_curl_once();
}

bool Downloader::scheme_allowed(const std::string& url) {
    const std::string lowered = lower(url);
    return lowered.starts_with("http://") || lowered.starts_with("https://");
}

DownloadResult Downloader::fetch(const std::string& url) const {
    DownloadResult result;

    if (!scheme_allowed(url)) {
        result.outcome = DownloadOutcome::BadScheme;
        result.error = "only http and https are fetched";
        return result;
    }

    const std::unique_ptr<CURL, CurlDeleter> handle(curl_easy_init());
    if (!handle) {
        result.error = "cannot create a curl handle";
        return result;
    }

    Transfer transfer;
    transfer.max_bytes = limits_.max_bytes;

    CURL* curl = handle.get();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Scheme restriction enforced by libcurl itself, belt to the braces of
    // the check above, and it also covers redirects into another scheme.
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, limits_.max_redirects);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, limits_.total_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, limits_.connect_timeout_seconds);

    // No signals, because this runs on a worker thread.
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    // The request carries nothing of ours: no cookies, no credentials, no
    // proxy, no referer.
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl, CURLOPT_COOKIESESSION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");

    // A plain wget user agent. Malware hosting often serves different content,
    // or nothing at all, to anything that looks like a researcher.
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Wget/1.21.2");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    // Certificate verification is off on purpose. The goal is to obtain the
    // bytes an attacker pointed at, and malware hosting routinely has expired
    // or self signed certificates. Nothing confidential is sent, so there is
    // nothing for an interceptor to steal, and a sample delivered by an
    // interceptor is still a sample worth having.
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &transfer);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, open_socket_callback);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &transfer);

    const CURLcode code = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_status);
    char* effective = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective) == CURLE_OK &&
        effective != nullptr) {
        result.final_url = effective;
    }
    char* content_type = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK &&
        content_type != nullptr) {
        result.content_type = content_type;
    }

    // Order matters: the specific reasons are checked before the generic
    // libcurl error, because a refused address surfaces as a connect failure.
    if (transfer.address_refused) {
        result.outcome = DownloadOutcome::BlockedAddress;
        result.blocked = transfer.blocked;
        result.error = std::string("refused to connect to a ") +
                       std::string(to_string(transfer.blocked)) + " address";
        return result;
    }
    if (transfer.exceeded) {
        result.outcome = DownloadOutcome::TooLarge;
        result.error = "sample exceeded the size cap";
        return result;
    }

    if (code == CURLE_OPERATION_TIMEDOUT) {
        result.outcome = DownloadOutcome::Timeout;
        result.error = curl_easy_strerror(code);
        return result;
    }
    if (code != CURLE_OK) {
        result.outcome = DownloadOutcome::ConnectFailed;
        result.error = curl_easy_strerror(code);
        return result;
    }
    if (result.http_status >= 400) {
        result.outcome = DownloadOutcome::HttpError;
        result.error = "server returned " + std::to_string(result.http_status);
        result.body = std::move(transfer.body);
        return result;
    }
    if (transfer.body.empty()) {
        result.outcome = DownloadOutcome::Empty;
        return result;
    }

    result.outcome = DownloadOutcome::Ok;
    result.body = std::move(transfer.body);
    return result;
}

}  // namespace arapuca::capture
