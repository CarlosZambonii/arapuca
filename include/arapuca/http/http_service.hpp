// The HTTP honeypot: a generic admin panel, a set of decoy files, and a catch
// all that records everything.
//
// What it is for is different from the SSH side. SSH traffic is mostly brute
// force; HTTP traffic is mostly scanners looking for one specific file. The
// value is in which file they ask for, in what order, and with what user
// agent, so the catch all records as much as the decoys do.
#pragma once

#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/http/decoys.hpp>
#include <arapuca/http/request_record.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

namespace httplib {
class Request;
class Response;
}  // namespace httplib

namespace arapuca::http {

struct HttpDependencies {
    const core::Config* config = nullptr;
    core::EventBus* bus = nullptr;
    const enrich::MitreMapper* mitre = nullptr;
    const enrich::GeoIp* geo = nullptr;
};

class HttpError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class HttpService {
public:
    explicit HttpService(HttpDependencies dependencies);
    HttpService(const HttpService&) = delete;
    HttpService& operator=(const HttpService&) = delete;
    HttpService(HttpService&&) = delete;
    HttpService& operator=(HttpService&&) = delete;
    ~HttpService();

    void start();
    void stop();

    [[nodiscard]] std::uint16_t port() const {
        return bound_port_;
    }

    [[nodiscard]] bool running() const {
        return running_;
    }

    [[nodiscard]] const DecoyStore& decoys() const {
        return decoys_;
    }

    /// Paths that answer with a login form. Exposed so the tests can check the
    /// list rather than restate it.
    [[nodiscard]] static const std::vector<std::string>& login_paths();

private:
    class Impl;

    /// Record one request as an event and set the common response headers.
    /// Returns the summary, so a caller that needs the user agent does not
    /// build it twice.
    RequestSummary record_request(const httplib::Request& request,
                                  httplib::Response& response,
                                  const std::string& decoy_label,
                                  int status,
                                  const std::string& server_header) const;
    void register_login_routes(const std::string& server_header);
    void register_catch_all(const std::string& server_header);

    HttpDependencies deps_;
    DecoyStore decoys_;
    std::unique_ptr<Impl> impl_;
    std::thread server_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint16_t> bound_port_{0};
};

}  // namespace arapuca::http
