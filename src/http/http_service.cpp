#include <arapuca/core/ids.hpp>
#include <arapuca/core/limits.hpp>
#include <arapuca/core/logging.hpp>
#include <arapuca/http/http_service.hpp>
#include <arapuca/http/request_record.hpp>
#include <arapuca/util/redaction.hpp>

#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <utility>

namespace arapuca::http {
namespace {

using core::Event;
using core::EventType;

/// A generic panel, on purpose. Anything branded would either impersonate a
/// real product or look wrong to a scanner that knows that product.
constexpr std::string_view kLoginPage = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Administration</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;padding:32px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.12);
width:320px}
h1{font-size:18px;margin:0 0 20px;color:#333}
label{display:block;font-size:13px;color:#555;margin-bottom:4px}
input{width:100%;padding:8px;margin-bottom:14px;border:1px solid #ccc;border-radius:3px;
box-sizing:border-box}
button{width:100%;padding:9px;background:#1b74c4;color:#fff;border:0;border-radius:3px;
cursor:pointer}
.err{background:#fdecea;color:#b3261e;padding:9px;border-radius:3px;font-size:13px;
margin-bottom:14px}
.foot{margin-top:18px;font-size:11px;color:#999;text-align:center}
</style>
</head>
<body>
<div class="card">
<h1>Administration</h1>
__ERROR__
<form method="post">
<label for="username">Username</label>
<input id="username" name="username" autocomplete="username" autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
<div class="foot">v2.4.11</div>
</div>
</body>
</html>
)HTML";

constexpr std::string_view kNotFound = R"HTML(<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at __HOST__ Port 80</address>
</body></html>
)HTML";

std::string login_page(bool with_error) {
    std::string page(kLoginPage);
    const std::string marker = "__ERROR__";
    const auto position = page.find(marker);
    if (position != std::string::npos) {
        page.replace(position,
                     marker.size(),
                     with_error ? "<div class=\"err\">Invalid username or password.</div>" : "");
    }
    return page;
}

std::string not_found_page(const std::string& host) {
    std::string page(kNotFound);
    const std::string marker = "__HOST__";
    const auto position = page.find(marker);
    if (position != std::string::npos) {
        page.replace(position, marker.size(), host.empty() ? "srv-web-03" : host);
    }
    return page;
}

Headers headers_of(const httplib::Request& request) {
    Headers out;
    out.reserve(request.headers.size());
    for (const auto& [name, value] : request.headers) {
        out.emplace_back(name, value);
    }
    return out;
}

}  // namespace

const std::vector<std::string>& HttpService::login_paths() {
    // The paths scanners actually ask for. Answering all of them with the same
    // form means whichever product the scanner was looking for, it finds
    // something that behaves like a login.
    static const std::vector<std::string> kPaths = {
        "/",
        "/admin",
        "/admin/",
        "/administrator",
        "/login",
        "/login.php",
        "/admin.php",
        "/wp-login.php",
        "/wp-admin",
        "/phpmyadmin",
        "/phpmyadmin/",
        "/manager/html",
        "/cpanel",
        "/webadmin",
        "/user/login",
    };
    return kPaths;
}

class HttpService::Impl {
public:
    httplib::Server server;
};

namespace {

/// Tuning that bounds what one connection can ask of the process. Applied
/// before any handler is registered, so it covers every route.
void apply_transport_limits(httplib::Server& server) {
    server.set_payload_max_length(limits::kMaxHttpBodyRead);
    server.set_read_timeout(10, 0);
    server.set_write_timeout(10, 0);
    server.set_keep_alive_max_count(16);
}

}  // namespace

HttpService::HttpService(HttpDependencies dependencies)
    : deps_(dependencies), impl_(std::make_unique<Impl>()) {}

HttpService::~HttpService() {
    stop();
}

/// Build the event for one request and set the common response headers.
/// A member function rather than a lambda inside start(), because start() was
/// doing too much to read in one go.
RequestSummary HttpService::record_request(const httplib::Request& request,
                                           httplib::Response& response,
                                           const std::string& decoy_label,
                                           int status,
                                           const std::string& server_header) const {
    RawRequest raw;
    raw.method = request.method;
    raw.path = request.path;
    raw.body = request.body;
    raw.remote_address = request.remote_addr;
    raw.remote_port = static_cast<std::uint16_t>(request.remote_port);
    raw.headers = headers_of(request);

    if (!request.params.empty()) {
        std::string query;
        for (const auto& [key, value] : request.params) {
            if (!query.empty()) {
                query += "&";
            }
            query += key;
            query += "=";
            query += value;
        }
        raw.query = query;
    }

    RequestSummary summary = summarize(raw, deps_.config->http.max_body_recorded);

    Event event = Event::make(EventType::HttpRequest, deps_.config->sensor_name);
    event.session_id = core::new_id();
    event.src_ip = raw.remote_address;
    event.src_port = raw.remote_port;
    event.dst_port = deps_.config->http.port;
    event.detail = summary.detail;
    event.detail["status"] = status;
    if (!decoy_label.empty()) {
        event.detail["decoy"] = decoy_label;
    }
    if (deps_.geo != nullptr) {
        event.geo = deps_.geo->lookup(raw.remote_address);
    }
    event.mitre = deps_.mitre->match(EventType::HttpRequest, request.path);
    (void)deps_.bus->publish(std::move(event));

    response.set_header("Server", server_header);
    return summary;
}

void HttpService::register_login_routes(const std::string& server_header) {
    auto& server = impl_->server;

    for (const auto& path : login_paths()) {
        server.Get(
            path,
            [this, server_header](const httplib::Request& request, httplib::Response& response) {
                (void)record_request(request, response, "login-form", 200, server_header);
                response.set_content(login_page(false), "text/html; charset=UTF-8");
            });

        server.Post(
            path,
            [this, server_header](const httplib::Request& request, httplib::Response& response) {
                (void)record_request(request, response, "login-form", 200, server_header);

                // The credentials are the product. Recorded in full, under the
                // same field names the SSH side uses, so one dashboard query
                // covers both services.
                const std::string username = request.has_param("username")
                                                 ? request.get_param_value("username")
                                                 : request.get_param_value("user");
                const std::string password = request.has_param("password")
                                                 ? request.get_param_value("password")
                                                 : request.get_param_value("pass");

                Event event = Event::make(EventType::HttpLoginAttempt, deps_.config->sensor_name);
                event.src_ip = request.remote_addr;
                event.src_port = static_cast<std::uint16_t>(request.remote_port);
                event.dst_port = deps_.config->http.port;
                event.detail = {{"username", util::sanitize(username, limits::kMaxUsername).text},
                                {"password", util::sanitize(password, limits::kMaxPassword).text},
                                {"path", util::sanitize(request.path, limits::kMaxHttpUrl).text},
                                {"accepted", false}};
                if (deps_.geo != nullptr) {
                    event.geo = deps_.geo->lookup(request.remote_addr);
                }
                event.mitre = deps_.mitre->match(EventType::HttpLoginAttempt, username);
                (void)deps_.bus->publish(std::move(event));

                // Always a failure. Letting an attacker through would mean
                // building a second fake application behind the form, and the
                // credentials are already collected at this point.
                response.status = 200;
                response.set_content(login_page(true), "text/html; charset=UTF-8");
            });
    }
}

void HttpService::register_catch_all(const std::string& server_header) {
    auto& server = impl_->server;

    // Real catch all routes rather than the error handler. cpp-httplib does
    // not read a request body for a route it has no handler for, and the body
    // of a POST to an unknown path is exactly the kind of thing worth
    // recording.
    const auto handler = [this, server_header](const httplib::Request& request,
                                               httplib::Response& response) {
        const Decoy* decoy = decoys_.find(request.path);
        if (decoy != nullptr) {
            (void)record_request(request, response, decoy->label, 200, server_header);
            response.status = 200;
            response.set_content(decoy->body, decoy->content_type);
            return;
        }

        (void)record_request(request, response, "", 404, server_header);
        response.status = 404;
        response.set_content(not_found_page(request.get_header_value("Host")),
                             "text/html; charset=iso-8859-1");
    };

    server.Get(".*", handler);
    server.Post(".*", handler);
    server.Put(".*", handler);
    server.Patch(".*", handler);
    server.Delete(".*", handler);
    server.Options(".*", handler);

    server.set_error_handler(
        [handler](const httplib::Request& request, httplib::Response& response) {
            handler(request, response);
        });
}

void HttpService::start() {
    if (running_) {
        return;
    }
    if (deps_.config == nullptr || deps_.bus == nullptr || deps_.mitre == nullptr) {
        throw HttpError("HttpService started without its dependencies");
    }

    decoys_ = DecoyStore::from_directory(deps_.config->http.decoy_dir);

    auto& server = impl_->server;
    const auto& config = deps_.config->http;

    // Read bound, enforced by the library before a byte reaches a handler.
    apply_transport_limits(server);

    const std::string server_header =
        config.server_header.empty() ? std::string("Apache/2.4.52 (Ubuntu)") : config.server_header;

    register_login_routes(server_header);
    register_catch_all(server_header);

    const std::string address = "0.0.0.0";
    const int requested = config.port;

    // Port zero means "any free port", which the tests use so parallel runs
    // do not collide. bind_to_port cannot report which port it chose, so the
    // two cases have to be separated.
    if (requested == 0) {
        const int chosen = server.bind_to_any_port(address);
        if (chosen <= 0) {
            throw HttpError("cannot bind an ephemeral HTTP port");
        }
        bound_port_ = static_cast<std::uint16_t>(chosen);
    } else {
        if (!server.bind_to_port(address, requested)) {
            throw HttpError("cannot bind HTTP port " + std::to_string(requested));
        }
        bound_port_ = static_cast<std::uint16_t>(requested);
    }

    running_ = true;
    server_ = std::thread([this] {
        if (!impl_->server.listen_after_bind()) {
            core::log().warn("HTTP honeypot stopped listening");
        }
    });

    core::log().info("HTTP honeypot listening on port {}", bound_port_.load());
}

void HttpService::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    impl_->server.stop();
    if (server_.joinable()) {
        server_.join();
    }
}

}  // namespace arapuca::http
