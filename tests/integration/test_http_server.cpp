// End to end tests against the HTTP honeypot, driven with a real HTTP client.

#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/http/http_service.hpp>

#include <httplib.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace {

using arapuca::core::Event;
using arapuca::core::EventBus;
using arapuca::core::EventType;
using namespace std::chrono_literals;

class Honeypot {
public:
    Honeypot() {
        config_.sensor_name = "arapuca-itest";
        config_.http.port = 0;
        config_.http.max_body_recorded = 2048;
        config_.http.server_header = "Apache/2.4.52 (Ubuntu)";

        mitre_ = arapuca::enrich::MitreMapper::from_file(std::string(ARAPUCA_CONFIG_DIR) +
                                                         "/mitre.yaml");

        arapuca::http::HttpDependencies deps;
        deps.config = &config_;
        deps.bus = &bus_;
        deps.mitre = &mitre_;
        deps.geo = &geo_;

        service_ = std::make_unique<arapuca::http::HttpService>(deps);
        service_->start();
    }

    Honeypot(const Honeypot&) = delete;
    Honeypot& operator=(const Honeypot&) = delete;
    Honeypot(Honeypot&&) = delete;
    Honeypot& operator=(Honeypot&&) = delete;

    ~Honeypot() {
        service_->stop();
    }

    [[nodiscard]] std::uint16_t port() const {
        return service_->port();
    }

    std::vector<Event> events() {
        std::vector<Event> out;
        for (int i = 0; i < 20 && out.empty(); ++i) {
            bus_.consume(out, 256, 25ms);
        }
        bus_.consume(out, 256, 25ms);
        return out;
    }

    static std::vector<Event> of_type(const std::vector<Event>& events, EventType type) {
        std::vector<Event> out;
        std::copy_if(
            events.begin(), events.end(), std::back_inserter(out), [type](const Event& event) {
                return event.type == type;
            });
        return out;
    }

private:
    arapuca::core::Config config_;
    EventBus bus_{4096};
    arapuca::enrich::MitreMapper mitre_;
    arapuca::enrich::GeoIp geo_;
    std::unique_ptr<arapuca::http::HttpService> service_;
};

httplib::Client client_for(std::uint16_t port) {
    httplib::Client client("127.0.0.1", port);
    client.set_connection_timeout(2, 0);
    client.set_read_timeout(2, 0);
    return client;
}

TEST(HttpServer, BindsAnEphemeralPort) {
    const Honeypot honeypot;
    EXPECT_GT(honeypot.port(), 0);
}

TEST(HttpServer, AdminPanelServesALoginForm) {
    const Honeypot honeypot;
    auto client = client_for(honeypot.port());

    for (const auto* path : {"/", "/admin", "/wp-login.php", "/phpmyadmin"}) {
        const auto response = client.Get(path);
        ASSERT_TRUE(response) << path;
        EXPECT_EQ(200, response->status) << path;
        EXPECT_NE(std::string::npos, response->body.find("<form method=\"post\">")) << path;
        EXPECT_NE(std::string::npos, response->body.find("password")) << path;
    }
}

TEST(HttpServer, ServerHeaderIsTheConfiguredLie) {
    const Honeypot honeypot;
    auto client = client_for(honeypot.port());
    const auto response = client.Get("/");
    ASSERT_TRUE(response);
    EXPECT_EQ("Apache/2.4.52 (Ubuntu)", response->get_header_value("Server"));
}

// The product of the HTTP side.
TEST(HttpServer, LoginAttemptIsRecordedWithCredentials) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    const auto response = client.Post("/admin",
                                      "username=administrator&password=P%40ssw0rd%21",
                                      "application/x-www-form-urlencoded");
    ASSERT_TRUE(response);
    EXPECT_EQ(200, response->status);
    EXPECT_NE(std::string::npos, response->body.find("Invalid username or password"));

    const auto attempts = Honeypot::of_type(honeypot.events(), EventType::HttpLoginAttempt);
    ASSERT_FALSE(attempts.empty());
    EXPECT_EQ("administrator", attempts.front().detail.at("username").get<std::string>());
    EXPECT_EQ("P@ssw0rd!", attempts.front().detail.at("password").get<std::string>());
    EXPECT_EQ("/admin", attempts.front().detail.at("path").get<std::string>());
    ASSERT_TRUE(attempts.front().mitre.has_value());
    EXPECT_EQ("T1110", attempts.front().mitre.value_or(arapuca::core::Mitre{}).technique_id);
}

TEST(HttpServer, LoginAlwaysFails) {
    const Honeypot honeypot;
    auto client = client_for(honeypot.port());
    for (const auto* body :
         {"username=admin&password=admin", "username=root&password=root", "username=&password="}) {
        const auto response = client.Post("/login", body, "application/x-www-form-urlencoded");
        ASSERT_TRUE(response);
        EXPECT_NE(std::string::npos, response->body.find("Invalid username or password"));
    }
}

TEST(HttpServer, DecoyFilesAreServedAndFlagged) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    const auto response = client.Get("/.env");
    ASSERT_TRUE(response);
    EXPECT_EQ(200, response->status);
    EXPECT_NE(std::string::npos, response->body.find("DB_PASSWORD"));

    const auto requests = Honeypot::of_type(honeypot.events(), EventType::HttpRequest);
    ASSERT_FALSE(requests.empty());
    EXPECT_EQ("env", requests.front().detail.at("decoy").get<std::string>());
    EXPECT_EQ(200, requests.front().detail.at("status").get<int>());
    // Reading credentials out of a file is exactly T1552.001.
    ASSERT_TRUE(requests.front().mitre.has_value());
    EXPECT_EQ("T1552.001", requests.front().mitre.value_or(arapuca::core::Mitre{}).technique_id);
}

TEST(HttpServer, SeveralDecoysAnswer) {
    const Honeypot honeypot;
    auto client = client_for(honeypot.port());
    for (const auto* path : {"/.git/config",
                             "/backup.sql",
                             "/wp-config.php",
                             "/.aws/credentials",
                             "/docker-compose.yml"}) {
        const auto response = client.Get(path);
        ASSERT_TRUE(response) << path;
        EXPECT_EQ(200, response->status) << path;
        EXPECT_FALSE(response->body.empty()) << path;
    }
}

TEST(HttpServer, UnknownPathGetsAPlausible404) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    const auto response = client.Get("/nothing/here");
    ASSERT_TRUE(response);
    EXPECT_EQ(404, response->status);
    EXPECT_NE(std::string::npos, response->body.find("404 Not Found"));
    EXPECT_NE(std::string::npos, response->body.find("Apache/2.4.52"));

    const auto requests = Honeypot::of_type(honeypot.events(), EventType::HttpRequest);
    ASSERT_FALSE(requests.empty());
    EXPECT_EQ(404, requests.front().detail.at("status").get<int>());
    EXPECT_FALSE(requests.front().detail.contains("decoy"));
}

// The catch all has to record as much as a decoy hit does. Which file a
// scanner asks for is the signal, whether or not we have one to give it.
TEST(HttpServer, EverythingIsRecordedIncludingMisses) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    const httplib::Headers headers = {
        {"User-Agent", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"},
        {"X-Forwarded-For", "10.0.0.9"}};
    const auto response = client.Get("/cgi-bin/../../../etc/passwd", headers);
    ASSERT_TRUE(response);

    const auto requests = Honeypot::of_type(honeypot.events(), EventType::HttpRequest);
    ASSERT_FALSE(requests.empty());
    const auto& detail = requests.front().detail;
    EXPECT_NE(std::string::npos, detail.at("path").get<std::string>().find("etc/passwd"));
    EXPECT_NE(std::string::npos, detail.at("user_agent").get<std::string>().find("Nmap"));
    EXPECT_EQ("10.0.0.9", detail.at("headers").at("X-Forwarded-For").get<std::string>());
}

TEST(HttpServer, PostBodyIsRecordedAndBounded) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    const std::string body(10000, 'A');
    const auto response = client.Post("/upload", body, "application/octet-stream");
    ASSERT_TRUE(response);

    const auto requests = Honeypot::of_type(honeypot.events(), EventType::HttpRequest);
    ASSERT_FALSE(requests.empty());
    const auto& detail = requests.front().detail;
    EXPECT_EQ(10000U, detail.at("body_bytes").get<std::size_t>());
    EXPECT_LE(detail.at("body").get<std::string>().size(), 2048U);
    EXPECT_TRUE(detail.at("body_truncated").get<bool>());
}

TEST(HttpServer, AuthorizationHeaderIsRedacted) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    const httplib::Headers headers = {{"Authorization", "Bearer ey.secret.value"}};
    (void)client.Get("/admin", headers);

    const auto requests = Honeypot::of_type(honeypot.events(), EventType::HttpRequest);
    ASSERT_FALSE(requests.empty());
    const std::string dumped = requests.front().detail.dump();
    EXPECT_EQ(std::string::npos, dumped.find("ey.secret.value"));
    EXPECT_NE(std::string::npos, dumped.find("[redacted]"));
}

TEST(HttpServer, UnusualMethodsAreAnsweredAndRecorded) {
    Honeypot honeypot;
    auto client = client_for(honeypot.port());

    (void)client.Put("/api/x", "{}", "application/json");
    (void)client.Delete("/api/x");
    (void)client.Options("/");

    const auto requests = Honeypot::of_type(honeypot.events(), EventType::HttpRequest);
    EXPECT_GE(requests.size(), 2U);
}

TEST(HttpServer, ConcurrentScannersAreAllServed) {
    Honeypot honeypot;
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;

    threads.reserve(6);
    for (int i = 0; i < 6; ++i) {
        threads.emplace_back([&honeypot, &ok] {
            auto client = client_for(honeypot.port());
            const auto response = client.Get("/.env");
            if (response && response->status == 200) {
                ++ok;
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_EQ(6, ok.load());
}

}  // namespace
