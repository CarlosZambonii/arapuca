#include <arapuca/core/ids.hpp>
#include <arapuca/core/limits.hpp>
#include <arapuca/core/logging.hpp>
#include <arapuca/enrich/session_classifier.hpp>
#include <arapuca/ssh/line_editor.hpp>
#include <arapuca/ssh/ssh_service.hpp>
#include <arapuca/util/redaction.hpp>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <system_error>
#include <utility>

namespace arapuca::ssh {
namespace {

using core::Event;
using core::EventType;

/// Peer address of a libssh session, as text. Empty when it cannot be read,
/// which must not be fatal: an event with no source is still an event.
std::string peer_address(ssh_session session, std::uint16_t& port) {
    port = 0;
    const socket_t descriptor = ssh_get_fd(session);
    if (descriptor < 0) {
        return {};
    }

    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    // The POSIX socket API is defined in terms of this cast: sockaddr_storage
    // exists precisely to be cast to the family specific struct.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getpeername(descriptor, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        return {};
    }

    std::array<char, INET6_ADDRSTRLEN> text{};
    if (address.ss_family == AF_INET) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto* in4 = reinterpret_cast<const sockaddr_in*>(&address);
        port = ntohs(in4->sin_port);
        if (::inet_ntop(AF_INET, &in4->sin_addr, text.data(), text.size()) == nullptr) {
            return {};
        }
    } else if (address.ss_family == AF_INET6) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&address);
        port = ntohs(in6->sin6_port);
        if (::inet_ntop(AF_INET6, &in6->sin6_addr, text.data(), text.size()) == nullptr) {
            return {};
        }
    } else {
        return {};
    }
    return {text.data()};
}

std::uint16_t bound_port_of(ssh_bind bind) {
    const socket_t descriptor = ssh_bind_get_fd(bind);
    if (descriptor < 0) {
        return 0;
    }
    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        return 0;
    }
    if (address.ss_family == AF_INET) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
    }
    if (address.ss_family == AF_INET6) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    }
    return 0;
}

std::string safe(std::string_view value, std::size_t limit) {
    return util::sanitize(value, limit).text;
}

/// Name of a denied channel or global request, for the event.
std::string_view denied_name(int type, int subtype) {
    if (type == SSH_REQUEST_GLOBAL) {
        return subtype == SSH_GLOBAL_REQUEST_TCPIP_FORWARD ? "tcpip-forward" : "global-request";
    }
    if (type == SSH_REQUEST_CHANNEL_OPEN) {
        switch (subtype) {
            case SSH_CHANNEL_DIRECT_TCPIP:
                return "direct-tcpip";
            case SSH_CHANNEL_FORWARDED_TCPIP:
                return "forwarded-tcpip";
            case SSH_CHANNEL_X11:
                return "x11";
            default:
                return "channel-open";
        }
    }
    if (type == SSH_REQUEST_CHANNEL) {
        switch (subtype) {
            case SSH_CHANNEL_REQUEST_SUBSYSTEM:
                return "subsystem";
            case SSH_CHANNEL_REQUEST_X11:
                return "x11-req";
            default:
                return "channel-request";
        }
    }
    return "unknown";
}

}  // namespace

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// One attacker connection, from key exchange to disconnect.
class SshService::Session {
public:
    Session(SshService& service, ssh_session session)
        : service_(service), session_(session), id_(core::new_id()), started_(core::Clock::now()) {}

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(Session&&) = delete;

    ~Session() {
        if (channel_ != nullptr) {
            ssh_channel_free(channel_);
        }
        ssh_disconnect(session_);
        ssh_free(session_);
    }

    void run();

    [[nodiscard]] const std::string& source_ip() const {
        return source_ip_;
    }

private:
    Event make_event(EventType type);
    void publish(Event event) const;
    void emit_auth(std::string_view user,
                   std::string_view password,
                   std::string_view method,
                   bool accepted,
                   std::string_view rule);
    void emit_denied(std::string_view request, std::string_view target_host, int target_port);
    void emit_command(const std::string& line, const Shell::Result& result);
    void emit_session_end();

    bool authenticate();
    bool open_channel();
    bool accept_session_channel();
    bool wait_for_shell_or_exec();
    void interactive();
    bool handle_line(const std::string& line);
    void run_once(const std::string& command);
    void send(std::string_view text);

    /// Sensor name, which Session reaches through the service rather than
    /// holding a second copy of the configuration.
    [[nodiscard]] std::string sensor() const {
        return service_.deps_.config->sensor_name;
    }

    SshService& service_;
    ssh_session session_;
    ssh_channel channel_ = nullptr;
    std::string id_;
    core::TimePoint started_;
    core::TimePoint last_command_;
    std::string source_ip_;
    std::uint16_t source_port_ = 0;
    std::string username_;
    std::string client_version_;
    std::optional<core::Geo> geo_;

    std::unique_ptr<Shell> shell_;
    LineEditor editor_;
    enrich::SessionSignals signals_;
    std::size_t command_count_ = 0;
};

Event SshService::Session::make_event(EventType type) {
    Event event = Event::make(type, sensor());
    event.session_id = id_;
    event.src_ip = source_ip_;
    event.src_port = source_port_;
    event.dst_port = service_.deps_.config->ssh.port;
    event.geo = geo_;
    return event;
}

void SshService::Session::publish(Event event) const {
    (void)service_.deps_.bus->publish(std::move(event));
}

void SshService::Session::emit_auth(std::string_view user,
                                    std::string_view password,
                                    std::string_view method,
                                    bool accepted,
                                    std::string_view rule) {
    Event event = make_event(EventType::SshAuthAttempt);
    event.detail = {{"username", safe(user, limits::kMaxUsername)},
                    {"password", safe(password, limits::kMaxPassword)},
                    {"auth_method", std::string(method)},
                    {"accepted", accepted},
                    {"rule", std::string(rule)},
                    {"client_version", client_version_}};
    event.mitre = service_.deps_.mitre->match(EventType::SshAuthAttempt, user);
    publish(std::move(event));
}

void SshService::Session::emit_denied(std::string_view request,
                                      std::string_view target_host,
                                      int target_port) {
    Event event = make_event(EventType::SshChannelDenied);
    event.detail = {{"request_type", std::string(request)}};
    if (!target_host.empty()) {
        event.detail["target_host"] = safe(target_host, 256);
        event.detail["target_port"] = target_port;
    }
    event.mitre = service_.deps_.mitre->match(EventType::SshChannelDenied, request);
    publish(std::move(event));
}

void SshService::Session::emit_command(const std::string& line, const Shell::Result& result) {
    const auto now = core::Clock::now();
    const auto since =
        command_count_ == 0
            ? 0
            : std::chrono::duration_cast<std::chrono::milliseconds>(now - last_command_).count();
    if (command_count_ > 0) {
        signals_.inter_command_gaps_ms.push_back(since);
    }
    last_command_ = now;
    ++command_count_;
    signals_.command_count = command_count_;
    signals_.unknown_commands += result.unknown_commands.size();

    Event event = make_event(EventType::SshCommand);
    event.detail = {{"command", safe(line, limits::kMaxCommandLine)},
                    {"command_argv0",
                     result.segments.empty() || result.segments.front().argv.empty()
                         ? std::string()
                         : safe(result.segments.front().argv.front(), 256)},
                    {"seq", command_count_},
                    {"since_prev_ms", since},
                    {"response_bytes", result.output.size()},
                    {"status", result.status},
                    {"unknown", !result.unknown_commands.empty()},
                    {"segments", result.segments.size()}};
    event.mitre = service_.deps_.mitre->match(EventType::SshCommand, line);
    publish(std::move(event));
}

void SshService::Session::emit_session_end() {
    signals_.duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(core::Clock::now() - started_)
            .count();
    signals_.used_line_editing = editor_.used_line_editing();
    signals_.used_tab_completion = editor_.used_tab();

    const auto classification = enrich::classify_session(signals_);

    Event event = make_event(EventType::SshSessionEnd);
    event.detail = {{"duration_ms", signals_.duration_ms},
                    {"command_count", command_count_},
                    {"username", username_},
                    {"classification", std::string(enrich::to_string(classification.verdict))},
                    {"classification_score", classification.score},
                    {"classification_reason", classification.reason}};
    publish(std::move(event));
}

void SshService::Session::send(std::string_view text) {
    if (channel_ == nullptr || text.empty()) {
        return;
    }
    (void)ssh_channel_write(channel_, text.data(), static_cast<std::uint32_t>(text.size()));
}

void SshService::Session::run() {
    std::uint16_t port = 0;
    source_ip_ = peer_address(session_, port);
    source_port_ = port;

    if (!service_.admit(source_ip_)) {
        core::log().debug("refusing connection from {}, limit reached", source_ip_);
        return;
    }

    // Scope guard: the session slot is released however this function leaves.
    // A unique_ptr with a custom deleter says that without an ad hoc class
    // that would drag in the rule of five.
    const std::unique_ptr<SshService, std::function<void(SshService*)>> release(
        &service_, [this](SshService* service) { service->release(source_ip_); });

    if (ssh_handle_key_exchange(session_) != SSH_OK) {
        core::log().debug("key exchange failed with {}: {}", source_ip_, ssh_get_error(session_));
        return;
    }

    const char* banner = ssh_get_clientbanner(session_);
    client_version_ = banner == nullptr ? std::string() : safe(banner, limits::kMaxClientVersion);

    if (service_.deps_.geo != nullptr) {
        geo_ = service_.deps_.geo->lookup(source_ip_);
    }

    Event start = make_event(EventType::SshSessionStart);
    start.detail = {{"client_version", client_version_}};
    publish(std::move(start));

    if (authenticate() && open_channel()) {
        interactive();
    }

    emit_session_end();
}

bool SshService::Session::authenticate() {
    ssh_set_auth_methods(session_, SSH_AUTH_METHOD_PASSWORD);

    const auto deadline = core::Clock::now() + std::chrono::seconds{30};

    while (core::Clock::now() < deadline) {
        ssh_message message = ssh_message_get(session_);
        if (message == nullptr) {
            return false;
        }

        const int type = ssh_message_type(message);
        const int subtype = ssh_message_subtype(message);

        if (type != SSH_REQUEST_AUTH) {
            ssh_message_reply_default(message);
            ssh_message_free(message);
            continue;
        }

        const char* raw_user = ssh_message_auth_user(message);
        const std::string user = raw_user == nullptr ? std::string() : raw_user;

        if (subtype == SSH_AUTH_METHOD_PASSWORD) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            // Deprecated in libssh 0.10 in favour of the server callbacks API.
            // The message API is kept here on purpose: it hands over the
            // password in clear text, which is the entire product of a
            // honeypot, and the callback form offers no equivalent that is
            // simpler. Revisit if a future libssh removes it outright.
            const char* raw_password = ssh_message_auth_password(message);
#pragma GCC diagnostic pop
            const std::string password = raw_password == nullptr ? std::string() : raw_password;

            AuthDecision decision = service_.deps_.auth->evaluate(user, password);
            if (!decision.accepted && service_.tracker_.record_failure_and_check(source_ip_)) {
                // The persistent brute forcer is let through, which is where
                // the interesting sessions come from.
                decision = {true, "after_failures"};
            }

            emit_auth(user, password, "password", decision.accepted, decision.rule);

            if (decision.accepted) {
                username_ = safe(user, limits::kMaxUsername);
                service_.tracker_.forget(source_ip_);
                ssh_message_auth_reply_success(message, 0);
                ssh_message_free(message);
                return true;
            }
            ssh_message_reply_default(message);
            ssh_message_free(message);
            continue;
        }

        // Public key and keyboard interactive are recorded and refused. A
        // honeypot that accepted a key would have to fake a shell for a
        // client that never sends a password, and the attempt itself is the
        // interesting part.
        const std::string method = subtype == SSH_AUTH_METHOD_PUBLICKEY ? "publickey" : "none";
        emit_auth(user, "", method, false, "method_not_offered");
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }
    return false;
}

/// Wait for the attacker to open a session channel, refusing everything else.
/// This is where safety invariant S10 is enforced: a direct-tcpip request is
/// an attempt to use the honeypot as a proxy, and is worth an event of its own.
bool SshService::Session::accept_session_channel() {
    const auto deadline = core::Clock::now() + std::chrono::seconds{30};

    while (channel_ == nullptr && core::Clock::now() < deadline) {
        ssh_message message = ssh_message_get(session_);
        if (message == nullptr) {
            return false;
        }

        const int type = ssh_message_type(message);
        const int subtype = ssh_message_subtype(message);

        if (type == SSH_REQUEST_CHANNEL_OPEN && subtype == SSH_CHANNEL_SESSION) {
            channel_ = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            continue;
        }

        if (type == SSH_REQUEST_CHANNEL_OPEN) {
            std::string host;
            int port = 0;
            if (subtype == SSH_CHANNEL_DIRECT_TCPIP) {
                const char* destination = ssh_message_channel_request_open_destination(message);
                host = destination == nullptr ? std::string() : destination;
                port = ssh_message_channel_request_open_destination_port(message);
            }
            emit_denied(denied_name(type, subtype), host, port);
        } else if (type == SSH_REQUEST_GLOBAL) {
            emit_denied(denied_name(type, subtype), "", 0);
        }

        ssh_message_reply_default(message);
        ssh_message_free(message);
    }
    return channel_ != nullptr;
}

/// Wait for a shell or an exec request on the accepted channel. Subsystems
/// and X11 are refused here, and each refusal is recorded.
///
/// Returns true when an interactive shell was requested. An exec request is
/// answered inside this function and returns false, because exec is one shot
/// and the session ends with it.
bool SshService::Session::wait_for_shell_or_exec() {
    const auto deadline = core::Clock::now() + std::chrono::seconds{30};

    while (core::Clock::now() < deadline) {
        ssh_message message = ssh_message_get(session_);
        if (message == nullptr) {
            return false;
        }

        const int type = ssh_message_type(message);
        const int subtype = ssh_message_subtype(message);

        if (type != SSH_REQUEST_CHANNEL) {
            ssh_message_reply_default(message);
            ssh_message_free(message);
            continue;
        }

        if (subtype == SSH_CHANNEL_REQUEST_PTY || subtype == SSH_CHANNEL_REQUEST_ENV) {
            ssh_message_channel_request_reply_success(message);
            ssh_message_free(message);
            continue;
        }
        if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
            ssh_message_channel_request_reply_success(message);
            ssh_message_free(message);
            return true;
        }
        if (subtype == SSH_CHANNEL_REQUEST_EXEC) {
            const char* command = ssh_message_channel_request_command(message);
            const std::string line = command == nullptr ? std::string() : command;
            ssh_message_channel_request_reply_success(message);
            ssh_message_free(message);
            run_once(line);
            return false;
        }

        emit_denied(denied_name(type, subtype), "", 0);
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }
    return false;
}

bool SshService::Session::open_channel() {
    return accept_session_channel() && wait_for_shell_or_exec();
}

void SshService::Session::run_once(const std::string& command) {
    ShellContext context;
    context.username = username_;
    context.cwd = context.home();
    context.vfs = *service_.deps_.filesystem;
    shell_ = std::make_unique<Shell>(*service_.deps_.registry, std::move(context));

    const Shell::Result result = shell_->execute(command);
    emit_command(command, result);

    for (const auto& url : result.urls) {
        if (service_.deps_.on_capture) {
            service_.deps_.on_capture(CaptureRequest{url, id_, source_ip_});
        }
    }

    send(result.output);
    if (channel_ != nullptr) {
        ssh_channel_send_eof(channel_);
    }
}

/// Handle one completed line: run it through the fake shell, record it, hand
/// any URLs to the capture engine, and write the response back.
///
/// Returns false when the session should end.
bool SshService::Session::handle_line(const std::string& line) {
    if (command_count_ >= limits::kMaxCommandsPerSession) {
        // The session keeps answering but stops being recorded, so a bot in a
        // loop cannot grow the transcript without bound.
        send(shell_->prompt());
        return true;
    }

    const Shell::Result result = shell_->execute(line);
    emit_command(line, result);

    for (const auto& url : result.urls) {
        if (service_.deps_.on_capture) {
            service_.deps_.on_capture(CaptureRequest{url, id_, source_ip_});
        }
    }

    // Output is produced with bare newlines and the attacker's terminal is in
    // raw mode, so every newline needs a carriage return or the display
    // stairsteps and the illusion breaks.
    std::string rendered;
    rendered.reserve(result.output.size() + 16);
    for (const char character : result.output) {
        if (character == '\n') {
            rendered.push_back('\r');
        }
        rendered.push_back(character);
    }
    send(rendered);

    if (result.exit_requested) {
        return false;
    }
    send(shell_->prompt());
    return true;
}

void SshService::Session::interactive() {
    ShellContext context;
    context.username = username_;
    context.cwd = context.home();
    context.vfs = *service_.deps_.filesystem;
    shell_ = std::make_unique<Shell>(*service_.deps_.registry, std::move(context));

    send(
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        "Last login: Mon Nov  2 03:11:07 2026 from 10.0.3.9\r\n");
    send(shell_->prompt());

    const auto timeout = service_.deps_.config->ssh.session_timeout;
    auto deadline = core::Clock::now() + timeout;
    std::array<char, 4096> buffer{};

    while (channel_ != nullptr && ssh_channel_is_open(channel_) != 0 &&
           ssh_channel_is_eof(channel_) == 0) {
        if (core::Clock::now() > deadline) {
            send("\r\ntimed out waiting for input\r\n");
            return;
        }

        const int read = ssh_channel_read_timeout(
            channel_, buffer.data(), static_cast<std::uint32_t>(buffer.size()), 0, 200);
        if (read == SSH_ERROR) {
            return;
        }
        if (read <= 0) {
            continue;
        }

        deadline = core::Clock::now() + timeout;

        const auto steps =
            editor_.feed(std::string_view(buffer.data(), static_cast<std::size_t>(read)));
        for (const auto& step : steps) {
            send(step.echo);

            if (step.event == LineEvent::EndOfFile) {
                send("logout\r\n");
                return;
            }
            if (step.event == LineEvent::Interrupt) {
                send(shell_->prompt());
                continue;
            }
            if (step.event != LineEvent::Line) {
                continue;
            }
            if (!handle_line(step.line)) {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

SshService::SshService(SshDependencies dependencies)
    : deps_(std::move(dependencies)),
      tracker_(deps_.auth == nullptr ? 0 : deps_.auth->accept_after_failures(),
               AttemptTracker::kDefaultMaxTracked) {}

SshService::~SshService() {
    stop();
}

void SshService::ensure_host_key(const std::filesystem::path& path) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        return;
    }
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }

    ssh_key key = nullptr;
    if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &key) != SSH_OK || key == nullptr) {
        throw SshError("cannot generate an SSH host key");
    }
    const int result =
        ssh_pki_export_privkey_file(key, nullptr, nullptr, nullptr, path.string().c_str());
    ssh_key_free(key);
    if (result != SSH_OK) {
        throw SshError("cannot write the SSH host key to " + path.string());
    }

    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec);
    core::log().info("generated a new SSH host key at {}", path.string());
}

void SshService::start() {
    if (running_) {
        return;
    }
    if (deps_.config == nullptr || deps_.bus == nullptr || deps_.registry == nullptr ||
        deps_.auth == nullptr || deps_.filesystem == nullptr || deps_.mitre == nullptr) {
        throw SshError("SshService started without its dependencies");
    }

    const auto& config = deps_.config->ssh;
    ensure_host_key(config.host_key);

    ssh_bind bind = ssh_bind_new();
    if (bind == nullptr) {
        throw SshError("cannot create the SSH listener");
    }

    const std::string host_key = config.host_key.string();
    const int port = config.port;
    const std::string address = "0.0.0.0";

    if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, host_key.c_str()) != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, address.c_str()) != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port) != SSH_OK) {
        const std::string message = ssh_get_error(bind);
        ssh_bind_free(bind);
        throw SshError("cannot configure the SSH listener: " + message);
    }

    // The version string an attacker sees. A honeypot advertising libssh would
    // be recognised instantly by the scanners that fingerprint before they
    // brute force.
    if (!config.banner.empty()) {
        const std::string banner =
            config.banner.starts_with("SSH-2.0-") ? config.banner.substr(8) : config.banner;
        (void)ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BANNER, banner.c_str());
    }

    if (ssh_bind_listen(bind) != SSH_OK) {
        const std::string message = ssh_get_error(bind);
        ssh_bind_free(bind);
        throw SshError("cannot listen on the SSH port: " + message);
    }

    bound_port_ = bound_port_of(bind);
    bind_ = bind;
    running_ = true;
    acceptor_ = std::thread([this] { accept_loop(); });

    core::log().info("SSH honeypot listening on port {}", bound_port_.load());
}

void SshService::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (bind_ != nullptr) {
        // Closing the listening descriptor is what wakes the acceptor out of
        // ssh_bind_accept, which has no timeout of its own.
        const socket_t descriptor = ssh_bind_get_fd(static_cast<ssh_bind>(bind_));
        if (descriptor >= 0) {
            ::shutdown(descriptor, SHUT_RDWR);
        }
    }

    if (acceptor_.joinable()) {
        acceptor_.join();
    }

    if (bind_ != nullptr) {
        ssh_bind_free(static_cast<ssh_bind>(bind_));
        bind_ = nullptr;
    }

    // Sessions run detached. Wait for them rather than tearing the process
    // down underneath a thread that is mid write.
    for (int i = 0; i < 100 && active_sessions() > 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
}

bool SshService::admit(const std::string& source_ip) {
    const std::lock_guard<std::mutex> lock(sessions_mutex_);
    if (active_ >= deps_.config->ssh.max_sessions) {
        return false;
    }
    auto& count = per_ip_[source_ip];
    if (count >= deps_.config->ssh.max_sessions_per_ip) {
        return false;
    }
    ++count;
    ++active_;
    return true;
}

void SshService::release(const std::string& source_ip) {
    const std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto found = per_ip_.find(source_ip);
    if (found != per_ip_.end() && --found->second == 0) {
        per_ip_.erase(found);
    }
    if (active_ > 0) {
        --active_;
    }
}

std::size_t SshService::active_sessions() const {
    const std::lock_guard<std::mutex> lock(sessions_mutex_);
    return active_;
}

void SshService::accept_loop() {
    auto* bind = static_cast<ssh_bind>(bind_);

    while (running_) {
        ssh_session session = ssh_new();
        if (session == nullptr) {
            continue;
        }

        if (ssh_bind_accept(bind, session) != SSH_OK) {
            ssh_free(session);
            if (!running_) {
                break;
            }
            continue;
        }

        std::thread([this, session] {
            try {
                Session runner(*this, session);
                runner.run();
            } catch (const std::exception& error) {
                core::log().warn("session ended with an exception: {}", error.what());
            } catch (...) {
                core::log().warn("session ended with an unknown exception");
            }
        }).detach();
    }
}

}  // namespace arapuca::ssh
