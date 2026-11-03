#include <arapuca/core/clock.hpp>
#include <arapuca/core/event.hpp>
#include <arapuca/core/limits.hpp>
#include <arapuca/core/logging.hpp>
#include <arapuca/enrich/session_classifier.hpp>
#include <arapuca/telnet/busybox.hpp>
#include <arapuca/telnet/protocol.hpp>
#include <arapuca/telnet/telnet_service.hpp>
#include <arapuca/util/redaction.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>

namespace arapuca::telnet {

using core::Event;
using core::EventType;

namespace {

std::string safe(std::string_view value, std::size_t limit) {
    return util::sanitize(value, limit).text;
}

/// The peer address and port of an accepted socket.
std::string peer_address(int fd, std::uint16_t& port) {
    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    // The POSIX API is defined in terms of this cast.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        port = 0;
        return "unknown";
    }

    std::array<char, INET6_ADDRSTRLEN> text{};
    if (address.ss_family == AF_INET) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
        port = ntohs(v4->sin_port);
        ::inet_ntop(AF_INET, &v4->sin_addr, text.data(), text.size());
    } else if (address.ss_family == AF_INET6) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
        port = ntohs(v6->sin6_port);
        ::inet_ntop(AF_INET6, &v6->sin6_addr, text.data(), text.size());
    } else {
        port = 0;
        return "unknown";
    }
    return {text.data()};
}

}  // namespace

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

class TelnetService::Session {
public:
    Session(TelnetService& service, int fd) : service_(service), fd_(fd) {}

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(Session&&) = delete;

    ~Session() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    void run();

private:
    [[nodiscard]] std::string_view sensor() const {
        return service_.deps_.config->sensor_name;
    }

    Event make_event(EventType type);
    void publish(Event event) const;
    void emit_auth(std::string_view user,
                   std::string_view password,
                   bool accepted,
                   std::string_view rule);
    void emit_command(const std::string& line, const ssh::Shell::Result& result);
    void emit_session_end();

    void send(std::string_view text) const;
    [[nodiscard]] bool read_line(std::string& line, core::TimePoint deadline);

    bool authenticate(core::TimePoint deadline);
    void interactive(core::TimePoint deadline);

    TelnetService& service_;
    int fd_;
    Decoder decoder_;
    std::string buffer_;  ///< decoded bytes not yet split into a line

    std::string id_;
    core::TimePoint started_;
    core::TimePoint last_command_;
    std::string source_ip_;
    std::uint16_t source_port_ = 0;
    std::string username_;
    std::optional<core::Geo> geo_;

    std::unique_ptr<ssh::Shell> shell_;
    enrich::SessionSignals signals_;
    std::size_t command_count_ = 0;
};

Event TelnetService::Session::make_event(EventType type) {
    Event event = Event::make(type, std::string(sensor()));
    event.session_id = id_;
    event.src_ip = source_ip_;
    event.src_port = source_port_;
    event.dst_port = service_.deps_.config->telnet.port;
    event.geo = geo_;
    return event;
}

void TelnetService::Session::publish(Event event) const {
    (void)service_.deps_.bus->publish(std::move(event));
}

void TelnetService::Session::emit_auth(std::string_view user,
                                       std::string_view password,
                                       bool accepted,
                                       std::string_view rule) {
    Event event = make_event(EventType::TelnetAuthAttempt);
    event.detail = {{"username", safe(user, limits::kMaxUsername)},
                    {"password", safe(password, limits::kMaxPassword)},
                    {"auth_method", "password"},
                    {"accepted", accepted},
                    {"rule", std::string(rule)}};
    // The technique is brute force whatever the transport, so the SSH rules
    // classify a Telnet attempt without a second copy of them in the yaml.
    event.mitre = service_.deps_.mitre->match(EventType::SshAuthAttempt, user);
    publish(std::move(event));
}

void TelnetService::Session::emit_command(const std::string& line,
                                          const ssh::Shell::Result& result) {
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

    Event event = make_event(EventType::TelnetCommand);
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

void TelnetService::Session::emit_session_end() {
    signals_.duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(core::Clock::now() - started_)
            .count();
    // A Telnet session has no line editor, so these stay false, which the
    // classifier already treats as the bot leaning signals they are.
    const auto classification = enrich::classify_session(signals_);

    Event event = make_event(EventType::TelnetSessionEnd);
    event.detail = {{"duration_ms", signals_.duration_ms},
                    {"command_count", command_count_},
                    {"username", username_},
                    {"classification", std::string(enrich::to_string(classification.verdict))},
                    {"classification_score", classification.score},
                    {"classification_reason", classification.reason}};
    publish(std::move(event));
}

void TelnetService::Session::send(std::string_view text) const {
    if (fd_ < 0 || text.empty()) {
        return;
    }
    std::size_t sent = 0;
    while (sent < text.size()) {
        const ssize_t wrote = ::send(fd_, text.data() + sent, text.size() - sent, MSG_NOSIGNAL);
        if (wrote <= 0) {
            return;  // a closed peer is routine; stop writing
        }
        sent += static_cast<std::size_t>(wrote);
    }
}

/// Read one line, stripping Telnet negotiation as it arrives. Returns false
/// when the peer closes, the deadline passes, or a line never terminates and
/// is cut at the length limit. The terminating CR, LF and NUL are removed.
bool TelnetService::Session::read_line(std::string& line, core::TimePoint deadline) {
    for (;;) {
        const auto newline = buffer_.find('\n');
        if (newline != std::string::npos) {
            line = buffer_.substr(0, newline);
            buffer_.erase(0, newline + 1);
            // Telnet ends a line with CR LF or CR NUL; drop a trailing CR and
            // any stray NUL so the command is the bytes the attacker meant.
            while (!line.empty() && (line.back() == '\r' || line.back() == '\0')) {
                line.pop_back();
            }
            return true;
        }

        // A line that never ends is cut, so a peer that never sends a newline
        // cannot grow the buffer without bound.
        if (buffer_.size() >= limits::kMaxTelnetLine) {
            line = buffer_.substr(0, limits::kMaxTelnetLine);
            buffer_.clear();
            return true;
        }

        if (core::Clock::now() >= deadline) {
            return false;
        }

        std::array<char, 2048> chunk{};
        const ssize_t got = ::recv(fd_, chunk.data(), chunk.size(), 0);
        if (got == 0) {
            return false;  // orderly close
        }
        if (got < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;  // recv timeout, check the deadline and read again
            }
            return false;
        }

        const Decoder::Output decoded =
            decoder_.feed(std::string_view(chunk.data(), static_cast<std::size_t>(got)));
        if (!decoded.response.empty()) {
            send(decoded.response);
        }
        buffer_ += decoded.clean;
    }
}

bool TelnetService::Session::authenticate(core::TimePoint deadline) {
    const auto& config = service_.deps_.config->telnet;
    if (!config.banner.empty()) {
        send(config.banner);
        send("\r\n");
    }

    // Real telnetd gives a few tries before dropping the connection.
    for (int attempt = 0; attempt < 3; ++attempt) {
        send(config.hostname + " login: ");
        std::string user;
        if (!read_line(user, deadline)) {
            return false;
        }
        send("Password: ");
        std::string password;
        if (!read_line(password, deadline)) {
            return false;
        }

        const ssh::AuthDecision decision = service_.deps_.auth->evaluate(user, password);
        const bool forced =
            !decision.accepted && service_.tracker_.record_failure_and_check(source_ip_);
        const bool accepted = decision.accepted || forced;
        emit_auth(user, password, accepted, forced ? "accept_after_failures" : decision.rule);

        if (accepted) {
            username_ = safe(user, limits::kMaxUsername);
            return true;
        }
        send("\r\nLogin incorrect\r\n");
    }
    return false;
}

void TelnetService::Session::interactive(core::TimePoint deadline) {
    ssh::ShellContext context;
    context.username = username_.empty() ? "root" : username_;
    context.hostname = service_.deps_.config->telnet.hostname;
    context.cwd = "/";
    context.persona = ssh::Persona::Busybox;
    context.vfs = *service_.deps_.filesystem;
    shell_ = std::make_unique<ssh::Shell>(*service_.deps_.registry, std::move(context));

    send(busybox_shell_banner());
    send(shell_->prompt());

    std::string line;
    while (read_line(line, deadline)) {
        if (command_count_ >= limits::kMaxCommandsPerSession) {
            break;
        }
        if (line.empty()) {
            send(shell_->prompt());
            continue;
        }

        const ssh::Shell::Result result = shell_->execute(line);
        emit_command(line, result);

        for (const auto& url : result.urls) {
            if (service_.deps_.on_capture) {
                service_.deps_.on_capture({safe(url, limits::kMaxCaptureUrl), id_, source_ip_});
            }
        }

        if (!result.output.empty()) {
            send(result.output);
        }
        if (result.exit_requested) {
            break;
        }
        send(shell_->prompt());
    }
}

void TelnetService::Session::run() {
    source_ip_ = peer_address(fd_, source_port_);

    if (!service_.admit(source_ip_)) {
        core::log().debug("refusing Telnet connection from {}, limit reached", source_ip_);
        return;
    }
    const std::unique_ptr<TelnetService, std::function<void(TelnetService*)>> release(
        &service_, [this](TelnetService* service) { service->release(source_ip_); });

    // A per read timeout so recv returns to check the overall deadline rather
    // than blocking on a silent peer forever.
    timeval timeout{};
    timeout.tv_sec = 2;
    (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    id_ = Event::make(EventType::TelnetSessionStart, std::string(sensor())).session_id;
    started_ = core::Clock::now();
    last_command_ = started_;
    const auto deadline = started_ + service_.deps_.config->telnet.session_timeout;

    if (service_.deps_.geo != nullptr) {
        geo_ = service_.deps_.geo->lookup(source_ip_);
    }

    Event start = make_event(EventType::TelnetSessionStart);
    start.session_id = id_;
    publish(std::move(start));

    if (authenticate(deadline)) {
        interactive(deadline);
    }

    emit_session_end();
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

TelnetService::TelnetService(TelnetDependencies dependencies)
    : deps_(std::move(dependencies)),
      tracker_(deps_.auth == nullptr ? 0 : deps_.auth->accept_after_failures(),
               ssh::AttemptTracker::kDefaultMaxTracked) {}

TelnetService::~TelnetService() {
    stop();
}

void TelnetService::start() {
    if (running_) {
        return;
    }
    if (deps_.config == nullptr || deps_.bus == nullptr || deps_.registry == nullptr ||
        deps_.auth == nullptr || deps_.filesystem == nullptr || deps_.mitre == nullptr) {
        throw TelnetError("TelnetService started without its dependencies");
    }

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw TelnetError("cannot create the Telnet socket");
    }

    const int one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(deps_.config->telnet.port);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        throw TelnetError("cannot bind the Telnet port");
    }
    if (::listen(fd, 64) != 0) {
        ::close(fd);
        throw TelnetError("cannot listen on the Telnet port");
    }

    // Read the port actually bound, so a configured port of zero still tells
    // a test where to connect.
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &length) == 0) {
        bound_port_ = ntohs(bound.sin_port);
    } else {
        bound_port_ = deps_.config->telnet.port;
    }

    listen_fd_ = fd;
    running_ = true;
    acceptor_ = std::thread([this] { accept_loop(); });

    core::log().info("Telnet honeypot listening on port {}", bound_port_.load());
}

void TelnetService::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    const int fd = listen_fd_.exchange(-1);
    if (fd >= 0) {
        // Shutting the listening descriptor down wakes the acceptor out of
        // accept(), which has no timeout of its own.
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
    }

    if (acceptor_.joinable()) {
        acceptor_.join();
    }

    for (int i = 0; i < 100 && active_sessions() > 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
}

bool TelnetService::admit(const std::string& source_ip) {
    const std::lock_guard<std::mutex> lock(sessions_mutex_);
    if (active_ >= deps_.config->telnet.max_sessions) {
        return false;
    }
    auto& count = per_ip_[source_ip];
    if (count >= deps_.config->telnet.max_sessions_per_ip) {
        return false;
    }
    ++count;
    ++active_;
    return true;
}

void TelnetService::release(const std::string& source_ip) {
    const std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto found = per_ip_.find(source_ip);
    if (found != per_ip_.end() && --found->second == 0) {
        per_ip_.erase(found);
    }
    if (active_ > 0) {
        --active_;
    }
}

std::size_t TelnetService::active_sessions() const {
    const std::lock_guard<std::mutex> lock(sessions_mutex_);
    return active_;
}

void TelnetService::accept_loop() {
    const int listener = listen_fd_.load();
    while (running_) {
        const int fd = ::accept(listener, nullptr, nullptr);
        if (fd < 0) {
            if (!running_) {
                break;
            }
            continue;
        }

        std::thread([this, fd] {
            try {
                Session runner(*this, fd);
                runner.run();
            } catch (const std::exception& error) {
                core::log().warn("Telnet session ended with an exception: {}", error.what());
            } catch (...) {
                core::log().warn("Telnet session ended with an unknown exception");
            }
        }).detach();
    }
}

}  // namespace arapuca::telnet
