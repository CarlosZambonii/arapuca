// The Telnet honeypot: a raw TCP listener that presents a BusyBox login and,
// once a weak credential is accepted, the same fake shell the SSH honeypot
// drives. There is no libssh here and no real PTY: the socket is read, the
// IAC negotiation is stripped, and every line goes to the shell that
// fabricates a response. Safety invariant S1 holds structurally, as it does
// for SSH: nothing an attacker sends reaches a process.
#pragma once

#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/ssh/auth_policy.hpp>
#include <arapuca/ssh/shell.hpp>
#include <arapuca/ssh/ssh_service.hpp>  // for ssh::CaptureRequest
#include <arapuca/ssh/vfs.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

namespace arapuca::telnet {

/// Collaborators the service borrows. All must outlive it. The capture request
/// is the SSH one: a URL handed to the same engine is the same request whether
/// a bot typed wget over SSH or tftp over Telnet.
struct TelnetDependencies {
    const core::Config* config = nullptr;
    core::EventBus* bus = nullptr;
    const ssh::CommandRegistry* registry = nullptr;
    const ssh::AuthPolicy* auth = nullptr;
    const ssh::Vfs* filesystem = nullptr;
    const enrich::MitreMapper* mitre = nullptr;
    const enrich::GeoIp* geo = nullptr;
    std::function<void(ssh::CaptureRequest)> on_capture;
};

class TelnetError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class TelnetService {
public:
    explicit TelnetService(TelnetDependencies dependencies);
    TelnetService(const TelnetService&) = delete;
    TelnetService& operator=(const TelnetService&) = delete;
    TelnetService(TelnetService&&) = delete;
    TelnetService& operator=(TelnetService&&) = delete;
    ~TelnetService();

    /// Bind, listen and start accepting. Throws TelnetError when the port
    /// cannot be bound.
    void start();

    /// Stop accepting and wait for running sessions to finish.
    void stop();

    /// The port actually bound, which equals the configured one unless that
    /// was zero, when the kernel chooses and the test reads it back here.
    [[nodiscard]] std::uint16_t bound_port() const {
        return bound_port_.load();
    }

    [[nodiscard]] std::size_t active_sessions() const;

private:
    class Session;
    friend class Session;

    bool admit(const std::string& source_ip);
    void release(const std::string& source_ip);
    void accept_loop();

    TelnetDependencies deps_;
    ssh::AttemptTracker tracker_;

    std::atomic<bool> running_{false};
    std::atomic<std::uint16_t> bound_port_{0};
    std::atomic<int> listen_fd_{-1};
    std::thread acceptor_;

    mutable std::mutex sessions_mutex_;
    std::size_t active_ = 0;
    std::unordered_map<std::string, std::size_t> per_ip_;
};

}  // namespace arapuca::telnet
