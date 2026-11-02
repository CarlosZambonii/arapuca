// The SSH honeypot itself: the libssh server, the session lifecycle, and the
// channel policy.
//
// Safety invariant S10 lives here. Only a session channel carrying a shell or
// an exec request is accepted. Port forwarding in both directions, X11
// forwarding, agent forwarding and every subsystem including SFTP and SCP are
// refused, and each refusal becomes an event of its own, because an attacker
// probing for a SOCKS proxy is telling us what they wanted the machine for.
//
// Safety invariant S1 holds structurally: the exec payload and every typed
// line go to the fake shell, which fabricates a response. Nothing reaches a
// process.
#pragma once

#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/ssh/auth_policy.hpp>
#include <arapuca/ssh/shell.hpp>
#include <arapuca/ssh/vfs.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace arapuca::ssh {

/// A URL an attacker asked the fake shell to fetch, handed to the capture
/// engine. Passed by value onto another thread, so it owns everything.
struct CaptureRequest {
    std::string url;
    std::string session_id;
    std::string source_ip;
};

/// Collaborators the service borrows. All must outlive it.
struct SshDependencies {
    const core::Config* config = nullptr;
    core::EventBus* bus = nullptr;
    const CommandRegistry* registry = nullptr;
    const AuthPolicy* auth = nullptr;
    /// Copied into every session, so each attacker gets a private machine.
    const Vfs* filesystem = nullptr;
    const enrich::MitreMapper* mitre = nullptr;
    const enrich::GeoIp* geo = nullptr;
    /// Called off the session thread for every URL seen. May be empty.
    std::function<void(CaptureRequest)> on_capture;
};

class SshError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class SshService {
public:
    explicit SshService(SshDependencies dependencies);
    SshService(const SshService&) = delete;
    SshService& operator=(const SshService&) = delete;
    SshService(SshService&&) = delete;
    SshService& operator=(SshService&&) = delete;
    ~SshService();

    /// Bind, listen and start accepting. Throws SshError when the port cannot
    /// be bound or the host key cannot be read or created.
    void start();

    /// Stop accepting and wait for running sessions to finish.
    void stop();

    /// The port actually bound, which differs from the configured one when
    /// zero was requested. Used by the integration tests.
    [[nodiscard]] std::uint16_t port() const {
        return bound_port_;
    }

    [[nodiscard]] std::size_t active_sessions() const;

    [[nodiscard]] bool running() const {
        return running_;
    }

    /// Create an ed25519 host key at `path` when none exists. The fingerprint
    /// has to be stable across restarts, or a returning attacker gets the
    /// changed key warning and leaves.
    static void ensure_host_key(const std::filesystem::path& path);

private:
    class Session;

    void accept_loop();
    bool admit(const std::string& source_ip);
    void release(const std::string& source_ip);

    SshDependencies deps_;
    void* bind_ = nullptr;  ///< ssh_bind, opaque so libssh stays out of this header
    std::thread acceptor_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint16_t> bound_port_{0};

    mutable std::mutex sessions_mutex_;
    std::size_t active_ = 0;
    std::unordered_map<std::string, std::size_t> per_ip_;
    AttemptTracker tracker_;
};

}  // namespace arapuca::ssh
