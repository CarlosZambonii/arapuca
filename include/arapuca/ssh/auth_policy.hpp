// Who gets let in to the fake shell.
//
// Only credentials on a list are accepted, and the list is weak on purpose:
// the honeypot is interesting precisely when an attacker believes a guess
// worked. Every attempt is recorded either way, so a refused login is as much
// of a product as an accepted one.
//
// Two mechanisms, kept apart because they have different natures:
//
//   AuthPolicy is pure. Given a username and a password it answers yes or no,
//   with no state, which makes it trivial to test exhaustively.
//
//   AttemptTracker is stateful and shared across threads. It implements the
//   optional "accept after N failures" behaviour that real honeypots use to
//   let a persistent brute forcer through eventually. Its failure map is
//   bounded, because an attacker with a large address pool would otherwise
//   grow it without limit.
#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <list>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace arapuca::ssh {

struct Credential {
    std::string username;
    std::string password;
};

struct AuthDecision {
    bool accepted = false;
    /// Which rule decided, for the event. One of "exact", "any_password",
    /// "any_username", "after_failures" or "no_match".
    std::string rule;
};

class AuthError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class AuthPolicy {
public:
    AuthPolicy() = default;

    [[nodiscard]] static AuthPolicy from_yaml(const std::string& yaml_text);
    [[nodiscard]] static AuthPolicy from_file(const std::filesystem::path& path);

    /// Decide on one attempt. Never throws, never allocates beyond the result:
    /// this runs on the session thread for every guess a brute forcer makes.
    [[nodiscard]] AuthDecision evaluate(std::string_view username, std::string_view password) const;

    [[nodiscard]] std::size_t size() const {
        return credentials_.size();
    }

    [[nodiscard]] const std::vector<Credential>& credentials() const {
        return credentials_;
    }

    /// Failures before an attempt is accepted regardless of the credential.
    /// Zero disables the behaviour, which is the default.
    [[nodiscard]] std::size_t accept_after_failures() const {
        return accept_after_failures_;
    }

private:
    std::vector<Credential> credentials_;
    std::size_t accept_after_failures_ = 0;
};

/// Per source address failure counting, with a bounded table.
class AttemptTracker {
public:
    AttemptTracker(std::size_t accept_after_failures, std::size_t max_tracked);

    /// Record a failure and report whether this attempt should be accepted
    /// anyway. Returns false when the behaviour is disabled.
    bool record_failure_and_check(std::string_view source);

    /// Forget an address, called once it has been let in.
    void forget(std::string_view source);

    [[nodiscard]] std::size_t failures_for(std::string_view source) const;
    [[nodiscard]] std::size_t tracked() const;
    /// Addresses dropped to stay within the table bound.
    [[nodiscard]] std::uint64_t evicted() const;

    static constexpr std::size_t kDefaultMaxTracked = 4096;

private:
    void evict_oldest_locked();

    mutable std::mutex mutex_;
    std::size_t accept_after_failures_;
    std::size_t max_tracked_;
    /// Insertion order, oldest first, so eviction is O(1).
    std::list<std::string> order_;

    struct Entry {
        std::size_t failures = 0;
        std::list<std::string>::iterator position;
    };

    std::unordered_map<std::string, Entry> failures_;
    std::uint64_t evicted_ = 0;
};

}  // namespace arapuca::ssh
