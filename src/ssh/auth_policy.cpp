#include <arapuca/ssh/auth_policy.hpp>

#include <yaml-cpp/yaml.h>

#include <fstream>
#include <sstream>
#include <utility>

namespace arapuca::ssh {
namespace {

constexpr std::string_view kAny = "*";

}  // namespace

AuthPolicy AuthPolicy::from_yaml(const std::string& yaml_text) {
    AuthPolicy policy;

    YAML::Node root;
    try {
        root = YAML::Load(yaml_text);
    } catch (const YAML::Exception& error) {
        throw AuthError(std::string("cannot parse credentials: ") + error.what());
    }

    if (!root || root.IsNull()) {
        return policy;
    }
    if (!root.IsMap()) {
        throw AuthError("credentials file must be a mapping");
    }

    if (const YAML::Node after = root["accept_after_failures"]) {
        const auto value = after.as<int>();
        if (value < 0) {
            throw AuthError("accept_after_failures must not be negative");
        }
        policy.accept_after_failures_ = static_cast<std::size_t>(value);
    }

    const YAML::Node list = root["credentials"];
    if (!list) {
        return policy;
    }
    if (!list.IsSequence()) {
        throw AuthError("credentials must be a sequence");
    }

    policy.credentials_.reserve(list.size());
    for (std::size_t index = 0; index < list.size(); ++index) {
        const YAML::Node entry = list[index];
        if (!entry.IsMap() || !entry["username"] || !entry["password"]) {
            throw AuthError("credential " + std::to_string(index) +
                            " needs a username and a password");
        }
        Credential credential;
        credential.username = entry["username"].as<std::string>();
        // Quoting matters here: 123456 is a number in YAML, and this field has
        // to survive as the string an attacker actually typed.
        credential.password = entry["password"].as<std::string>();
        policy.credentials_.push_back(std::move(credential));
    }

    return policy;
}

AuthPolicy AuthPolicy::from_file(const std::filesystem::path& path) {
    const std::ifstream input(path);
    if (!input) {
        throw AuthError("cannot open credentials file: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return from_yaml(buffer.str());
}

AuthDecision AuthPolicy::evaluate(std::string_view username, std::string_view password) const {
    for (const auto& credential : credentials_) {
        const bool user_matches = credential.username == kAny || credential.username == username;
        if (!user_matches) {
            continue;
        }

        if (credential.password == kAny) {
            return {true, credential.username == kAny ? "any_username" : "any_password"};
        }
        if (credential.password == password) {
            return {true, credential.username == kAny ? "any_username" : "exact"};
        }
    }
    return {false, "no_match"};
}

AttemptTracker::AttemptTracker(std::size_t accept_after_failures, std::size_t max_tracked)
    : accept_after_failures_(accept_after_failures),
      max_tracked_(max_tracked == 0 ? 1 : max_tracked) {}

void AttemptTracker::evict_oldest_locked() {
    if (order_.empty()) {
        return;
    }
    failures_.erase(order_.front());
    order_.pop_front();
    ++evicted_;
}

bool AttemptTracker::record_failure_and_check(std::string_view source) {
    if (accept_after_failures_ == 0) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(mutex_);
    const std::string key(source);

    auto found = failures_.find(key);
    if (found == failures_.end()) {
        // The table is bounded: a brute forcer with a large address pool must
        // not be able to grow it without limit.
        if (failures_.size() >= max_tracked_) {
            evict_oldest_locked();
        }
        order_.push_back(key);
        auto position = std::prev(order_.end());
        found = failures_.emplace(key, Entry{0, position}).first;
    }

    ++found->second.failures;
    return found->second.failures >= accept_after_failures_;
}

void AttemptTracker::forget(std::string_view source) {
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = failures_.find(std::string(source));
    if (found == failures_.end()) {
        return;
    }
    order_.erase(found->second.position);
    failures_.erase(found);
}

std::size_t AttemptTracker::failures_for(std::string_view source) const {
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = failures_.find(std::string(source));
    return found == failures_.end() ? 0 : found->second.failures;
}

std::size_t AttemptTracker::tracked() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return failures_.size();
}

std::uint64_t AttemptTracker::evicted() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return evicted_;
}

}  // namespace arapuca::ssh
