#include <arapuca/core/config.hpp>
#include <arapuca/core/limits.hpp>

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace arapuca::core {
namespace {

/// Read an optional scalar, leaving the default in place when the key is
/// absent. A missing key is never an error: a minimal config file should be
/// enough to start the honeypot.
template<typename T>
void read(const YAML::Node& node, const char* key, T& target) {
    if (!node || !node.IsMap()) {
        return;
    }
    const YAML::Node value = node[key];
    if (!value || value.IsNull()) {
        return;
    }
    try {
        target = value.as<T>();
    } catch (const YAML::Exception& error) {
        throw ConfigError(std::string("invalid value for '") + key + "': " + error.what());
    }
}

void read_path(const YAML::Node& node, const char* key, std::filesystem::path& target) {
    std::string text;
    if (!node || !node.IsMap()) {
        return;
    }
    const YAML::Node value = node[key];
    if (!value || value.IsNull()) {
        return;
    }
    read(node, key, text);
    if (!text.empty()) {
        target = text;
    }
}

void read_port(const YAML::Node& node, const char* key, std::uint16_t& target) {
    if (!node || !node.IsMap() || !node[key] || node[key].IsNull()) {
        return;
    }
    int port = 0;
    read(node, key, port);
    if (port < 1 || port > 65535) {
        throw ConfigError(std::string("port out of range for '") + key +
                          "': " + std::to_string(port));
    }
    target = static_cast<std::uint16_t>(port);
}

std::string env(const char* name) {
    // getenv races with setenv. The configuration is loaded once at startup,
    // before any service thread exists, and nothing in this process ever calls
    // setenv, so there is no race to lose.
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
}

template<typename T>
bool clamp_to(T& value, T ceiling, const char* label, std::vector<std::string>& clamped) {
    if (value > ceiling) {
        clamped.emplace_back(std::string(label) + " reduced from " + std::to_string(value) +
                             " to " + std::to_string(ceiling));
        value = ceiling;
        return true;
    }
    return false;
}

}  // namespace

Config Config::parse(const std::string& yaml_text) {
    Config config;

    YAML::Node root;
    try {
        root = YAML::Load(yaml_text);
    } catch (const YAML::Exception& error) {
        throw ConfigError(std::string("cannot parse configuration: ") + error.what());
    }

    if (!root || root.IsNull()) {
        return config;  // an empty file means "all defaults", which is valid
    }
    if (!root.IsMap()) {
        throw ConfigError("configuration root must be a mapping");
    }

    read(root, "sensor_name", config.sensor_name);

    if (const YAML::Node events = root["events"]) {
        read_path(events, "path", config.events.path);
        read(events, "flush_every", config.events.flush_every);
        read(events, "bus_capacity", config.events.bus_capacity);
        auto interval_ms = static_cast<std::size_t>(config.events.flush_interval.count());
        read(events, "flush_interval_ms", interval_ms);
        config.events.flush_interval = std::chrono::milliseconds(static_cast<long>(interval_ms));
    }

    if (const YAML::Node ssh = root["ssh"]) {
        read(ssh, "enabled", config.ssh.enabled);
        read_port(ssh, "port", config.ssh.port);
        read(ssh, "banner", config.ssh.banner);
        read_path(ssh, "host_key", config.ssh.host_key);
        read_path(ssh, "credentials_file", config.ssh.credentials_file);
        read_path(ssh, "filesystem_file", config.ssh.filesystem_file);
        read(ssh, "max_sessions", config.ssh.max_sessions);
        read(ssh, "max_sessions_per_ip", config.ssh.max_sessions_per_ip);
        auto timeout = static_cast<std::size_t>(config.ssh.session_timeout.count());
        read(ssh, "session_timeout_seconds", timeout);
        config.ssh.session_timeout = std::chrono::seconds(static_cast<long>(timeout));
    }

    if (const YAML::Node http = root["http"]) {
        read(http, "enabled", config.http.enabled);
        read_port(http, "port", config.http.port);
        read_path(http, "decoy_dir", config.http.decoy_dir);
        read(http, "server_header", config.http.server_header);
        read(http, "max_body_recorded", config.http.max_body_recorded);
    }

    if (const YAML::Node capture = root["capture"]) {
        read(capture, "enabled", config.capture.enabled);
        read_path(capture, "quarantine_dir", config.capture.quarantine_dir);
        read(capture, "zip_password", config.capture.zip_password);
        read(capture, "max_sample_bytes", config.capture.max_sample_bytes);
        read(capture, "quarantine_max_total_bytes", config.capture.quarantine_max_total_bytes);
        read(capture, "quarantine_max_files", config.capture.quarantine_max_files);
        if (const YAML::Node vt = capture["virustotal"]) {
            read(vt, "enabled", config.capture.virustotal_enabled);
            read(vt, "requests_per_minute", config.capture.vt_requests_per_minute);
            read(vt, "requests_per_day", config.capture.vt_requests_per_day);
            if (vt["api_key"]) {
                // Refused rather than ignored. Silently dropping a key that an
                // operator believed was in use is worse than failing to start.
                throw ConfigError(
                    "capture.virustotal.api_key must not be in the configuration file, "
                    "set the VT_API_KEY environment variable instead");
            }
        }
    }

    if (const YAML::Node geo = root["geo"]) {
        read_path(geo, "city_db", config.geo.city_db);
        read_path(geo, "asn_db", config.geo.asn_db);
    }

    if (const YAML::Node mitre = root["mitre"]) {
        read_path(mitre, "rules_file", config.mitre.rules_file);
    }

    if (const YAML::Node logging = root["logging"]) {
        std::string level = std::string(to_string(config.logging.level));
        read(logging, "level", level);
        config.logging.level = parse_log_level(level);
        read_path(logging, "file", config.logging.file);
    }

    return config;
}

void Config::apply_environment() {
    virustotal_api_key = env("VT_API_KEY");
    if (virustotal_api_key.empty()) {
        // No key means the lookup is disabled, not that the honeypot refuses
        // to run. Capture and quarantine work without VirusTotal.
        capture.virustotal_enabled = false;
    }

    const std::string sensor = env("ARAPUCA_SENSOR_NAME");
    if (!sensor.empty()) {
        sensor_name = sensor;
    }
}

std::vector<std::string> Config::validate_and_clamp() {
    std::vector<std::string> clamped;

    if (sensor_name.empty()) {
        throw ConfigError("sensor_name must not be empty");
    }
    if (events.path.empty()) {
        throw ConfigError("events.path must not be empty");
    }
    if (ssh.enabled && ssh.port == 0) {
        throw ConfigError("ssh.port must not be zero");
    }
    if (http.enabled && http.port == 0) {
        throw ConfigError("http.port must not be zero");
    }
    if (ssh.enabled && http.enabled && ssh.port == http.port) {
        throw ConfigError("ssh.port and http.port must differ");
    }
    if (capture.enabled && capture.quarantine_dir.empty()) {
        throw ConfigError("capture.quarantine_dir must not be empty");
    }

    if (events.flush_every == 0) {
        events.flush_every = 1;
    }
    if (events.bus_capacity == 0) {
        events.bus_capacity = 1;
    }

    // Everything below is a ceiling, never a floor. A configuration file can
    // ask for stricter limits than the compiled ones and gets them.
    clamp_to(events.bus_capacity, limits::kEventBusCapacity, "events.bus_capacity", clamped);
    clamp_to(ssh.max_sessions, limits::kMaxSshSessions, "ssh.max_sessions", clamped);
    clamp_to(
        ssh.max_sessions_per_ip, limits::kMaxSshSessionsPerIp, "ssh.max_sessions_per_ip", clamped);
    clamp_to(
        http.max_body_recorded, limits::kMaxHttpBodyRecorded, "http.max_body_recorded", clamped);
    clamp_to(
        capture.max_sample_bytes, limits::kMaxSampleBytes, "capture.max_sample_bytes", clamped);

    if (ssh.max_sessions_per_ip > ssh.max_sessions) {
        clamped.emplace_back("ssh.max_sessions_per_ip reduced to ssh.max_sessions");
        ssh.max_sessions_per_ip = ssh.max_sessions;
    }

    return clamped;
}

void Config::resolve_paths_against(const std::filesystem::path& base) {
    if (base.empty()) {
        return;
    }
    const auto fix = [&base](std::filesystem::path& target) {
        if (!target.empty() && target.is_relative()) {
            target = base / target;
        }
    };

    fix(events.path);
    fix(ssh.host_key);
    fix(ssh.credentials_file);
    fix(ssh.filesystem_file);
    fix(http.decoy_dir);
    fix(capture.quarantine_dir);
    fix(geo.city_db);
    fix(geo.asn_db);
    fix(mitre.rules_file);
    fix(logging.file);
}

Config Config::load(const std::filesystem::path& path) {
    const std::ifstream input(path);
    if (!input) {
        throw ConfigError("cannot open configuration file: " + path.string());
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();

    Config config = parse(buffer.str());
    config.resolve_paths_against(std::filesystem::absolute(path).parent_path());
    config.apply_environment();
    (void)config.validate_and_clamp();
    return config;
}

}  // namespace arapuca::core
