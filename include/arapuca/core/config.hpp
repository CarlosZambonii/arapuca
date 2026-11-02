// Configuration, loaded from YAML once at startup.
//
// Two rules shape this file:
//
//   1. Secrets never appear in the YAML. They come from the environment, so a
//      configuration file can be committed to a public repository without a
//      review step, and a leaked config leaks nothing.
//
//   2. Every limit read from the file is clamped to the compile time ceiling
//      in limits.hpp. A configuration mistake can make the honeypot stricter,
//      never more permissive than the audited bound.
#pragma once

#include <arapuca/core/logging.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace arapuca::core {

struct EventLogConfig {
    std::filesystem::path path = "/var/log/arapuca/events.jsonl";
    std::size_t flush_every = 16;
    std::chrono::milliseconds flush_interval{1000};
    std::size_t bus_capacity = 8192;
};

struct SshConfig {
    bool enabled = true;
    std::uint16_t port = 2222;
    std::string banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4";
    std::filesystem::path host_key = "/var/lib/arapuca/ssh_host_ed25519_key";
    std::filesystem::path credentials_file = "config/credentials.yaml";
    std::filesystem::path filesystem_file = "config/filesystem.yaml";
    std::size_t max_sessions = 256;
    std::size_t max_sessions_per_ip = 8;
    std::chrono::seconds session_timeout{300};
};

struct HttpConfig {
    bool enabled = true;
    std::uint16_t port = 8080;
    std::filesystem::path decoy_dir = "config/http";
    std::string server_header = "Apache/2.4.52 (Ubuntu)";
    std::size_t max_body_recorded = 8192;
};

struct CaptureConfig {
    bool enabled = true;
    std::filesystem::path quarantine_dir = "/var/lib/arapuca/quarantine";
    std::string zip_password = "infected";
    std::size_t max_sample_bytes = 32UL * 1024 * 1024;
    /// Total quarantine budget. Oldest samples are evicted past this, so an
    /// attacker cannot fill the disk by downloading in a loop.
    std::uint64_t quarantine_max_total_bytes = 2UL * 1024 * 1024 * 1024;
    std::size_t quarantine_max_files = 5000;
    bool virustotal_enabled = true;
    /// Free tier allowances. Exceeding them gets the key throttled, so the
    /// client refuses rather than discovers it the hard way.
    std::size_t vt_requests_per_minute = 4;
    std::size_t vt_requests_per_day = 500;
};

struct GeoConfig {
    std::filesystem::path city_db = "/var/lib/arapuca/geoip/GeoLite2-City.mmdb";
    std::filesystem::path asn_db = "/var/lib/arapuca/geoip/GeoLite2-ASN.mmdb";
};

struct MitreConfig {
    std::filesystem::path rules_file = "config/mitre.yaml";
};

struct LoggingConfig {
    LogLevel level = LogLevel::Info;
    std::filesystem::path file;
};

struct Config {
    std::string sensor_name = "arapuca";
    EventLogConfig events;
    SshConfig ssh;
    HttpConfig http;
    CaptureConfig capture;
    GeoConfig geo;
    MitreConfig mitre;
    LoggingConfig logging;

    /// Secrets, never read from the YAML.
    std::string virustotal_api_key;

    /// Load from a file. Throws ConfigError on a malformed or invalid file.
    [[nodiscard]] static Config load(const std::filesystem::path& path);

    /// Parse from a string. Used by the tests and by the fuzzer.
    [[nodiscard]] static Config parse(const std::string& yaml_text);

    /// Overlay the environment. Called by load(), and separately by tests.
    void apply_environment();

    /// Resolve every relative path against `base`, which is the directory the
    /// configuration file came from. Without this, `config/mitre.yaml` means
    /// something different depending on the working directory, and in a
    /// container it means nothing at all.
    void resolve_paths_against(const std::filesystem::path& base);

    /// Clamp every limit to the ceiling in limits.hpp and reject nonsense.
    /// Throws ConfigError when a value cannot be made safe, for example a
    /// zero port. Returns the list of values that were clamped, so startup
    /// can log them instead of silently disagreeing with the file.
    std::vector<std::string> validate_and_clamp();
};

class ConfigError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

}  // namespace arapuca::core
