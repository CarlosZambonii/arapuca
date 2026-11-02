// Where captured samples go.
//
// Every sample is stored as `<sha256>.zip`, encrypted with the password
// "infected". That convention exists for a practical reason rather than a
// security one: antivirus on an analyst's machine deletes a bare malware
// sample the moment it touches disk, and a password protected zip survives
// long enough to be moved to a sandbox. It also stops an accidental double
// click. It is not a security boundary and is not treated as one.
//
// Retention is a safety control. An attacker in a loop downloading a large
// file would otherwise fill the disk of a 50 GB instance and take the
// honeypot down, so there is a total byte cap and a file count cap, and the
// oldest samples are evicted when either is crossed.
#pragma once

#include <arapuca/core/clock.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::capture {

struct QuarantineConfig {
    std::filesystem::path directory;
    std::string password = "infected";
    std::uint64_t max_total_bytes = 2UL * 1024 * 1024 * 1024;
    std::size_t max_files = 5000;
};

struct QuarantineEntry {
    std::string sha256;
    std::filesystem::path path;
    std::uint64_t stored_bytes = 0;
    std::filesystem::file_time_type stored_at;
};

struct StoreResult {
    bool stored = false;
    /// True when this exact sample was already held. A dropper fetched from a
    /// thousand sessions is one file and a counter, not a thousand files.
    bool duplicate = false;
    std::string sha256;
    std::string md5;
    std::filesystem::path path;
    std::uint64_t original_bytes = 0;
    std::uint64_t stored_bytes = 0;
    std::size_t evicted = 0;
    std::string error;
};

class QuarantineError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Quarantine {
public:
    explicit Quarantine(QuarantineConfig config);

    /// Store a sample. Returns what happened, never throws for an expected
    /// condition: a full disk and a duplicate are both results worth
    /// recording, not exceptions.
    StoreResult store(std::string_view data, std::string_view original_name);

    [[nodiscard]] bool holds(std::string_view sha256) const;
    [[nodiscard]] std::uint64_t total_bytes() const;
    [[nodiscard]] std::size_t count() const;
    [[nodiscard]] std::vector<QuarantineEntry> entries() const;

    /// Bring the store back under its caps, oldest first. Called by store(),
    /// and separately on startup so a cap lowered in the configuration takes
    /// effect without waiting for the next sample.
    std::size_t enforce_limits();

    [[nodiscard]] const QuarantineConfig& config() const {
        return config_;
    }

private:
    [[nodiscard]] std::vector<QuarantineEntry> scan_locked() const;

    mutable std::mutex mutex_;
    QuarantineConfig config_;
};

/// Write `data` into a zip at `path` under `entry_name`, encrypted with
/// `password`. Separated from the store so it can be tested on its own.
void write_encrypted_zip(const std::filesystem::path& path,
                         std::string_view entry_name,
                         std::string_view data,
                         const std::string& password);

}  // namespace arapuca::capture
