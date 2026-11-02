#include <arapuca/capture/hashing.hpp>
#include <arapuca/capture/quarantine.hpp>
#include <arapuca/core/logging.hpp>

#include <nlohmann/json.hpp>

#include <minizip/zip.h>
#include <zlib.h>

#include <algorithm>
#include <fstream>
#include <system_error>
#include <utility>

namespace arapuca::capture {
namespace {

/// Names a sample safely. The attacker chose the original name, so it is kept
/// only as metadata; the entry inside the zip is derived from the hash plus a
/// sanitized suffix, and can never contain a path separator.
std::string zip_entry_name(std::string_view sha256, std::string_view original) {
    std::string suffix;
    const auto dot = original.find_last_of('.');
    if (dot != std::string_view::npos && original.size() - dot <= 8) {
        for (const char character : original.substr(dot)) {
            if (std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '.') {
                suffix.push_back(character);
            }
        }
    }
    return std::string(sha256) + suffix + ".sample";
}

}  // namespace

void write_encrypted_zip(const std::filesystem::path& path,
                         std::string_view entry_name,
                         std::string_view data,
                         const std::string& password) {
    zipFile archive = zipOpen64(path.string().c_str(), APPEND_STATUS_CREATE);
    if (archive == nullptr) {
        throw QuarantineError("cannot create the quarantine archive " + path.string());
    }

    const zip_fileinfo info{};

    // minizip needs the CRC of the plaintext up front to seed the legacy
    // encryption stream.
    // zlib takes unsigned char*, and a sample is a byte buffer by definition.
    // The suppression is on the line itself rather than above it, because a
    // NOLINTNEXTLINE at the top of a multi line comment applies to the next
    // comment line, not to the code.
    const auto* bytes = reinterpret_cast<const Bytef*>(data.data());  // NOLINT
    const uLong crc = ::crc32(0L, bytes, static_cast<uInt>(data.size()));

    const std::string entry(entry_name);
    const int opened = zipOpenNewFileInZip3_64(archive,
                                               entry.c_str(),
                                               &info,
                                               nullptr,
                                               0,
                                               nullptr,
                                               0,
                                               nullptr,
                                               Z_DEFLATED,
                                               Z_DEFAULT_COMPRESSION,
                                               0,
                                               -MAX_WBITS,
                                               DEF_MEM_LEVEL,
                                               Z_DEFAULT_STRATEGY,
                                               password.empty() ? nullptr : password.c_str(),
                                               crc,
                                               1);
    if (opened != ZIP_OK) {
        zipClose(archive, nullptr);
        throw QuarantineError("cannot add an entry to " + path.string());
    }

    if (!data.empty()) {
        const int written =
            zipWriteInFileInZip(archive, data.data(), static_cast<unsigned>(data.size()));
        if (written != ZIP_OK) {
            zipCloseFileInZip(archive);
            zipClose(archive, nullptr);
            throw QuarantineError("cannot write the sample into " + path.string());
        }
    }

    zipCloseFileInZip(archive);
    zipClose(archive, "captured by arapuca, password: infected");
}

Quarantine::Quarantine(QuarantineConfig config) : config_(std::move(config)) {
    if (config_.directory.empty()) {
        throw QuarantineError("quarantine directory must be configured");
    }
    std::error_code ec;
    std::filesystem::create_directories(config_.directory, ec);
    if (ec) {
        throw QuarantineError("cannot create the quarantine directory: " + ec.message());
    }
}

std::vector<QuarantineEntry> Quarantine::scan_locked() const {
    std::vector<QuarantineEntry> out;
    std::error_code ec;

    for (const auto& item : std::filesystem::directory_iterator(config_.directory, ec)) {
        if (!item.is_regular_file() || item.path().extension() != ".zip") {
            continue;
        }
        QuarantineEntry entry;
        entry.path = item.path();
        entry.sha256 = item.path().stem().string();
        entry.stored_bytes = item.file_size(ec);
        entry.stored_at = item.last_write_time(ec);
        out.push_back(std::move(entry));
    }

    std::sort(out.begin(), out.end(), [](const QuarantineEntry& a, const QuarantineEntry& b) {
        return a.stored_at < b.stored_at;
    });
    return out;
}

std::size_t Quarantine::enforce_limits() {
    const std::lock_guard<std::mutex> lock(mutex_);

    auto held = scan_locked();
    std::uint64_t total = 0;
    for (const auto& entry : held) {
        total += entry.stored_bytes;
    }

    std::size_t evicted = 0;
    std::size_t index = 0;
    // Oldest first: the list is already sorted by modification time.
    while (index < held.size() &&
           (total > config_.max_total_bytes || held.size() - index > config_.max_files)) {
        std::error_code ec;
        std::filesystem::remove(held[index].path, ec);
        std::filesystem::remove(held[index].path.string() + ".json", ec);
        if (!ec) {
            total -= std::min(total, held[index].stored_bytes);
            ++evicted;
        }
        ++index;
    }

    if (evicted > 0) {
        core::log().info("quarantine evicted {} sample(s) to stay within its limits", evicted);
    }
    return evicted;
}

StoreResult Quarantine::store(std::string_view data, std::string_view original_name) {
    StoreResult result;
    const Digests digests = digests_of(data);
    result.sha256 = digests.sha256;
    result.md5 = digests.md5;
    result.original_bytes = data.size();

    if (result.sha256.empty()) {
        result.error = "hashing failed";
        return result;
    }

    const std::filesystem::path target = config_.directory / (result.sha256 + ".zip");
    result.path = target;

    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::error_code ec;
        if (std::filesystem::exists(target, ec)) {
            // Seen before. One file and a counter, rather than one file per
            // session that fetched the same dropper.
            result.duplicate = true;
            result.stored = true;
            result.stored_bytes = std::filesystem::file_size(target, ec);
            std::filesystem::last_write_time(
                target, std::filesystem::file_time_type::clock::now(), ec);
            return result;
        }

        try {
            write_encrypted_zip(
                target, zip_entry_name(result.sha256, original_name), data, config_.password);
        } catch (const QuarantineError& error) {
            result.error = error.what();
            return result;
        }

        // Read only, owner only. A sample is never executable, and safety
        // invariant S3 says so structurally rather than by convention.
        std::filesystem::permissions(
            target, std::filesystem::perms::owner_read, std::filesystem::perm_options::replace, ec);
        result.stored_bytes = std::filesystem::file_size(target, ec);
        result.stored = true;

        const nlohmann::json metadata = {{"sha256", result.sha256},
                                         {"md5", result.md5},
                                         {"original_name", std::string(original_name)},
                                         {"original_bytes", result.original_bytes},
                                         {"stored_bytes", result.stored_bytes},
                                         {"zip_password", config_.password}};
        std::ofstream sidecar(target.string() + ".json");
        if (sidecar) {
            sidecar << metadata.dump(2) << "\n";
        }
    }

    result.evicted = enforce_limits();
    return result;
}

bool Quarantine::holds(std::string_view sha256) const {
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    return std::filesystem::exists(config_.directory / (std::string(sha256) + ".zip"), ec);
}

std::uint64_t Quarantine::total_bytes() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    std::uint64_t total = 0;
    for (const auto& entry : scan_locked()) {
        total += entry.stored_bytes;
    }
    return total;
}

std::size_t Quarantine::count() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return scan_locked().size();
}

std::vector<QuarantineEntry> Quarantine::entries() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return scan_locked();
}

}  // namespace arapuca::capture
