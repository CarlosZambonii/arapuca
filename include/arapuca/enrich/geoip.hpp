// GeoIP enrichment from the MaxMind GeoLite2 databases.
//
// Absence is a normal state, not an error. The .mmdb files are not committed
// (MaxMind's licence does not allow redistribution) and they are downloaded at
// deploy time with an account key. A developer cloning this repository has no
// account and must still be able to build, run and test the honeypot, so a
// missing database disables enrichment and nothing else: the event is emitted
// without a geo field rather than not emitted at all.
#pragma once

#include <arapuca/core/event.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

// Forward declaration of the libmaxminddb handle, so this header does not drag
// the C library into every translation unit that records an event.
// NOLINTNEXTLINE(readability-identifier-naming)
struct MMDB_s;

namespace arapuca::enrich {

class GeoIp {
public:
    /// Constructs a disabled lookup. Every lookup returns nothing.
    GeoIp() = default;

    GeoIp(const GeoIp&) = delete;
    GeoIp& operator=(const GeoIp&) = delete;
    GeoIp(GeoIp&& other) noexcept;
    GeoIp& operator=(GeoIp&& other) noexcept;
    ~GeoIp();

    /// Open what is available. A missing or unreadable file disables that one
    /// database and leaves the other working, so an ASN only deployment is a
    /// supported configuration rather than a half broken one.
    [[nodiscard]] static GeoIp open(const std::filesystem::path& city_db,
                                    const std::filesystem::path& asn_db);

    /// Look up an address. Returns nothing when no database is open, when the
    /// address is not valid, or when the databases hold nothing for it, which
    /// is common for reserved and cloud ranges.
    [[nodiscard]] std::optional<core::Geo> lookup(std::string_view ip) const;

    [[nodiscard]] bool city_available() const {
        return city_ != nullptr;
    }

    [[nodiscard]] bool asn_available() const {
        return asn_ != nullptr;
    }

    [[nodiscard]] bool enabled() const {
        return city_available() || asn_available();
    }

    /// Why a database is not open, for the startup log. Empty when all is well.
    [[nodiscard]] const std::string& status() const {
        return status_;
    }

private:
    void close();

    MMDB_s* city_ = nullptr;
    MMDB_s* asn_ = nullptr;
    std::string status_;
};

}  // namespace arapuca::enrich
