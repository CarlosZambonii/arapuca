#include <arapuca/core/logging.hpp>
#include <arapuca/enrich/geoip.hpp>

#include <maxminddb.h>

#include <cstring>
#include <new>
#include <utility>

namespace arapuca::enrich {
namespace {

// libmaxminddb is a C library. Its result type is a union and its accessor is
// variadic, and neither can be avoided from this side of the interface. The
// suppressions are scoped to the three helpers that touch the C API, so the
// checks stay active for the rest of the file.
// NOLINTBEGIN(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-type-vararg)

MMDB_s* open_database(const std::filesystem::path& path, std::string& status, const char* label) {
    if (path.empty()) {
        return nullptr;
    }

    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        status += std::string(label) + " database not found at " + path.string() + "; ";
        return nullptr;
    }

    auto* handle = new (std::nothrow) MMDB_s{};
    if (handle == nullptr) {
        return nullptr;
    }

    const int result = MMDB_open(path.c_str(), MMDB_MODE_MMAP, handle);
    if (result != MMDB_SUCCESS) {
        status += std::string(label) + " database at " + path.string() +
                  " could not be opened: " + MMDB_strerror(result) + "; ";
        delete handle;
        return nullptr;
    }

    return handle;
}

std::string utf8_string(const MMDB_entry_data_s& data) {
    if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        return {data.utf8_string, data.data_size};
    }
    return {};
}

/// Read one path out of an entry, swallowing a lookup miss. A database that
/// does not carry a city for an address is the normal case, not a failure.
template<typename... Keys>
MMDB_entry_data_s get(MMDB_entry_s& entry, Keys... keys) {
    MMDB_entry_data_s data{};
    if (MMDB_get_value(&entry, &data, keys..., nullptr) != MMDB_SUCCESS) {
        data.has_data = false;
    }
    return data;
}

// NOLINTEND(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-type-vararg)

}  // namespace

GeoIp::GeoIp(GeoIp&& other) noexcept
    : city_(std::exchange(other.city_, nullptr)),
      asn_(std::exchange(other.asn_, nullptr)),
      status_(std::move(other.status_)) {}

GeoIp& GeoIp::operator=(GeoIp&& other) noexcept {
    if (this != &other) {
        close();
        city_ = std::exchange(other.city_, nullptr);
        asn_ = std::exchange(other.asn_, nullptr);
        status_ = std::move(other.status_);
    }
    return *this;
}

GeoIp::~GeoIp() {
    close();
}

void GeoIp::close() {
    if (city_ != nullptr) {
        MMDB_close(city_);
        delete city_;
        city_ = nullptr;
    }
    if (asn_ != nullptr) {
        MMDB_close(asn_);
        delete asn_;
        asn_ = nullptr;
    }
}

GeoIp GeoIp::open(const std::filesystem::path& city_db, const std::filesystem::path& asn_db) {
    GeoIp instance;
    instance.city_ = open_database(city_db, instance.status_, "GeoLite2 City");
    instance.asn_ = open_database(asn_db, instance.status_, "GeoLite2 ASN");

    if (!instance.enabled()) {
        core::log().warn("GeoIP enrichment disabled: {}",
                         instance.status_.empty() ? "no database configured" : instance.status_);
    } else if (!instance.status_.empty()) {
        core::log().warn("GeoIP partially enabled: {}", instance.status_);
    }

    return instance;
}

std::optional<core::Geo> GeoIp::lookup(std::string_view ip) const {
    if (!enabled() || ip.empty()) {
        return std::nullopt;
    }

    // The C API needs a terminated string, and the caller usually has a
    // string_view into a larger buffer.
    const std::string address(ip);
    core::Geo geo;
    bool found_anything = false;

    if (city_ != nullptr) {
        int gai_error = 0;
        int mmdb_error = MMDB_SUCCESS;
        MMDB_lookup_result_s result =
            MMDB_lookup_string(city_, address.c_str(), &gai_error, &mmdb_error);

        // gai_error means the string was not an address at all, which happens
        // whenever something upstream hands us a hostname by mistake.
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry) {
            found_anything = true;

            geo.country_iso = utf8_string(get(result.entry, "country", "iso_code"));
            geo.country = utf8_string(get(result.entry, "country", "names", "en"));
            geo.city = utf8_string(get(result.entry, "city", "names", "en"));

            // NOLINTBEGIN(cppcoreguidelines-pro-type-union-access)
            const auto latitude = get(result.entry, "location", "latitude");
            if (latitude.has_data && latitude.type == MMDB_DATA_TYPE_DOUBLE) {
                geo.latitude = latitude.double_value;
            }
            const auto longitude = get(result.entry, "location", "longitude");
            if (longitude.has_data && longitude.type == MMDB_DATA_TYPE_DOUBLE) {
                geo.longitude = longitude.double_value;
            }
            // NOLINTEND(cppcoreguidelines-pro-type-union-access)
        }
    }

    if (asn_ != nullptr) {
        int gai_error = 0;
        int mmdb_error = MMDB_SUCCESS;
        MMDB_lookup_result_s result =
            MMDB_lookup_string(asn_, address.c_str(), &gai_error, &mmdb_error);

        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry) {
            const auto number = get(result.entry, "autonomous_system_number");
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
            if (number.has_data && number.type == MMDB_DATA_TYPE_UINT32) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                geo.asn = number.uint32;
                found_anything = true;
            }
            const std::string org =
                utf8_string(get(result.entry, "autonomous_system_organization"));
            if (!org.empty()) {
                geo.as_org = org;
                found_anything = true;
            }
        }
    }

    if (!found_anything) {
        return std::nullopt;
    }
    return geo;
}

}  // namespace arapuca::enrich
