#include <arapuca/enrich/geoip.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

using arapuca::enrich::GeoIp;

// The GeoLite2 databases are not redistributable, so they are not in this
// repository and they are not in CI. Everything below therefore tests the
// behavior that matters when they are absent, which is also the behavior a
// contributor without a MaxMind account will see. Lookups against a real
// database belong to the integration suite on a deployed sensor.

TEST(GeoIp, DefaultConstructedIsDisabled) {
    const GeoIp geo;
    EXPECT_FALSE(geo.enabled());
    EXPECT_FALSE(geo.city_available());
    EXPECT_FALSE(geo.asn_available());
}

// A missing database must not stop the honeypot from starting. Attack data
// without a country field is still attack data.
TEST(GeoIp, MissingFilesDisableEnrichmentWithoutThrowing) {
    GeoIp geo;
    EXPECT_NO_THROW({
        geo = GeoIp::open("/nonexistent/GeoLite2-City.mmdb", "/nonexistent/GeoLite2-ASN.mmdb");
    });
    EXPECT_FALSE(geo.enabled());
    EXPECT_FALSE(geo.status().empty()) << "the reason must be reportable at startup";
    EXPECT_NE(std::string::npos, geo.status().find("not found"));
}

TEST(GeoIp, EmptyPathsAreTreatedAsNotConfigured) {
    const GeoIp geo = GeoIp::open("", "");
    EXPECT_FALSE(geo.enabled());
}

TEST(GeoIp, DisabledLookupReturnsNothing) {
    const GeoIp geo = GeoIp::open("", "");
    EXPECT_FALSE(geo.lookup("8.8.8.8").has_value());
    EXPECT_FALSE(geo.lookup("2001:4860:4860::8888").has_value());
}

TEST(GeoIp, EmptyAddressReturnsNothing) {
    const GeoIp geo = GeoIp::open("", "");
    EXPECT_FALSE(geo.lookup("").has_value());
}

// A corrupt file must be reported and ignored, not crash or be treated as a
// working database.
TEST(GeoIp, CorruptDatabaseIsReportedAndDisabled) {
    const auto path = std::filesystem::temp_directory_path() / "arapuca-not-a-database.mmdb";
    {
        std::ofstream out(path, std::ios::binary);
        out << "this is definitely not a MaxMind database";
    }

    GeoIp geo;
    EXPECT_NO_THROW({ geo = GeoIp::open(path, ""); });
    EXPECT_FALSE(geo.enabled());
    EXPECT_NE(std::string::npos, geo.status().find("could not be opened"));

    std::filesystem::remove(path);
}

TEST(GeoIp, MoveTransfersOwnership) {
    GeoIp first = GeoIp::open("", "");
    GeoIp second = std::move(first);
    EXPECT_FALSE(second.enabled());
    EXPECT_NO_THROW({ (void)second.lookup("1.1.1.1"); });
}

// Garbage in the address field must never reach the resolver as a hostname
// lookup, which would turn an attacker controlled string into a DNS query
// from the honeypot.
TEST(GeoIp, MalformedAddressesAreSafe) {
    const GeoIp geo = GeoIp::open("", "");
    for (const auto* address : {"not-an-ip",
                                "999.999.999.999",
                                "evil.example.com",
                                "127.0.0.1; rm -rf /",
                                "::::::",
                                "0",
                                " "}) {
        EXPECT_NO_THROW({ (void)geo.lookup(address); }) << address;
        EXPECT_FALSE(geo.lookup(address).has_value()) << address;
    }
}

}  // namespace
