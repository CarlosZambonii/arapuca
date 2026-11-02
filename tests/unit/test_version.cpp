#include <arapuca/version.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

TEST(Version, BannerCarriesNameAndVersion) {
    const std::string banner = arapuca::build_banner();
    EXPECT_NE(banner.find(arapuca::kProjectName), std::string::npos);
    EXPECT_NE(banner.find(arapuca::kVersion), std::string::npos);
}

TEST(Version, ComponentsMatchTheVersionString) {
    const std::string expected = std::to_string(arapuca::kVersionMajor) + "." +
                                 std::to_string(arapuca::kVersionMinor) + "." +
                                 std::to_string(arapuca::kVersionPatch);
    EXPECT_EQ(expected, std::string(arapuca::kVersion));
}

// The event schema version is part of the contract with the New Relic
// dashboards and with the IoC export. Bumping it is a deliberate, breaking
// change, so it is pinned here and this test has to be updated on purpose.
TEST(Version, EventSchemaVersionIsPinned) {
    EXPECT_EQ(1, arapuca::kEventSchemaVersion);
}

}  // namespace
