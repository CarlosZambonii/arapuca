#include <arapuca/core/clock.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <regex>
#include <string>

namespace {

using arapuca::core::Clock;
using arapuca::core::to_rfc3339_millis;
using arapuca::core::to_unix_millis;

TEST(ClockFormat, MatchesRfc3339WithMillis) {
    const std::regex pattern(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$)");
    EXPECT_TRUE(std::regex_match(to_rfc3339_millis(Clock::now()), pattern));
}

TEST(ClockFormat, EpochIsRenderedExactly) {
    EXPECT_EQ("1970-01-01T00:00:00.000Z", to_rfc3339_millis(Clock::time_point{}));
}

TEST(ClockFormat, MillisecondsAreZeroPadded) {
    const auto when = Clock::time_point{} + std::chrono::milliseconds{7};
    EXPECT_EQ("1970-01-01T00:00:00.007Z", to_rfc3339_millis(when));
}

TEST(ClockFormat, IsUtcNotLocalTime) {
    // A fixed instant, so this fails if the formatter ever picks up TZ.
    const auto when = Clock::time_point{} + std::chrono::hours{24};
    EXPECT_EQ("1970-01-02T00:00:00.000Z", to_rfc3339_millis(when));
}

TEST(ClockMillis, RoundTrips) {
    const auto when = Clock::time_point{} + std::chrono::milliseconds{1762091467482};
    EXPECT_EQ(1762091467482, to_unix_millis(when));
}

}  // namespace
