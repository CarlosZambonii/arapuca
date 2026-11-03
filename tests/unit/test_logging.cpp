#include <arapuca/core/logging.hpp>

#include "../support/read_file.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

using arapuca::core::init_logging;
using arapuca::core::log;
using arapuca::core::LogLevel;
using arapuca::core::parse_log_level;

TEST(LogLevelParsing, KnownNames) {
    EXPECT_EQ(LogLevel::Trace, parse_log_level("trace"));
    EXPECT_EQ(LogLevel::Debug, parse_log_level("debug"));
    EXPECT_EQ(LogLevel::Info, parse_log_level("info"));
    EXPECT_EQ(LogLevel::Warn, parse_log_level("warn"));
    EXPECT_EQ(LogLevel::Warn, parse_log_level("warning"));
    EXPECT_EQ(LogLevel::Error, parse_log_level("error"));
    EXPECT_EQ(LogLevel::Off, parse_log_level("off"));
}

TEST(LogLevelParsing, IsCaseInsensitive) {
    EXPECT_EQ(LogLevel::Debug, parse_log_level("DEBUG"));
    EXPECT_EQ(LogLevel::Error, parse_log_level("Error"));
}

// A typo in the config must not silence the operator log, which would leave
// the honeypot running blind.
TEST(LogLevelParsing, UnknownFallsBackToInfoNotOff) {
    EXPECT_EQ(LogLevel::Info, parse_log_level("verbose"));
    EXPECT_EQ(LogLevel::Info, parse_log_level(""));
    EXPECT_EQ(LogLevel::Info, parse_log_level("inf0"));
}

TEST(LogLevelParsing, RoundTripsThroughToString) {
    for (const auto level : {LogLevel::Trace,
                             LogLevel::Debug,
                             LogLevel::Info,
                             LogLevel::Warn,
                             LogLevel::Error,
                             LogLevel::Off}) {
        EXPECT_EQ(level, parse_log_level(arapuca::core::to_string(level)));
    }
}

TEST(Logging, WorksBeforeInitialization) {
    EXPECT_NO_THROW({ log().info("operator log before init"); });
}

TEST(Logging, WritesToTheConfiguredFile) {
    const auto path = std::filesystem::temp_directory_path() / "arapuca-operator-test.log";
    std::filesystem::remove(path);

    init_logging(LogLevel::Debug, path);
    log().warn("honeypot started with a test marker {}", 42);
    log().flush();

    const std::string content = arapuca::testing::read_whole_file(path);
    EXPECT_NE(std::string::npos, content.find("test marker 42"));

    init_logging(LogLevel::Info);
    std::filesystem::remove(path);
}

TEST(Logging, RespectsTheConfiguredLevel) {
    const auto path = std::filesystem::temp_directory_path() / "arapuca-level-test.log";
    std::filesystem::remove(path);

    init_logging(LogLevel::Error, path);
    log().info("this must not appear");
    log().error("this must appear");
    log().flush();

    const std::string content = arapuca::testing::read_whole_file(path);
    EXPECT_EQ(std::string::npos, content.find("must not appear"));
    EXPECT_NE(std::string::npos, content.find("this must appear"));

    init_logging(LogLevel::Info);
    std::filesystem::remove(path);
}

}  // namespace
