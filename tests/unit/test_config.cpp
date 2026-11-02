#include <arapuca/core/config.hpp>
#include <arapuca/core/limits.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

using arapuca::core::Config;
using arapuca::core::ConfigError;
using arapuca::core::LogLevel;

TEST(ConfigParse, EmptyDocumentYieldsDefaults) {
    const Config config = Config::parse("");
    EXPECT_EQ("arapuca", config.sensor_name);
    EXPECT_TRUE(config.ssh.enabled);
    EXPECT_EQ(2222, config.ssh.port);
    EXPECT_EQ(8080, config.http.port);
}

TEST(ConfigParse, PartialFileKeepsDefaultsForAbsentKeys) {
    const Config config = Config::parse("sensor_name: arapuca-sa\nssh:\n  port: 2022\n");
    EXPECT_EQ("arapuca-sa", config.sensor_name);
    EXPECT_EQ(2022, config.ssh.port);
    // Untouched keys keep their defaults rather than being zeroed.
    EXPECT_EQ(8080, config.http.port);
    EXPECT_FALSE(config.ssh.banner.empty());
}

TEST(ConfigParse, ReadsEverySection) {
    const std::string yaml = R"(
sensor_name: arapuca-test
events:
  path: /tmp/arapuca/events.jsonl
  flush_every: 4
  flush_interval_ms: 250
  bus_capacity: 1024
ssh:
  enabled: true
  port: 2222
  banner: "SSH-2.0-OpenSSH_9.6p1"
  max_sessions: 64
  max_sessions_per_ip: 4
http:
  port: 8080
  server_header: "nginx/1.24.0"
  max_body_recorded: 4096
capture:
  quarantine_dir: /tmp/arapuca/quarantine
  max_sample_bytes: 1048576
  quarantine_max_total_bytes: 536870912
  virustotal:
    enabled: true
    requests_per_minute: 4
geo:
  city_db: /tmp/GeoLite2-City.mmdb
mitre:
  rules_file: /tmp/mitre.yaml
logging:
  level: debug
)";
    const Config config = Config::parse(yaml);
    EXPECT_EQ("arapuca-test", config.sensor_name);
    EXPECT_EQ("/tmp/arapuca/events.jsonl", config.events.path);
    EXPECT_EQ(4U, config.events.flush_every);
    EXPECT_EQ(250, config.events.flush_interval.count());
    EXPECT_EQ("SSH-2.0-OpenSSH_9.6p1", config.ssh.banner);
    EXPECT_EQ(64U, config.ssh.max_sessions);
    EXPECT_EQ("nginx/1.24.0", config.http.server_header);
    EXPECT_EQ(1048576U, config.capture.max_sample_bytes);
    EXPECT_EQ("/tmp/GeoLite2-City.mmdb", config.geo.city_db);
    EXPECT_EQ(LogLevel::Debug, config.logging.level);
}

TEST(ConfigParse, MalformedYamlIsRejected) {
    EXPECT_THROW({ (void)Config::parse("ssh:\n  port: [unclosed\n"); }, ConfigError);
}

TEST(ConfigParse, NonMappingRootIsRejected) {
    EXPECT_THROW({ (void)Config::parse("- a\n- b\n"); }, ConfigError);
}

TEST(ConfigParse, WrongTypeIsRejectedWithTheKeyName) {
    try {
        (void)Config::parse("ssh:\n  max_sessions: not-a-number\n");
        FAIL() << "expected ConfigError";
    } catch (const ConfigError& error) {
        EXPECT_NE(std::string::npos, std::string(error.what()).find("max_sessions"));
    }
}

TEST(ConfigParse, PortOutOfRangeIsRejected) {
    EXPECT_THROW({ (void)Config::parse("ssh:\n  port: 70000\n"); }, ConfigError);
    EXPECT_THROW({ (void)Config::parse("ssh:\n  port: 0\n"); }, ConfigError);
    EXPECT_THROW({ (void)Config::parse("http:\n  port: -1\n"); }, ConfigError);
}

// A secret in a committed configuration file is the mistake this check exists
// to prevent, and ignoring the key would be worse than refusing it: the
// operator would believe the key was in use.
TEST(ConfigParse, ApiKeyInTheFileIsRefusedNotIgnored) {
    try {
        (void)Config::parse("capture:\n  virustotal:\n    api_key: abc123\n");
        FAIL() << "expected ConfigError";
    } catch (const ConfigError& error) {
        const std::string message = error.what();
        EXPECT_NE(std::string::npos, message.find("VT_API_KEY"));
    }
}

TEST(ConfigEnvironment, VirusTotalKeyComesFromTheEnvironment) {
    ::setenv("VT_API_KEY", "deadbeef", 1);
    Config config = Config::parse("");
    config.apply_environment();
    EXPECT_EQ("deadbeef", config.virustotal_api_key);
    EXPECT_TRUE(config.capture.virustotal_enabled);
    ::unsetenv("VT_API_KEY");
}

TEST(ConfigEnvironment, MissingKeyDisablesVirusTotalInsteadOfFailing) {
    ::unsetenv("VT_API_KEY");
    Config config = Config::parse("capture:\n  virustotal:\n    enabled: true\n");
    config.apply_environment();
    EXPECT_TRUE(config.virustotal_api_key.empty());
    EXPECT_FALSE(config.capture.virustotal_enabled);
}

TEST(ConfigEnvironment, SensorNameCanBeOverridden) {
    ::setenv("ARAPUCA_SENSOR_NAME", "arapuca-from-env", 1);
    Config config = Config::parse("sensor_name: from-file\n");
    config.apply_environment();
    EXPECT_EQ("arapuca-from-env", config.sensor_name);
    ::unsetenv("ARAPUCA_SENSOR_NAME");
}

// A configuration file may ask for stricter limits and gets them. It may not
// ask for looser ones than the audited compile time bound.
TEST(ConfigClamp, CeilingIsEnforcedAndReported) {
    Config config = Config::parse("ssh:\n  max_sessions: 999999\n");
    const auto clamped = config.validate_and_clamp();
    EXPECT_EQ(arapuca::limits::kMaxSshSessions, config.ssh.max_sessions);
    ASSERT_FALSE(clamped.empty());
    EXPECT_NE(std::string::npos, clamped.front().find("ssh.max_sessions"));
}

TEST(ConfigClamp, StricterThanTheCeilingIsLeftAlone) {
    Config config = Config::parse("ssh:\n  max_sessions: 10\n");
    const auto clamped = config.validate_and_clamp();
    EXPECT_EQ(10U, config.ssh.max_sessions);
    EXPECT_TRUE(clamped.empty());
}

TEST(ConfigClamp, BodyAndSampleCeilingsAreEnforced) {
    Config config = Config::parse(
        "http:\n  max_body_recorded: 99999999\ncapture:\n"
        "  max_sample_bytes: 999999999999\n");
    (void)config.validate_and_clamp();
    EXPECT_EQ(arapuca::limits::kMaxHttpBodyRecorded, config.http.max_body_recorded);
    EXPECT_EQ(arapuca::limits::kMaxSampleBytes, config.capture.max_sample_bytes);
}

TEST(ConfigClamp, PerIpLimitCannotExceedTheGlobalLimit) {
    Config config = Config::parse("ssh:\n  max_sessions: 4\n  max_sessions_per_ip: 8\n");
    (void)config.validate_and_clamp();
    EXPECT_EQ(4U, config.ssh.max_sessions_per_ip);
}

TEST(ConfigValidate, EmptySensorNameIsRejected) {
    Config config = Config::parse("sensor_name: \"\"\n");
    EXPECT_THROW({ (void)config.validate_and_clamp(); }, ConfigError);
}

TEST(ConfigValidate, CollidingPortsAreRejected) {
    Config config = Config::parse("ssh:\n  port: 8080\nhttp:\n  port: 8080\n");
    EXPECT_THROW({ (void)config.validate_and_clamp(); }, ConfigError);
}

TEST(ConfigValidate, ZeroesAreClampedUpToOne) {
    Config config = Config::parse("events:\n  flush_every: 0\n  bus_capacity: 0\n");
    (void)config.validate_and_clamp();
    EXPECT_EQ(1U, config.events.flush_every);
    EXPECT_EQ(1U, config.events.bus_capacity);
}

TEST(ConfigLoad, MissingFileIsReported) {
    EXPECT_THROW({ (void)Config::load("/nonexistent/arapuca.yaml"); }, ConfigError);
}

TEST(ConfigLoad, ReadsFromDisk) {
    const auto path = std::filesystem::temp_directory_path() / "arapuca-config-test.yaml";
    {
        std::ofstream out(path);
        out << "sensor_name: disk-test\nssh:\n  port: 2200\n";
    }
    const Config config = Config::load(path);
    EXPECT_EQ("disk-test", config.sensor_name);
    EXPECT_EQ(2200, config.ssh.port);
    std::filesystem::remove(path);
}

}  // namespace
