#include <arapuca/core/event.hpp>
#include <arapuca/version.hpp>

#include <nlohmann/json.hpp>

#include <gtest/gtest.h>

#include <array>
#include <string>

namespace {

using arapuca::core::Event;
using arapuca::core::EventType;
using arapuca::core::Geo;
using arapuca::core::Mitre;

Event sample() {
    Event event = Event::make(EventType::SshCommand, "arapuca-test");
    event.session_id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
    event.src_ip = "203.0.113.45";
    event.src_port = 54122;
    event.dst_port = 22;
    event.detail = {{"command", "uname -a"}, {"seq", 3}};
    return event;
}

// The field names below are the contract with the New Relic dashboards and the
// IoC export. A rename is a breaking change, so this test exists to make that
// break loud rather than silent.
TEST(EventSchema, EnvelopeFieldsArePresent) {
    const auto json = sample().to_json();

    EXPECT_EQ(arapuca::kEventSchemaVersion, json.at("schema_version").get<int>());
    EXPECT_EQ("ssh.command", json.at("event_type").get<std::string>());
    EXPECT_EQ("ssh", json.at("service").get<std::string>());
    EXPECT_EQ("arapuca-test", json.at("sensor").get<std::string>());
    EXPECT_EQ("203.0.113.45", json.at("src_ip").get<std::string>());
    EXPECT_EQ(54122, json.at("src_port").get<int>());
    EXPECT_EQ(22, json.at("dst_port").get<int>());
    EXPECT_TRUE(json.contains("event_id"));
    EXPECT_TRUE(json.contains("timestamp"));
    EXPECT_TRUE(json.contains("session_id"));
}

TEST(EventSchema, DetailFieldsAreMergedAtTopLevel) {
    const auto json = sample().to_json();
    EXPECT_EQ("uname -a", json.at("command").get<std::string>());
    EXPECT_EQ(3, json.at("seq").get<int>());
}

// A producer that puts "src_ip" in its detail object must not be able to
// overwrite the real source address, which would poison the IoC feed.
TEST(EventSchema, DetailCannotShadowEnvelopeFields) {
    Event event = sample();
    event.detail["src_ip"] = "127.0.0.1";
    event.detail["event_type"] = "something.else";

    const auto json = event.to_json();
    EXPECT_EQ("203.0.113.45", json.at("src_ip").get<std::string>());
    EXPECT_EQ("ssh.command", json.at("event_type").get<std::string>());
}

TEST(EventSchema, SessionIdIsOmittedWhenEmpty) {
    const Event event = Event::make(EventType::HoneypotLifecycle, "arapuca-test");
    EXPECT_FALSE(event.to_json().contains("session_id"));
}

TEST(EventSchema, GeoIsNestedAndOptional) {
    Event event = sample();
    EXPECT_FALSE(event.to_json().contains("geo"));

    Geo geo;
    geo.country_iso = "CN";
    geo.country = "China";
    geo.city = "Hangzhou";
    geo.asn = 37963U;
    geo.as_org = "Alibaba";
    event.geo = geo;

    const auto json = event.to_json();
    EXPECT_EQ("CN", json.at("geo").at("country_iso").get<std::string>());
    EXPECT_EQ(37963U, json.at("geo").at("asn").get<unsigned>());
    EXPECT_FALSE(json.at("geo").contains("latitude"));
}

TEST(EventSchema, MitreIsNestedAndOptional) {
    Event event = sample();
    EXPECT_FALSE(event.to_json().contains("mitre"));

    event.mitre = Mitre{"T1082", "System Information Discovery", "Discovery"};
    const auto json = event.to_json();
    EXPECT_EQ("T1082", json.at("mitre").at("technique_id").get<std::string>());
    EXPECT_EQ("Discovery", json.at("mitre").at("tactic").get<std::string>());
}

TEST(EventTypes, WireNamesAreStable) {
    const std::array<std::pair<EventType, std::string>, 10> expected = {{
        {EventType::SshAuthAttempt, "ssh.auth_attempt"},
        {EventType::SshSessionStart, "ssh.session_start"},
        {EventType::SshCommand, "ssh.command"},
        {EventType::SshChannelDenied, "ssh.channel_denied"},
        {EventType::SshSessionEnd, "ssh.session_end"},
        {EventType::HttpRequest, "http.request"},
        {EventType::HttpLoginAttempt, "http.login_attempt"},
        {EventType::CaptureDownload, "capture.download"},
        {EventType::CaptureVtLookup, "capture.vt_lookup"},
        {EventType::HoneypotLifecycle, "honeypot.lifecycle"},
    }};
    for (const auto& [type, name] : expected) {
        EXPECT_EQ(name, std::string(arapuca::core::to_string(type)));
    }
}

TEST(EventTypes, ServiceBucketsAreCorrect) {
    EXPECT_EQ("ssh", std::string(arapuca::core::service_of(EventType::SshCommand)));
    EXPECT_EQ("http", std::string(arapuca::core::service_of(EventType::HttpRequest)));
    EXPECT_EQ("capture", std::string(arapuca::core::service_of(EventType::CaptureDownload)));
    EXPECT_EQ("honeypot", std::string(arapuca::core::service_of(EventType::HoneypotLifecycle)));
}

// One event is one line, with no exceptions, or the log stops being readable
// by a line oriented log shipper.
TEST(EventSerialization, IsExactlyOneLine) {
    Event event = sample();
    event.detail["command"] = "echo 'line one\nline two'";

    const std::string line = event.to_jsonl();
    EXPECT_EQ('\n', line.back());
    EXPECT_EQ(line.size() - 1, line.find_last_of('\n'));
}

TEST(EventSerialization, SurvivesInvalidUtf8WithoutThrowing) {
    Event event = sample();
    event.detail["command"] = std::string("\xFF\xFE bad bytes", 12);
    EXPECT_NO_THROW({ (void)event.to_jsonl(); });
}

TEST(EventSerialization, LineParsesBackToTheSameFields) {
    const Event event = sample();
    const auto parsed = nlohmann::json::parse(event.to_jsonl());
    EXPECT_EQ(event.src_ip, parsed.at("src_ip").get<std::string>());
    EXPECT_EQ("uname -a", parsed.at("command").get<std::string>());
}

}  // namespace
