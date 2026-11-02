// The event model. One Event becomes exactly one line of JSON in the event
// log, and the field names here are the contract with the New Relic dashboards
// and with the IoC export, so changing one is a breaking change that bumps
// kEventSchemaVersion.
#pragma once

#include <arapuca/core/clock.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace arapuca::core {

enum class EventType : std::uint8_t {
    SshAuthAttempt,
    SshSessionStart,
    SshCommand,
    SshChannelDenied,
    SshSessionEnd,
    HttpRequest,
    HttpLoginAttempt,
    CaptureDownload,
    CaptureVtLookup,
    HoneypotLifecycle,
};

/// Wire name, for example "ssh.auth_attempt". Stable, part of the schema.
[[nodiscard]] std::string_view to_string(EventType type);

/// Service bucket derived from the event type: "ssh", "http", "capture" or
/// "honeypot". Derived rather than stored so the two can never disagree.
[[nodiscard]] std::string_view service_of(EventType type);

struct Geo {
    std::string country_iso;
    std::string country;
    std::string city;
    std::optional<double> latitude;
    std::optional<double> longitude;
    std::optional<std::uint32_t> asn;
    std::string as_org;
};

struct Mitre {
    std::string technique_id;  ///< for example "T1110"
    std::string technique;     ///< for example "Brute Force"
    std::string tactic;        ///< for example "Credential Access"
};

/// One recorded interaction.
///
/// The envelope is typed. Everything specific to a single event type lives in
/// `detail`, a JSON object that is merged into the top level on serialization.
/// That keeps the common fields impossible to misspell while letting each
/// producer carry its own payload without a class per event type.
struct Event {
    EventType type = EventType::HoneypotLifecycle;
    TimePoint timestamp{};
    std::string event_id;
    std::string session_id;
    std::string sensor;
    std::string src_ip;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::optional<Geo> geo;
    std::optional<Mitre> mitre;
    nlohmann::json detail = nlohmann::json::object();

    /// Build an event with the identifier and timestamp already filled in.
    [[nodiscard]] static Event make(EventType type, std::string sensor);

    /// Serialize to the documented schema.
    [[nodiscard]] nlohmann::json to_json() const;

    /// Serialize to exactly one line, newline included. This is what the sink
    /// writes and what the New Relic agent reads.
    [[nodiscard]] std::string to_jsonl() const;
};

}  // namespace arapuca::core
