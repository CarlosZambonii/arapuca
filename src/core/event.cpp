#include <arapuca/core/event.hpp>

#include <arapuca/core/ids.hpp>
#include <arapuca/version.hpp>

#include <utility>

namespace arapuca::core {

std::string_view to_string(EventType type) {
    switch (type) {
        case EventType::SshAuthAttempt:    return "ssh.auth_attempt";
        case EventType::SshSessionStart:   return "ssh.session_start";
        case EventType::SshCommand:        return "ssh.command";
        case EventType::SshChannelDenied:  return "ssh.channel_denied";
        case EventType::SshSessionEnd:     return "ssh.session_end";
        case EventType::HttpRequest:       return "http.request";
        case EventType::HttpLoginAttempt:  return "http.login_attempt";
        case EventType::CaptureDownload:   return "capture.download";
        case EventType::CaptureVtLookup:   return "capture.vt_lookup";
        case EventType::HoneypotLifecycle: return "honeypot.lifecycle";
    }
    return "unknown";
}

std::string_view service_of(EventType type) {
    switch (type) {
        case EventType::SshAuthAttempt:
        case EventType::SshSessionStart:
        case EventType::SshCommand:
        case EventType::SshChannelDenied:
        case EventType::SshSessionEnd:
            return "ssh";
        case EventType::HttpRequest:
        case EventType::HttpLoginAttempt:
            return "http";
        case EventType::CaptureDownload:
        case EventType::CaptureVtLookup:
            return "capture";
        case EventType::HoneypotLifecycle:
            return "honeypot";
    }
    return "unknown";
}

Event Event::make(EventType type, std::string sensor) {
    Event event;
    event.type = type;
    event.timestamp = Clock::now();
    event.event_id = new_id();
    event.sensor = std::move(sensor);
    return event;
}

nlohmann::json Event::to_json() const {
    // The detail object goes in first and the envelope is written over it, so
    // a producer cannot accidentally shadow a schema field such as src_ip.
    nlohmann::json out = detail.is_object() ? detail : nlohmann::json::object();

    out["schema_version"] = kEventSchemaVersion;
    out["event_id"] = event_id;
    out["event_type"] = to_string(type);
    out["timestamp"] = to_rfc3339_millis(timestamp);
    out["service"] = service_of(type);
    out["sensor"] = sensor;
    out["src_ip"] = src_ip;
    out["src_port"] = src_port;
    out["dst_port"] = dst_port;

    if (!session_id.empty()) {
        out["session_id"] = session_id;
    }

    if (geo.has_value()) {
        nlohmann::json geo_json = nlohmann::json::object();
        geo_json["country_iso"] = geo->country_iso;
        geo_json["country"] = geo->country;
        geo_json["city"] = geo->city;
        if (geo->latitude.has_value()) {
            geo_json["latitude"] = *geo->latitude;
        }
        if (geo->longitude.has_value()) {
            geo_json["longitude"] = *geo->longitude;
        }
        if (geo->asn.has_value()) {
            geo_json["asn"] = *geo->asn;
        }
        if (!geo->as_org.empty()) {
            geo_json["as_org"] = geo->as_org;
        }
        out["geo"] = std::move(geo_json);
    }

    if (mitre.has_value()) {
        out["mitre"] = nlohmann::json{{"technique_id", mitre->technique_id},
                                      {"technique", mitre->technique},
                                      {"tactic", mitre->tactic}};
    }

    return out;
}

std::string Event::to_jsonl() const {
    // error_handler_t::replace rather than the default throwing handler. Every
    // attacker string is sanitized before it gets here, so this should never
    // fire, but a throw on the writer thread would take the honeypot down and
    // a replaced byte would not. Defence in depth for safety invariant S2.
    std::string line = to_json().dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    line.push_back('\n');
    return line;
}

}  // namespace arapuca::core
