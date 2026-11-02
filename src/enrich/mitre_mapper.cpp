#include <arapuca/enrich/mitre_mapper.hpp>

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

namespace arapuca::enrich {
namespace {

std::string lower(std::string_view input) {
    std::string out(input);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::optional<core::EventType> parse_event_type(std::string_view name) {
    using core::EventType;
    static const std::pair<std::string_view, EventType> kNames[] = {
        {"ssh.auth_attempt", EventType::SshAuthAttempt},
        {"ssh.session_start", EventType::SshSessionStart},
        {"ssh.command", EventType::SshCommand},
        {"ssh.channel_denied", EventType::SshChannelDenied},
        {"ssh.session_end", EventType::SshSessionEnd},
        {"http.request", EventType::HttpRequest},
        {"http.login_attempt", EventType::HttpLoginAttempt},
        {"capture.download", EventType::CaptureDownload},
        {"capture.vt_lookup", EventType::CaptureVtLookup},
        {"honeypot.lifecycle", EventType::HoneypotLifecycle},
    };
    for (const auto& [text, type] : kNames) {
        if (text == name) {
            return type;
        }
    }
    return std::nullopt;
}

}  // namespace

std::optional<MatchKind> parse_match_kind(std::string_view name) {
    if (name == "contains") {
        return MatchKind::Contains;
    }
    if (name == "prefix") {
        return MatchKind::Prefix;
    }
    if (name == "equals") {
        return MatchKind::Equals;
    }
    if (name == "regex") {
        return MatchKind::Regex;
    }
    return std::nullopt;
}

bool MitreRule::matches(core::EventType type, std::string_view subject) const {
    if (!event_types.empty() &&
        std::find(event_types.begin(), event_types.end(), type) == event_types.end()) {
        return false;
    }

    if (subject.size() > MitreMapper::kMaxSubject) {
        subject = subject.substr(0, MitreMapper::kMaxSubject);
    }

    const std::string haystack = case_sensitive ? std::string(subject) : lower(subject);
    const std::string needle = case_sensitive ? pattern : lower(pattern);

    switch (kind) {
        case MatchKind::Contains:
            return haystack.find(needle) != std::string::npos;
        case MatchKind::Prefix:
            return haystack.rfind(needle, 0) == 0;
        case MatchKind::Equals:
            return haystack == needle;
        case MatchKind::Regex:
            if (!compiled.has_value()) {
                return false;
            }
            try {
                return std::regex_search(haystack, *compiled);
            } catch (const std::regex_error&) {
                // A regex that blows its complexity budget must not take the
                // session thread with it. No match is the safe answer.
                return false;
            }
    }
    return false;
}

MitreMapper MitreMapper::from_yaml(const std::string& yaml_text) {
    MitreMapper mapper;

    YAML::Node root;
    try {
        root = YAML::Load(yaml_text);
    } catch (const YAML::Exception& error) {
        throw MitreError(std::string("cannot parse MITRE rules: ") + error.what());
    }

    if (!root || root.IsNull()) {
        return mapper;
    }

    const YAML::Node rules = root.IsMap() ? root["rules"] : root;
    if (!rules || !rules.IsSequence()) {
        throw MitreError("MITRE rules must be a sequence under the key 'rules'");
    }

    for (std::size_t index = 0; index < rules.size(); ++index) {
        const YAML::Node node = rules[index];
        const std::string where = "rule " + std::to_string(index);
        if (!node.IsMap()) {
            throw MitreError(where + " must be a mapping");
        }

        MitreRule rule;
        rule.id = node["id"] ? node["id"].as<std::string>() : ("rule-" + std::to_string(index));

        if (!node["technique_id"] || !node["technique"] || !node["pattern"]) {
            throw MitreError(where + " (" + rule.id +
                             ") needs technique_id, technique and pattern");
        }
        rule.technique_id = node["technique_id"].as<std::string>();
        rule.technique = node["technique"].as<std::string>();
        rule.tactic = node["tactic"] ? node["tactic"].as<std::string>() : std::string();
        rule.pattern = node["pattern"].as<std::string>();

        if (node["case_sensitive"]) {
            rule.case_sensitive = node["case_sensitive"].as<bool>();
        }

        if (node["match"]) {
            const auto kind = parse_match_kind(node["match"].as<std::string>());
            if (!kind.has_value()) {
                throw MitreError(where + " (" + rule.id + ") has unknown match kind '" +
                                 node["match"].as<std::string>() +
                                 "', expected contains, prefix, equals or regex");
            }
            rule.kind = *kind;
        }

        if (const YAML::Node types = node["event_types"]) {
            if (!types.IsSequence()) {
                throw MitreError(where + " (" + rule.id + ") event_types must be a sequence");
            }
            for (const auto& entry : types) {
                const std::string name = entry.as<std::string>();
                const auto type = parse_event_type(name);
                if (!type.has_value()) {
                    throw MitreError(where + " (" + rule.id + ") has unknown event type '" + name +
                                     "'");
                }
                rule.event_types.push_back(*type);
            }
        }

        if (rule.kind == MatchKind::Regex) {
            try {
                // Compiled once at load, never per event. A broken expression
                // is a startup failure, which is the right time to find out.
                auto flags = std::regex::ECMAScript | std::regex::optimize;
                if (!rule.case_sensitive) {
                    flags |= std::regex::icase;
                }
                rule.compiled.emplace(rule.pattern, flags);
            } catch (const std::regex_error& error) {
                throw MitreError(where + " (" + rule.id +
                                 ") has an invalid regex: " + error.what());
            }
        }

        mapper.rules_.push_back(std::move(rule));
    }

    return mapper;
}

MitreMapper MitreMapper::from_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw MitreError("cannot open MITRE rules file: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return from_yaml(buffer.str());
}

const MitreRule* MitreMapper::match_rule(core::EventType type, std::string_view subject) const {
    for (const auto& rule : rules_) {
        if (rule.matches(type, subject)) {
            return &rule;
        }
    }
    return nullptr;
}

std::optional<core::Mitre> MitreMapper::match(core::EventType type,
                                              std::string_view subject) const {
    const MitreRule* rule = match_rule(type, subject);
    if (rule == nullptr) {
        return std::nullopt;
    }
    return core::Mitre{rule->technique_id, rule->technique, rule->tactic};
}

}  // namespace arapuca::enrich
