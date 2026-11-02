// Mapping of observed behavior to MITRE ATT&CK techniques.
//
// The rules live in YAML, not in C++, because the interesting part of a
// honeypot is how fast you can describe a newly seen behavior. Adding a
// technique is editing a file and restarting, not a rebuild.
//
// Matching is deliberately boring. Four match kinds are offered and three of
// them are plain string operations, because attacker input is matched against
// these rules on the session thread, and a backtracking regular expression
// over hostile input is a denial of service waiting to happen. Regex is
// available where it genuinely helps, and the subject is length capped before
// it is ever handed to the engine.
#pragma once

#include <arapuca/core/event.hpp>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::enrich {

enum class MatchKind : std::uint8_t { Contains, Prefix, Equals, Regex };

[[nodiscard]] std::optional<MatchKind> parse_match_kind(std::string_view name);

struct MitreRule {
    std::string id;
    std::string technique_id;
    std::string technique;
    std::string tactic;
    /// Empty means the rule applies to every event type.
    std::vector<core::EventType> event_types;
    MatchKind kind = MatchKind::Contains;
    std::string pattern;
    bool case_sensitive = false;
    std::optional<std::regex> compiled;

    [[nodiscard]] bool matches(core::EventType type, std::string_view subject) const;
};

class MitreError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class MitreMapper {
public:
    MitreMapper() = default;

    [[nodiscard]] static MitreMapper from_file(const std::filesystem::path& path);
    [[nodiscard]] static MitreMapper from_yaml(const std::string& yaml_text);

    /// First matching rule wins, so order in the file is priority. Returns
    /// nothing when no rule applies, which is normal and not an error.
    [[nodiscard]] std::optional<core::Mitre> match(core::EventType type,
                                                   std::string_view subject) const;

    /// The rule that matched, for tests and for explaining a classification.
    [[nodiscard]] const MitreRule* match_rule(core::EventType type, std::string_view subject) const;

    [[nodiscard]] std::size_t size() const {
        return rules_.size();
    }

    [[nodiscard]] const std::vector<MitreRule>& rules() const {
        return rules_;
    }

    /// Longest subject handed to a matcher. Anything beyond is ignored: a
    /// technique is never identified by the tail of an eight kilobyte line,
    /// and the cap keeps worst case matching cost bounded.
    static constexpr std::size_t kMaxSubject = 1024;

private:
    std::vector<MitreRule> rules_;
};

}  // namespace arapuca::enrich
