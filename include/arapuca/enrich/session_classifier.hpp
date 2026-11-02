// Bot or likely human, decided from how a session was typed rather than from
// what was typed.
//
// The useful signal in a honeypot is rhythm. A script pastes a fixed command
// list at machine speed with almost no variation between commands, while a
// person pauses to read output, makes typing mistakes, and uses the line
// editor. None of that requires understanding the commands themselves, which
// is why this is a few arithmetic checks and not a model.
//
// The output is deliberately three valued. A two command session carries no
// evidence either way, and reporting Unknown is more honest, and more useful
// on a dashboard, than guessing.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::enrich {

enum class SessionClass : std::uint8_t { Unknown, Bot, LikelyHuman };

[[nodiscard]] std::string_view to_string(SessionClass verdict);

/// What the SSH session recorded while it was alive.
struct SessionSignals {
    /// Milliseconds between consecutive commands. One entry per command after
    /// the first, so a session of N commands has N-1 gaps.
    std::vector<std::int64_t> inter_command_gaps_ms;
    std::size_t command_count = 0;
    std::int64_t duration_ms = 0;
    /// Commands the fake shell did not recognize. A person mistypes, a script
    /// usually does not.
    std::size_t unknown_commands = 0;
    /// Backspace or arrow keys seen in the raw input stream.
    bool used_line_editing = false;
    /// Tab pressed. Almost conclusive on its own: a script has no reason to
    /// ask a remote shell to complete a word for it.
    bool used_tab_completion = false;
};

struct Classification {
    SessionClass verdict = SessionClass::Unknown;
    /// Negative leans bot, positive leans human, zero is no evidence. Kept in
    /// the event so a dashboard can show how confident the call was.
    double score = 0.0;
    /// Human readable explanation of which signals fired.
    std::string reason;
};

/// Minimum commands before a verdict other than Unknown is produced.
inline constexpr std::size_t kMinimumCommandsForVerdict = 3;

/// Score at or beyond which the verdict is decided.
inline constexpr double kVerdictThreshold = 0.25;

/// Gaps needed before the rhythm signals (regularity and irregularity) are
/// trusted at all. The coefficient of variation over three or four samples is
/// noise, and treating it as evidence let a near constant four command session
/// outvote a tab completion, which is close to conclusive on its own.
inline constexpr std::size_t kMinimumGapsForRhythm = 5;

[[nodiscard]] Classification classify_session(const SessionSignals& signals);

/// Helpers exposed for the tests, and because a dashboard query sometimes
/// wants the same numbers.
[[nodiscard]] double median(std::vector<std::int64_t> values);
[[nodiscard]] double coefficient_of_variation(const std::vector<std::int64_t>& values);

}  // namespace arapuca::enrich
