// Time handling. Every timestamp in an event is UTC with millisecond
// precision, in RFC 3339 form, because that is what New Relic parses without
// a custom rule.
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace arapuca::core {

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

/// Format a time point as "2026-11-02T14:31:07.482Z".
[[nodiscard]] std::string to_rfc3339_millis(TimePoint tp);

/// Milliseconds since the Unix epoch, used by the identifier generator and by
/// the session pacing classifier.
[[nodiscard]] std::int64_t to_unix_millis(TimePoint tp);

}  // namespace arapuca::core
