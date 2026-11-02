// Normalization of attacker controlled text before it enters an event.
//
// Two problems are solved here, and both are security problems rather than
// cosmetic ones:
//
//   1. Invalid UTF-8. nlohmann::json throws when asked to serialize a string
//      that is not valid UTF-8, and attacker input is arbitrary bytes. An
//      unhandled throw on the session thread would be a remote denial of
//      service, so every attacker string is made valid before it is stored.
//
//   2. Control characters. Terminal escape sequences in a log file can forge
//      output in the operator's terminal when the file is read with cat, and
//      raw newlines would break the one event per line format.
//
// Bytes that cannot be kept are rendered as a readable \xNN escape rather than
// dropped, because the exact bytes an attacker sent are evidence.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace arapuca::util {

struct Sanitized {
    std::string text;
    bool truncated = false;

    friend bool operator==(const Sanitized&, const Sanitized&) = default;
};

/// Make `input` safe to serialize and safe to print, capped at `max_bytes`.
///
/// Valid UTF-8 sequences are preserved as they are. C0 and C7 control
/// characters, and any byte that is not part of a valid UTF-8 sequence, are
/// replaced by a literal \xNN escape. Truncation happens on the input, never
/// in the middle of a produced escape, and never splits a UTF-8 sequence.
[[nodiscard]] Sanitized sanitize(std::string_view input, std::size_t max_bytes);

/// Convenience overload for fields with no specific limit.
[[nodiscard]] std::string sanitize_text(std::string_view input);

}  // namespace arapuca::util
