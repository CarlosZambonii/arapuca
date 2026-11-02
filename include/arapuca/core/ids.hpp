// Identifier generation for events and sessions.
//
// The format is a ULID: a 48 bit millisecond timestamp followed by 80 bits of
// randomness, rendered in Crockford base32 as 26 characters. It is preferred
// over a UUIDv4 here because it sorts lexicographically by creation time,
// which makes a raw `sort` over the JSONL log produce chronological order even
// when the writer interleaved events from several threads.
#pragma once

#include <arapuca/core/clock.hpp>

#include <string>

namespace arapuca::core {

/// Generate a new identifier from the current time.
[[nodiscard]] std::string new_id();

/// Generate an identifier for a specific time point. Exposed for tests.
[[nodiscard]] std::string new_id_at(TimePoint tp);

/// Number of characters in a generated identifier.
inline constexpr std::size_t kIdLength = 26;

}  // namespace arapuca::core
