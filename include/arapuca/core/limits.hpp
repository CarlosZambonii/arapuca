// Central bounds for every piece of attacker controlled input.
//
// Safety invariant S2: no attacker controlled buffer grows without a limit.
// Every limit lives here, and nowhere else, so the whole attack surface of the
// process can be reviewed by reading one file.
#pragma once

#include <cstddef>

namespace arapuca::limits {

// --- SSH -------------------------------------------------------------------

/// Longest username accepted in an authentication attempt. OpenSSH itself
/// caps this well below 256, so anything longer is an overflow probe and is
/// recorded truncated rather than rejected silently.
inline constexpr std::size_t kMaxUsername = 256;

/// Longest password recorded. Passwords are stored in full on purpose: they
/// are the product of the honeypot.
inline constexpr std::size_t kMaxPassword = 512;

/// Longest single command line accepted from the fake shell.
inline constexpr std::size_t kMaxCommandLine = 8192;

/// Longest SSH client version string recorded.
inline constexpr std::size_t kMaxClientVersion = 256;

/// Commands recorded per session. Past this the session keeps answering but
/// stops growing the transcript, so a bot in a loop cannot exhaust memory.
inline constexpr std::size_t kMaxCommandsPerSession = 2000;

/// Concurrent SSH sessions, process wide and per source address.
inline constexpr std::size_t kMaxSshSessions = 256;
inline constexpr std::size_t kMaxSshSessionsPerIp = 8;

// --- HTTP ------------------------------------------------------------------

inline constexpr std::size_t kMaxHttpUrl = 4096;
inline constexpr std::size_t kMaxHttpHeaderName = 256;
inline constexpr std::size_t kMaxHttpHeaderValue = 4096;
inline constexpr std::size_t kMaxHttpHeaders = 64;

/// Request body bytes kept in the event. Larger bodies are read and discarded,
/// and the event carries body_truncated true.
inline constexpr std::size_t kMaxHttpBodyRecorded = 8192;

/// Request body bytes read off the wire at all.
inline constexpr std::size_t kMaxHttpBodyRead = std::size_t{1024} * 1024;

// --- Capture ---------------------------------------------------------------

/// Largest sample downloaded. The transfer is aborted the moment this is
/// exceeded, it is not read and then discarded.
inline constexpr std::size_t kMaxSampleBytes = std::size_t{32} * 1024 * 1024;

/// Longest URL followed by the capture engine.
inline constexpr std::size_t kMaxCaptureUrl = 2048;

/// Redirects followed before giving up. Every hop is address checked again.
inline constexpr long kMaxRedirects = 3;

/// Wall clock budget for one download, in seconds.
inline constexpr long kDownloadTimeoutSeconds = 30;
inline constexpr long kConnectTimeoutSeconds = 10;

// --- Events ----------------------------------------------------------------

/// Longest value kept for any single free form string field in an event.
inline constexpr std::size_t kMaxEventStringField = 8192;

/// Events buffered between the producers and the writer thread. Past this,
/// events are dropped and counted, which degrades telemetry under a flood but
/// never memory.
inline constexpr std::size_t kEventBusCapacity = 8192;

}  // namespace arapuca::limits
