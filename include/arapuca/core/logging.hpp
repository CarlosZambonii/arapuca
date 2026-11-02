// The operator log, which is a different thing from the event log.
//
// Two streams, on purpose:
//
//   * The event log (JSONL, written by EventSink) is the product. It is what
//     New Relic ingests and what the IoC export reads, and every line in it is
//     a recorded attacker interaction.
//
//   * The operator log (this file) is diagnostics about the honeypot itself:
//     startup, configuration, dropped events, a failed GeoIP lookup. It is
//     human readable and nothing automated depends on its format.
//
// Mixing the two would mean either parsing noise in the dashboards or losing
// diagnostics in the ingest pipeline.
#pragma once

#include <spdlog/spdlog.h>

#include <filesystem>
#include <string_view>

namespace arapuca::core {

enum class LogLevel : std::uint8_t { Trace, Debug, Info, Warn, Error, Off };

/// Parse a level name, case insensitive. Returns Info for anything unknown,
/// because a typo in the configuration must not silence the operator log.
[[nodiscard]] LogLevel parse_log_level(std::string_view name);

[[nodiscard]] std::string_view to_string(LogLevel level);

/// Set up the operator log. Writes to stderr, and additionally to `file` when
/// one is given. Calling it again reconfigures, which is what a configuration
/// reload needs.
void init_logging(LogLevel level, const std::filesystem::path& file = {});

/// The operator logger. Safe to call before init_logging, in which case it is
/// the default stderr logger at Info.
[[nodiscard]] spdlog::logger& log();

}  // namespace arapuca::core
