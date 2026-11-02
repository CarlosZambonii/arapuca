#include <arapuca/core/logging.hpp>

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace arapuca::core {
namespace {

std::shared_ptr<spdlog::logger>& logger_slot() {
    static std::shared_ptr<spdlog::logger> instance;
    return instance;
}

std::mutex& logger_mutex() {
    static std::mutex mutex;
    return mutex;
}

spdlog::level::level_enum to_spdlog(LogLevel level) {
    // clang-format off
    switch (level) {
        case LogLevel::Trace: return spdlog::level::trace;
        case LogLevel::Debug: return spdlog::level::debug;
        case LogLevel::Info:  return spdlog::level::info;
        case LogLevel::Warn:  return spdlog::level::warn;
        case LogLevel::Error: return spdlog::level::err;
        case LogLevel::Off:   return spdlog::level::off;
    }
    // clang-format on
    return spdlog::level::info;
}

}  // namespace

LogLevel parse_log_level(std::string_view name) {
    std::string lowered(name);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (lowered == "trace") {
        return LogLevel::Trace;
    }
    if (lowered == "debug") {
        return LogLevel::Debug;
    }
    if (lowered == "warn" || lowered == "warning") {
        return LogLevel::Warn;
    }
    if (lowered == "error" || lowered == "err") {
        return LogLevel::Error;
    }
    if (lowered == "off" || lowered == "none") {
        return LogLevel::Off;
    }
    // Anything unrecognized, including an empty string, falls back to Info
    // rather than to silence. A configuration typo must not turn off the
    // operator's only view of the process.
    return LogLevel::Info;
}

std::string_view to_string(LogLevel level) {
    // clang-format off
    switch (level) {
        case LogLevel::Trace: return "trace";
        case LogLevel::Debug: return "debug";
        case LogLevel::Info:  return "info";
        case LogLevel::Warn:  return "warn";
        case LogLevel::Error: return "error";
        case LogLevel::Off:   return "off";
    }
    // clang-format on
    return "info";
}

void init_logging(LogLevel level, const std::filesystem::path& file) {
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    if (!file.empty()) {
        sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(file.string(), false));
    }

    auto logger = std::make_shared<spdlog::logger>("arapuca", sinks.begin(), sinks.end());
    logger->set_level(to_spdlog(level));
    logger->set_pattern("%Y-%m-%dT%H:%M:%S.%e%z [%^%l%$] %v");
    // Diagnostics are worth little if the last ones before a crash are lost in
    // a buffer, and the operator log is low volume by design.
    logger->flush_on(spdlog::level::warn);

    const std::lock_guard<std::mutex> lock(logger_mutex());
    logger_slot() = std::move(logger);
}

spdlog::logger& log() {
    const std::lock_guard<std::mutex> lock(logger_mutex());
    if (!logger_slot()) {
        auto fallback = spdlog::stderr_color_mt("arapuca-default");
        fallback->set_level(spdlog::level::info);
        logger_slot() = std::move(fallback);
    }
    return *logger_slot();
}

}  // namespace arapuca::core
