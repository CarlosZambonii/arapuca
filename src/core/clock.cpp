#include <arapuca/core/clock.hpp>

#include <array>
#include <cstdio>
#include <ctime>

namespace arapuca::core {

std::string to_rfc3339_millis(TimePoint tp) {
    const auto since_epoch = tp.time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch - seconds);

    const std::time_t time = seconds.count();
    std::tm utc{};
    // gmtime_r rather than gmtime: the writer thread is not the only caller,
    // and gmtime returns a shared static buffer.
    gmtime_r(&time, &utc);

    std::array<char, 32> buffer{};
    const std::size_t date_len =
        std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%S", &utc);
    if (date_len == 0) {
        return "1970-01-01T00:00:00.000Z";
    }

    std::array<char, 8> fraction{};
    std::snprintf(fraction.data(), fraction.size(), ".%03dZ",
                  static_cast<int>(millis.count()));

    std::string out(buffer.data(), date_len);
    out.append(fraction.data());
    return out;
}

std::int64_t to_unix_millis(TimePoint tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch())
        .count();
}

}  // namespace arapuca::core
