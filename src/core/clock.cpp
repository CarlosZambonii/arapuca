#include <arapuca/core/clock.hpp>

#include <array>
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

    // The fractional part is written by hand rather than with snprintf. This
    // runs for every event, and avoiding a variadic call removes both the cost
    // and the question of whether anyone checked its return value.
    const auto fraction = static_cast<unsigned>(millis.count());
    std::string out(buffer.data(), date_len);
    out.push_back('.');
    out.push_back(static_cast<char>('0' + ((fraction / 100) % 10)));
    out.push_back(static_cast<char>('0' + ((fraction / 10) % 10)));
    out.push_back(static_cast<char>('0' + (fraction % 10)));
    out.push_back('Z');
    return out;
}

std::int64_t to_unix_millis(TimePoint tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

}  // namespace arapuca::core
