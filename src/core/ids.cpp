#include <arapuca/core/ids.hpp>

#include <array>
#include <cstdint>
#include <random>

namespace arapuca::core {
namespace {

// Crockford base32: no I, L, O or U, so an identifier read off a dashboard
// cannot be mistyped into a different valid one.
constexpr std::array<char, 32> kAlphabet = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                                            'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N',
                                            'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z'};

constexpr std::size_t kTimeChars = 10;    // 48 bit millisecond timestamp
constexpr std::size_t kRandomChars = 16;  // 80 bits of randomness

std::mt19937_64& rng() {
    // One generator per thread: sessions run on their own threads and a shared
    // generator would need a lock on a path taken for every single event.
    thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

}  // namespace

std::string new_id_at(TimePoint tp) {
    std::string out(kIdLength, '0');

    auto millis = static_cast<std::uint64_t>(to_unix_millis(tp));
    for (std::size_t i = kTimeChars; i > 0; --i) {
        out[i - 1] = kAlphabet[millis & 0x1FU];
        millis >>= 5U;
    }

    std::uint64_t bits = rng()();
    std::size_t available = 64;
    for (std::size_t i = 0; i < kRandomChars; ++i) {
        if (available < 5) {
            bits = rng()();
            available = 64;
        }
        out[kTimeChars + i] = kAlphabet[bits & 0x1FU];
        bits >>= 5U;
        available -= 5;
    }

    return out;
}

std::string new_id() {
    return new_id_at(Clock::now());
}

}  // namespace arapuca::core
