// Hashing for captured samples.
//
// SHA256 is the identity of a sample everywhere in this project: the
// quarantine file name, the VirusTotal lookup key, the deduplication key and
// the IoC feed entry. MD5 is computed alongside it only because a lot of
// threat intelligence is still keyed on it.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace arapuca::capture {

struct Digests {
    std::string sha256;
    std::string md5;
    std::size_t bytes = 0;
};

/// Lower case hexadecimal, which is what every tool and API expects.
[[nodiscard]] std::string sha256_hex(std::string_view data);
[[nodiscard]] std::string md5_hex(std::string_view data);
[[nodiscard]] Digests digests_of(std::string_view data);

}  // namespace arapuca::capture
