#include <arapuca/core/limits.hpp>
#include <arapuca/util/redaction.hpp>

#include <array>
#include <cstdint>

namespace arapuca::util {
namespace {

constexpr std::array<char, 16> kHex = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/// Length of the UTF-8 sequence a lead byte announces, or 0 if it is not a
/// valid lead byte.
std::size_t sequence_length(unsigned char lead) {
    if (lead < 0x80U) {
        return 1;
    }
    if ((lead & 0xE0U) == 0xC0U) {
        return 2;
    }
    if ((lead & 0xF0U) == 0xE0U) {
        return 3;
    }
    if ((lead & 0xF8U) == 0xF0U) {
        return 4;
    }
    return 0;  // continuation byte or an invalid 5 or 6 byte lead
}

/// Validate a full sequence, rejecting overlong encodings, surrogates and
/// anything above U+10FFFF. Those are exactly the inputs that make a naive
/// decoder disagree with the JSON serializer.
bool is_valid_sequence(std::string_view input, std::size_t pos, std::size_t len) {
    if (pos + len > input.size()) {
        return false;
    }
    const auto byte_at = [&](std::size_t i) { return static_cast<unsigned char>(input[pos + i]); };

    for (std::size_t i = 1; i < len; ++i) {
        if ((byte_at(i) & 0xC0U) != 0x80U) {
            return false;
        }
    }

    const unsigned char lead = byte_at(0);
    std::uint32_t code_point = 0;
    switch (len) {
        case 1:
            return true;
        case 2:
            code_point = ((lead & 0x1FU) << 6) | (byte_at(1) & 0x3FU);
            return code_point >= 0x80U;
        case 3:
            code_point =
                ((lead & 0x0FU) << 12) | ((byte_at(1) & 0x3FU) << 6) | (byte_at(2) & 0x3FU);
            return code_point >= 0x800U && (code_point < 0xD800U || code_point > 0xDFFFU);
        case 4:
            code_point = ((lead & 0x07U) << 18) | ((byte_at(1) & 0x3FU) << 12) |
                         ((byte_at(2) & 0x3FU) << 6) | (byte_at(3) & 0x3FU);
            return code_point >= 0x10000U && code_point <= 0x10FFFFU;
        default:
            return false;
    }
}

void append_escape(std::string& out, unsigned char byte) {
    out.push_back('\\');
    out.push_back('x');
    // Both indices are masked to four bits and kHex holds exactly sixteen
    // entries, so the bound is a property of the expression. This runs once
    // per escaped byte of attacker input, which is the hot path under a flood.
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    out.push_back(kHex[(byte >> 4U) & 0x0FU]);
    out.push_back(kHex[byte & 0x0FU]);
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
}

bool is_control(unsigned char byte) {
    return byte < 0x20U || byte == 0x7FU;
}

}  // namespace

Sanitized sanitize(std::string_view input, std::size_t max_bytes) {
    Sanitized result;
    result.text.reserve(input.size() < max_bytes ? input.size() : max_bytes);

    std::size_t pos = 0;
    while (pos < input.size()) {
        const auto byte = static_cast<unsigned char>(input[pos]);

        // Control characters and invalid bytes both become a visible escape,
        // which costs four output bytes. Checking the budget before appending
        // is what keeps the result from ever ending in a half written escape.
        if (is_control(byte)) {
            if (result.text.size() + 4 > max_bytes) {
                result.truncated = true;
                break;
            }
            append_escape(result.text, byte);
            ++pos;
            continue;
        }

        const std::size_t len = sequence_length(byte);
        if (len == 0 || !is_valid_sequence(input, pos, len)) {
            if (result.text.size() + 4 > max_bytes) {
                result.truncated = true;
                break;
            }
            append_escape(result.text, byte);
            ++pos;
            continue;
        }

        if (result.text.size() + len > max_bytes) {
            result.truncated = true;
            break;
        }
        result.text.append(input.substr(pos, len));
        pos += len;
    }

    return result;
}

std::string sanitize_text(std::string_view input) {
    return sanitize(input, limits::kMaxEventStringField).text;
}

}  // namespace arapuca::util
