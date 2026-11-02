#include <arapuca/ssh/command_line.hpp>

#include <cstdint>
#include <utility>

namespace arapuca::ssh {
namespace {

/// State of the quoting machine. Single quotes take everything literally,
/// double quotes take everything except a backslash escape, which is close
/// enough to a real shell for the text to be recorded faithfully.
enum class Quote : std::uint8_t { None, Single, Double };

bool is_space(char character) {
    return character == ' ' || character == '\t' || character == '\r';
}

/// Flip the quoting state when `character` is a quote that is active in the
/// current state. Returns true when the byte was a quote and is consumed.
bool toggle_quote(Quote& quote, char character) {
    if (character == '\'' && quote != Quote::Double) {
        quote = quote == Quote::Single ? Quote::None : Quote::Single;
        return true;
    }
    if (character == '"' && quote != Quote::Single) {
        quote = quote == Quote::Double ? Quote::None : Quote::Double;
        return true;
    }
    return false;
}

/// Handle a backslash. Returns the number of input bytes consumed, which is
/// zero when the byte was not an escape in this state.
std::size_t apply_escape(Quote quote, std::string_view input, std::size_t index, std::string& out) {
    if (input[index] != '\\' || index + 1 >= input.size() || quote == Quote::Single) {
        return 0;
    }

    const char next = input[index + 1];
    if (quote == Quote::None) {
        out.push_back(next);
        return 2;
    }

    // Inside double quotes a backslash only escapes a few characters.
    // Anywhere else it stays a literal backslash, which is what a transcript
    // should show.
    if (next == '"' || next == '\\' || next == '$' || next == '`') {
        out.push_back(next);
        return 2;
    }
    out.push_back('\\');
    return 1;
}

struct SeparatorMatch {
    Separator separator = Separator::None;
    std::size_t width = 0;
};

/// Recognise a separator at `index`, outside quotes.
SeparatorMatch match_separator(std::string_view line, std::size_t index) {
    const char character = line[index];
    const auto doubled = [&](char expected) {
        return index + 1 < line.size() && line[index + 1] == expected;
    };

    if (character == ';') {
        return {Separator::Semicolon, 1};
    }
    if (character == '|') {
        return doubled('|') ? SeparatorMatch{Separator::Or, 2} : SeparatorMatch{Separator::Pipe, 1};
    }
    if (character == '&') {
        return doubled('&') ? SeparatorMatch{Separator::And, 2}
                            : SeparatorMatch{Separator::Background, 1};
    }
    return {};
}

}  // namespace

std::string_view to_string(Separator separator) {
    // clang-format off
    switch (separator) {
        case Separator::None:       return "none";
        case Separator::Semicolon:  return ";";
        case Separator::And:        return "&&";
        case Separator::Or:         return "||";
        case Separator::Pipe:       return "|";
        case Separator::Background: return "&";
    }
    // clang-format on
    return "none";
}

std::vector<std::string> tokenize(std::string_view input) {
    std::vector<std::string> tokens;
    std::string current;
    bool have_token = false;
    Quote quote = Quote::None;

    for (std::size_t index = 0; index < input.size(); ++index) {
        if (const std::size_t consumed = apply_escape(quote, input, index, current); consumed > 0) {
            index += consumed - 1;
            have_token = true;
            continue;
        }

        const char character = input[index];
        if (toggle_quote(quote, character)) {
            have_token = true;
            continue;
        }

        if (quote == Quote::None && is_space(character)) {
            if (!have_token) {
                continue;
            }
            if (tokens.size() >= kMaxTokensPerSegment) {
                return tokens;
            }
            tokens.push_back(std::move(current));
            current.clear();
            have_token = false;
            continue;
        }

        if (current.size() < kMaxTokenLength) {
            current.push_back(character);
        }
        have_token = true;
    }

    if (have_token && tokens.size() < kMaxTokensPerSegment) {
        tokens.push_back(std::move(current));
    }
    return tokens;
}

ParsedCommandLine parse_command_line(std::string_view line) {
    ParsedCommandLine parsed;

    std::size_t start = 0;
    Separator pending = Separator::None;
    Quote quote = Quote::None;

    const auto flush = [&](std::size_t end, Separator next_separator, std::size_t skip) {
        const std::string_view raw = line.substr(start, end - start);
        auto argv = tokenize(raw);
        if (!argv.empty()) {
            if (parsed.segments.size() >= kMaxSegments) {
                parsed.truncated = true;
                return false;
            }
            Segment segment;
            segment.argv = std::move(argv);
            segment.separator = pending;
            segment.raw = std::string(raw);
            parsed.segments.push_back(std::move(segment));
        }
        pending = next_separator;
        start = end + skip;
        return true;
    };

    for (std::size_t index = 0; index < line.size(); ++index) {
        const char character = line[index];

        if (quote == Quote::None && character == '\\' && index + 1 < line.size()) {
            ++index;  // an escaped separator is not a separator
            continue;
        }
        if (toggle_quote(quote, character)) {
            continue;
        }
        if (quote != Quote::None) {
            continue;
        }

        const SeparatorMatch match = match_separator(line, index);
        if (match.width == 0) {
            continue;
        }
        if (!flush(index, match.separator, match.width)) {
            return parsed;
        }
        index += match.width - 1;
    }

    parsed.unterminated_quote = quote != Quote::None;
    (void)flush(line.size(), Separator::None, 0);
    return parsed;
}

}  // namespace arapuca::ssh
