// The terminal line editor of the fake shell.
//
// Separated from the SSH plumbing because it is pure: bytes in, an echo and
// possibly a completed line out. That makes it testable without a socket and
// fuzzable on its own, which matters because this is the first thing attacker
// bytes touch after decryption.
//
// It is deliberately a small subset of a real line editor. Enough to feel
// real (echo, backspace, Ctrl+C, Ctrl+D, and tab noticed but not acted on),
// and no more, because every additional behaviour is more attacker reachable
// state.
//
// Tab and line editing use are recorded rather than implemented, because they
// are among the strongest signals that a human rather than a script is typing.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::ssh {

enum class LineEvent : std::uint8_t {
    None,       ///< byte consumed, nothing to report
    Line,       ///< a complete line is ready
    Interrupt,  ///< Ctrl+C
    EndOfFile,  ///< Ctrl+D on an empty line
};

struct EditorStep {
    LineEvent event = LineEvent::None;
    /// Bytes to echo back to the attacker's terminal.
    std::string echo;
    /// The finished line, when event is Line.
    std::string line;
};

class LineEditor {
public:
    /// Feed one byte. Returns what to echo and whether a line finished.
    EditorStep feed(char byte);

    /// Feed a block, returning one step per completed line or signal. Echo is
    /// accumulated into each step in order.
    std::vector<EditorStep> feed(std::string_view bytes);

    [[nodiscard]] const std::string& buffer() const {
        return buffer_;
    }

    void reset();

    /// True once a backspace or an arrow key has been seen. A script almost
    /// never sends these, a person does constantly.
    [[nodiscard]] bool used_line_editing() const {
        return used_line_editing_;
    }

    /// True once a tab has been seen. Close to conclusive on its own: nothing
    /// a script does requires asking a remote shell to complete a word.
    [[nodiscard]] bool used_tab() const {
        return used_tab_;
    }

    /// Longest line accepted. Past this, bytes are dropped rather than
    /// buffered, so a paste of ten megabytes costs nothing.
    static constexpr std::size_t kMaxLineLength = 8192;

private:
    std::string buffer_;
    bool used_line_editing_ = false;
    bool used_tab_ = false;
    /// Escape sequence state, so an arrow key is recognised rather than echoed
    /// as three stray characters.
    std::uint8_t escape_ = 0;
};

}  // namespace arapuca::ssh
