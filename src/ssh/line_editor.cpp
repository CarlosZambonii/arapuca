#include <arapuca/ssh/line_editor.hpp>

namespace arapuca::ssh {
namespace {

constexpr char kCtrlC = '\x03';
constexpr char kCtrlD = '\x04';
constexpr char kBackspace = '\x08';
constexpr char kDelete = '\x7f';
constexpr char kEscape = '\x1b';
constexpr char kTab = '\t';

}  // namespace

void LineEditor::reset() {
    buffer_.clear();
    escape_ = 0;
}

EditorStep LineEditor::feed(char byte) {
    EditorStep step;

    // An arrow key arrives as ESC [ A. Tracking the three bytes keeps them out
    // of the buffer and out of the echo, and tells us a person is editing.
    if (escape_ == 1) {
        escape_ = byte == '[' || byte == 'O' ? 2 : 0;
        return step;
    }
    if (escape_ == 2) {
        escape_ = 0;
        used_line_editing_ = true;
        return step;
    }

    switch (byte) {
        case kEscape:
            escape_ = 1;
            return step;

        case '\r':
        case '\n':
            step.event = LineEvent::Line;
            step.line = buffer_;
            step.echo = "\r\n";
            buffer_.clear();
            return step;

        case kCtrlC:
            step.event = LineEvent::Interrupt;
            step.echo = "^C\r\n";
            buffer_.clear();
            return step;

        case kCtrlD:
            if (buffer_.empty()) {
                step.event = LineEvent::EndOfFile;
                return step;
            }
            return step;

        case kBackspace:
        case kDelete:
            used_line_editing_ = true;
            if (!buffer_.empty()) {
                buffer_.pop_back();
                // Move left, overwrite with a space, move left again. This is
                // what a real terminal does and what makes the editing look
                // right on the attacker's screen.
                step.echo = "\b \b";
            }
            return step;

        case kTab:
            used_tab_ = true;
            // Noticed, not acted on. Completing would mean exposing the fake
            // filesystem's shape through timing and output in a way that is
            // easy to get subtly wrong.
            return step;

        default:
            break;
    }

    // Other control characters are swallowed: echoing them would let an
    // attacker write escape sequences into the operator's terminal through
    // the transcript.
    if (static_cast<unsigned char>(byte) < 0x20) {
        return step;
    }

    if (buffer_.size() < kMaxLineLength) {
        buffer_.push_back(byte);
        step.echo.push_back(byte);
    }
    return step;
}

std::vector<EditorStep> LineEditor::feed(std::string_view bytes) {
    std::vector<EditorStep> steps;
    std::string pending_echo;

    for (const char byte : bytes) {
        EditorStep step = feed(byte);
        pending_echo += step.echo;

        if (step.event != LineEvent::None) {
            step.echo = std::move(pending_echo);
            pending_echo.clear();
            steps.push_back(std::move(step));
        }
    }

    if (!pending_echo.empty()) {
        EditorStep tail;
        tail.echo = std::move(pending_echo);
        steps.push_back(std::move(tail));
    }
    return steps;
}

}  // namespace arapuca::ssh
