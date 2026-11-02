#include <arapuca/util/redaction.hpp>

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>

#include <string>

namespace {

using arapuca::util::sanitize;

TEST(Redaction, PlainAsciiPassesThrough) {
    const auto result = sanitize("cat /etc/passwd", 100);
    EXPECT_EQ("cat /etc/passwd", result.text);
    EXPECT_FALSE(result.truncated);
}

TEST(Redaction, ValidUtf8IsPreserved) {
    // "ação" in UTF-8, the kind of thing a real user types and a mangled
    // encoding would destroy.
    const std::string input = "a\xC3\xA7\xC3\xA3o";
    const auto result = sanitize(input, 100);
    EXPECT_EQ(input, result.text);
}

TEST(Redaction, ControlCharactersBecomeVisibleEscapes) {
    const auto result = sanitize(std::string("a\nb\tc\x1b[2J", 9), 100);
    EXPECT_EQ("a\\x0ab\\x09c\\x1b[2J", result.text);
    EXPECT_EQ(std::string::npos, result.text.find('\n'));
}

// A terminal escape in a log file can forge output in the operator's terminal
// when the file is read with cat. Neutralizing it is the whole point.
TEST(Redaction, NoRawEscapeSurvives) {
    const auto result = sanitize(std::string("\x1b]0;pwned\x07", 10), 100);
    EXPECT_EQ(std::string::npos, result.text.find('\x1b'));
    EXPECT_EQ(std::string::npos, result.text.find('\x07'));
}

TEST(Redaction, InvalidUtf8BecomesEscapes) {
    const auto result = sanitize(std::string("\xFF\xFE", 2), 100);
    EXPECT_EQ("\\xff\\xfe", result.text);
}

TEST(Redaction, TruncatedUtf8SequenceIsEscaped) {
    // A lead byte announcing three bytes but only two present.
    const auto result = sanitize(std::string("\xE2\x82", 2), 100);
    EXPECT_EQ("\\xe2\\x82", result.text);
}

TEST(Redaction, OverlongEncodingIsRejected) {
    // 0xC0 0xAF is an overlong encoding of '/', the classic path traversal
    // smuggling trick. It must not decode to a slash.
    const auto result = sanitize(std::string("\xC0\xAF", 2), 100);
    EXPECT_EQ("\\xc0\\xaf", result.text);
    EXPECT_EQ(std::string::npos, result.text.find('/'));
}

TEST(Redaction, SurrogateHalfIsRejected) {
    const auto result = sanitize(std::string("\xED\xA0\x80", 3), 100);
    EXPECT_EQ("\\xed\\xa0\\x80", result.text);
}

TEST(Redaction, TruncationIsFlaggedAndNeverSplitsASequence) {
    const std::string input = "aaa\xC3\xA7";  // three ASCII then a two byte sequence
    const auto result = sanitize(input, 4);
    EXPECT_EQ("aaa", result.text);
    EXPECT_TRUE(result.truncated);
}

TEST(Redaction, TruncationNeverSplitsAnEscape) {
    const auto result = sanitize(std::string("ab\x01", 3), 5);
    // Two ASCII bytes leave three of the budget, and an escape needs four.
    EXPECT_EQ("ab", result.text);
    EXPECT_TRUE(result.truncated);
}

TEST(Redaction, EmptyInput) {
    const auto result = sanitize("", 100);
    EXPECT_TRUE(result.text.empty());
    EXPECT_FALSE(result.truncated);
}

TEST(Redaction, ZeroBudget) {
    const auto result = sanitize("abc", 0);
    EXPECT_TRUE(result.text.empty());
    EXPECT_TRUE(result.truncated);
}

// The reason this module exists: nlohmann::json throws on invalid UTF-8, and
// a throw on a session thread would be a remote denial of service.
TEST(Redaction, OutputIsAlwaysJsonSerializable) {
    for (int byte = 0; byte < 256; ++byte) {
        const std::string input(3, static_cast<char>(byte));
        const auto result = sanitize(input, 64);
        const nlohmann::json value = result.text;
        EXPECT_NO_THROW({ (void)value.dump(); }) << "byte " << byte;
    }
}

TEST(Redaction, EveryTwoByteCombinationIsSerializable) {
    for (int first = 0xC0; first < 0x100; ++first) {
        for (int second = 0; second < 256; ++second) {
            std::string input;
            input.push_back(static_cast<char>(first));
            input.push_back(static_cast<char>(second));
            const auto result = sanitize(input, 64);
            const nlohmann::json value = result.text;
            EXPECT_NO_THROW({ (void)value.dump(); }) << first << " " << second;
        }
    }
}

}  // namespace
