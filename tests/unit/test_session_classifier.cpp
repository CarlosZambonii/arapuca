#include <arapuca/enrich/session_classifier.hpp>

#include <gtest/gtest.h>

#include <vector>

namespace {

using arapuca::enrich::classify_session;
using arapuca::enrich::coefficient_of_variation;
using arapuca::enrich::median;
using arapuca::enrich::SessionClass;
using arapuca::enrich::SessionSignals;

TEST(Median, OddAndEvenCounts) {
    EXPECT_DOUBLE_EQ(3.0, median({1, 3, 5}));
    EXPECT_DOUBLE_EQ(4.0, median({1, 3, 5, 7}));
    EXPECT_DOUBLE_EQ(0.0, median({}));
    EXPECT_DOUBLE_EQ(5.0, median({5}));
}

TEST(Median, IgnoresInputOrder) {
    EXPECT_DOUBLE_EQ(3.0, median({5, 1, 3}));
}

TEST(CoefficientOfVariation, ConstantSeriesIsZero) {
    EXPECT_DOUBLE_EQ(0.0, coefficient_of_variation({100, 100, 100, 100}));
}

TEST(CoefficientOfVariation, SpreadSeriesIsLarge) {
    EXPECT_GT(coefficient_of_variation({10, 500, 30, 2000, 80}), 0.6);
}

TEST(CoefficientOfVariation, TooFewValuesIsZero) {
    EXPECT_DOUBLE_EQ(0.0, coefficient_of_variation({42}));
    EXPECT_DOUBLE_EQ(0.0, coefficient_of_variation({}));
}

// A session with almost nothing in it carries no evidence. Saying so is more
// useful than guessing, and most honeypot sessions are exactly this short.
TEST(Classifier, TooFewCommandsIsUnknown) {
    SessionSignals signals;
    signals.command_count = 2;
    signals.inter_command_gaps_ms = {40};

    const auto result = classify_session(signals);
    EXPECT_EQ(SessionClass::Unknown, result.verdict);
    EXPECT_NE(std::string::npos, result.reason.find("too few"));
}

TEST(Classifier, MiraiStyleScriptIsABot) {
    // The classic pattern: a fixed command list pasted at once.
    SessionSignals signals;
    signals.command_count = 8;
    signals.inter_command_gaps_ms = {12, 14, 11, 13, 12, 15, 12};
    signals.duration_ms = 120;

    const auto result = classify_session(signals);
    EXPECT_EQ(SessionClass::Bot, result.verdict);
    EXPECT_LT(result.score, 0.0);
    EXPECT_NE(std::string::npos, result.reason.find("below human typing speed"));
    EXPECT_NE(std::string::npos, result.reason.find("scripted"));
}

TEST(Classifier, PersonExploringIsLikelyHuman) {
    SessionSignals signals;
    signals.command_count = 7;
    signals.inter_command_gaps_ms = {2400, 800, 5200, 1500, 9000, 3100};
    signals.duration_ms = 22000;
    signals.used_line_editing = true;
    signals.unknown_commands = 1;

    const auto result = classify_session(signals);
    EXPECT_EQ(SessionClass::LikelyHuman, result.verdict);
    EXPECT_GT(result.score, 0.0);
}

// Nothing a script does requires asking a remote shell to complete a word.
TEST(Classifier, TabCompletionPushesTowardHuman) {
    SessionSignals signals;
    signals.command_count = 5;
    signals.inter_command_gaps_ms = {700, 900, 650, 800};
    signals.used_tab_completion = true;

    const auto result = classify_session(signals);
    EXPECT_EQ(SessionClass::LikelyHuman, result.verdict);
    EXPECT_NE(std::string::npos, result.reason.find("tab completion"));
}

TEST(Classifier, MetronomeTimingIsABotEvenAtHumanSpeed) {
    // Every gap identical, at a speed a person could physically type. The
    // regularity is what gives it away: this is a script with a sleep in it.
    SessionSignals signals;
    signals.command_count = 10;
    signals.inter_command_gaps_ms = {1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000};

    const auto result = classify_session(signals);
    EXPECT_EQ(SessionClass::Bot, result.verdict) << result.reason;
    EXPECT_LT(result.score, 0.0);
    EXPECT_NE(std::string::npos, result.reason.find("near constant"));
}

// Rhythm is only trusted with enough samples. Four nearly equal gaps are not
// evidence of scripting, and must not cancel a signal as strong as tab
// completion.
TEST(Classifier, ShortRegularSessionDoesNotCountAsScripted) {
    SessionSignals signals;
    signals.command_count = 5;
    signals.inter_command_gaps_ms = {700, 900, 650, 800};

    const auto result = classify_session(signals);
    EXPECT_EQ(std::string::npos, result.reason.find("near constant"));
}

TEST(Classifier, AmbiguousSessionStaysUnknown) {
    SessionSignals signals;
    signals.command_count = 4;
    signals.inter_command_gaps_ms = {800, 400, 900};

    const auto result = classify_session(signals);
    EXPECT_EQ(SessionClass::Unknown, result.verdict);
}

TEST(Classifier, ScoreIsClampedToTheUnitRange) {
    SessionSignals bot;
    bot.command_count = 20;
    bot.inter_command_gaps_ms = std::vector<std::int64_t>(19, 5);
    EXPECT_GE(classify_session(bot).score, -1.0);

    SessionSignals human;
    human.command_count = 20;
    human.inter_command_gaps_ms = {3000, 500, 9000, 1200, 7000, 400, 15000};
    human.used_line_editing = true;
    human.used_tab_completion = true;
    human.unknown_commands = 3;
    EXPECT_LE(classify_session(human).score, 1.0);
}

TEST(Classifier, ReasonIsNeverEmpty) {
    SessionSignals signals;
    signals.command_count = 5;
    signals.inter_command_gaps_ms = {800, 700, 900, 750};
    EXPECT_FALSE(classify_session(signals).reason.empty());
}

TEST(Classifier, VerdictNamesAreStableForTheSchema) {
    EXPECT_EQ("bot", std::string(arapuca::enrich::to_string(SessionClass::Bot)));
    EXPECT_EQ("likely_human", std::string(arapuca::enrich::to_string(SessionClass::LikelyHuman)));
    EXPECT_EQ("unknown", std::string(arapuca::enrich::to_string(SessionClass::Unknown)));
}

TEST(Classifier, MissingGapsDoesNotCrash) {
    SessionSignals signals;
    signals.command_count = 5;
    EXPECT_NO_THROW({ (void)classify_session(signals); });
}

}  // namespace
