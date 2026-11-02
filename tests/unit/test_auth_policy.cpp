#include <arapuca/ssh/auth_policy.hpp>

#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

namespace {

using arapuca::ssh::AttemptTracker;
using arapuca::ssh::AuthError;
using arapuca::ssh::AuthPolicy;

AuthPolicy small() {
    return AuthPolicy::from_yaml(R"(
credentials:
  - { username: "root", password: "123456" }
  - { username: "admin", password: "admin" }
  - { username: "guest", password: "*" }
  - { username: "*", password: "letmein" }
)");
}

TEST(AuthPolicy, EmptyDocumentAcceptsNothing) {
    const auto policy = AuthPolicy::from_yaml("");
    EXPECT_EQ(0U, policy.size());
    EXPECT_FALSE(policy.evaluate("root", "123456").accepted);
}

TEST(AuthPolicy, AcceptsAListedPair) {
    const auto decision = small().evaluate("root", "123456");
    EXPECT_TRUE(decision.accepted);
    EXPECT_EQ("exact", decision.rule);
}

TEST(AuthPolicy, RefusesAnUnlistedPair) {
    const auto decision = small().evaluate("root", "hunter2");
    EXPECT_FALSE(decision.accepted);
    EXPECT_EQ("no_match", decision.rule);
}

TEST(AuthPolicy, UsernameMustMatchToo) {
    // The right password under the wrong account is still a refusal.
    EXPECT_FALSE(small().evaluate("admin", "123456").accepted);
}

TEST(AuthPolicy, WildcardPasswordAcceptsAnything) {
    const auto decision = small().evaluate("guest", "anything at all");
    EXPECT_TRUE(decision.accepted);
    EXPECT_EQ("any_password", decision.rule);
}

TEST(AuthPolicy, WildcardUsernameAcceptsAnyAccount) {
    const auto decision = small().evaluate("somebody-new", "letmein");
    EXPECT_TRUE(decision.accepted);
    EXPECT_EQ("any_username", decision.rule);
}

TEST(AuthPolicy, EmptyPasswordIsARealCredential) {
    const auto policy =
        AuthPolicy::from_yaml("credentials:\n  - { username: \"root\", password: \"\" }\n");
    EXPECT_TRUE(policy.evaluate("root", "").accepted);
    EXPECT_FALSE(policy.evaluate("root", "x").accepted);
}

TEST(AuthPolicy, ComparisonIsCaseSensitive) {
    EXPECT_FALSE(small().evaluate("ROOT", "123456").accepted);
    EXPECT_FALSE(small().evaluate("root", "123456 ").accepted);
}

TEST(AuthPolicy, LongInputIsRefusedNotCrashed) {
    const auto policy = small();
    const std::string huge(100000, 'a');
    EXPECT_NO_THROW({ (void)policy.evaluate(huge, huge); });
    EXPECT_FALSE(policy.evaluate(huge, huge).accepted);
}

TEST(AuthPolicy, BinaryInputIsSafe) {
    const auto policy = small();
    const std::string binary("\xFF\xFE\x00\x01 bad", 8);
    EXPECT_NO_THROW({ (void)policy.evaluate(binary, binary); });
}

TEST(AuthPolicy, MalformedYamlIsRejected) {
    EXPECT_THROW({ (void)AuthPolicy::from_yaml("credentials: [unclosed\n"); }, AuthError);
}

TEST(AuthPolicy, IncompleteCredentialIsRejectedWithItsIndex) {
    try {
        (void)AuthPolicy::from_yaml("credentials:\n  - { username: \"root\" }\n");
        FAIL() << "expected AuthError";
    } catch (const AuthError& error) {
        EXPECT_NE(std::string::npos, std::string(error.what()).find("credential 0"));
    }
}

TEST(AuthPolicy, NegativeAcceptAfterFailuresIsRejected) {
    EXPECT_THROW({ (void)AuthPolicy::from_yaml("accept_after_failures: -1\n"); }, AuthError);
}

TEST(AuthPolicy, ShippedListLoadsAndCoversTheUsualGuesses) {
    const auto policy =
        AuthPolicy::from_file(std::string(ARAPUCA_CONFIG_DIR) + "/credentials.yaml");
    EXPECT_GT(policy.size(), 25U);

    EXPECT_TRUE(policy.evaluate("root", "123456").accepted);
    EXPECT_TRUE(policy.evaluate("admin", "admin").accepted);
    EXPECT_TRUE(policy.evaluate("pi", "raspberry").accepted);
    EXPECT_TRUE(policy.evaluate("ubnt", "ubnt").accepted);

    // A password that is not on the list stays refused, which is most of the
    // traffic and most of the recorded value.
    EXPECT_FALSE(policy.evaluate("root", "Tr0ub4dor&3").accepted);
}

// The password 123456 is unquoted in half the lists on the internet. If it
// ever gets read as a number, every event in the dashboard changes shape.
TEST(AuthPolicy, NumericLookingPasswordsStayStrings) {
    const auto policy =
        AuthPolicy::from_file(std::string(ARAPUCA_CONFIG_DIR) + "/credentials.yaml");
    for (const auto& credential : policy.credentials()) {
        if (credential.username == "root" && credential.password == "123456") {
            SUCCEED();
            return;
        }
    }
    FAIL() << "the numeric password did not survive as a string";
}

// --- AttemptTracker -------------------------------------------------------

TEST(AttemptTracker, DisabledByDefault) {
    AttemptTracker tracker(0, 100);
    for (int i = 0; i < 100; ++i) {
        EXPECT_FALSE(tracker.record_failure_and_check("203.0.113.1"));
    }
}

TEST(AttemptTracker, AcceptsAfterTheConfiguredFailures) {
    AttemptTracker tracker(3, 100);
    EXPECT_FALSE(tracker.record_failure_and_check("203.0.113.1"));
    EXPECT_FALSE(tracker.record_failure_and_check("203.0.113.1"));
    EXPECT_TRUE(tracker.record_failure_and_check("203.0.113.1"));
}

TEST(AttemptTracker, CountsPerAddress) {
    AttemptTracker tracker(3, 100);
    tracker.record_failure_and_check("203.0.113.1");
    tracker.record_failure_and_check("203.0.113.1");
    EXPECT_FALSE(tracker.record_failure_and_check("203.0.113.2"));
    EXPECT_EQ(2U, tracker.failures_for("203.0.113.1"));
    EXPECT_EQ(1U, tracker.failures_for("203.0.113.2"));
}

TEST(AttemptTracker, ForgetResetsAnAddress) {
    AttemptTracker tracker(3, 100);
    tracker.record_failure_and_check("203.0.113.1");
    tracker.record_failure_and_check("203.0.113.1");
    tracker.forget("203.0.113.1");
    EXPECT_EQ(0U, tracker.failures_for("203.0.113.1"));
    EXPECT_EQ(0U, tracker.tracked());
}

// A brute forcer with a large address pool must not be able to grow this
// table without limit. It is a memory bound, not a tuning knob.
TEST(AttemptTracker, TableIsBoundedAndEvictsOldest) {
    AttemptTracker tracker(10, 8);
    for (int i = 0; i < 100; ++i) {
        tracker.record_failure_and_check("203.0.113." + std::to_string(i));
    }
    EXPECT_EQ(8U, tracker.tracked());
    EXPECT_GT(tracker.evicted(), 90U);
    // The oldest entries are the ones that went.
    EXPECT_EQ(0U, tracker.failures_for("203.0.113.0"));
    EXPECT_EQ(1U, tracker.failures_for("203.0.113.99"));
}

TEST(AttemptTracker, ZeroCapacityIsClampedNotFatal) {
    AttemptTracker tracker(2, 0);
    EXPECT_NO_THROW({ (void)tracker.record_failure_and_check("203.0.113.1"); });
    EXPECT_LE(tracker.tracked(), 1U);
}

TEST(AttemptTracker, ConcurrentFailuresAreCountedExactly) {
    AttemptTracker tracker(1000000, 4096);
    constexpr std::size_t kThreads = 8;
    constexpr std::size_t kPerThread = 500;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (std::size_t t = 0; t < kThreads; ++t) {
        threads.emplace_back([&tracker] {
            for (std::size_t i = 0; i < kPerThread; ++i) {
                (void)tracker.record_failure_and_check("198.51.100.7");
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    EXPECT_EQ(kThreads * kPerThread, tracker.failures_for("198.51.100.7"));
}

}  // namespace
