#include <arapuca/capture/downloader.hpp>
#include <arapuca/capture/hashing.hpp>
#include <arapuca/capture/quarantine.hpp>
#include <arapuca/capture/virustotal.hpp>

#include "../support/read_file.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

using arapuca::capture::digests_of;
using arapuca::capture::Downloader;
using arapuca::capture::DownloadOutcome;
using arapuca::capture::md5_hex;
using arapuca::capture::parse_file_report;
using arapuca::capture::Quarantine;
using arapuca::capture::QuarantineConfig;
using arapuca::capture::RateLimiter;
using arapuca::capture::sha256_hex;
using arapuca::capture::VtStatus;

// --- hashing --------------------------------------------------------------

TEST(Hashing, KnownVectors) {
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256_hex(""));
    EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              sha256_hex("abc"));
    EXPECT_EQ("d41d8cd98f00b204e9800998ecf8427e", md5_hex(""));
    EXPECT_EQ("900150983cd24fb0d6963f7d28e17f72", md5_hex("abc"));
}

TEST(Hashing, DigestsCarryTheSize) {
    const auto digests = digests_of("hello");
    EXPECT_EQ(5U, digests.bytes);
    EXPECT_EQ(64U, digests.sha256.size());
    EXPECT_EQ(32U, digests.md5.size());
}

TEST(Hashing, HandlesBinaryAndLargeInput) {
    const std::string binary("\x00\xFF\xFE\x01", 4);
    EXPECT_EQ(64U, sha256_hex(binary).size());
    EXPECT_EQ(64U, sha256_hex(std::string(5UL * 1024 * 1024, 'A')).size());
}

// --- downloader -----------------------------------------------------------

TEST(Downloader, OnlyHttpAndHttpsAreAccepted) {
    EXPECT_TRUE(Downloader::scheme_allowed("http://example.invalid/x"));
    EXPECT_TRUE(Downloader::scheme_allowed("HTTPS://example.invalid/x"));

    for (const auto* url : {"file:///etc/passwd",
                            "ftp://host/x",
                            "gopher://host/",
                            "dict://host:11211/",
                            "ldap://host/",
                            "/etc/passwd",
                            ""}) {
        EXPECT_FALSE(Downloader::scheme_allowed(url)) << url;
    }
}

TEST(Downloader, RefusedSchemeNeverConnects) {
    const Downloader downloader;
    const auto result = downloader.fetch("file:///etc/passwd");
    EXPECT_EQ(DownloadOutcome::BadScheme, result.outcome);
    EXPECT_TRUE(result.body.empty());
}

// The control that matters. Nothing is mocked: the address really is refused
// at connect time, by the same callback the live path uses.
TEST(Downloader, CloudMetadataIsRefusedAtConnectTime) {
    const Downloader downloader;
    const auto result = downloader.fetch("http://169.254.169.254/opc/v2/instance/");
    EXPECT_EQ(DownloadOutcome::BlockedAddress, result.outcome);
    EXPECT_EQ(arapuca::capture::AddressVerdict::LinkLocal, result.blocked);
    EXPECT_TRUE(result.body.empty());
}

TEST(Downloader, LoopbackAndPrivateAreRefusedAtConnectTime) {
    const Downloader downloader;
    for (const auto* url :
         {"http://127.0.0.1/", "http://10.0.0.1/", "http://192.168.1.1/", "http://[::1]/"}) {
        const auto result = downloader.fetch(url);
        EXPECT_EQ(DownloadOutcome::BlockedAddress, result.outcome) << url;
        EXPECT_TRUE(result.body.empty()) << url;
    }
}

TEST(Downloader, OutcomeNamesAreStableForTheSchema) {
    EXPECT_EQ("ok", std::string(arapuca::capture::to_string(DownloadOutcome::Ok)));
    EXPECT_EQ("blocked_address",
              std::string(arapuca::capture::to_string(DownloadOutcome::BlockedAddress)));
    EXPECT_EQ("too_large", std::string(arapuca::capture::to_string(DownloadOutcome::TooLarge)));
}

// --- quarantine -----------------------------------------------------------

class QuarantineTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = std::filesystem::temp_directory_path() /
               ("arapuca-quarantine-" +
                std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        std::filesystem::remove_all(dir_);
    }

    void TearDown() override {
        std::filesystem::remove_all(dir_);
    }

    QuarantineConfig config() {
        QuarantineConfig config;
        config.directory = dir_;
        config.password = "infected";
        return config;
    }

    std::filesystem::path dir_;
};

TEST_F(QuarantineTest, StoresASample) {
    Quarantine quarantine(config());
    const auto result = quarantine.store("malicious bytes", "bot.sh");

    EXPECT_TRUE(result.stored);
    EXPECT_FALSE(result.duplicate);
    EXPECT_EQ(sha256_hex("malicious bytes"), result.sha256);
    EXPECT_TRUE(std::filesystem::exists(result.path));
    EXPECT_EQ(1U, quarantine.count());
}

// The file name is the hash, which makes the quarantine content addressed and
// the dedup trivial.
TEST_F(QuarantineTest, FileIsNamedAfterTheHash) {
    Quarantine quarantine(config());
    const auto result = quarantine.store("x", "whatever.bin");
    EXPECT_EQ(result.sha256 + ".zip", result.path.filename().string());
}

// Safety invariant S3: a sample is never executable, and never writable.
TEST_F(QuarantineTest, StoredSampleIsReadOnlyAndNotExecutable) {
    Quarantine quarantine(config());
    const auto result = quarantine.store("payload", "x.elf");

    const auto permissions = std::filesystem::status(result.path).permissions();
    using std::filesystem::perms;
    EXPECT_EQ(perms::none, (permissions & perms::owner_exec));
    EXPECT_EQ(perms::none, (permissions & perms::group_exec));
    EXPECT_EQ(perms::none, (permissions & perms::others_exec));
    EXPECT_EQ(perms::none, (permissions & perms::owner_write));
}

TEST_F(QuarantineTest, ArchiveIsAZipAndIsEncrypted) {
    Quarantine quarantine(config());
    const auto result = quarantine.store("secret payload bytes", "x.bin");

    const std::string content = arapuca::testing::read_whole_file(result.path);

    ASSERT_GE(content.size(), 4U);
    EXPECT_EQ("PK\x03\x04", content.substr(0, 4));
    // The payload must not be readable in the archive. That is the whole
    // reason for the password: antivirus on an analyst's machine deletes a
    // bare sample on sight.
    EXPECT_EQ(std::string::npos, content.find("secret payload bytes"));
}

TEST_F(QuarantineTest, SidecarMetadataIsWritten) {
    Quarantine quarantine(config());
    const auto result = quarantine.store("data", "original-name.sh");

    const auto sidecar = result.path.string() + ".json";
    ASSERT_TRUE(std::filesystem::exists(sidecar));

    std::ifstream file(sidecar);
    nlohmann::json metadata;
    file >> metadata;
    EXPECT_EQ(result.sha256, metadata.at("sha256").get<std::string>());
    EXPECT_EQ("original-name.sh", metadata.at("original_name").get<std::string>());
    EXPECT_EQ("infected", metadata.at("zip_password").get<std::string>());
}

// A dropper fetched by a thousand sessions is one file and a counter.
TEST_F(QuarantineTest, DuplicateIsRecognised) {
    Quarantine quarantine(config());
    const auto first = quarantine.store("same bytes", "a.sh");
    const auto second = quarantine.store("same bytes", "b.sh");

    EXPECT_FALSE(first.duplicate);
    EXPECT_TRUE(second.duplicate);
    EXPECT_EQ(first.sha256, second.sha256);
    EXPECT_EQ(1U, quarantine.count());
}

TEST_F(QuarantineTest, HoldsReportsWhatIsStored) {
    Quarantine quarantine(config());
    const auto result = quarantine.store("x", "x");
    EXPECT_TRUE(quarantine.holds(result.sha256));
    EXPECT_FALSE(quarantine.holds(std::string(64, 'a')));
}

// Retention is a safety control: an attacker in a loop must not be able to
// fill a 50 GB instance and take the honeypot down.
TEST_F(QuarantineTest, FileCountCapEvictsOldestFirst) {
    auto settings = config();
    settings.max_files = 3;
    Quarantine quarantine(std::move(settings));

    std::vector<std::string> hashes;
    for (int i = 0; i < 8; ++i) {
        const auto result = quarantine.store("sample " + std::to_string(i), "x.bin");
        hashes.push_back(result.sha256);
        // Distinct modification times, so "oldest" is well defined.
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    EXPECT_LE(quarantine.count(), 3U);
    EXPECT_FALSE(quarantine.holds(hashes.front()));
    EXPECT_TRUE(quarantine.holds(hashes.back()));
}

TEST_F(QuarantineTest, TotalByteCapIsEnforced) {
    auto settings = config();
    settings.max_total_bytes = 1024;
    Quarantine quarantine(std::move(settings));

    for (int i = 0; i < 12; ++i) {
        (void)quarantine.store(std::string(2000, static_cast<char>('a' + i)), "big.bin");
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    EXPECT_LE(quarantine.total_bytes(), 2048U) << "the cap must bound the directory";
}

TEST_F(QuarantineTest, EmptyDirectoryConfigIsRejected) {
    const QuarantineConfig broken;
    EXPECT_THROW({ const Quarantine quarantine(broken); }, arapuca::capture::QuarantineError);
}

// --- rate limiter ---------------------------------------------------------

TEST(RateLimiter, AllowsUpToTheMinuteBudget) {
    RateLimiter limiter(4, 500);
    const auto now = arapuca::core::Clock::now();

    EXPECT_TRUE(limiter.try_acquire(now));
    EXPECT_TRUE(limiter.try_acquire(now));
    EXPECT_TRUE(limiter.try_acquire(now));
    EXPECT_TRUE(limiter.try_acquire(now));
    EXPECT_FALSE(limiter.try_acquire(now)) << "the fifth request in a minute must be refused";
    EXPECT_EQ(4U, limiter.used_this_minute());
}

TEST(RateLimiter, TheNextMinuteStartsFresh) {
    RateLimiter limiter(2, 500);
    const auto now = arapuca::core::Clock::now();

    EXPECT_TRUE(limiter.try_acquire(now));
    EXPECT_TRUE(limiter.try_acquire(now));
    EXPECT_FALSE(limiter.try_acquire(now));
    EXPECT_TRUE(limiter.try_acquire(now + std::chrono::minutes{1}));
}

TEST(RateLimiter, TheDailyBudgetAlsoBinds) {
    RateLimiter limiter(100, 3);
    auto now = arapuca::core::Clock::now();

    EXPECT_TRUE(limiter.try_acquire(now));
    now += std::chrono::minutes{1};
    EXPECT_TRUE(limiter.try_acquire(now));
    now += std::chrono::minutes{1};
    EXPECT_TRUE(limiter.try_acquire(now));
    now += std::chrono::minutes{1};
    EXPECT_FALSE(limiter.try_acquire(now)) << "the daily cap must hold across minutes";
}

// A crash loop must not burn the daily allowance, which is the whole reason
// the budget is on disk rather than in memory.
TEST(RateLimiter, BudgetSurvivesARestart) {
    const auto state = std::filesystem::temp_directory_path() / "arapuca-vt-budget.json";
    std::filesystem::remove(state);
    const auto now = arapuca::core::Clock::now();

    {
        RateLimiter limiter(4, 500, state);
        EXPECT_TRUE(limiter.try_acquire(now));
        EXPECT_TRUE(limiter.try_acquire(now));
    }
    {
        RateLimiter restarted(4, 500, state);
        EXPECT_EQ(2U, restarted.used_this_minute());
        EXPECT_TRUE(restarted.try_acquire(now));
        EXPECT_TRUE(restarted.try_acquire(now));
        EXPECT_FALSE(restarted.try_acquire(now));
    }
    std::filesystem::remove(state);
}

TEST(RateLimiter, CorruptStateStartsFreshRatherThanFailing) {
    const auto state = std::filesystem::temp_directory_path() / "arapuca-vt-corrupt.json";
    {
        std::ofstream out(state);
        out << "this is not json";
    }
    RateLimiter limiter(4, 500, state);
    EXPECT_EQ(0U, limiter.used_today());
    EXPECT_TRUE(limiter.try_acquire(arapuca::core::Clock::now()));
    std::filesystem::remove(state);
}

// --- VirusTotal report parsing --------------------------------------------

TEST(VirusTotalParse, RealShapedResponse) {
    const auto body = nlohmann::json::parse(R"({
      "data": {
        "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "attributes": {
          "last_analysis_stats": {
            "malicious": 54, "suspicious": 2, "undetected": 10,
            "harmless": 0, "timeout": 1, "type-unsupported": 3, "failure": 0
          },
          "popular_threat_classification": {
            "suggested_threat_label": "trojan.mirai/gafgyt"
          },
          "first_submission_date": 1700000000
        }
      }
    })");

    const auto report = parse_file_report(body);
    EXPECT_EQ(VtStatus::Ok, report.status);
    EXPECT_EQ(56, report.detections) << "malicious plus suspicious";
    EXPECT_EQ(70, report.total_engines);
    EXPECT_EQ("trojan.mirai/gafgyt", report.popular_label);
    EXPECT_FALSE(report.first_seen.empty());
}

TEST(VirusTotalParse, CleanFile) {
    const auto body = nlohmann::json::parse(
        R"({"data":{"attributes":{"last_analysis_stats":{"malicious":0,"undetected":72}}}})");
    const auto report = parse_file_report(body);
    EXPECT_EQ(VtStatus::Ok, report.status);
    EXPECT_EQ(0, report.detections);
    EXPECT_EQ(72, report.total_engines);
}

TEST(VirusTotalParse, MissingOrMalformedBodyIsNotFoundNotACrash) {
    EXPECT_EQ(VtStatus::NotFound, parse_file_report(nlohmann::json::object()).status);
    EXPECT_EQ(VtStatus::NotFound, parse_file_report(nlohmann::json::array()).status);
    EXPECT_EQ(VtStatus::NotFound,
              parse_file_report(nlohmann::json::parse(R"({"data":{}})")).status);
}

TEST(VirusTotalClientTest, WithoutAKeyItIsDisabledAndNeverCalls) {
    const arapuca::capture::VirusTotalConfig config;
    arapuca::capture::VirusTotalClient client(config);
    EXPECT_FALSE(client.enabled());
    EXPECT_EQ(VtStatus::Disabled, client.lookup(std::string(64, 'a')).status);
}

TEST(VirusTotalClientTest, NonHashInputIsRefusedWithoutARequest) {
    arapuca::capture::VirusTotalConfig config;
    config.api_key = "not-a-real-key";
    arapuca::capture::VirusTotalClient client(std::move(config));

    const auto report = client.lookup("../../etc/passwd");
    EXPECT_EQ(VtStatus::Error, report.status);
    EXPECT_NE(std::string::npos, report.error.find("sha256"));
    // Nothing was spent on a request that could not have been valid.
    EXPECT_EQ(0U, client.limiter().used_today());
}

TEST(VirusTotalStatus, NamesAreStableForTheSchema) {
    EXPECT_EQ("ok", std::string(arapuca::capture::to_string(VtStatus::Ok)));
    EXPECT_EQ("not_found", std::string(arapuca::capture::to_string(VtStatus::NotFound)));
    EXPECT_EQ("rate_limited", std::string(arapuca::capture::to_string(VtStatus::RateLimited)));
}

}  // namespace
