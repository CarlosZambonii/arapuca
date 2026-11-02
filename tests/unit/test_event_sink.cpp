#include <arapuca/core/event_sink.hpp>

#include <nlohmann/json.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using arapuca::core::Event;
using arapuca::core::EventType;
using arapuca::core::JsonlFileSink;

class SinkTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ =
            std::filesystem::temp_directory_path() /
            ("arapuca-sink-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
             "-" + ::testing::UnitTest::GetInstance()->current_test_info()->name());
        std::filesystem::remove_all(dir_);
        path_ = dir_ / "events.jsonl";
    }

    void TearDown() override {
        std::filesystem::remove_all(dir_);
    }

    static Event make_event(const std::string& command) {
        Event event = Event::make(EventType::SshCommand, "arapuca-test");
        event.src_ip = "203.0.113.45";
        event.detail = {{"command", command}};
        return event;
    }

    std::vector<std::string> read_lines() const {
        std::vector<std::string> lines;
        std::ifstream input(path_);
        std::string line;
        while (std::getline(input, line)) {
            lines.push_back(line);
        }
        return lines;
    }

    std::filesystem::path dir_;
    std::filesystem::path path_;
};

TEST_F(SinkTest, CreatesMissingParentDirectories) {
    const JsonlFileSink sink(path_);
    EXPECT_TRUE(std::filesystem::exists(dir_));
}

TEST_F(SinkTest, WritesOneParseableLinePerEvent) {
    {
        JsonlFileSink sink(path_);
        sink.write(make_event("whoami"));
        sink.write(make_event("uname -a"));
        sink.flush();
    }

    const auto lines = read_lines();
    ASSERT_EQ(2U, lines.size());
    EXPECT_EQ("whoami", nlohmann::json::parse(lines[0]).at("command").get<std::string>());
    EXPECT_EQ("uname -a", nlohmann::json::parse(lines[1]).at("command").get<std::string>());
}

TEST_F(SinkTest, MultilineCommandStaysOnOneLine) {
    {
        JsonlFileSink sink(path_);
        sink.write(make_event("echo a\nrm -rf /\n"));
        sink.flush();
    }
    EXPECT_EQ(1U, read_lines().size());
}

TEST_F(SinkTest, CountsWhatItWrote) {
    JsonlFileSink sink(path_);
    for (int i = 0; i < 5; ++i) {
        sink.write(make_event("ls"));
    }
    EXPECT_EQ(5U, sink.written());
}

TEST_F(SinkTest, AppendsInsteadOfTruncatingOnReopen) {
    {
        JsonlFileSink sink(path_);
        sink.write(make_event("first"));
        sink.flush();
    }
    {
        JsonlFileSink sink(path_);
        sink.write(make_event("second"));
        sink.flush();
    }
    EXPECT_EQ(2U, read_lines().size());
}

// logrotate moves the file aside and signals the process. Until reopen() is
// called the sink keeps writing to the moved file, and after it, to the new
// path. Getting this wrong silently stops all telemetry after the first
// rotation, which is a failure mode worth a test of its own.
TEST_F(SinkTest, ReopenFollowsTheRotatedPath) {
    JsonlFileSink sink(path_);
    sink.write(make_event("before rotation"));
    sink.flush();

    const auto rotated = dir_ / "events.jsonl.1";
    std::filesystem::rename(path_, rotated);

    sink.reopen();
    sink.write(make_event("after rotation"));
    sink.flush();

    ASSERT_TRUE(std::filesystem::exists(rotated));
    ASSERT_TRUE(std::filesystem::exists(path_));

    const auto lines = read_lines();
    ASSERT_EQ(1U, lines.size());
    EXPECT_EQ("after rotation", nlohmann::json::parse(lines[0]).at("command").get<std::string>());
}

TEST_F(SinkTest, FlushesAutomaticallyAfterTheConfiguredCount) {
    JsonlFileSink sink(path_, 2, std::chrono::hours{1});
    sink.write(make_event("one"));
    sink.write(make_event("two"));
    // Two events with flush_every of two means the data is on disk already,
    // without an explicit flush call.
    EXPECT_EQ(2U, read_lines().size());
}

TEST_F(SinkTest, ThrowsWhenThePathCannotBeOpened) {
    const auto bad = std::filesystem::path("/proc/arapuca-cannot-exist/events.jsonl");
    EXPECT_THROW({ JsonlFileSink sink(bad); }, std::runtime_error);
}

}  // namespace
