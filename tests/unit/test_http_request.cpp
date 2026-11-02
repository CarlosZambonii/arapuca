#include <arapuca/core/limits.hpp>
#include <arapuca/http/decoys.hpp>
#include <arapuca/http/request_record.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::http::DecoyStore;
using arapuca::http::default_decoys;
using arapuca::http::is_sensitive_header;
using arapuca::http::RawRequest;
using arapuca::http::summarize;

RawRequest basic() {
    RawRequest request;
    request.method = "GET";
    request.path = "/.env";
    request.remote_address = "203.0.113.45";
    request.remote_port = 54122;
    request.headers = {{"Host", "srv-web-03"}, {"User-Agent", "curl/7.81.0"}, {"Accept", "*/*"}};
    return request;
}

TEST(HttpRecord, CapturesTheBasics) {
    const auto summary = summarize(basic(), 8192);
    EXPECT_EQ("GET", summary.detail.at("method").get<std::string>());
    EXPECT_EQ("/.env", summary.detail.at("path").get<std::string>());
    EXPECT_EQ("curl/7.81.0", summary.detail.at("user_agent").get<std::string>());
    EXPECT_EQ("srv-web-03", summary.detail.at("headers").at("Host").get<std::string>());
}

TEST(HttpRecord, BodyIsRecordedAndMeasured) {
    RawRequest request = basic();
    request.method = "POST";
    request.body = "username=admin&password=hunter2";

    const auto summary = summarize(request, 8192);
    EXPECT_EQ(request.body.size(), summary.detail.at("body_bytes").get<std::size_t>());
    EXPECT_EQ(request.body, summary.detail.at("body").get<std::string>());
    EXPECT_FALSE(summary.detail.at("body_truncated").get<bool>());
}

// An analyst reading a payload needs to know whether they are reading all of
// it, which is why the flag exists and why the full size is kept separately.
TEST(HttpRecord, OversizedBodyIsCutAndFlagged) {
    RawRequest request = basic();
    request.body = std::string(100000, 'A');

    const auto summary = summarize(request, 1024);
    EXPECT_LE(summary.detail.at("body").get<std::string>().size(), 1024U);
    EXPECT_TRUE(summary.detail.at("body_truncated").get<bool>());
    EXPECT_EQ(100000U, summary.detail.at("body_bytes").get<std::size_t>());
}

TEST(HttpRecord, AbsentBodyProducesNoBodyField) {
    const auto summary = summarize(basic(), 8192);
    EXPECT_FALSE(summary.detail.contains("body"));
    EXPECT_EQ(0U, summary.detail.at("body_bytes").get<std::size_t>());
}

// A bearer token replayed by a scanner belongs to a third party. That it was
// sent is signal, its contents are not ours to keep.
TEST(HttpRecord, SensitiveHeadersAreRedactedNotDropped) {
    RawRequest request = basic();
    request.headers.emplace_back("Authorization", "Bearer ey.very.secret");
    request.headers.emplace_back("Cookie", "session=abc123");

    const auto summary = summarize(request, 8192);
    EXPECT_EQ("[redacted]", summary.detail.at("headers").at("Authorization").get<std::string>());
    EXPECT_EQ("[redacted]", summary.detail.at("headers").at("Cookie").get<std::string>());
}

TEST(HttpRecord, SensitiveHeaderMatchIsCaseInsensitive) {
    EXPECT_TRUE(is_sensitive_header("authorization"));
    EXPECT_TRUE(is_sensitive_header("AUTHORIZATION"));
    EXPECT_TRUE(is_sensitive_header("Cookie"));
    EXPECT_FALSE(is_sensitive_header("User-Agent"));
}

TEST(HttpRecord, HeaderCountIsBounded) {
    RawRequest request = basic();
    for (std::size_t i = 0; i < arapuca::limits::kMaxHttpHeaders * 3; ++i) {
        request.headers.emplace_back("X-Pad-" + std::to_string(i), "v");
    }

    const auto summary = summarize(request, 8192);
    EXPECT_LE(summary.detail.at("headers").size(), arapuca::limits::kMaxHttpHeaders);
    EXPECT_GT(summary.headers_dropped, 0U);
    EXPECT_TRUE(summary.detail.contains("headers_dropped"));
}

TEST(HttpRecord, LongPathIsCut) {
    RawRequest request = basic();
    request.path = "/" + std::string(arapuca::limits::kMaxHttpUrl * 3, 'a');
    const auto summary = summarize(request, 8192);
    EXPECT_LE(summary.detail.at("path").get<std::string>().size(), arapuca::limits::kMaxHttpUrl);
}

// Scanner traffic is full of malformed bytes, and a serializer throwing on
// one would be a remote denial of service.
TEST(HttpRecord, BinaryEverythingIsSerializable) {
    RawRequest request;
    request.method = std::string("\xFF\xFE", 2);
    request.path = std::string("/\x00\x01\xFF", 4);
    request.body = std::string("\xC0\xAF\xED\xA0\x80", 5);
    request.headers = {{std::string("\xFF", 1), std::string("\xFE", 1)}};

    const auto summary = summarize(request, 8192);
    EXPECT_NO_THROW({ (void)summary.detail.dump(); });
}

TEST(HttpRecord, PathTraversalIsRecordedLiterally) {
    RawRequest request = basic();
    request.path = "/../../../../etc/passwd";
    const auto summary = summarize(request, 8192);
    // Recorded exactly as sent. Nothing resolves it, because nothing here
    // touches a real filesystem.
    EXPECT_EQ("/../../../../etc/passwd", summary.detail.at("path").get<std::string>());
}

// --- decoys ---------------------------------------------------------------

TEST(Decoys, TheBuiltInSetCoversWhatScannersAskFor) {
    const auto store = default_decoys();
    for (const auto* path : {"/.env",
                             "/.git/config",
                             "/config.php",
                             "/wp-config.php",
                             "/backup.sql",
                             "/.aws/credentials",
                             "/docker-compose.yml"}) {
        EXPECT_NE(nullptr, store.find(path)) << path;
    }
}

TEST(Decoys, ContentLooksLikeTheRealThing) {
    const auto store = default_decoys();

    const auto* env = store.find("/.env");
    ASSERT_NE(nullptr, env);
    EXPECT_NE(std::string::npos, env->body.find("DB_PASSWORD"));
    EXPECT_NE(std::string::npos, env->body.find("AWS_SECRET_ACCESS_KEY"));
    EXPECT_EQ("env", env->label);

    const auto* git = store.find("/.git/config");
    ASSERT_NE(nullptr, git);
    EXPECT_NE(std::string::npos, git->body.find("[remote \"origin\"]"));
}

TEST(Decoys, UnknownPathHasNoDecoy) {
    EXPECT_EQ(nullptr, default_decoys().find("/nothing-here"));
}

TEST(Decoys, SeveralPathsShareOneDecoy) {
    const auto store = default_decoys();
    const auto* a = store.find("/.env");
    const auto* b = store.find("/.env.production");
    ASSERT_NE(nullptr, a);
    ASSERT_NE(nullptr, b);
    EXPECT_EQ(a->body, b->body);
}

TEST(Decoys, MissingDirectoryFallsBackToTheBuiltInSet) {
    const auto store = DecoyStore::from_directory("/nonexistent/decoys");
    EXPECT_GT(store.size(), 5U);
    EXPECT_NE(nullptr, store.find("/.env"));
}

}  // namespace
