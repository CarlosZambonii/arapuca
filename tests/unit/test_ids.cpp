#include <arapuca/core/ids.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <set>
#include <string>

namespace {

using arapuca::core::Clock;
using arapuca::core::kIdLength;
using arapuca::core::new_id;
using arapuca::core::new_id_at;

TEST(Ids, HasTheDocumentedLength) {
    EXPECT_EQ(kIdLength, new_id().size());
}

TEST(Ids, UsesOnlyCrockfordAlphabet) {
    const std::string allowed = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for (int i = 0; i < 200; ++i) {
        for (const char character : new_id()) {
            EXPECT_NE(std::string::npos, allowed.find(character))
                << "unexpected character " << character;
        }
    }
}

TEST(Ids, AreUnique) {
    std::set<std::string> seen;
    for (int i = 0; i < 20000; ++i) {
        EXPECT_TRUE(seen.insert(new_id()).second);
    }
}

// The reason a ULID is used instead of a UUIDv4: sorting the log file by this
// field has to produce chronological order, so an operator can `sort` a raw
// JSONL file without parsing timestamps.
TEST(Ids, SortLexicographicallyByTime) {
    const auto early = Clock::now();
    const auto later = early + std::chrono::seconds{1};
    const auto much_later = early + std::chrono::hours{48};

    EXPECT_LT(new_id_at(early), new_id_at(later));
    EXPECT_LT(new_id_at(later), new_id_at(much_later));
}

TEST(Ids, SameMillisecondStillDiffers) {
    const auto when = Clock::now();
    EXPECT_NE(new_id_at(when), new_id_at(when));
}

}  // namespace
