// The Telnet IAC decoder. It is the one attacker facing parser the Telnet
// service adds, so it is tested for the sequences a real client and a hostile
// one both send: plain data, escaped IAC, option negotiation, subnegotiation,
// and all of those split across chunk boundaries.

#include <arapuca/core/limits.hpp>
#include <arapuca/telnet/protocol.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::telnet::Decoder;

std::string bytes(std::initializer_list<unsigned char> values) {
    std::string out;
    for (const unsigned char value : values) {
        out.push_back(static_cast<char>(value));
    }
    return out;
}

TEST(TelnetProtocol, PlainDataPassesThrough) {
    Decoder decoder;
    const auto out = decoder.feed("root\r\n");
    EXPECT_EQ(out.clean, "root\r\n");
    EXPECT_TRUE(out.response.empty());
}

TEST(TelnetProtocol, EscapedIacBecomesOneLiteralByte) {
    Decoder decoder;
    // IAC IAC is the way a literal 0xFF travels in the data stream.
    const auto out = decoder.feed(bytes({'a', 255, 255, 'b'}));
    ASSERT_EQ(out.clean.size(), 3U);
    EXPECT_EQ(out.clean[0], 'a');
    EXPECT_EQ(static_cast<unsigned char>(out.clean[1]), 255U);
    EXPECT_EQ(out.clean[2], 'b');
}

TEST(TelnetProtocol, NegotiationIsStrippedAndRefused) {
    Decoder decoder;
    using namespace arapuca::telnet;
    // IAC DO ECHO, around some data.
    const auto out = decoder.feed(bytes({'h', kIac, kDo, 1, 'i'}));
    EXPECT_EQ(out.clean, "hi");
    // DO is answered WONT, so the peer stays in line mode.
    ASSERT_EQ(out.response.size(), 3U);
    EXPECT_EQ(static_cast<unsigned char>(out.response[0]), kIac);
    EXPECT_EQ(static_cast<unsigned char>(out.response[1]), kWont);
    EXPECT_EQ(static_cast<unsigned char>(out.response[2]), 1U);
    EXPECT_EQ(decoder.negotiations(), 1U);
}

TEST(TelnetProtocol, WillIsAnsweredDont) {
    Decoder decoder;
    using namespace arapuca::telnet;
    const auto out = decoder.feed(bytes({kIac, kWill, 24}));  // WILL TERMINAL-TYPE
    EXPECT_TRUE(out.clean.empty());
    ASSERT_EQ(out.response.size(), 3U);
    EXPECT_EQ(static_cast<unsigned char>(out.response[1]), kDont);
}

TEST(TelnetProtocol, SubnegotiationIsSwallowed) {
    Decoder decoder;
    using namespace arapuca::telnet;
    // IAC SB TERMINAL-TYPE "xterm" IAC SE, wrapped in data.
    const auto out =
        decoder.feed(bytes({'a', kIac, kSb, 24, 'x', 't', 'e', 'r', 'm', kIac, kSe, 'b'}));
    EXPECT_EQ(out.clean, "ab");
    EXPECT_TRUE(out.response.empty());
}

TEST(TelnetProtocol, SequenceSplitAcrossChunks) {
    Decoder decoder;
    using namespace arapuca::telnet;
    // IAC then, in the next read, DO ECHO. The decoder must remember it is
    // mid sequence.
    auto first = decoder.feed(bytes({'x', kIac}));
    EXPECT_EQ(first.clean, "x");
    EXPECT_TRUE(first.response.empty());
    auto second = decoder.feed(bytes({kDo, 1, 'y'}));
    EXPECT_EQ(second.clean, "y");
    EXPECT_EQ(second.response.size(), 3U);
}

TEST(TelnetProtocol, EscapedIacSplitAcrossChunks) {
    Decoder decoder;
    using namespace arapuca::telnet;
    auto first = decoder.feed(bytes({kIac}));
    EXPECT_TRUE(first.clean.empty());
    auto second = decoder.feed(bytes({kIac}));
    ASSERT_EQ(second.clean.size(), 1U);
    EXPECT_EQ(static_cast<unsigned char>(second.clean[0]), 255U);
}

TEST(TelnetProtocol, ResponsesAreBoundedByTheNegotiationCap) {
    Decoder decoder;
    using namespace arapuca::telnet;
    std::string flood;
    const std::size_t many = arapuca::limits::kMaxTelnetNegotiations + 50;
    for (std::size_t i = 0; i < many; ++i) {
        flood.push_back(static_cast<char>(kIac));
        flood.push_back(static_cast<char>(kDo));
        flood.push_back(static_cast<char>(1));
    }
    const auto out = decoder.feed(flood);
    // Past the cap the decoder keeps parsing but stops replying, so the peer
    // cannot make the response grow without bound.
    EXPECT_EQ(decoder.negotiations(), arapuca::limits::kMaxTelnetNegotiations);
    EXPECT_EQ(out.response.size(), arapuca::limits::kMaxTelnetNegotiations * 3);
    EXPECT_TRUE(out.clean.empty());
}

}  // namespace
