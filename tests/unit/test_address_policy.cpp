#include <arapuca/capture/address_policy.hpp>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>

#include <cstring>
#include <string>

namespace {

using arapuca::capture::AddressVerdict;
using arapuca::capture::classify;
using arapuca::capture::classify_text;
using arapuca::capture::is_allowed;

// The single most important test in this file. An attacker typing
// `wget http://169.254.169.254/opc/v2/instance/` into the fake shell is asking
// the honeypot to fetch its own cloud credentials and hand them over.
TEST(AddressPolicy, CloudMetadataIsRefused) {
    EXPECT_EQ(AddressVerdict::LinkLocal, classify_text("169.254.169.254"));
    EXPECT_FALSE(is_allowed(classify_text("169.254.169.254")));

    // Every cloud puts it somewhere in the same range.
    EXPECT_FALSE(is_allowed(classify_text("169.254.169.253")));
    EXPECT_FALSE(is_allowed(classify_text("169.254.0.1")));
    EXPECT_FALSE(is_allowed(classify_text("169.254.255.255")));
}

// Writing the same address in IPv6 form must not get around the check.
TEST(AddressPolicy, MappedIpv4FormsAreUnwrapped) {
    EXPECT_EQ(AddressVerdict::LinkLocal, classify_text("::ffff:169.254.169.254"));
    EXPECT_EQ(AddressVerdict::Loopback, classify_text("::ffff:127.0.0.1"));
    EXPECT_EQ(AddressVerdict::Private, classify_text("::ffff:10.0.0.1"));
    EXPECT_EQ(AddressVerdict::Private, classify_text("::ffff:192.168.1.1"));
}

TEST(AddressPolicy, LoopbackIsRefused) {
    EXPECT_EQ(AddressVerdict::Loopback, classify_text("127.0.0.1"));
    EXPECT_EQ(AddressVerdict::Loopback, classify_text("127.255.255.254"));
    EXPECT_EQ(AddressVerdict::Loopback, classify_text("::1"));
}

TEST(AddressPolicy, PrivateRangesAreRefused) {
    for (const auto* address : {"10.0.0.1",
                                "10.255.255.255",
                                "172.16.0.1",
                                "172.31.255.255",
                                "192.168.0.1",
                                "192.168.255.255"}) {
        EXPECT_EQ(AddressVerdict::Private, classify_text(address)) << address;
    }
}

// 172.15 and 172.32 are outside 172.16.0.0/12. Getting the prefix wrong here
// would either block the public internet or let the private range through.
TEST(AddressPolicy, PrivateRangeBoundariesAreExact) {
    EXPECT_EQ(AddressVerdict::Allowed, classify_text("172.15.255.255"));
    EXPECT_EQ(AddressVerdict::Private, classify_text("172.16.0.0"));
    EXPECT_EQ(AddressVerdict::Private, classify_text("172.31.255.255"));
    EXPECT_EQ(AddressVerdict::Allowed, classify_text("172.32.0.0"));

    EXPECT_EQ(AddressVerdict::Allowed, classify_text("9.255.255.255"));
    EXPECT_EQ(AddressVerdict::Private, classify_text("10.0.0.0"));
    EXPECT_EQ(AddressVerdict::Allowed, classify_text("11.0.0.0"));
}

TEST(AddressPolicy, CarrierGradeNatIsRefused) {
    EXPECT_EQ(AddressVerdict::CarrierGrade, classify_text("100.64.0.1"));
    EXPECT_EQ(AddressVerdict::CarrierGrade, classify_text("100.127.255.255"));
    EXPECT_EQ(AddressVerdict::Allowed, classify_text("100.63.255.255"));
    EXPECT_EQ(AddressVerdict::Allowed, classify_text("100.128.0.0"));
}

TEST(AddressPolicy, UnspecifiedMulticastAndReservedAreRefused) {
    EXPECT_EQ(AddressVerdict::Unspecified, classify_text("0.0.0.0"));
    EXPECT_EQ(AddressVerdict::Multicast, classify_text("224.0.0.1"));
    EXPECT_EQ(AddressVerdict::Multicast, classify_text("239.255.255.255"));
    EXPECT_EQ(AddressVerdict::Reserved, classify_text("240.0.0.1"));
    EXPECT_EQ(AddressVerdict::Reserved, classify_text("255.255.255.255"));
    EXPECT_EQ(AddressVerdict::Benchmark, classify_text("198.18.0.1"));
}

TEST(AddressPolicy, Ipv6PrivateFormsAreRefused) {
    EXPECT_EQ(AddressVerdict::UniqueLocal, classify_text("fc00::1"));
    EXPECT_EQ(AddressVerdict::UniqueLocal, classify_text("fd12:3456::1"));
    EXPECT_EQ(AddressVerdict::LinkLocal, classify_text("fe80::1"));
    EXPECT_EQ(AddressVerdict::Multicast, classify_text("ff02::1"));
    EXPECT_EQ(AddressVerdict::Unspecified, classify_text("::"));
}

// The whole point is that real malware hosting is still reachable. A policy
// that blocked everything would be safe and useless.
TEST(AddressPolicy, PublicAddressesAreAllowed) {
    for (const auto* address :
         {"8.8.8.8", "1.1.1.1", "93.184.216.34", "137.131.150.1", "2606:4700:4700::1111"}) {
        EXPECT_TRUE(is_allowed(classify_text(address))) << address;
    }
}

TEST(AddressPolicy, DocumentationRangesAreRefused) {
    // Used throughout this repository's own tests and docs, and nothing real
    // is there, so a request for one is a probe.
    EXPECT_FALSE(is_allowed(classify_text("192.0.2.1")));
    EXPECT_FALSE(is_allowed(classify_text("198.51.100.9")));
    EXPECT_FALSE(is_allowed(classify_text("203.0.113.45")));
    EXPECT_FALSE(is_allowed(classify_text("2001:db8::1")));
}

TEST(AddressPolicy, NonAddressTextIsRefused) {
    for (const auto* text : {"",
                             "evil.example.com",
                             "not-an-ip",
                             "999.999.999.999",
                             "127.0.0.1; rm -rf /",
                             "0x7f000001",
                             "2130706433"}) {
        EXPECT_FALSE(is_allowed(classify_text(text))) << text;
    }
}

// --- the form the live path actually sees ---------------------------------

TEST(AddressPolicy, ClassifiesASockaddr) {
    sockaddr_in in4{};
    in4.sin_family = AF_INET;
    ASSERT_EQ(1, ::inet_pton(AF_INET, "169.254.169.254", &in4.sin_addr));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_EQ(AddressVerdict::LinkLocal, classify(reinterpret_cast<const sockaddr*>(&in4)));

    ASSERT_EQ(1, ::inet_pton(AF_INET, "8.8.8.8", &in4.sin_addr));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_EQ(AddressVerdict::Allowed, classify(reinterpret_cast<const sockaddr*>(&in4)));
}

TEST(AddressPolicy, ClassifiesAnIpv6Sockaddr) {
    sockaddr_in6 in6{};
    in6.sin6_family = AF_INET6;
    ASSERT_EQ(1, ::inet_pton(AF_INET6, "fe80::1", &in6.sin6_addr));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_EQ(AddressVerdict::LinkLocal, classify(reinterpret_cast<const sockaddr*>(&in6)));
}

TEST(AddressPolicy, NullAndUnknownFamiliesAreRefused) {
    EXPECT_EQ(AddressVerdict::UnsupportedFamily, classify(nullptr));

    sockaddr unknown{};
    unknown.sa_family = AF_UNIX;
    EXPECT_FALSE(is_allowed(classify(&unknown)));
}

TEST(AddressPolicy, VerdictNamesAreStableForTheSchema) {
    EXPECT_EQ("allowed", std::string(arapuca::capture::to_string(AddressVerdict::Allowed)));
    EXPECT_EQ("link_local", std::string(arapuca::capture::to_string(AddressVerdict::LinkLocal)));
    EXPECT_EQ("private", std::string(arapuca::capture::to_string(AddressVerdict::Private)));
}

// Sweep the whole IPv4 space at a coarse stride. This is the test that would
// catch a mask computed with the wrong operator precedence.
TEST(AddressPolicy, NoPrivateAddressIsEverAllowed) {
    const auto blocked = [](std::uint32_t address) {
        return !is_allowed(arapuca::capture::classify_ipv4(address));
    };

    for (std::uint32_t octet = 0; octet < 256; ++octet) {
        for (std::uint32_t second = 0; second < 256; second += 7) {
            const std::uint32_t address = (octet << 24) | (second << 16) | 0x0101U;
            const bool must_block = octet == 0 || octet == 127 || octet == 10 ||
                                    (octet == 172 && second >= 16 && second <= 31) ||
                                    (octet == 192 && second == 168) ||
                                    (octet == 100 && second >= 64 && second <= 127) ||
                                    (octet == 169 && second == 254) || octet >= 224;
            if (must_block) {
                EXPECT_TRUE(blocked(address))
                    << octet << "." << second << ".1.1 must never be allowed";
            }
        }
    }
}

}  // namespace
