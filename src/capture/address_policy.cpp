#include <arapuca/capture/address_policy.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace arapuca::capture {
namespace {

constexpr std::uint32_t mask_for(int prefix) {
    return prefix == 0 ? 0U : (0xFFFFFFFFU << (32 - prefix));
}

constexpr bool in_network(std::uint32_t address, std::uint32_t network, int prefix) {
    return (address & mask_for(prefix)) == (network & mask_for(prefix));
}

constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return (static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
           (static_cast<std::uint32_t>(c) << 8) | static_cast<std::uint32_t>(d);
}

}  // namespace

std::string_view to_string(AddressVerdict verdict) {
    // clang-format off
    switch (verdict) {
        case AddressVerdict::Allowed:           return "allowed";
        case AddressVerdict::Loopback:          return "loopback";
        case AddressVerdict::Private:           return "private";
        case AddressVerdict::LinkLocal:         return "link_local";
        case AddressVerdict::CarrierGrade:      return "carrier_grade_nat";
        case AddressVerdict::Multicast:         return "multicast";
        case AddressVerdict::Reserved:          return "reserved";
        case AddressVerdict::Unspecified:       return "unspecified";
        case AddressVerdict::Benchmark:         return "benchmark";
        case AddressVerdict::UniqueLocal:       return "unique_local";
        case AddressVerdict::UnsupportedFamily: return "unsupported_family";
    }
    // clang-format on
    return "reserved";
}

bool is_allowed(AddressVerdict verdict) {
    return verdict == AddressVerdict::Allowed;
}

AddressVerdict classify_ipv4(std::uint32_t host_order) {
    // Ordered from most specific to least, so 169.254.169.254 is reported as
    // link local rather than swallowed by a broader rule.
    if (in_network(host_order, ipv4(0, 0, 0, 0), 8)) {
        return AddressVerdict::Unspecified;
    }
    if (in_network(host_order, ipv4(127, 0, 0, 0), 8)) {
        return AddressVerdict::Loopback;
    }
    if (in_network(host_order, ipv4(169, 254, 0, 0), 16)) {
        return AddressVerdict::LinkLocal;
    }
    if (in_network(host_order, ipv4(10, 0, 0, 0), 8) ||
        in_network(host_order, ipv4(172, 16, 0, 0), 12) ||
        in_network(host_order, ipv4(192, 168, 0, 0), 16)) {
        return AddressVerdict::Private;
    }
    if (in_network(host_order, ipv4(100, 64, 0, 0), 10)) {
        return AddressVerdict::CarrierGrade;
    }
    if (in_network(host_order, ipv4(198, 18, 0, 0), 15)) {
        return AddressVerdict::Benchmark;
    }
    if (in_network(host_order, ipv4(192, 0, 0, 0), 24) ||
        in_network(host_order, ipv4(192, 0, 2, 0), 24) ||
        in_network(host_order, ipv4(198, 51, 100, 0), 24) ||
        in_network(host_order, ipv4(203, 0, 113, 0), 24)) {
        // Documentation and protocol assignment ranges. Nothing real lives
        // there, so a request for one is a probe rather than a download.
        return AddressVerdict::Reserved;
    }
    if (in_network(host_order, ipv4(224, 0, 0, 0), 4)) {
        return AddressVerdict::Multicast;
    }
    if (in_network(host_order, ipv4(240, 0, 0, 0), 4)) {
        return AddressVerdict::Reserved;
    }
    return AddressVerdict::Allowed;
}

AddressVerdict classify_ipv6(const std::array<std::uint8_t, 16>& bytes) {
    const auto all_zero_until = [&bytes](std::size_t count) {
        return std::all_of(bytes.begin(),
                           bytes.begin() + static_cast<std::ptrdiff_t>(count),
                           [](std::uint8_t byte) { return byte == 0; });
    };

    // ::ffff:a.b.c.d and ::a.b.c.d both carry an IPv4 address. Classifying
    // them as IPv6 would let ::ffff:169.254.169.254 straight through.
    if (all_zero_until(10) && bytes[10] == 0xFF && bytes[11] == 0xFF) {
        const std::uint32_t packed = (static_cast<std::uint32_t>(bytes[12]) << 24) |
                                     (static_cast<std::uint32_t>(bytes[13]) << 16) |
                                     (static_cast<std::uint32_t>(bytes[14]) << 8) |
                                     static_cast<std::uint32_t>(bytes[15]);
        return classify_ipv4(packed);
    }
    if (all_zero_until(12)) {
        const std::uint32_t packed = (static_cast<std::uint32_t>(bytes[12]) << 24) |
                                     (static_cast<std::uint32_t>(bytes[13]) << 16) |
                                     (static_cast<std::uint32_t>(bytes[14]) << 8) |
                                     static_cast<std::uint32_t>(bytes[15]);
        if (packed == 0) {
            return AddressVerdict::Unspecified;
        }
        if (packed == 1) {
            return AddressVerdict::Loopback;
        }
        return classify_ipv4(packed);
    }

    if ((bytes[0] & 0xFEU) == 0xFCU) {
        return AddressVerdict::UniqueLocal;  // fc00::/7
    }
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0U) == 0x80U) {
        return AddressVerdict::LinkLocal;  // fe80::/10
    }
    if (bytes[0] == 0xFF) {
        return AddressVerdict::Multicast;  // ff00::/8
    }
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8) {
        return AddressVerdict::Reserved;  // 2001:db8::/32, documentation
    }
    return AddressVerdict::Allowed;
}

AddressVerdict classify(const sockaddr* address) {
    if (address == nullptr) {
        return AddressVerdict::UnsupportedFamily;
    }

    if (address->sa_family == AF_INET) {
        sockaddr_in in4{};
        std::memcpy(&in4, address, sizeof(in4));
        return classify_ipv4(ntohl(in4.sin_addr.s_addr));
    }

    if (address->sa_family == AF_INET6) {
        sockaddr_in6 in6{};
        std::memcpy(&in6, address, sizeof(in6));
        std::array<std::uint8_t, 16> bytes{};
        std::memcpy(bytes.data(), in6.sin6_addr.s6_addr, bytes.size());
        return classify_ipv6(bytes);
    }

    // Unix sockets and anything else. A download has no business using them.
    return AddressVerdict::UnsupportedFamily;
}

AddressVerdict classify_text(std::string_view address) {
    const std::string text(address);

    in_addr v4{};
    if (::inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        return classify_ipv4(ntohl(v4.s_addr));
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
        std::array<std::uint8_t, 16> bytes{};
        std::memcpy(bytes.data(), v6.s6_addr, bytes.size());
        return classify_ipv6(bytes);
    }

    // Not an address at all. Refusing is the safe answer: the live path never
    // sees a hostname, because it classifies what libcurl is about to connect
    // to, and that is always numeric by then.
    return AddressVerdict::UnsupportedFamily;
}

}  // namespace arapuca::capture
