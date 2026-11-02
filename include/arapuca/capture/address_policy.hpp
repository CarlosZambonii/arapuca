// Which addresses the capture engine is allowed to connect to.
//
// This is safety invariant S9, and it is the control that stops the honeypot
// from being turned against its own cloud instance. An attacker who types
// `wget http://169.254.169.254/opc/v2/instance/` into the fake shell is asking
// the honeypot to fetch the instance metadata service, which on most clouds
// hands out credentials. Answering that request would be worse than any
// command the fake shell could have executed.
//
// Two properties matter and both are easy to get wrong:
//
//   1. The check runs on the RESOLVED address, never on the URL text. A
//      hostname can point anywhere, and an attacker controls the DNS for the
//      name they hand over.
//   2. It runs again on every redirect hop, immediately before each connect.
//      Checking once after resolution leaves a DNS rebinding window where the
//      second lookup returns a different answer than the first.
//
// The predicate lives here, alone, so there is one place to review and one
// place to add a range.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

struct sockaddr;

namespace arapuca::capture {

enum class AddressVerdict : std::uint8_t {
    Allowed,
    Loopback,
    Private,
    LinkLocal,     ///< includes 169.254.169.254, the cloud metadata service
    CarrierGrade,  ///< 100.64.0.0/10
    Multicast,
    Reserved,
    Unspecified,
    Benchmark,    ///< 198.18.0.0/15
    UniqueLocal,  ///< fc00::/7
    UnsupportedFamily,
};

[[nodiscard]] std::string_view to_string(AddressVerdict verdict);
[[nodiscard]] bool is_allowed(AddressVerdict verdict);

/// Classify a packed IPv4 address given in host byte order.
[[nodiscard]] AddressVerdict classify_ipv4(std::uint32_t host_order);

/// Classify a 16 byte IPv6 address. IPv4 mapped and IPv4 compatible forms are
/// unwrapped and classified as IPv4, which closes the obvious bypass of
/// writing ::ffff:169.254.169.254.
[[nodiscard]] AddressVerdict classify_ipv6(const std::array<std::uint8_t, 16>& bytes);

/// Classify a socket address, which is the form libcurl hands over right
/// before it connects.
[[nodiscard]] AddressVerdict classify(const sockaddr* address);

/// Classify a textual address. Used by the tests and by the configuration
/// validator; the live path always classifies a sockaddr.
[[nodiscard]] AddressVerdict classify_text(std::string_view address);

}  // namespace arapuca::capture
