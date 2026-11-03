// The Telnet wire protocol, reduced to what a honeypot needs: strip the IAC
// negotiation out of the byte stream, hand back the plain text the attacker
// typed, and answer every option negotiation with a refusal so the session
// stays in the default line mode.
//
// This is the one attacker facing parser the Telnet service adds, so it is
// written to be driven by the fuzzer: a pure state machine over bytes, with
// no sockets and no allocation the caller cannot bound.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace arapuca::telnet {

// The Telnet command bytes this honeypot recognises. The rest of the protocol
// is swallowed rather than interpreted.
inline constexpr unsigned char kIac = 255;   // interpret as command
inline constexpr unsigned char kSe = 240;    // end of subnegotiation
inline constexpr unsigned char kSb = 250;    // begin subnegotiation
inline constexpr unsigned char kWill = 251;  // peer will enable an option
inline constexpr unsigned char kWont = 252;  // peer will not
inline constexpr unsigned char kDo = 253;    // peer asks us to enable
inline constexpr unsigned char kDont = 254;  // peer asks us not to

/// Decodes a Telnet byte stream across arbitrary chunk boundaries. One decoder
/// per session: an IAC sequence split between two reads is remembered here.
class Decoder {
public:
    struct Output {
        std::string clean;     ///< the data bytes, with all IAC removed
        std::string response;  ///< negotiation replies to send back, may be empty
    };

    /// Consume a chunk. Returns the plain bytes it contained and whatever must
    /// be written back to keep the peer in line mode.
    [[nodiscard]] Output feed(std::string_view bytes);

    /// How many option negotiations have been answered. Past the limit the
    /// decoder keeps parsing but stops replying, so a peer that only
    /// negotiates cannot grow the response without bound.
    [[nodiscard]] std::size_t negotiations() const {
        return negotiations_;
    }

private:
    enum class State : std::uint8_t {
        Data,       ///< ordinary bytes
        Iac,        ///< saw IAC, the next byte is a command
        Option,     ///< saw IAC WILL/WONT/DO/DONT, the next byte is the option
        Subneg,     ///< inside IAC SB ... swallowing
        SubnegIac,  ///< saw IAC inside a subnegotiation, expecting SE
    };

    State state_ = State::Data;
    unsigned char command_ = 0;
    std::size_t negotiations_ = 0;
};

}  // namespace arapuca::telnet
