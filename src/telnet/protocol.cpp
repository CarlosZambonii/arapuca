#include <arapuca/core/limits.hpp>
#include <arapuca/telnet/protocol.hpp>

namespace arapuca::telnet {

Decoder::Output Decoder::feed(std::string_view bytes) {
    Output out;
    out.clean.reserve(bytes.size());

    for (const char raw : bytes) {
        const auto byte = static_cast<unsigned char>(raw);

        switch (state_) {
            case State::Data:
                if (byte == kIac) {
                    state_ = State::Iac;
                } else {
                    out.clean.push_back(raw);
                }
                break;

            case State::Iac:
                if (byte == kIac) {
                    // IAC IAC is a literal 0xFF in the data stream.
                    out.clean.push_back(static_cast<char>(kIac));
                    state_ = State::Data;
                } else if (byte == kWill || byte == kWont || byte == kDo || byte == kDont) {
                    command_ = byte;
                    state_ = State::Option;
                } else if (byte == kSb) {
                    state_ = State::Subneg;
                } else {
                    // A two byte command with no option: NOP, GA, and the rest.
                    // Nothing to answer and nothing to record.
                    state_ = State::Data;
                }
                break;

            case State::Option: {
                // Refuse every option, which keeps the peer in the default line
                // mode where it buffers a line and sends it on the newline. A
                // request that we do something is answered WONT, a claim that
                // the peer will do something is answered DONT.
                if (negotiations_ < limits::kMaxTelnetNegotiations) {
                    const unsigned char reply =
                        (command_ == kDo || command_ == kDont) ? kWont : kDont;
                    out.response.push_back(static_cast<char>(kIac));
                    out.response.push_back(static_cast<char>(reply));
                    out.response.push_back(raw);
                    ++negotiations_;
                }
                state_ = State::Data;
                break;
            }

            case State::Subneg:
                // Swallow subnegotiation payload until its terminating IAC SE.
                if (byte == kIac) {
                    state_ = State::SubnegIac;
                }
                break;

            case State::SubnegIac:
                if (byte == kSe) {
                    state_ = State::Data;
                } else {
                    // An escaped IAC inside the subnegotiation, or anything
                    // unexpected: keep swallowing until a real SE arrives.
                    state_ = State::Subneg;
                }
                break;
        }
    }

    return out;
}

}  // namespace arapuca::telnet
