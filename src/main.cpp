// Arapuca honeypot daemon.
//
// Safety invariant S1: this process never executes anything an attacker sends.
// There is no call to system(), exec*(), popen() or fork() of a shell anywhere
// in this codebase, and scripts/check_no_exec.sh enforces that in CI.

#include <arapuca/version.hpp>

#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

void print_usage(std::ostream& out) {
    out << "Arapuca, a medium interaction SSH and HTTP honeypot.\n"
           "\n"
           "Usage:\n"
           "  arapucad [options]\n"
           "\n"
           "Options:\n"
           "  -c, --config <path>   Path to arapuca.yaml (default: config/arapuca.yaml)\n"
           "  -v, --version         Print the version and exit\n"
           "  -h, --help            Print this help and exit\n"
           "\n"
           "Arapuca records attacker interactions and never executes them.\n";
}

}  // namespace

int main(int argc, char** argv) {
    // A span rather than pointer arithmetic on argv, so the bound comes from
    // argc once instead of being recomputed at every use.
    const std::span<char*> raw(argv, static_cast<std::size_t>(argc));
    std::vector<std::string_view> args;
    args.reserve(raw.empty() ? 0 : raw.size() - 1);
    for (const auto* argument : raw.subspan(raw.empty() ? 0 : 1)) {
        args.emplace_back(argument);
    }

    for (const auto& arg : args) {
        if (arg == "-h" || arg == "--help") {
            print_usage(std::cout);
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::cout << arapuca::build_banner() << '\n';
            return 0;
        }
    }

    // Phase 0 is the build system skeleton. The service wiring lands in the
    // phases that follow: core event pipeline, enrichment, SSH, HTTP, capture.
    std::cout << arapuca::build_banner() << '\n';
    std::cerr << "no services configured yet, see PLAN.md for the phase roadmap\n";
    return 0;
}
