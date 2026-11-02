// Arapuca honeypot daemon.
//
// Safety invariant S1: this process never executes anything an attacker sends.
// There is no call to system(), exec*(), popen() or fork() of a shell anywhere
// in this codebase, and scripts/check_no_exec.sh enforces that in CI.

#include <arapuca/version.hpp>

#include <cstdio>
#include <string_view>
#include <vector>

namespace {

void print_usage() {
    std::fputs(
        "Arapuca, a medium interaction SSH and HTTP honeypot.\n"
        "\n"
        "Usage:\n"
        "  arapucad [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Path to arapuca.yaml (default: config/arapuca.yaml)\n"
        "  -v, --version         Print the version and exit\n"
        "  -h, --help            Print this help and exit\n"
        "\n"
        "Arapuca records attacker interactions and never executes them.\n",
        stdout);
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<std::string_view> args(argv + 1, argv + argc);

    for (const auto& arg : args) {
        if (arg == "-h" || arg == "--help") {
            print_usage();
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::printf("%s\n", arapuca::build_banner().c_str());
            return 0;
        }
    }

    // Phase 0 is the build system skeleton. The service wiring lands in the
    // phases that follow: core event pipeline, enrichment, SSH, HTTP, capture.
    std::printf("%s\n", arapuca::build_banner().c_str());
    std::fputs("no services configured yet, see PLAN.md for the phase roadmap\n", stderr);
    return 0;
}
