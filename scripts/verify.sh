#!/usr/bin/env bash
# Everything CI runs, locally, in one command.
#
# This exists because a Debug only check is not the same check. GCC enables
# analyses under optimization that it cannot perform at -O0, and a warning
# that only appears in a release build reached CI once because the local gate
# only ever built the dev preset.
#
#   ./scripts/verify.sh          everything
#   ./scripts/verify.sh quick    format, dev build and tests only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:-full}"
failures=0

step() { printf '\n== %s ==\n' "$1"; }
check() {
    if "$@"; then
        return 0
    fi
    printf 'FAILED: %s\n' "$*"
    failures=$((failures + 1))
}

step "formatting"
mapfile -t sources < <(find src include tests -type f \( -name '*.cpp' -o -name '*.hpp' \))
check clang-format --dry-run --Werror "${sources[@]}"

step "safety and text rules"
check ./scripts/check_no_exec.sh
check ./scripts/check_text_rules.sh

step "debug build and tests"
check cmake --preset dev
check cmake --build --preset dev
check ctest --preset dev

if [ "$MODE" = "quick" ]; then
    printf '\n%s\n' "quick check done, $failures failure(s)"
    exit "$failures"
fi

# The one that caught a real defect that Debug could not see.
step "release build and tests"
check cmake --preset release
check cmake --build --preset release
check ctest --preset release

step "sanitizers, address and undefined behaviour"
check cmake --preset asan
check cmake --build --preset asan
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    check ctest --preset asan

# The honeypot is threaded by nature: an accept loop per service, a capture
# worker, a bounded bus and a sink shared between them. ASan cannot see a
# data race, and this project had a preset for TSan that nothing ever ran.
# setarch -R disables address space randomisation for the child. Without it
# ThreadSanitizer aborts with "unexpected memory mapping" on any kernel built
# with 32 bits of mmap entropy, which is every current Ubuntu, and it aborts
# during the build: gtest_discover_tests runs the binary to enumerate the
# tests. The alternative is sysctl vm.mmap_rnd_bits=28, which needs root.
step "sanitizers, threads"
check cmake --preset tsan
check setarch -R cmake --build --preset tsan
TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 \
    check setarch -R ctest --preset tsan

step "clang-tidy"
check cmake --preset tidy
check cmake --build --preset tidy

printf '\n%s\n' "verification done, $failures failure(s)"
exit "$failures"
