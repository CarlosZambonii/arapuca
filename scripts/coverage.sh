#!/usr/bin/env bash
# Line and branch coverage over the whole test suite.
#
#   ./scripts/coverage.sh            measure, print a summary, fail under the floor
#   MIN_LINE=0 ./scripts/coverage.sh just measure
#
# Leaves build/coverage/report/index.html behind, which is the useful part:
# the percentage is a number to defend, the annotated source is what shows
# which branch of the address policy nothing has ever exercised.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Floors, not targets. They exist to catch a change that deletes tests, not to
# be chased upwards with tests that assert nothing.
# Measured at 74.6% line and 65.0% branch when these were set. The floors sit
# a little under that: enough slack that an ordinary change does not trip them,
# tight enough that deleting a test suite does.
MIN_LINE="${MIN_LINE:-70}"
MIN_BRANCH="${MIN_BRANCH:-55}"

if ! command -v gcovr >/dev/null 2>&1; then
    echo "gcovr is not installed: pip install gcovr" >&2
    exit 1
fi

cmake --preset coverage
cmake --build --preset coverage
ctest --preset coverage

mkdir -p build/coverage/report

# Only this project's own sources are measured. The fetched dependencies and
# the test files themselves would both flatter the number.
gcovr \
    --root "$ROOT" \
    --filter 'src/' \
    --filter 'include/arapuca/' \
    --exclude '.*/build/.*' \
    --exclude-unreachable-branches \
    --exclude-throw-branches \
    --print-summary \
    --html-details build/coverage/report/index.html \
    --xml-pretty --output build/coverage/coverage.xml \
    --fail-under-line "$MIN_LINE" \
    --fail-under-branch "$MIN_BRANCH"

echo
echo "report: build/coverage/report/index.html"
