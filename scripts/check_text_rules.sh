#!/usr/bin/env bash
# Project text conventions:
#   1. No em dash anywhere. Commas, colons and parentheses instead.
#   2. No real VPS address committed. A public IPv4 literal in the deployment
#      or configuration directories is almost always an accident.
#
# Only files tracked by git are checked, so build output and fetched third party
# sources are out of scope. The em dash is written as an escape below so this
# script does not fail its own check.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EM_DASH=$'\xe2\x80\x94'
status=0

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "SKIP: not a git work tree, nothing to check"
    exit 0
fi

mapfile -t -d '' tracked < <(git ls-files -z)

echo "== em dash check =="
found_em_dash=0
for file in "${tracked[@]}"; do
    case "$file" in
        *.md|*.cpp|*.hpp|*.yml|*.yaml|*.tf|*.py|*.sh|*.json|*.in|*.txt) ;;
        *) continue ;;
    esac
    if matches=$(grep -n -- "$EM_DASH" "$file" 2>/dev/null); then
        echo "FAIL: em dash in $file"
        echo "$matches" | sed 's/^/    /'
        found_em_dash=1
    fi
done
if [ "$found_em_dash" -eq 0 ]; then
    echo "OK: no em dash in tracked files"
else
    status=1
fi

echo "== hardcoded public address check =="
# Private, loopback, link local, documentation and example ranges are fine.
ALLOWED='^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|224\.|240\.|255\.)'
scoped=()
for file in "${tracked[@]}"; do
    case "$file" in
        deploy/*|config/*) scoped+=("$file") ;;
    esac
done

if [ ${#scoped[@]} -gt 0 ]; then
    found=$(grep -rhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${scoped[@]}" 2>/dev/null \
        | sort -u | grep -vE "$ALLOWED" || true)
    if [ -n "$found" ]; then
        echo "FAIL: public IPv4 literal in deploy/ or config/"
        echo "$found" | sed 's/^/    /'
        status=1
    else
        echo "OK: no public IPv4 literal committed"
    fi
else
    echo "OK: no deploy/ or config/ files tracked yet"
fi

exit "$status"
