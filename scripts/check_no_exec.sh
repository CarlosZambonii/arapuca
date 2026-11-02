#!/usr/bin/env bash
# Safety invariant S1: Arapuca never executes attacker input.
#
# This check fails the build if any process spawning primitive appears in the
# C++ sources. It is intentionally blunt: there is no legitimate reason for this
# codebase to contain any of them, so there is no allowlist to argue about.
#
# Comments and string literals are stripped before matching, so prose that
# merely names these functions (such as the banner comment in main.cpp) does not
# trip the check, while real calls still do.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - "$@" <<'PYEOF'
import pathlib
import re
import sys

FORBIDDEN = re.compile(
    r"\b(system|popen|execl|execlp|execle|execv|execvp|execvpe|execve"
    r"|posix_spawn|posix_spawnp|fork|vfork|wordexp)\s*\("
)

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")
STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"', re.DOTALL)


def blank_out(match: re.Match) -> str:
    """Replace a span with blanks, keeping newlines so line numbers survive."""
    return "".join(ch if ch == "\n" else " " for ch in match.group(0))


failed = False
checked = 0

for root in ("src", "include"):
    for path in sorted(pathlib.Path(root).rglob("*")):
        if path.suffix not in (".cpp", ".hpp", ".cc", ".h", ".in"):
            continue
        checked += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        code = BLOCK_COMMENT.sub(blank_out, text)
        code = LINE_COMMENT.sub(blank_out, code)
        code = STRING_LITERAL.sub(blank_out, code)
        for number, line in enumerate(code.splitlines(), start=1):
            if FORBIDDEN.search(line):
                print(f"FAIL: process execution primitive in {path}:{number}")
                print(f"    {text.splitlines()[number - 1].strip()}")
                failed = True

if failed:
    sys.exit(1)

print(f"OK: no process execution primitives in {checked} source files")
PYEOF
