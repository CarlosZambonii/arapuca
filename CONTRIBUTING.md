# Contributing

Pull requests are welcome, including ones that only tell me the code is
wrong. Before opening one, two things are worth knowing: what the gates
expect, and the conventions that are not negotiable because they are what the
repository is demonstrating.

## Run the gates before you push

```bash
./scripts/verify.sh          # everything CI runs, locally, in one command
./scripts/verify.sh quick    # format, debug build and tests only
./scripts/coverage.sh        # line and branch coverage, with an HTML report
```

`verify.sh` is the whole gate: formatting, the no execution check, the text
rules, a debug build and tests, a release build and tests, AddressSanitizer
and UndefinedBehaviorSanitizer, ThreadSanitizer, and clang-tidy. It takes a
while. It takes less time than a CI round trip.

The Python in `tools/` has its own gate:

```bash
pip install -r tools/requirements.txt -r tools/requirements-dev.txt
ruff check . && ruff format --check . && mypy
```

## Safety invariants

`PLAN.md` section 2 lists ten invariants, with the enforcement for each. They
are not preferences. A change that weakens one is a defect even if every test
passes, and the two that have automated enforcement will simply fail the
build:

* **Nothing an attacker sends is ever executed.** `scripts/check_no_exec.sh`
  fails the build if `system`, `exec*`, `popen` or `fork` appears in the
  sources.
* **Every attacker controlled bound lives in `include/arapuca/core/limits.hpp`**,
  not inline at the point of use. New attacker facing input gets its bound
  there.

## Conventions

* **Code, comments, commit messages and documentation in English.** The
  conversation can be in any language; the repository is read in English.
* **No em dashes**, anywhere, including documentation. Use a comma, a colon or
  parentheses. `scripts/check_text_rules.sh` enforces this, along with the
  rule that the sensor's public address is never committed.
* **Conventional Commits**: `feat(ssh):`, `fix(capture):`, `docs:`, `test:`,
  `chore(deps):`. The subject line says what changed, the body says why.
* **A comment explains why, not what.** The code already says what it does. If
  a line is surprising, the comment is the place the surprise is explained.
* **One logical change per pull request**, with its tests in the same commit.

## Tests

A bug fix comes with the test that fails without it. A new attacker facing
parser comes with a fuzz target in `tests/fuzz/` and a seed corpus. A crash
the fuzzer finds is committed to `tests/fuzz/crashes/`, which the ordinary
build replays as a CTest case, so a regression found once stays found.
