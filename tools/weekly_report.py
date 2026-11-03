#!/usr/bin/env python3
"""Generate the weekly report from the honeypot's own telemetry.

Writes reports/YYYY-Www.md and refreshes reports/latest.md.

The report is written for someone who was not watching: it answers what
changed this week, not what the dashboards already show live. Where a number
is zero that is said plainly rather than hidden, because a quiet week on a
public address usually means the sensor broke.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from collections import OrderedDict
from datetime import UTC, date, datetime
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from nerdgraph import run_nrql, settings_from_environment

SCOPE = "logtype = 'arapuca'"
WINDOW = "SINCE 7 days ago"
PREVIOUS = "SINCE 14 days ago UNTIL 7 days ago"

QUERIES: OrderedDict[str, str] = OrderedDict(
    totals=f"SELECT count(*) AS events, uniqueCount(src_ip) AS attackers, "
    f"uniqueCount(session_id) AS sessions FROM Log WHERE {SCOPE} {{window}}",
    by_service=f"SELECT count(*) FROM Log WHERE {SCOPE} FACET service {{window}}",
    top_passwords=f"SELECT count(*) AS attempts FROM Log WHERE {SCOPE} AND event_type "
    f"IN ('ssh.auth_attempt', 'http.login_attempt') FACET password LIMIT 15 {{window}}",
    top_usernames=f"SELECT count(*) AS attempts FROM Log WHERE {SCOPE} AND event_type "
    f"IN ('ssh.auth_attempt', 'http.login_attempt') FACET username LIMIT 15 {{window}}",
    accepted=f"SELECT count(*) AS sessions FROM Log WHERE {SCOPE} AND "
    f"event_type = 'ssh.auth_attempt' AND accepted IS TRUE FACET username, password "
    f"LIMIT 10 {{window}}",
    top_commands=f"SELECT count(*) AS seen FROM Log WHERE {SCOPE} AND "
    f"event_type = 'ssh.command' FACET command LIMIT 20 {{window}}",
    countries=f"SELECT count(*) FROM Log WHERE {SCOPE} AND geo.country IS NOT NULL "
    f"FACET geo.country LIMIT 15 {{window}}",
    techniques=f"SELECT count(*) FROM Log WHERE {SCOPE} AND mitre.technique_id IS NOT NULL "
    f"FACET mitre.technique_id, mitre.technique LIMIT 15 {{window}}",
    decoys=f"SELECT count(*) AS hits FROM Log WHERE {SCOPE} AND decoy IS NOT NULL "
    f"FACET decoy LIMIT 15 {{window}}",
    samples=f"SELECT latest(url) AS url, latest(size_bytes) AS size, "
    f"latest(vt_popular_label) AS label FROM Log WHERE {SCOPE} AND "
    f"event_type = 'capture.download' AND quarantined IS TRUE AND duplicate IS FALSE "
    f"FACET sha256 LIMIT 25 {{window}}",
    blocked=f"SELECT count(*) AS attempts FROM Log WHERE {SCOPE} AND "
    f"outcome = 'blocked_address' FACET blocked_range LIMIT 10 {{window}}",
    denied=f"SELECT count(*) AS attempts FROM Log WHERE {SCOPE} AND "
    f"event_type = 'ssh.channel_denied' FACET request_type LIMIT 10 {{window}}",
    classification=f"SELECT count(*) FROM Log WHERE {SCOPE} AND "
    f"event_type = 'ssh.session_end' FACET classification {{window}}",
    unknown_commands=f"SELECT count(*) AS seen FROM Log WHERE {SCOPE} AND "
    f"event_type = 'ssh.command' AND unknown IS TRUE FACET command_argv0 LIMIT 15 {{window}}",
)


def facet_of(row: dict[str, Any]) -> str:
    value = row.get("facet")
    if isinstance(value, list):
        return " / ".join(str(item) for item in value)
    return str(value) if value is not None else ""


def first_number(row: dict[str, Any]) -> int:
    for key, value in row.items():
        if key != "facet" and isinstance(value, (int, float)):
            return int(value)
    return 0


def table(rows: list[dict[str, Any]], label: str, value_label: str = "count") -> str:
    if not rows:
        return "_Nothing recorded this week._\n"
    lines = [f"| {label} | {value_label} |", "|---|---:|"]
    for row in rows:
        name = facet_of(row).replace("|", "\\|") or "(empty)"
        lines.append(f"| `{name}` | {first_number(row):,} |")
    return "\n".join(lines) + "\n"


def change(current: int, previous: int) -> str:
    """Describe a change without pretending to more precision than exists."""
    if previous == 0:
        return "no comparable week" if current == 0 else "first week with data"
    delta = (current - previous) / previous * 100
    if abs(delta) < 5:
        return "about the same as the week before"
    direction = "up" if delta > 0 else "down"
    return f"{direction} {abs(delta):.0f}% on the week before"


def build(results: dict[str, Any], previous: dict[str, Any], week: str) -> str:
    totals = (results["totals"] or [{}])[0]
    before = (previous["totals"] or [{}])[0]

    events = int(totals.get("events") or 0)
    attackers = int(totals.get("attackers") or 0)
    sessions = int(totals.get("sessions") or 0)

    samples = results["samples"]
    blocked = results["blocked"]

    parts = [
        f"# Arapuca weekly report, {week}",
        "",
        f"_Generated {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M UTC')} "
        "from the sensor's own telemetry._",
        "",
        "## Summary",
        "",
        f"- **{events:,} events** from **{attackers:,} distinct addresses** "
        f"across **{sessions:,} sessions** ({change(events, int(before.get('events') or 0))}).",
        f"- **{len(samples)} new samples** captured and quarantined.",
        f"- **{sum(first_number(row) for row in blocked)} download attempts refused** "
        "by the address policy.",
        "",
    ]

    if events == 0:
        parts += [
            "> **No events at all this week.** On a public address that is almost",
            "> never real. Check that the sensor is running, that the log shipper",
            "> is forwarding, and that the disk is not full.",
            "",
        ]

    parts += [
        "## Credentials tried",
        "",
        "These are the passwords being sprayed at the internet right now. The",
        "honeypot accepts only a short list, so most of these failed and were",
        "recorded anyway: a refused login is as much of a product as an accepted",
        "one.",
        "",
        "### Passwords",
        "",
        table(results["top_passwords"], "password", "attempts"),
        "",
        "### Usernames",
        "",
        table(results["top_usernames"], "username", "attempts"),
        "",
        "### Credentials that worked",
        "",
        "Pairs that matched the weak credential list, meaning the session reached",
        "the fake shell. These are the sessions worth reading.",
        "",
        table(results["accepted"], "username / password", "sessions"),
        "",
        "## What they did once inside",
        "",
        table(results["top_commands"], "command", "times"),
        "",
        "### Commands the shell does not implement",
        "",
        "Automated traffic repeats itself, so an unrecognised command usually",
        "means a person or a toolkit not seen here before. Worth implementing the",
        "common ones: a shell that answers more convincingly keeps attackers",
        "longer.",
        "",
        table(results["unknown_commands"], "command", "times"),
        "",
        "## MITRE ATT&CK",
        "",
        table(results["techniques"], "technique", "events"),
        "",
        "## Where from",
        "",
        table(results["countries"], "country", "events"),
        "",
        "## Sessions",
        "",
        table(results["classification"], "classification", "sessions"),
        "",
        "Classification is by rhythm, not content: a script pastes commands at",
        "machine speed with almost no variation, a person pauses to read, mistypes",
        "and uses the line editor. `unknown` means the session was too short to",
        "carry evidence either way, which is most of them.",
        "",
        "## Decoy files taken",
        "",
        "Whoever took these credentials will use them somewhere, and that use is",
        "visible from elsewhere. Every value in them is fabricated.",
        "",
        table(results["decoys"], "decoy", "hits"),
        "",
        "## Samples captured",
        "",
    ]

    if samples:
        parts += [
            "| sha256 | size | URL | VirusTotal label |",
            "|---|---:|---|---|",
        ]
        for row in samples:
            sha = facet_of(row)
            url = str(row.get("url") or "").replace("|", "\\|")[:80]
            label = str(row.get("label") or "unknown to VirusTotal")
            size = int(row.get("size") or 0)
            parts.append(f"| `{sha[:16]}...` | {size:,} | `{url}` | {label} |")
        parts += [
            "",
            "Each one is in quarantine as `<sha256>.zip`, encrypted with the",
            "password `infected`, stored read only, and never executed. A hash",
            "VirusTotal does not recognise is the most interesting outcome: nobody",
            "has seen that sample yet.",
        ]
    else:
        parts.append("_No new samples this week._")

    parts += [
        "",
        "## Refused by the honeypot's own limits",
        "",
        "### Download attempts to blocked ranges",
        "",
        "An attacker aiming the honeypot at a private range or at the cloud",
        "metadata service. The address is checked after resolution and before",
        "every connect, so none of these reached anything.",
        "",
        table(results["blocked"], "range", "attempts"),
        "",
        "### SSH channel requests refused",
        "",
        "Port forwarding and subsystem requests. Someone wanted a proxy or a file",
        "transfer, not a shell.",
        "",
        table(results["denied"], "request type", "attempts"),
        "",
        "---",
        "",
        "Generated by `tools/weekly_report.py`. Every figure comes from events this",
        "sensor recorded itself.",
        "",
    ]

    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports", help="directory to write into")
    arguments = parser.parse_args()

    api = settings_from_environment()

    results = {
        name: run_nrql(query.format(window=WINDOW), **api) for name, query in QUERIES.items()
    }
    previous = {"totals": run_nrql(QUERIES["totals"].format(window=PREVIOUS), **api)}

    today = date.today()
    week = f"{today.isocalendar().year}-W{today.isocalendar().week:02d}"

    directory = pathlib.Path(arguments.output)
    directory.mkdir(parents=True, exist_ok=True)

    content = build(results, previous, week)
    (directory / f"{week}.md").write_text(content, encoding="utf-8")
    (directory / "latest.md").write_text(content, encoding="utf-8")

    print(f"wrote reports/{week}.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
