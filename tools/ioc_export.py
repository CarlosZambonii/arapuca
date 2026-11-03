#!/usr/bin/env python3
"""Export indicators of compromise from the honeypot's own telemetry.

Writes two pairs of files under iocs/:

    iocs/ips-<date>.csv / .json      source addresses seen attacking
    iocs/hashes-<date>.csv / .json   sha256 of samples captured

plus iocs/latest-ips.csv and iocs/latest-hashes.csv, which are stable paths
something else can fetch without knowing today's date.

Everything published here was observed by this sensor. An address appears
because it connected to a machine that advertises nothing and serves nobody,
which is why there is no confidence score: there is nothing to be unsure
about.
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys
from datetime import UTC, date, datetime
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from nerdgraph import ApiSettings, run_nrql, settings_from_environment

IPS_QUERY = """
SELECT count(*) AS events,
       uniqueCount(session_id) AS sessions,
       earliest(timestamp) AS first_seen,
       latest(timestamp) AS last_seen,
       latest(geo.country_iso) AS country,
       latest(geo.as_org) AS network
FROM Log
WHERE logtype = 'arapuca' AND src_ip IS NOT NULL AND src_ip != ''
FACET src_ip
LIMIT MAX
SINCE {window}
"""

HASHES_QUERY = """
SELECT count(*) AS captures,
       latest(url) AS url,
       latest(size_bytes) AS size_bytes,
       latest(md5) AS md5,
       earliest(timestamp) AS first_seen
FROM Log
WHERE logtype = 'arapuca' AND event_type = 'capture.download'
      AND quarantined IS TRUE AND sha256 IS NOT NULL
FACET sha256
LIMIT MAX
SINCE {window}
"""

VT_QUERY = """
SELECT latest(vt_detections) AS detections,
       latest(vt_total_engines) AS engines,
       latest(vt_popular_label) AS label
FROM Log
WHERE logtype = 'arapuca' AND event_type = 'capture.vt_lookup'
FACET sha256
LIMIT MAX
SINCE {window}
"""


def facet_of(row: dict[str, Any]) -> str:
    """NerdGraph returns the facet value under 'facet'."""
    value = row.get("facet")
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def as_timestamp(value: Any) -> str:
    """Milliseconds since the epoch to an ISO 8601 string."""
    if not value:
        return ""
    try:
        return (
            datetime.fromtimestamp(float(value) / 1000.0, tz=UTC).isoformat().replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OSError):
        return ""


def write_csv(path: pathlib.Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect_ips(window: str, api: ApiSettings) -> list[dict[str, Any]]:
    rows = run_nrql(IPS_QUERY.format(window=window), **api)
    out: list[dict[str, Any]] = []
    for row in rows:
        address = facet_of(row)
        if not address:
            continue
        out.append(
            {
                "ip": address,
                "events": int(row.get("events") or 0),
                "sessions": int(row.get("sessions") or 0),
                "first_seen": as_timestamp(row.get("first_seen")),
                "last_seen": as_timestamp(row.get("last_seen")),
                "country": row.get("country") or "",
                "network": row.get("network") or "",
            }
        )
    out.sort(key=lambda item: item["events"], reverse=True)
    return out


def collect_hashes(window: str, api: ApiSettings) -> list[dict[str, Any]]:
    samples = run_nrql(HASHES_QUERY.format(window=window), **api)
    verdicts = {facet_of(row): row for row in run_nrql(VT_QUERY.format(window=window), **api)}

    out: list[dict[str, Any]] = []
    for row in samples:
        sha256 = facet_of(row)
        if not sha256:
            continue
        verdict = verdicts.get(sha256, {})
        out.append(
            {
                "sha256": sha256,
                "md5": row.get("md5") or "",
                "size_bytes": int(row.get("size_bytes") or 0),
                "url": row.get("url") or "",
                "captures": int(row.get("captures") or 0),
                "first_seen": as_timestamp(row.get("first_seen")),
                "vt_detections": verdict.get("detections"),
                "vt_total_engines": verdict.get("engines"),
                "vt_label": verdict.get("label") or "",
            }
        )
    out.sort(key=lambda item: item["first_seen"], reverse=True)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--window",
        default="1 day ago",
        help="NRQL SINCE window, for example '1 day ago' or '7 days ago'",
    )
    parser.add_argument("--output", default="iocs", help="directory to write into")
    arguments = parser.parse_args()

    api = settings_from_environment()

    ips = collect_ips(arguments.window, api)
    hashes = collect_hashes(arguments.window, api)

    today = date.today().isoformat()
    directory = pathlib.Path(arguments.output)

    generated = {
        "generated_at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
        "window": arguments.window,
        "source": "arapuca honeypot, self observed",
    }

    ip_columns = ["ip", "events", "sessions", "first_seen", "last_seen", "country", "network"]
    hash_columns = [
        "sha256",
        "md5",
        "size_bytes",
        "url",
        "captures",
        "first_seen",
        "vt_detections",
        "vt_total_engines",
        "vt_label",
    ]

    write_csv(directory / f"ips-{today}.csv", ips, ip_columns)
    write_csv(directory / "latest-ips.csv", ips, ip_columns)
    write_json(directory / f"ips-{today}.json", {**generated, "count": len(ips), "ips": ips})

    write_csv(directory / f"hashes-{today}.csv", hashes, hash_columns)
    write_csv(directory / "latest-hashes.csv", hashes, hash_columns)
    write_json(
        directory / f"hashes-{today}.json",
        {**generated, "count": len(hashes), "hashes": hashes},
    )

    print(f"wrote {len(ips)} addresses and {len(hashes)} hashes for {today}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
