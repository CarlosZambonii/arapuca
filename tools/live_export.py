#!/usr/bin/env python3
"""Export the public live view of the honeypot.

Reads the sensor's own telemetry back out of New Relic through NerdGraph and
writes web/data/live.json, which the public page renders. The New Relic key
stays here, in CI, and never reaches a browser: a page that queried the API
directly would hand every visitor read access to the whole account.

The page is a public invitation to attack the sensor, so what it publishes is
deliberately coarser than what the IoC feed publishes:

  * Source addresses are shown with the last octet masked. An attacker can
    still recognise their own attempt, and a bystander is not named.
  * Passwords are shown because they are the product of the honeypot and are
    not anybody's secret: they are what is being sprayed at the internet.
  * Nothing identifies the operator's own access path.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from nerdgraph import run_nrql, settings_from_environment

SCOPE = "logtype = 'arapuca'"

# ISO 3166-1 alpha-2 to numeric, packed as fixed five character blocks.
# The world map's geometry is keyed on the numeric code, and the honeypot
# records the alpha-2 one, so something has to bridge them. Generated once
# from the iso-codes package rather than fetched at runtime, so the export has
# no dependency that can disappear.
_ISO_PACKED = (
    "AD020AE784AF004AG028AI660AL008AM051AO024AQ010AR032AS016AT040"
    "AU036AW533AX248AZ031BA070BB052BD050BE056BF854BG100BH048BI108"
    "BJ204BL652BM060BN096BO068BQ535BR076BS044BT064BV074BW072BY112"
    "BZ084CA124CC166CD180CF140CG178CH756CI384CK184CL152CM120CN156"
    "CO170CR188CU192CV132CW531CX162CY196CZ203DE276DJ262DK208DM212"
    "DO214DZ012EC218EE233EG818EH732ER232ES724ET231FI246FJ242FK238"
    "FM583FO234FR250GA266GB826GD308GE268GF254GG831GH288GI292GL304"
    "GM270GN324GP312GQ226GR300GS239GT320GU316GW624GY328HK344HM334"
    "HN340HR191HT332HU348ID360IE372IL376IM833IN356IO086IQ368IR364"
    "IS352IT380JE832JM388JO400JP392KE404KG417KH116KI296KM174KN659"
    "KP408KR410KW414KY136KZ398LA418LB422LC662LI438LK144LR430LS426"
    "LT440LU442LV428LY434MA504MC492MD498ME499MF663MG450MH584MK807"
    "ML466MM104MN496MO446MP580MQ474MR478MS500MT470MU480MV462MW454"
    "MX484MY458MZ508NA516NC540NE562NF574NG566NI558NL528NO578NP524"
    "NR520NU570NZ554OM512PA591PE604PF258PG598PH608PK586PL616PM666"
    "PN612PR630PS275PT620PW585PY600QA634RE638RO642RS688RU643RW646"
    "SA682SB090SC690SD729SE752SG702SH654SI705SJ744SK703SL694SM674"
    "SN686SO706SR740SS728ST678SV222SX534SY760SZ748TC796TD148TF260"
    "TG768TH764TJ762TK772TL626TM795TN788TO776TR792TT780TV798TW158"
    "TZ834UA804UG800UM581US840UY858UZ860VA336VC670VE862VG092VI850"
    "VN704VU548WF876WS882YE887YT175ZA710ZM894ZW716"
)

ISO_NUMERIC = {
    _ISO_PACKED[i : i + 2]: _ISO_PACKED[i + 2 : i + 5] for i in range(0, len(_ISO_PACKED), 5)
}

QUERIES = {
    "totals": f"SELECT count(*) AS events, uniqueCount(src_ip) AS attackers, "
    f"uniqueCount(session_id) AS sessions FROM Log WHERE {SCOPE} SINCE 30 days ago",
    "captures": f"SELECT uniqueCount(sha256) AS samples FROM Log WHERE {SCOPE} "
    f"AND event_type = 'capture.download' AND quarantined IS TRUE SINCE 30 days ago",
    "countries": f"SELECT count(*) AS attacks, uniqueCount(src_ip) AS attackers "
    f"FROM Log WHERE {SCOPE} AND geo.country_iso IS NOT NULL "
    f"FACET geo.country_iso, geo.country LIMIT MAX SINCE 30 days ago",
    "passwords": f"SELECT count(*) AS tries FROM Log WHERE {SCOPE} AND event_type "
    f"IN ('ssh.auth_attempt', 'http.login_attempt') FACET password LIMIT 12 SINCE 30 days ago",
    "usernames": f"SELECT count(*) AS tries FROM Log WHERE {SCOPE} AND event_type "
    f"IN ('ssh.auth_attempt', 'http.login_attempt') FACET username LIMIT 12 SINCE 30 days ago",
    "commands": f"SELECT count(*) AS seen FROM Log WHERE {SCOPE} AND "
    f"event_type = 'ssh.command' FACET command LIMIT 12 SINCE 30 days ago",
    "techniques": f"SELECT count(*) AS events FROM Log WHERE {SCOPE} AND "
    f"mitre.technique_id IS NOT NULL FACET mitre.technique_id, mitre.technique "
    f"LIMIT 10 SINCE 30 days ago",
    "recent": f"SELECT timestamp, src_ip, geo.country_iso, event_type, username, "
    f"password, command FROM Log WHERE {SCOPE} AND event_type "
    f"IN ('ssh.auth_attempt', 'ssh.command', 'http.login_attempt') "
    f"LIMIT 40 SINCE 2 days ago",
    "daily": f"SELECT count(*) FROM Log WHERE {SCOPE} TIMESERIES 1 day SINCE 30 days ago",
    # The attack map needs a point, not a country: the city facet carries the
    # coordinates, and latest() is enough because every event from one city
    # resolves to the same place.
    "origins": f"SELECT count(*) AS attacks, uniqueCount(src_ip) AS attackers, "
    f"latest(geo.latitude) AS lat, latest(geo.longitude) AS lon "
    f"FROM Log WHERE {SCOPE} AND geo.city IS NOT NULL AND geo.city != '' "
    f"FACET geo.city, geo.country_iso, geo.country LIMIT 60 SINCE 30 days ago",
    # How many events the map can actually draw. The page states the gap
    # rather than letting the counters and the map quietly disagree.
    "located": f"SELECT count(*) AS located FROM Log WHERE {SCOPE} "
    f"AND geo.country_iso IS NOT NULL SINCE 30 days ago",
}


def facet(row: dict[str, Any]) -> list[str]:
    value = row.get("facet")
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)] if value is not None else []


def mask(address: str) -> str:
    """Mask the host part of an address.

    An attacker still recognises their own attempt on the map; a bystander
    sharing a carrier grade NAT pool is not named on a public page.
    """
    if ":" in address:  # IPv6
        head = address.split(":")[:3]
        return ":".join(head) + ":...."
    parts = address.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".x"
    return "unknown"


def iso_timestamp(value: Any) -> str:
    try:
        return (
            datetime.fromtimestamp(float(value) / 1000.0, tz=UTC).isoformat().replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OSError):
        return ""


def build(
    results: dict[str, list[dict[str, Any]]], target: str, sensor: dict[str, Any] | None
) -> dict[str, Any]:
    totals = (results["totals"] or [{}])[0]
    captures = (results["captures"] or [{}])[0]

    countries: list[dict[str, Any]] = []
    for row in results["countries"]:
        names = facet(row)
        if not names or not names[0] or names[0] == "None":
            continue
        iso2 = names[0].upper()
        countries.append(
            {
                "iso2": iso2,
                "id": ISO_NUMERIC.get(iso2, ""),
                "name": names[1] if len(names) > 1 else iso2,
                "attacks": int(row.get("attacks") or 0),
                "attackers": int(row.get("attackers") or 0),
            }
        )
    countries.sort(key=lambda item: item["attacks"], reverse=True)

    def simple(key: str, value_field: str) -> list[dict[str, Any]]:
        out = []
        for row in results[key]:
            names = facet(row)
            label = names[0] if names else ""
            if label in ("", "None"):
                label = "(empty)"
            out.append({"label": label, "value": int(row.get(value_field) or 0)})
        return out

    techniques = []
    for row in results["techniques"]:
        names = facet(row)
        if not names:
            continue
        techniques.append(
            {
                "id": names[0],
                "name": names[1] if len(names) > 1 else "",
                "events": int(row.get("events") or 0),
            }
        )

    recent = []
    for row in results["recent"]:
        address = str(row.get("src_ip") or "")
        if not address:
            continue
        recent.append(
            {
                "at": iso_timestamp(row.get("timestamp")),
                "ip": mask(address),
                "country": row.get("geo.country_iso") or "",
                "kind": row.get("event_type") or "",
                "username": row.get("username") or "",
                "password": row.get("password") or "",
                "command": (row.get("command") or "")[:120],
            }
        )
    recent.sort(key=lambda item: item["at"], reverse=True)

    origins: list[dict[str, Any]] = []
    for row in results["origins"]:
        names = facet(row)
        if len(names) < 2:
            continue
        lat, lon = row.get("lat"), row.get("lon")
        if lat is None or lon is None:
            continue
        origins.append(
            {
                "city": names[0],
                "iso2": names[1].upper(),
                "country": names[2] if len(names) > 2 else names[1],
                "lat": float(lat),
                "lon": float(lon),
                "attacks": int(row.get("attacks") or 0),
                "attackers": int(row.get("attackers") or 0),
            }
        )
    origins.sort(key=lambda item: item["attacks"], reverse=True)

    located = int((results["located"] or [{}])[0].get("located") or 0)

    daily = [
        {
            "at": iso_timestamp(row.get("beginTimeSeconds", 0) * 1000),
            "count": int(row.get("count") or 0),
        }
        for row in results["daily"]
        if row.get("beginTimeSeconds")
    ]

    return {
        "generated_at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
        "window": "30 days",
        "target": target,
        "sensor_location": sensor,
        "totals": {
            "events": int(totals.get("events") or 0),
            "attackers": int(totals.get("attackers") or 0),
            "sessions": int(totals.get("sessions") or 0),
            "samples": int(captures.get("samples") or 0),
            "countries": len(countries),
        },
        "countries": countries,
        "origins": origins,
        "located_events": located,
        "passwords": simple("passwords", "tries"),
        "usernames": simple("usernames", "tries"),
        "commands": simple("commands", "seen"),
        "techniques": techniques,
        "recent": recent[:30],
        "daily": daily,
    }


# Every result key build() reads. Kept beside the queries so the two drift
# loudly rather than quietly.
REQUIRED_RESULTS = (
    "totals",
    "captures",
    "countries",
    "origins",
    "located",
    "passwords",
    "usernames",
    "commands",
    "techniques",
    "recent",
    "daily",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="web/data/live.json")
    parser.add_argument(
        "--target",
        default="",
        help="Public host attackers should aim at. Comes from a repository variable, "
        "never from a committed file.",
    )
    parser.add_argument(
        "--sensor-location",
        default="",
        help="Where the sensor itself sits, as 'lat,lon,city,country'. Drawn as the "
        "centre of the attack map. Empty leaves the marker off.",
    )
    arguments = parser.parse_args()

    api = settings_from_environment()

    results = {name: run_nrql(query, **api) for name, query in QUERIES.items()}

    # A key that build() reads but QUERIES never asked for is a KeyError after
    # every query has already been paid for. It has happened once; the check
    # costs nothing and names the key.
    missing = [name for name in REQUIRED_RESULTS if name not in results]
    if missing:
        raise SystemExit("QUERIES is missing: " + ", ".join(missing))

    sensor = None
    if arguments.sensor_location:
        parts = [piece.strip() for piece in arguments.sensor_location.split(",")]
        if len(parts) >= 2:
            try:
                sensor = {
                    "lat": float(parts[0]),
                    "lon": float(parts[1]),
                    "city": parts[2] if len(parts) > 2 else "",
                    "country": parts[3] if len(parts) > 3 else "",
                }
            except ValueError:
                print("ignoring an unparseable sensor location", file=sys.stderr)

    payload = build(results, arguments.target, sensor)

    path = pathlib.Path(arguments.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(
        f"wrote {path}: {payload['totals']['events']} events, "
        f"{payload['located_events']} located, {len(payload['countries'])} countries, "
        f"{len(payload['origins'])} origin cities"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
