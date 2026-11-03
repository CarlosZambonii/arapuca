"""The IoC feed: facet extraction, timestamps, and the collectors that turn
rows into the committed indicators."""

import ioc_export


def test_facet_of_takes_the_first_value():
    assert ioc_export.facet_of({"facet": ["203.0.113.5"]}) == "203.0.113.5"
    assert ioc_export.facet_of({"facet": "abc123"}) == "abc123"
    assert ioc_export.facet_of({"facet": []}) == ""
    assert ioc_export.facet_of({}) == ""


def test_as_timestamp():
    assert ioc_export.as_timestamp(1_700_000_000_000) == "2023-11-14T22:13:20Z"
    assert ioc_export.as_timestamp(0) == ""
    assert ioc_export.as_timestamp(None) == ""
    assert ioc_export.as_timestamp("bad") == ""


def test_collect_ips_shapes_and_sorts(monkeypatch):
    rows = [
        {
            "facet": "198.51.100.1",
            "events": 5,
            "sessions": 2,
            "first_seen": 1_700_000_000_000,
            "last_seen": 1_700_000_100_000,
            "country": "FR",
            "network": "AS1",
        },
        {
            "facet": "203.0.113.9",
            "events": 40,
            "sessions": 9,
            "first_seen": 1_700_000_000_000,
            "last_seen": 1_700_000_100_000,
            "country": "SG",
            "network": "AS2",
        },
        {"facet": "", "events": 99},  # no address, dropped
    ]
    monkeypatch.setattr(ioc_export, "run_nrql", lambda *a, **k: rows)
    out = ioc_export.collect_ips("1 day ago", {"account_id": 1, "api_key": "k", "region": "US"})
    assert [item["ip"] for item in out] == ["203.0.113.9", "198.51.100.1"]  # busiest first
    assert out[0]["events"] == 40


def test_collect_hashes_joins_virustotal(monkeypatch):
    samples = [
        {
            "facet": "a" * 64,
            "md5": "d" * 32,
            "size_bytes": 1024,
            "url": "http://x/y",
            "captures": 2,
            "first_seen": 1_700_000_000_000,
        }
    ]
    verdicts = [{"facet": "a" * 64, "detections": 7, "engines": 70, "label": "trojan"}]

    def fake_run(query, **_):
        return verdicts if "vt_lookup" in query or "vt_detections" in query else samples

    monkeypatch.setattr(ioc_export, "run_nrql", fake_run)
    out = ioc_export.collect_hashes("1 day ago", {"account_id": 1, "api_key": "k", "region": "US"})
    assert len(out) == 1
    assert out[0]["sha256"] == "a" * 64
    assert out[0]["vt_detections"] == 7
    assert out[0]["vt_label"] == "trojan"


def test_write_csv_and_json(tmp_path):
    rows = [{"ip": "203.0.113.9", "events": 40}]
    csv_path = tmp_path / "ips.csv"
    ioc_export.write_csv(csv_path, rows, ["ip", "events"])
    text = csv_path.read_text(encoding="utf-8")
    assert "ip,events" in text
    assert "203.0.113.9,40" in text

    json_path = tmp_path / "ips.json"
    ioc_export.write_json(json_path, {"ips": rows})
    assert '"203.0.113.9"' in json_path.read_text(encoding="utf-8")
