"""The NerdGraph client: endpoint choice, environment parsing, and the retry
and error handling that only ever runs unattended on a schedule."""

import pytest

import nerdgraph


def test_endpoint_defaults_to_us_and_is_case_insensitive():
    assert nerdgraph.endpoint_for("US") == nerdgraph.US_ENDPOINT
    assert nerdgraph.endpoint_for("us") == nerdgraph.US_ENDPOINT
    assert nerdgraph.endpoint_for("EU") == nerdgraph.EU_ENDPOINT
    assert nerdgraph.endpoint_for("eu") == nerdgraph.EU_ENDPOINT
    # Anything unrecognised falls back to US rather than failing a scheduled job.
    assert nerdgraph.endpoint_for("mars") == nerdgraph.US_ENDPOINT


def test_settings_reads_the_environment(monkeypatch):
    monkeypatch.setenv("NEW_RELIC_ACCOUNT_ID", "8434342")
    monkeypatch.setenv("NEW_RELIC_API_KEY", "secret")
    monkeypatch.setenv("NEW_RELIC_REGION", "EU")
    settings = nerdgraph.settings_from_environment()
    assert settings == {"account_id": 8434342, "api_key": "secret", "region": "EU"}


def test_settings_region_defaults_to_us(monkeypatch):
    monkeypatch.setenv("NEW_RELIC_ACCOUNT_ID", "1")
    monkeypatch.setenv("NEW_RELIC_API_KEY", "k")
    monkeypatch.delenv("NEW_RELIC_REGION", raising=False)
    assert nerdgraph.settings_from_environment()["region"] == "US"


def test_settings_exits_cleanly_when_a_variable_is_missing(monkeypatch):
    monkeypatch.delenv("NEW_RELIC_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("NEW_RELIC_API_KEY", "k")
    # A traceback in a scheduled job teaches nobody anything; a SystemExit with
    # a message is the contract.
    with pytest.raises(SystemExit):
        nerdgraph.settings_from_environment()


def test_settings_rejects_a_non_numeric_account(monkeypatch):
    monkeypatch.setenv("NEW_RELIC_ACCOUNT_ID", "not-a-number")
    monkeypatch.setenv("NEW_RELIC_API_KEY", "k")
    with pytest.raises(SystemExit):
        nerdgraph.settings_from_environment()


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


def test_run_nrql_returns_rows(monkeypatch):
    rows = [{"facet": "FR", "count": 7}]
    body = {"data": {"actor": {"account": {"nrql": {"results": rows}}}}}
    monkeypatch.setattr(nerdgraph.requests, "post", lambda *a, **k: _Response(200, body))
    assert nerdgraph.run_nrql("SELECT 1", account_id=1, api_key="k") == rows


def test_run_nrql_raises_on_a_graphql_error_under_a_200(monkeypatch):
    # GraphQL reports query errors with a 200, so the status code is not enough.
    body = {"errors": [{"message": "bad query"}]}
    monkeypatch.setattr(nerdgraph.requests, "post", lambda *a, **k: _Response(200, body))
    with pytest.raises(nerdgraph.NerdGraphError):
        nerdgraph.run_nrql("SELECT bad", account_id=1, api_key="k")


def test_run_nrql_does_not_retry_a_4xx(monkeypatch):
    calls = {"n": 0}

    def post(*args, **kwargs):
        calls["n"] += 1
        return _Response(401, "unauthorised")

    monkeypatch.setattr(nerdgraph.requests, "post", post)
    with pytest.raises(nerdgraph.NerdGraphError):
        nerdgraph.run_nrql("SELECT 1", account_id=1, api_key="bad", attempts=3)
    # A bad key will not fix itself, so it is asked exactly once.
    assert calls["n"] == 1


def test_run_nrql_retries_a_5xx_then_succeeds(monkeypatch):
    calls = {"n": 0}
    rows = [{"facet": "x"}]
    ok = {"data": {"actor": {"account": {"nrql": {"results": rows}}}}}

    def post(*args, **kwargs):
        calls["n"] += 1
        return _Response(500, "boom") if calls["n"] == 1 else _Response(200, ok)

    monkeypatch.setattr(nerdgraph.requests, "post", post)
    monkeypatch.setattr(nerdgraph.time, "sleep", lambda *_: None)  # no real backoff
    assert nerdgraph.run_nrql("SELECT 1", account_id=1, api_key="k", attempts=3) == rows
    assert calls["n"] == 2
