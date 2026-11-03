"""Minimal New Relic NerdGraph client.

Shared by the IoC export and the weekly report. Deliberately small: one
function that runs an NRQL query and returns rows, plus the error handling
that matters when this runs unattended on a schedule.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, TypedDict

import requests

US_ENDPOINT = "https://api.newrelic.com/graphql"
EU_ENDPOINT = "https://api.eu.newrelic.com/graphql"

_QUERY = """
query($accountId: Int!, $nrql: Nrql!) {
  actor {
    account(id: $accountId) {
      nrql(query: $nrql, timeout: 60) {
        results
      }
    }
  }
}
"""


class NerdGraphError(RuntimeError):
    """Raised when the API cannot be reached or refuses the query."""


class ApiSettings(TypedDict):
    """Everything run_nrql needs to reach the account.

    A TypedDict rather than three loose values, so `run_nrql(query, **api)`
    is checked rather than taking whatever the caller happened to assemble.
    """

    account_id: int
    api_key: str
    region: str


def endpoint_for(region: str) -> str:
    return EU_ENDPOINT if region.upper() == "EU" else US_ENDPOINT


def run_nrql(
    nrql: str,
    *,
    account_id: int,
    api_key: str,
    region: str = "US",
    attempts: int = 3,
) -> list[dict[str, Any]]:
    """Run one NRQL query and return its rows.

    Retries on transport errors and on 5xx, because this runs on a schedule
    with nobody watching and a transient failure should not produce an empty
    feed. A 4xx is not retried: a bad key or a bad query will not fix itself.
    """
    payload = {"query": _QUERY, "variables": {"accountId": account_id, "nrql": nrql}}
    headers = {"API-Key": api_key, "Content-Type": "application/json"}

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(
                endpoint_for(region), json=payload, headers=headers, timeout=90
            )
        except requests.RequestException as error:  # network level
            last_error = error
            time.sleep(2**attempt)
            continue

        if 400 <= response.status_code < 500:
            raise NerdGraphError(
                f"NerdGraph refused the request ({response.status_code}): {response.text[:300]}"
            )
        if response.status_code >= 500:
            last_error = NerdGraphError(f"NerdGraph returned {response.status_code}")
            time.sleep(2**attempt)
            continue

        body = response.json()

        # GraphQL reports query errors with a 200, so the status code alone
        # is not enough to know the query worked.
        if body.get("errors"):
            raise NerdGraphError(f"NerdGraph query failed: {body['errors']}")

        try:
            return body["data"]["actor"]["account"]["nrql"]["results"] or []
        except (KeyError, TypeError) as error:
            raise NerdGraphError(f"unexpected response shape: {body}") from error

    raise NerdGraphError(f"NerdGraph unreachable after {attempts} attempts: {last_error}")


def settings_from_environment() -> ApiSettings:
    """Read account, key and region from the environment.

    Exits with a clear message rather than a traceback: this runs in CI and
    a traceback in a scheduled job teaches nobody anything.
    """
    account = os.environ.get("NEW_RELIC_ACCOUNT_ID", "")
    key = os.environ.get("NEW_RELIC_API_KEY", "")
    region = os.environ.get("NEW_RELIC_REGION", "US")

    missing = [
        name
        for name, value in (
            ("NEW_RELIC_ACCOUNT_ID", account),
            ("NEW_RELIC_API_KEY", key),
        )
        if not value
    ]
    if missing:
        print(f"missing required environment: {', '.join(missing)}", file=sys.stderr)
        raise SystemExit(2)

    try:
        return {"account_id": int(account), "api_key": key, "region": region}
    except ValueError:
        print("NEW_RELIC_ACCOUNT_ID must be a number", file=sys.stderr)
        raise SystemExit(2) from None
