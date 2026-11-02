# Event schema

Arapuca writes one JSON object per line to `events.jsonl`. The New Relic
Infrastructure Agent parses each line, so every field below is queryable in
NRQL without a parsing rule.

This document is the contract. The dashboards in
`deploy/terraform/newrelic/`, the IoC export in `tools/`, and the C++ writer
all agree on these names, and a rename breaks all three at once. That is why
`schema_version` exists and why `tests/unit/test_event.cpp` pins the wire
names with a test.

**Current version: 1.**

## Envelope

Present in every event, whatever its type.

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | integer | Bumped only on a breaking change |
| `event_id` | string | ULID, 26 characters. Sorts chronologically, so a raw `sort` over the log file produces time order without parsing timestamps |
| `event_type` | string | See the table below |
| `timestamp` | string | RFC 3339, UTC, millisecond precision, for example `2026-11-02T14:31:07.482Z` |
| `service` | string | `ssh`, `http`, `capture` or `honeypot`. Derived from `event_type` rather than stored, so the two cannot disagree |
| `sensor` | string | Which honeypot produced this. Set from `sensor_name` or `ARAPUCA_SENSOR_NAME` |
| `src_ip` | string | Attacker address. Empty when not applicable |
| `src_port` | integer | Attacker source port |
| `dst_port` | integer | Port on the honeypot that was reached |
| `session_id` | string | ULID. Present on everything that belongs to a session, absent otherwise |
| `geo` | object | Absent when the GeoLite2 databases are not installed |
| `mitre` | object | Absent when no rule matched, which is normal |

### `geo`

Absent entirely rather than present and empty. A honeypot with no GeoLite2
database still collects everything else.

| Field | Type |
|-------|------|
| `geo.country_iso` | string, two letters |
| `geo.country` | string |
| `geo.city` | string |
| `geo.latitude` | number, optional |
| `geo.longitude` | number, optional |
| `geo.asn` | integer, optional |
| `geo.as_org` | string, optional |

### `mitre`

Populated by the first matching rule in `config/mitre.yaml`.

| Field | Type | Example |
|-------|------|---------|
| `mitre.technique_id` | string | `T1110` |
| `mitre.technique` | string | `Brute Force` |
| `mitre.tactic` | string | `Credential Access` |

## Event types

| `event_type` | When |
|--------------|------|
| `ssh.auth_attempt` | Every login attempt, accepted or not |
| `ssh.session_start` | Key exchange completed |
| `ssh.command` | One command line typed or sent by exec |
| `ssh.channel_denied` | A channel or global request the policy refuses |
| `ssh.session_end` | Session finished, with its classification |
| `http.request` | Every HTTP request, including 404s |
| `http.login_attempt` | Credentials posted to the fake admin panel |
| `capture.download` | A download was attempted, whatever the outcome |
| `capture.vt_lookup` | A hash was looked up on VirusTotal |
| `honeypot.lifecycle` | Start, stop and the process counters |

## Per type fields

### `ssh.auth_attempt`

| Field | Type | Notes |
|-------|------|-------|
| `username` | string | As sent, sanitized and capped |
| `password` | string | **Recorded in full.** This is the product |
| `auth_method` | string | `password`, `publickey` or `none` |
| `accepted` | boolean | Whether the session reached the fake shell |
| `rule` | string | Which rule decided: `exact`, `any_password`, `any_username`, `after_failures`, `no_match`, `method_not_offered` |
| `client_version` | string | The attacker's SSH client banner, a good fingerprint of their tooling |

### `ssh.session_start`

| Field | Type |
|-------|------|
| `client_version` | string |

### `ssh.command`

| Field | Type | Notes |
|-------|------|-------|
| `command` | string | The line as typed |
| `command_argv0` | string | First token, for grouping without parsing in NRQL |
| `seq` | integer | Position in the session, starting at 1 |
| `since_prev_ms` | integer | Milliseconds since the previous command. The signal the classifier reads |
| `response_bytes` | integer | Size of what the fake shell answered |
| `status` | integer | Exit status the fake shell reported |
| `unknown` | boolean | True when no handler claimed the command. High signal: automated traffic repeats itself |
| `segments` | integer | Commands on the line, so `a; b && c` is three |

### `ssh.channel_denied`

Safety invariant S10. Each refusal is its own event, because an attacker
probing for a SOCKS proxy is telling you what they wanted the machine for.

| Field | Type | Notes |
|-------|------|-------|
| `request_type` | string | `direct-tcpip`, `forwarded-tcpip`, `tcpip-forward`, `x11`, `x11-req`, `subsystem` |
| `target_host` | string | Where a forward was aimed, when the request carried one |
| `target_port` | integer | |

### `ssh.session_end`

| Field | Type | Notes |
|-------|------|-------|
| `duration_ms` | integer | |
| `command_count` | integer | |
| `username` | string | The account that got in, when one did |
| `classification` | string | `bot`, `likely_human` or `unknown` |
| `classification_score` | number | Negative leans bot, positive leans human, clamped to [-1, 1] |
| `classification_reason` | string | Which signals fired, in words |

### `http.request`

| Field | Type | Notes |
|-------|------|-------|
| `method` | string | |
| `path` | string | Recorded exactly as sent, including traversal attempts. Nothing resolves it |
| `query` | string | Present when there were parameters |
| `status` | integer | What the honeypot answered |
| `user_agent` | string | Pulled out of the headers for convenience |
| `headers` | object | Name to value. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` are replaced with `[redacted]` |
| `headers_dropped` | integer | Present when the header count was capped |
| `body_bytes` | integer | Full size, even when the stored copy was cut |
| `body` | string | Up to `http.max_body_recorded` bytes |
| `body_truncated` | boolean | |
| `decoy` | string | Present when a decoy answered: `env`, `git-config`, `config-php`, `backup-sql`, `aws-credentials`, `docker-compose`, `server-status`, `login-form` |

### `http.login_attempt`

| Field | Type |
|-------|------|
| `username` | string |
| `password` | string |
| `path` | string |
| `accepted` | boolean, always false |

### `capture.download`

Emitted whatever the outcome, because a refused download is often more
interesting than a successful one.

| Field | Type | Notes |
|-------|------|-------|
| `url` | string | What the attacker asked for |
| `outcome` | string | `ok`, `bad_scheme`, `blocked_address`, `too_large`, `timeout`, `connect_failed`, `http_error`, `empty`, `internal_error` |
| `http_status` | integer | |
| `content_type` | string | As served |
| `final_url` | string | Present when redirects moved it |
| `blocked_range` | string | Present when `outcome` is `blocked_address`: `loopback`, `private`, `link_local`, `carrier_grade_nat`, `multicast`, `reserved`, `unspecified`, `benchmark`, `unique_local`, `unsupported_family` |
| `size_bytes` | integer | |
| `sha256` | string | |
| `md5` | string | |
| `quarantined` | boolean | |
| `duplicate` | boolean | True when this exact sample was already held |
| `stored_bytes` | integer | Size of the encrypted archive |
| `evicted` | integer | Samples removed to stay within the retention caps |
| `quarantine_path` | string | File name only, never a full path |
| `error` | string | |

### `capture.vt_lookup`

| Field | Type | Notes |
|-------|------|-------|
| `sha256` | string | |
| `vt_status` | string | `ok`, `not_found`, `disabled`, `rate_limited`, `error` |
| `vt_detections` | integer | Malicious plus suspicious |
| `vt_total_engines` | integer | |
| `vt_popular_label` | string | For example `trojan.mirai/gafgyt` |
| `vt_first_seen` | string | When VirusTotal first saw this hash |
| `error` | string | |

`not_found` is the interesting outcome: nobody has seen that sample yet.

### `honeypot.lifecycle`

| Field | Type | Notes |
|-------|------|-------|
| `phase` | string | `start` or `stop` |
| `version` | string | |
| `dropped_events` | integer | Events the bounded bus refused. A gap in telemetry, made visible rather than silent |
| `written_events` | integer | |
| `write_failures` | integer | Short writes, usually a full disk |

## Worked examples

A refused login:

```json
{"schema_version":1,"event_id":"01JBQ3...","event_type":"ssh.auth_attempt",
 "timestamp":"2026-11-02T14:31:07.482Z","service":"ssh","sensor":"arapuca-sa",
 "src_ip":"203.0.113.45","src_port":54122,"dst_port":22,"session_id":"01JBQ3...",
 "geo":{"country_iso":"CN","country":"China","city":"Hangzhou","asn":37963,
        "as_org":"Alibaba"},
 "mitre":{"technique_id":"T1110","technique":"Brute Force",
          "tactic":"Credential Access"},
 "username":"root","password":"123456","auth_method":"password",
 "accepted":false,"rule":"no_match","client_version":"SSH-2.0-libssh2_1.9.0"}
```

A download refused because it aimed at the cloud metadata service:

```json
{"schema_version":1,"event_type":"capture.download","service":"capture",
 "timestamp":"2026-11-02T14:32:10.004Z","src_ip":"203.0.113.45",
 "url":"http://169.254.169.254/opc/v2/instance/","outcome":"blocked_address",
 "blocked_range":"link_local","http_status":0,
 "error":"refused to connect to a link_local address",
 "mitre":{"technique_id":"T1105","technique":"Ingress Tool Transfer",
          "tactic":"Command and Control"}}
```

## Useful NRQL

```sql
-- Passwords being sprayed right now
SELECT count(*) FROM Log
WHERE logtype = 'arapuca' AND event_type IN ('ssh.auth_attempt', 'http.login_attempt')
FACET password SINCE 7 days ago

-- Sessions that got in, and what they did
SELECT timestamp, src_ip, command FROM Log
WHERE logtype = 'arapuca' AND event_type = 'ssh.command'
AND session_id IN (
  SELECT uniques(session_id) FROM Log
  WHERE logtype = 'arapuca' AND event_type = 'ssh.auth_attempt' AND accepted IS TRUE
) SINCE 1 day ago

-- Attackers who tried to use the honeypot as a proxy
SELECT count(*) FROM Log
WHERE logtype = 'arapuca' AND event_type = 'ssh.channel_denied'
FACET src_ip, request_type, target_host SINCE 30 days ago

-- Samples nobody has seen before
SELECT sha256, url FROM Log
WHERE logtype = 'arapuca' AND event_type = 'capture.vt_lookup' AND vt_status = 'not_found'
SINCE 30 days ago

-- Telemetry gaps, which are worth knowing about
SELECT latest(dropped_events), latest(write_failures) FROM Log
WHERE logtype = 'arapuca' AND event_type = 'honeypot.lifecycle'
FACET sensor SINCE 7 days ago
```

## Handling of attacker text

Every string an attacker controls passes through `util::sanitize` before it
reaches an event:

* Invalid UTF-8 becomes a readable `\xNN` escape. `nlohmann::json` throws on
  invalid UTF-8, and a throw on a session thread would be a remote denial of
  service. The exact bytes sent are evidence, so they are escaped rather than
  dropped.
* Control characters become the same escape. A terminal escape sequence
  reaching an operator's screen through a transcript would let an attacker
  write to that screen.
* Overlong encodings, surrogate halves and out of range code points are
  rejected, so an overlong encoded slash cannot smuggle a path separator.
* Every field is length capped, and truncation never splits a UTF-8 sequence
  or a half written escape.

Passwords are the exception to nothing: they are recorded in full, because
they are what the honeypot is for.
