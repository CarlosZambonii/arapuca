# Dashboards as code.
#
# Every query is scoped to logtype='arapuca', which the Infrastructure Agent
# attaches, and to one sensor. The agent parses each line as JSON because the
# honeypot writes one complete object per line, so every field in the event
# schema is queryable without a parsing rule.
#
# Field names here are the contract documented in docs/EVENT_SCHEMA.md. A
# rename there breaks these queries, which is why the schema has a version
# and the C++ side has a test pinning the names.

locals {
  # Repeated in every query. Written once so adding a second sensor later is
  # a variable change rather than an edit to twenty queries.
  scope = "logtype = 'arapuca' AND sensor = '${var.sensor_name}'"
}

resource "newrelic_one_dashboard" "overview" {
  name        = "Arapuca, overview"
  description = "What is attacking the honeypot, from where, and with what"
  permissions = "public_read_only"

  page {
    name = "Overview"

    # --- the single numbers that tell you whether anything is happening ---
    widget_billboard {
      title  = "Events, last 24 hours"
      row    = 1
      column = 1
      width  = 3
      height = 2

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} SINCE 24 hours ago"
      }
    }

    widget_billboard {
      title  = "Unique attackers, last 24 hours"
      row    = 1
      column = 4
      width  = 3
      height = 2

      nrql_query {
        query = "SELECT uniqueCount(src_ip) FROM Log WHERE ${local.scope} SINCE 24 hours ago"
      }
    }

    widget_billboard {
      title  = "Successful logins"
      row    = 1
      column = 7
      width  = 3
      height = 2

      # A successful login is the interesting case: it means a session got
      # into the fake shell, and those are the sessions worth reading.
      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} AND event_type = 'ssh.auth_attempt' AND accepted IS TRUE SINCE 24 hours ago"
      }
    }

    widget_billboard {
      title  = "Samples captured"
      row    = 1
      column = 10
      width  = 3
      height = 2

      nrql_query {
        query = "SELECT uniqueCount(sha256) FROM Log WHERE ${local.scope} AND event_type = 'capture.download' AND quarantined IS TRUE SINCE 24 hours ago"
      }
    }

    # --- shape of the traffic over time ---------------------------------
    widget_area {
      title  = "Attacks per hour, by service"
      row    = 3
      column = 1
      width  = 8
      height = 3

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} FACET service TIMESERIES 1 hour SINCE 7 days ago"
      }
    }

    widget_pie {
      title  = "Sessions, bot or human"
      row    = 3
      column = 9
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} AND event_type = 'ssh.session_end' FACET classification SINCE 7 days ago"
      }
    }

    # --- where from ------------------------------------------------------
    widget_markdown {
      title  = "Note"
      row    = 6
      column = 1
      width  = 4
      height = 3

      text = <<-EOT
        ## Reading this board

        Every number here is traffic that chose to connect to a machine that
        advertises nothing and serves nobody. There are no false positives in
        the usual sense: a connection is an attack by definition.

        **Geo fields are absent** when the GeoLite2 databases are not
        installed. Enrichment degrades, collection does not.

        **Passwords are recorded in full.** They are the product.
      EOT
    }

    widget_bar {
      title  = "Top source countries"
      row    = 6
      column = 5
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} AND geo.country IS NOT NULL FACET geo.country LIMIT 15 SINCE 7 days ago"
      }
    }

    widget_bar {
      title  = "Top networks (ASN)"
      row    = 6
      column = 9
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} AND geo.as_org IS NOT NULL FACET geo.as_org LIMIT 15 SINCE 7 days ago"
      }
    }

    # --- credentials -----------------------------------------------------
    widget_table {
      title  = "Top passwords tried"
      row    = 9
      column = 1
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) AS attempts FROM Log WHERE ${local.scope} AND event_type IN ('ssh.auth_attempt', 'http.login_attempt') FACET password LIMIT 25 SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Top usernames tried"
      row    = 9
      column = 5
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) AS attempts FROM Log WHERE ${local.scope} AND event_type IN ('ssh.auth_attempt', 'http.login_attempt') FACET username LIMIT 25 SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Credential pairs that worked"
      row    = 9
      column = 9
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) AS sessions FROM Log WHERE ${local.scope} AND event_type = 'ssh.auth_attempt' AND accepted IS TRUE FACET username, password LIMIT 25 SINCE 7 days ago"
      }
    }

    # --- behaviour --------------------------------------------------------
    widget_table {
      title  = "Top commands typed"
      row    = 12
      column = 1
      width  = 6
      height = 3

      nrql_query {
        query = "SELECT count(*) AS seen FROM Log WHERE ${local.scope} AND event_type = 'ssh.command' FACET command LIMIT 30 SINCE 7 days ago"
      }
    }

    widget_bar {
      title  = "MITRE ATT&CK techniques"
      row    = 12
      column = 7
      width  = 6
      height = 3

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} AND mitre.technique_id IS NOT NULL FACET mitre.technique_id, mitre.technique LIMIT 20 SINCE 7 days ago"
      }
    }

    widget_bar {
      title  = "ATT&CK tactics"
      row    = 15
      column = 1
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) FROM Log WHERE ${local.scope} AND mitre.tactic IS NOT NULL FACET mitre.tactic SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Paths requested over HTTP"
      row    = 15
      column = 5
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT count(*) AS requests FROM Log WHERE ${local.scope} AND event_type = 'http.request' FACET path LIMIT 30 SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Decoy files taken"
      row    = 15
      column = 9
      width  = 4
      height = 3

      # A decoy hit is high signal: whoever took those credentials will use
      # them somewhere, and that use is visible elsewhere.
      nrql_query {
        query = "SELECT count(*) AS hits, uniqueCount(src_ip) AS attackers FROM Log WHERE ${local.scope} AND decoy IS NOT NULL FACET decoy SINCE 7 days ago"
      }
    }

    # --- captured malware --------------------------------------------------
    widget_table {
      title  = "Captured samples"
      row    = 18
      column = 1
      width  = 8
      height = 3

      nrql_query {
        query = "SELECT latest(timestamp) AS seen, latest(url) AS url, latest(size_bytes) AS bytes FROM Log WHERE ${local.scope} AND event_type = 'capture.download' AND quarantined IS TRUE FACET sha256 LIMIT 30 SINCE 30 days ago"
      }
    }

    widget_table {
      title  = "VirusTotal verdicts"
      row    = 18
      column = 9
      width  = 4
      height = 3

      nrql_query {
        query = "SELECT latest(vt_detections) AS detections, latest(vt_total_engines) AS engines, latest(vt_popular_label) AS label FROM Log WHERE ${local.scope} AND event_type = 'capture.vt_lookup' FACET sha256 LIMIT 30 SINCE 30 days ago"
      }
    }

    widget_table {
      title  = "Downloads refused by the address policy"
      row    = 21
      column = 1
      width  = 6
      height = 3

      # The most interesting failure there is: an attacker aiming the
      # honeypot at a private range or at the cloud metadata service.
      nrql_query {
        query = "SELECT count(*) AS attempts, latest(url) AS last_url FROM Log WHERE ${local.scope} AND outcome = 'blocked_address' FACET blocked_range, src_ip LIMIT 25 SINCE 30 days ago"
      }
    }

    widget_table {
      title  = "Channel requests refused"
      row    = 21
      column = 7
      width  = 6
      height = 3

      # Port forwarding attempts: someone wanted a proxy, not a shell.
      nrql_query {
        query = "SELECT count(*) AS attempts FROM Log WHERE ${local.scope} AND event_type = 'ssh.channel_denied' FACET request_type, src_ip LIMIT 25 SINCE 30 days ago"
      }
    }
  }
}

resource "newrelic_one_dashboard" "sessions" {
  name        = "Arapuca, sessions"
  description = "Drill into individual attacker sessions"
  permissions = "public_read_only"

  page {
    name = "Sessions"

    widget_table {
      title  = "Longest sessions"
      row    = 1
      column = 1
      width  = 6
      height = 3

      nrql_query {
        query = "SELECT latest(duration_ms) AS ms, latest(command_count) AS commands, latest(classification) AS kind, latest(username) AS user FROM Log WHERE ${local.scope} AND event_type = 'ssh.session_end' FACET session_id, src_ip LIMIT 30 SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Sessions that look human"
      row    = 1
      column = 7
      width  = 6
      height = 3

      # The rare ones, and the ones worth reading line by line.
      nrql_query {
        query = "SELECT latest(command_count) AS commands, latest(classification_reason) AS why, latest(src_ip) AS source FROM Log WHERE ${local.scope} AND event_type = 'ssh.session_end' AND classification = 'likely_human' FACET session_id LIMIT 30 SINCE 30 days ago"
      }
    }

    widget_table {
      title  = "Command transcript, newest first"
      row    = 4
      column = 1
      width  = 12
      height = 4

      # Add `AND session_id = '...'` to follow one attacker end to end.
      nrql_query {
        query = "SELECT timestamp, src_ip, session_id, seq, command, mitre.technique_id FROM Log WHERE ${local.scope} AND event_type = 'ssh.command' LIMIT 100 SINCE 24 hours ago"
      }
    }

    widget_line {
      title  = "Typing rhythm, median gap between commands"
      row    = 8
      column = 1
      width  = 6
      height = 3

      # The signal the classifier reads. A flat line near zero is a script.
      nrql_query {
        query = "SELECT median(since_prev_ms) FROM Log WHERE ${local.scope} AND event_type = 'ssh.command' AND seq > 1 TIMESERIES 1 hour SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Commands never seen before"
      row    = 8
      column = 7
      width  = 6
      height = 3

      nrql_query {
        query = "SELECT count(*) AS seen, latest(src_ip) AS source FROM Log WHERE ${local.scope} AND event_type = 'ssh.command' AND unknown IS TRUE FACET command_argv0 LIMIT 30 SINCE 7 days ago"
      }
    }

    widget_table {
      title  = "Honeypot health"
      row    = 11
      column = 1
      width  = 12
      height = 2

      # Dropped events mean the bus saturated, which means telemetry has a
      # gap. A silent gap would be worse than a noisy one.
      nrql_query {
        query = "SELECT latest(version) AS version, latest(dropped_events) AS dropped, latest(written_events) AS written, latest(write_failures) AS write_failures FROM Log WHERE ${local.scope} AND event_type = 'honeypot.lifecycle' FACET sensor SINCE 7 days ago"
      }
    }
  }
}
