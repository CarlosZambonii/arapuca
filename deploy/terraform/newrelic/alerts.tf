# Alerts as code.
#
# Four conditions, chosen because each one means something different and
# each one is actionable. A honeypot generates constant noise by design, so
# an alert that fires on "attack detected" is useless: everything here is an
# attack. These fire on changes in character, not on volume.

resource "newrelic_alert_policy" "arapuca" {
  name                = "Arapuca"
  incident_preference = "PER_CONDITION"
}

# --- 1. a spike in login attempts -----------------------------------------
#
# Baseline rather than a fixed threshold. The normal rate depends on the
# address, the time of year and whichever botnet is currently sweeping, so a
# number chosen today is wrong next month. What matters is a departure from
# this sensor's own normal.

resource "newrelic_nrql_alert_condition" "login_spike" {
  policy_id = newrelic_alert_policy.arapuca.id
  type      = "baseline"
  name      = "Login attempt spike"
  enabled   = true

  description = <<-EOT
    Login attempts departed from this sensor's own baseline.

    Usually a new botnet campaign discovering the address. Worth looking at
    the top usernames and passwords for the window: a campaign with a new
    credential list is the interesting case.
  EOT

  baseline_direction = "UPPER_ONLY"

  nrql {
    query = "SELECT count(*) FROM Log WHERE logtype = 'arapuca' AND sensor = '${var.sensor_name}' AND event_type IN ('ssh.auth_attempt', 'http.login_attempt')"
  }

  critical {
    operator              = "above"
    threshold             = 4 # standard deviations
    threshold_duration    = 600
    threshold_occurrences = "ALL"
  }

  aggregation_window           = 300
  aggregation_method           = "event_flow"
  aggregation_delay            = 120
  violation_time_limit_seconds = 86400
  fill_option                  = "none"
}

# --- 2. a command nobody has typed before ---------------------------------
#
# The highest signal condition of the three. Automated traffic repeats
# itself, so a command this honeypot has never seen usually means a person,
# a new toolkit, or a new campaign.

resource "newrelic_nrql_alert_condition" "unseen_command" {
  policy_id = newrelic_alert_policy.arapuca.id
  type      = "static"
  name      = "Command never seen before"
  enabled   = true

  description = <<-EOT
    The fake shell was given a command it does not implement.

    Automated traffic repeats itself, so this usually means a person at a
    keyboard or a toolkit that has not been seen here yet. Read the session
    transcript: filter the Sessions dashboard by the session_id on the
    incident.

    If the command is one a real server would have, consider implementing it
    in config and the command registry. A honeypot that answers more
    convincingly keeps attackers longer.
  EOT

  nrql {
    query = "SELECT count(*) FROM Log WHERE logtype = 'arapuca' AND sensor = '${var.sensor_name}' AND event_type = 'ssh.command' AND unknown IS TRUE"
  }

  critical {
    operator              = "above"
    threshold             = 0
    threshold_duration    = 60
    threshold_occurrences = "AT_LEAST_ONCE"
  }

  aggregation_window           = 60
  aggregation_method           = "event_flow"
  aggregation_delay            = 120
  violation_time_limit_seconds = 86400
}

# --- 3. a sample was captured ---------------------------------------------
#
# Not an emergency, but the thing the honeypot exists to produce. Worth
# knowing the same day rather than the same week.

resource "newrelic_nrql_alert_condition" "malware_captured" {
  policy_id = newrelic_alert_policy.arapuca.id
  type      = "static"
  name      = "Malware captured"
  enabled   = true

  description = <<-EOT
    A sample was downloaded and quarantined.

    The file is at /var/lib/docker/volumes/arapuca_arapuca-quarantine/_data/
    named <sha256>.zip, encrypted with the password "infected". It is stored
    read only and was never executed.

    Check the VirusTotal verdict on the overview dashboard. A hash VirusTotal
    does not know is the most interesting outcome: nobody has seen that
    sample yet.
  EOT

  nrql {
    query = "SELECT count(*) FROM Log WHERE logtype = 'arapuca' AND sensor = '${var.sensor_name}' AND event_type = 'capture.download' AND quarantined IS TRUE AND duplicate IS FALSE"
  }

  critical {
    operator              = "above"
    threshold             = 0
    threshold_duration    = 60
    threshold_occurrences = "AT_LEAST_ONCE"
  }

  aggregation_window           = 60
  aggregation_method           = "event_flow"
  aggregation_delay            = 120
  violation_time_limit_seconds = 86400
}

# --- 4. the honeypot stopped reporting ------------------------------------
#
# Not in the original three, but a honeypot that silently stopped collecting
# is the one failure that costs data rather than producing it.

resource "newrelic_nrql_alert_condition" "sensor_silent" {
  policy_id = newrelic_alert_policy.arapuca.id
  type      = "static"
  name      = "Sensor stopped reporting"
  enabled   = true

  description = <<-EOT
    No events for an hour.

    On a public address this means the sensor is down, the log shipper
    stopped, or the disk filled. A quiet honeypot is almost always a broken
    honeypot.
  EOT

  nrql {
    query = "SELECT count(*) FROM Log WHERE logtype = 'arapuca' AND sensor = '${var.sensor_name}'"
  }

  critical {
    operator              = "below"
    threshold             = 1
    threshold_duration    = 3600
    threshold_occurrences = "ALL"
  }

  aggregation_window           = 300
  aggregation_method           = "event_flow"
  aggregation_delay            = 120
  violation_time_limit_seconds = 86400
  fill_option                  = "static"
  fill_value                   = 0
}

# --- notification ----------------------------------------------------------

resource "newrelic_notification_destination" "email" {
  count = var.alert_email == "" ? 0 : 1

  name = "Arapuca email"
  type = "EMAIL"

  property {
    key   = "email"
    value = var.alert_email
  }
}

resource "newrelic_notification_channel" "email" {
  count = var.alert_email == "" ? 0 : 1

  name           = "Arapuca email"
  type           = "EMAIL"
  destination_id = newrelic_notification_destination.email[0].id
  product        = "IINT"

  property {
    key   = "subject"
    value = "Arapuca: {{ issueTitle }}"
  }
}

resource "newrelic_workflow" "arapuca" {
  count = var.alert_email == "" ? 0 : 1

  name                  = "Arapuca"
  muting_rules_handling = "NOTIFY_ALL_ISSUES"

  issues_filter {
    name = "Arapuca policy"
    type = "FILTER"

    predicate {
      attribute = "labels.policyIds"
      operator  = "EXACTLY_MATCHES"
      values    = [newrelic_alert_policy.arapuca.id]
    }
  }

  destination {
    channel_id = newrelic_notification_channel.email[0].id
  }
}
