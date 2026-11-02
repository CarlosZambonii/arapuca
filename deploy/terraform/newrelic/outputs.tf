output "overview_dashboard_url" {
  description = "Permalink to the overview dashboard."
  value       = newrelic_one_dashboard.overview.permalink
}

output "sessions_dashboard_url" {
  description = "Permalink to the session drilldown dashboard."
  value       = newrelic_one_dashboard.sessions.permalink
}

output "alert_policy_id" {
  description = "Alert policy id, for attaching further notification channels."
  value       = newrelic_alert_policy.arapuca.id
}
