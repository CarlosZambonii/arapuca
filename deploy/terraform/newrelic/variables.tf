variable "account_id" {
  description = "New Relic account id."
  type        = number
}

variable "api_key" {
  description = "New Relic user API key. Comes from the environment as NEW_RELIC_API_KEY, never from a file here."
  type        = string
  sensitive   = true
}

variable "region" {
  description = "New Relic data region, US or EU. Must match where the account lives."
  type        = string
  default     = "US"

  validation {
    condition     = contains(["US", "EU"], var.region)
    error_message = "Region must be US or EU."
  }
}

variable "sensor_name" {
  description = "Sensor to scope every query to. Matches sensor_name in arapuca.yaml."
  type        = string
  default     = "arapuca"
}

variable "alert_email" {
  description = "Where alerts go. Empty disables notifications, leaving the conditions in place."
  type        = string
  default     = ""
}
