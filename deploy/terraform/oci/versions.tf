# Provider versions are pinned to a minor range. A honeypot that stops being
# reachable because a provider changed a default is a honeypot that collected
# nothing for a week before anyone noticed.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 9.11"
    }
  }
}

provider "oci" {
  # Credentials come from ~/.oci/config or from the standard OCI_* environment
  # variables. Nothing authentication related is written in this directory.
  region = var.region
}
