variable "region" {
  description = "OCI region. Always Free resources exist only in the tenancy home region, so this has to be that one."
  type        = string
}

variable "compartment_ocid" {
  description = "Compartment the honeypot lives in. The tenancy OCID is a valid answer for a small tenancy."
  type        = string
}

variable "availability_domain" {
  description = "Availability domain name, for example XOLo:SA-SAOPAULO-1-AD-1."
  type        = string
}

variable "instance_shape" {
  description = <<-EOT
    Compute shape.

    VM.Standard.A1.Flex is the better machine and the code runs on arm64, but
    A1 capacity is frequently exhausted and a launch fails with
    "Out of host capacity". VM.Standard.E2.1.Micro is what is reliably
    obtainable, and it is what this deployment targets.
  EOT
  type        = string
  default     = "VM.Standard.E2.1.Micro"

  validation {
    # Always Free only. Anything else bills, and a honeypot that quietly
    # starts costing money is a bad surprise.
    condition = contains(
      ["VM.Standard.E2.1.Micro", "VM.Standard.A1.Flex"],
      var.instance_shape
    )
    error_message = "Only Always Free shapes are allowed: VM.Standard.E2.1.Micro or VM.Standard.A1.Flex."
  }
}

variable "instance_ocpus" {
  description = "OCPUs, used only by the A1 flexible shape. Ignored for the micro shape."
  type        = number
  default     = 2

  validation {
    condition     = var.instance_ocpus >= 1 && var.instance_ocpus <= 4
    error_message = "The Always Free A1 allowance is at most 4 OCPUs."
  }
}

variable "instance_memory_gb" {
  description = "Memory in GB, used only by the A1 flexible shape."
  type        = number
  default     = 12

  validation {
    condition     = var.instance_memory_gb >= 1 && var.instance_memory_gb <= 24
    error_message = "The Always Free A1 allowance is at most 24 GB."
  }
}

variable "boot_volume_size_gb" {
  description = "Boot volume size. 50 is the minimum and the Always Free allowance is 200 in total."
  type        = number
  default     = 50

  validation {
    condition     = var.boot_volume_size_gb >= 50 && var.boot_volume_size_gb <= 200
    error_message = "Boot volume must be between 50 and 200 GB to stay within Always Free."
  }
}

variable "image_ocid" {
  description = "Canonical Ubuntu 24.04 image OCID for the chosen shape and architecture."
  type        = string
}

variable "ssh_public_key" {
  description = "Public key installed for the operator account. Never the private one."
  type        = string
}

variable "operator_ssh_port" {
  description = <<-EOT
    Port the real sshd is moved to by cloud-init, before port 22 is ever
    reachable. Safety invariant S6.

    Deliberately a variable with no default: the literal port is not committed,
    because this repository is public.
  EOT
  type        = number

  validation {
    condition     = var.operator_ssh_port > 1024 && var.operator_ssh_port < 65536 && var.operator_ssh_port != 22
    error_message = "The operator port must be unprivileged and must not be 22."
  }
}

variable "operator_cidr" {
  description = <<-EOT
    Addresses allowed to reach the operator SSH port.

    0.0.0.0/0 is accepted because residential addresses change and locking
    yourself out of the only management path is worse than the exposure: the
    port is non standard, password authentication is off, and only a key gets
    in. Narrow it when you have a fixed address.
  EOT
  type        = string
  default     = "0.0.0.0/0"
}

variable "expose_honeypot_ports" {
  description = <<-EOT
    Whether to open 22 and 80 to the internet.

    Starts false on purpose. Opening 22 before the honeypot container is
    running would expose the real sshd, which is exactly what safety invariant
    S6 forbids. Flip it to true once Ansible reports the stack is up.
  EOT
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "arapuca"
}

variable "vcn_cidr" {
  description = "CIDR for the VCN."
  type        = string
  default     = "10.10.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for the public subnet."
  type        = string
  default     = "10.10.1.0/24"
}
