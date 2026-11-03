# Arapuca infrastructure on Oracle Cloud, Always Free only.
#
# Port ordering is the security property this file encodes. The security list
# opens the operator SSH port at creation and nothing else. Ports 22 and 80
# stay closed until `expose_honeypot_ports` is set to true, which happens only
# after Ansible has the honeypot container running. Opening 22 before then
# would expose the real sshd, which is safety invariant S6.

locals {
  # Ports the honeypot itself answers on, once it exists.
  honeypot_ports = var.expose_honeypot_ports ? [22, 23, 80, 8080] : []

  common_tags = {
    project = "arapuca"
    managed = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "oci_core_vcn" "arapuca" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = [var.vcn_cidr]
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = var.name_prefix

  freeform_tags = local.common_tags
}

resource "oci_core_internet_gateway" "arapuca" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.arapuca.id
  display_name   = "${var.name_prefix}-igw"
  enabled        = true

  freeform_tags = local.common_tags
}

resource "oci_core_route_table" "arapuca" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.arapuca.id
  display_name   = "${var.name_prefix}-routes"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.arapuca.id
    description       = "default route to the internet"
  }

  freeform_tags = local.common_tags
}

resource "oci_core_security_list" "arapuca" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.arapuca.id
  display_name   = "${var.name_prefix}-seclist"

  # Outbound is unrestricted: package updates, the New Relic agent, the
  # VirusTotal lookups and the sample captures all need it. The capture engine
  # applies its own address policy on top, which is what stops an attacker
  # aiming the honeypot at the cloud metadata service.
  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "outbound: updates, telemetry, sample capture"
  }

  # The operator path. Open from the moment the instance exists, because it is
  # the only way in.
  ingress_security_rules {
    protocol    = "6" # TCP
    source      = var.operator_cidr
    source_type = "CIDR_BLOCK"
    description = "operator SSH on the relocated port"

    tcp_options {
      min = var.operator_ssh_port
      max = var.operator_ssh_port
    }
  }

  # The honeypot ports, opened only once there is a honeypot behind them.
  dynamic "ingress_security_rules" {
    for_each = local.honeypot_ports
    content {
      protocol    = "6"
      source      = "0.0.0.0/0"
      source_type = "CIDR_BLOCK"
      description = "honeypot port ${ingress_security_rules.value}"

      tcp_options {
        min = ingress_security_rules.value
        max = ingress_security_rules.value
      }
    }
  }

  # Path MTU discovery. Without it, large responses silently vanish on paths
  # with a smaller MTU, which looks like an intermittent honeypot.
  ingress_security_rules {
    protocol    = "1" # ICMP
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    description = "path MTU discovery"

    icmp_options {
      type = 3
      code = 4
    }
  }

  freeform_tags = local.common_tags
}

resource "oci_core_subnet" "arapuca" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.arapuca.id
  cidr_block                 = var.subnet_cidr
  display_name               = "${var.name_prefix}-subnet"
  dns_label                  = "${var.name_prefix}sub"
  route_table_id             = oci_core_route_table.arapuca.id
  security_list_ids          = [oci_core_security_list.arapuca.id]
  prohibit_public_ip_on_vnic = false

  freeform_tags = local.common_tags
}

# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------

resource "oci_core_instance" "arapuca" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = "${var.name_prefix}-honeypot"
  shape               = var.instance_shape

  # Only the flexible shape takes a size. The micro shape is fixed at 1 OCPU
  # and 1 GB, and passing a config for it is an error.
  dynamic "shape_config" {
    for_each = var.instance_shape == "VM.Standard.A1.Flex" ? [1] : []
    content {
      ocpus         = var.instance_ocpus
      memory_in_gbs = var.instance_memory_gb
    }
  }

  source_details {
    source_type             = "image"
    source_id               = var.image_ocid
    boot_volume_size_in_gbs = var.boot_volume_size_gb
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.arapuca.id
    display_name     = "${var.name_prefix}-vnic"
    hostname_label   = var.name_prefix
    assign_public_ip = false # a reserved IP is attached below instead
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data = base64encode(
      replace(
        file("${path.module}/../../cloud-init/bootstrap.yaml.tmpl"),
        "__REAL_SSH_PORT__",
        tostring(var.operator_ssh_port)
      )
    )
  }

  freeform_tags = local.common_tags

  lifecycle {
    # Changing the image rebuilds the instance, which loses the host key and
    # therefore every returning attacker. Do it deliberately, not by drift.
    ignore_changes = [source_details[0].source_id]
  }
}

# ---------------------------------------------------------------------------
# Reserved public address
# ---------------------------------------------------------------------------
#
# Reserved rather than ephemeral, so the sensor keeps its address across
# rebuilds. An address that has been scanned for months is worth keeping: the
# traffic finds it again immediately.

data "oci_core_vnic_attachments" "arapuca" {
  compartment_id = var.compartment_ocid
  instance_id    = oci_core_instance.arapuca.id
}

data "oci_core_private_ips" "arapuca" {
  vnic_id = data.oci_core_vnic_attachments.arapuca.vnic_attachments[0].vnic_id
}

resource "oci_core_public_ip" "arapuca" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name_prefix}-ip"
  lifetime       = "RESERVED"
  private_ip_id  = data.oci_core_private_ips.arapuca.private_ips[0].id

  freeform_tags = local.common_tags
}
