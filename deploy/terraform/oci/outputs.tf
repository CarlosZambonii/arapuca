output "public_ip" {
  description = "Public address of the sensor. Never commit this value."
  value       = oci_core_public_ip.arapuca.ip_address
}

output "instance_id" {
  description = "OCID of the instance, for the OCI CLI and the console."
  value       = oci_core_instance.arapuca.id
}

output "operator_ssh_command" {
  description = "How to reach the operator account once cloud-init has finished."
  value       = "ssh -p ${var.operator_ssh_port} ubuntu@${oci_core_public_ip.arapuca.ip_address}"
}

output "honeypot_ports_open" {
  description = "Whether 22 and 80 are exposed. False until the container is running."
  value       = var.expose_honeypot_ports
}

output "ansible_inventory" {
  description = "Inventory fragment for the Ansible playbook. Write it to a file that is git ignored."
  sensitive   = true
  value       = <<-EOT
    all:
      hosts:
        arapuca:
          ansible_host: ${oci_core_public_ip.arapuca.ip_address}
          ansible_port: ${var.operator_ssh_port}
          ansible_user: ubuntu
  EOT
}
