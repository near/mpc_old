output "node_public_ip" {
  value = google_compute_global_address.external_ips[*].address
}