output "node_public_ip" {
  value = google_compute_address.external_ips[*].address
}