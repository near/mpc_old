module "vpc" {
  count   = var.create_network ? 1 : 0
  source  = "terraform-google-modules/network/google"
  version = "~> 9.0"

  project_id   = var.project_id
  network_name = var.network
  routing_mode = "GLOBAL"

  subnets = [
    {
      subnet_name   = var.subnetwork
      subnet_ip     = "10.10.10.0/24"
      subnet_region = var.region
    }
  ]

  routes = [
    {
      name              = "egress-internet"
      description       = "route through IGW to access internet"
      destination_range = "0.0.0.0/0"
      tags              = "egress-inet"
      next_hop_internet = "true"
    }
  ]

  ingress_rules = [
    {
      name          = "allow-iap-ssh"
      description   = "this rule allows you to connect to your VM via SSH without port 22 being public"
      source_ranges = ["35.235.240.0/20"]
      target_tags   = ["allow-ssh"]
      allow = [
        {
          protocol = "tcp",
          ports    = ["22"]
        }
      ]
    },
  ]
}

resource "google_compute_router" "router" {
  name    = "default"
  network = var.network
  project = var.project_id
  region  = var.region
}

resource "google_compute_router_nat" "nat" {
  name                               = "nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}