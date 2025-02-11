provider "google" {
  project = var.project_id
}
provider "google-beta" {
  project = var.project_id
}

module "gce-container" {
  count   = length(var.node_configs)
  source  = "terraform-google-modules/container-vm/google"
  version = "~> 3.0"
}

#####################################################################
# Account definitions
#####################################################################

resource "google_service_account" "service_account" {
  account_id   = "multichain-partner-${var.env}"
  display_name = "Multichain ${var.env} Account"
}

resource "google_project_iam_member" "sa-roles" {
  for_each = toset([
    "roles/datastore.user",
    "roles/secretmanager.admin",
    "roles/storage.objectAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.logWriter",
  ])

  role    = each.key
  member  = "serviceAccount:${google_service_account.service_account.email}"
  project = var.project_id
}

#####################################################################
# External ip resevation
#####################################################################
resource "google_compute_global_address" "external_ips" {
  count        = length(var.node_configs)
  name         = "multichain-partner-mainnet-${count.index}"
  address_type = "EXTERNAL"

  lifecycle {
    prevent_destroy = true
  }
}
#####################################################################
# Cloud init config
#####################################################################
data "cloudinit_config" "mpc_config" {
  count         = length(var.node_configs)
  gzip          = false
  base64_encode = false

  part {
    content_type = "text/cloud-config"
    content = templatefile("../configs/mpc_cloud_config.yml", {
      docker_image                       = var.image
      data_dir                           = "/home/mpc/"
      gcp_project_id                     = var.project_id
      gcp_keyshare_secret_id             = var.node_configs["${count.index}"].gcp_keyshare_secret_id
      gcp_local_encryption_key_secret_id = var.node_configs["${count.index}"].gcp_local_encryption_key_secret_id
      gcp_p2p_private_key_secret_id      = var.node_configs["${count.index}"].gcp_p2p_private_key_secret_id
      gcp_account_sk_secret_id           = var.node_configs["${count.index}"].gcp_account_sk_secret_id
      mpc_account_id                     = var.node_configs["${count.index}"].account
      near_boot_nodes                    = var.near_boot_nodes
      mpc_contract_id                    = "v1.signer"
      mpc_local_address                  = var.node_configs[count.index].domain
      chain_id                           = var.env
    })
    filename = "mpc_cloud_config.yml"
  }
}

#####################################################################
# Instance definitions
#####################################################################
module "ig_template" {
  count      = length(var.node_configs)
  source     = "../modules/mig_template"
  network    = var.network
  subnetwork = var.subnetwork
  region     = var.region
  service_account = {
    email  = google_service_account.service_account.email,
    scopes = ["cloud-platform"]
  }
  name_prefix          = "multichain-partner-mainnet-${count.index}"
  source_image_family  = "cos-113-lts"
  source_image_project = "cos-cloud"
  machine_type         = "n2d-standard-16"

  startup_script = file("${path.module}/../scripts/mpc_init.sh")

  additional_disks = [{
    description  = "MPC partner mainnet data disk"
    disk_name    = "mpc-partner-mainnet-${count.index}"
    auto_delete  = false
    boot         = false
    disk_size_gb = 1024
    disk_type    = "pd-ssd"
    disk_labels  = {}
    device_name  = "mpc-partner-mainnet-${count.index}"
  }]


  source_image = reverse(split("/", module.gce-container[count.index].source_image))[0]
  metadata     = { user-data = data.cloudinit_config.mpc_config[count.index].rendered }
  tags = [
    "multichain",
    "allow-ssh"
  ]
  labels = {
    "container-vm" = module.gce-container[count.index].vm_container_label
  }

  depends_on = [google_compute_global_address.external_ips]
}


module "instances" {
  count      = length(var.node_configs)
  source     = "../modules/instance-from-tpl"
  region     = var.region
  project_id = var.project_id
  hostname   = "multichain-mainnet-partner-${count.index}"
  network    = var.network
  subnetwork = var.subnetwork

  instance_template = module.ig_template[count.index].self_link_unique

}

#####################################################################
# Firewall template
#####################################################################
resource "google_compute_firewall" "app_port" {
  name    = "allow-multichain-healthcheck-access"
  network = var.network

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  source_tags   = ["multichain"]

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "3030", "3000"]
  }

}

#####################################################################
# LOAD BALANCER definition
#####################################################################
resource "google_compute_health_check" "multichain_healthcheck" {
  name = "multichain-testnet-partner-tcp-healthcheck"

  http_health_check {
    port         = 3030
    proxy_header = "NONE"
    request_path = "/metrics"
  }
}

resource "google_compute_instance_group" "multichain_group" {
  name       = "multichain-partner-instance-group"
  instances  = module.instances[*].self_links[0]
  depends_on = [module.instances]

  zone = var.zone
  named_port {
    name = "http"
    port = 80
  }
  named_port {
    name = "http-alt"
    port = 8080
  }
  named_port {
    name = "metrics"
    port = 3030
  }
}

resource "google_compute_backend_service" "mpc_backend_http" {
  name                  = "mpc-partner-backend-service-http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "TCP"
  port_name             = "http"
  timeout_sec           = 30
  backend {
    group = google_compute_instance_group.multichain_group.id
  }

  health_checks = [google_compute_health_check.multichain_healthcheck.id]
}

resource "google_compute_target_tcp_proxy" "mpc_proxy_http" {
  count           = length(var.node_configs)
  name            = "mpc-partner-target-proxy-http-${count.index}"
  description     = "MPC proxy for http(80) port"
  backend_service = google_compute_backend_service.mpc_backend_http.id
}

resource "google_compute_global_forwarding_rule" "mpc_frontend_http" {
  count                 = length(var.node_configs)
  name                  = "mpc-partner-rule-http-${count.index}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_tcp_proxy.mpc_proxy_http[count.index].id
  ip_address            = google_compute_global_address.external_ips[count.index].address
}

resource "google_compute_backend_service" "mpc_backend_http_alt" {
  name                  = "mpc-partner-backend-service-http-alt"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "TCP"
  port_name             = "http-alt"
  timeout_sec           = 30
  backend {
    group = google_compute_instance_group.multichain_group.id
  }

  health_checks = [google_compute_health_check.multichain_healthcheck.id]
}

resource "google_compute_target_tcp_proxy" "mpc_proxy_http_alt" {
  count           = length(var.node_configs)
  name            = "mpc-partner-target-proxy-http-alt-${count.index}"
  description     = "MPC proxy for http-alt(8080) port"
  backend_service = google_compute_backend_service.mpc_backend_http_alt.id
}

resource "google_compute_global_forwarding_rule" "mpc_frontend_http_alt" {
  count                 = length(var.node_configs)
  name                  = "mpc-partner-rule-http-alt-${count.index}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "8080"
  target                = google_compute_target_tcp_proxy.mpc_proxy_http_alt[count.index].id
  ip_address            = google_compute_global_address.external_ips[count.index].address
}

resource "google_compute_backend_service" "mpc_backend_metrics" {
  name                  = "mpc-partner-backend-service-metrics"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "TCP"
  port_name             = "metrics"
  timeout_sec           = 30
  backend {
    group = google_compute_instance_group.multichain_group.id
  }

  health_checks = [google_compute_health_check.multichain_healthcheck.id]
}

resource "google_compute_target_tcp_proxy" "mpc_proxy_metrics" {
  count           = length(var.node_configs)
  name            = "mpc-partner-target-proxy-metrics-${count.index}"
  description     = "MPC proxy for metrics(8080) port"
  backend_service = google_compute_backend_service.mpc_backend_metrics.id
}

resource "google_compute_global_forwarding_rule" "mpc_frontend_metrics" {
  count                 = length(var.node_configs)
  name                  = "mpc-partner-rule-metrics-${count.index}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "3000"
  target                = google_compute_target_tcp_proxy.mpc_proxy_metrics[count.index].id
  ip_address            = google_compute_global_address.external_ips[count.index].address
}