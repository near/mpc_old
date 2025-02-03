provider "google" {
  project = var.project_id
}
provider "google-beta" {
  project = var.project_id
}

resource "google_compute_project_metadata_item" "project_logging" {
  key   = "google-logging-enabled"
  value = "true"
}

module "gce-container" {
  count   = length(var.node_configs)
  source  = "terraform-google-modules/container-vm/google"
  version = "~> 3.0"
  volumes = [
    {
      name = "data-0"
      hostPath = {
        path = "/home/mpc/data"
      }
    }
  ]
  container = {
    name           = "mpc_node"
    image          = var.image
    args           = ["/app/gcp-start.sh"]
    restart_policy = "always"

    volumeMounts = [
      {
        name      = "data-0"
        mountPath = "/data"
        readOnly  = false
      }
    ]

    env = concat(var.static_env, [
      {
        name  = "MPC_NODE_ID"
        value = "${count.index}"
      },
      {
        name  = "MPC_ACCOUNT_ID"
        value = var.node_configs["${count.index}"].account
      },
      {
        name  = "RUST_LOG"
        value = "debug,info"
      },
      {
        name  = "RUST_BACKTRACE"
        value = "full"
      },
      {
        name  = "AWS_ACCESS_KEY_ID"
        value = data.google_secret_manager_secret_version.aws_access_key_secret_id.secret_data
      },
      {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = data.google_secret_manager_secret_version.aws_secret_key_secret_id.secret_data
      },
      {
        name  = "MPC_LOCAL_ADDRESS"
        value = "http://${google_compute_address.external_ips[count.index].address}"
      },
      {
        name  = "MPC_ENV",
        value = var.env
      },
      {
        name  = "GCP_PROJECT_ID",
        value = var.project_id
      },
      {
        name  = "GCP_KEYSHARE_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_keyshare_secret_id
      },
      {
        name  = "GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_local_encryption_key_secret_id
      },
      {
        name  = "GCP_P2P_PRIVATE_KEY_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_p2p_private_key_secret_id
      },
      {
        name  = "GCP_ACCOUNT_SK_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_account_sk_secret_id
      },
      {
        name  = "MPC_HOME_DIR"
        value = var.node_configs["${count.index}"].mpc_home_dir
      },
      {
        name  = "NEAR_BOOT_NODES"
        value = var.near_boot_nodes
      },
    ])
  }
}

#####################################################################
# Account definitions
#####################################################################

resource "google_service_account" "service_account" {
  account_id   = "multichain-${var.env}"
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
resource "google_compute_address" "external_ips" {
  count        = length(var.node_configs)
  name         = "multichain-dev-parnter-${count.index}"
  region       = var.region
  address_type = "EXTERNAL"
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
  name_prefix          = "multichain-partner-${count.index}"
  source_image_family  = "cos-stable"
  source_image_project = "cos-cloud"
  machine_type         = "n2d-standard-16"

  startup_script = file("${path.module}/../scripts/mpc_init.sh")

  additional_disks = [{
    description  = "Main data disk"
    disk_name    = "mpc-partner-testnet-${count.index}"
    auto_delete  = false
    boot         = false
    disk_size_gb = 500
    disk_type    = "pd-ssd"
    disk_labels  = {}
    device_name  = "mpc-partner-testnet-${count.index}"
  }]

  source_image = reverse(split("/", module.gce-container[count.index].source_image))[0]
  metadata     = merge(var.additional_metadata, { "gce-container-declaration" = module.gce-container["${count.index}"].metadata_value })
  tags = [
    "multichain",
    "allow-ssh"
  ]
  labels = {
    "container-vm" = module.gce-container[count.index].vm_container_label
  }

  depends_on = [google_compute_address.external_ips]
}

module "instances" {
  count      = length(var.node_configs)
  source     = "../modules/instance-from-tpl"
  region     = var.region
  project_id = var.project_id
  hostname   = "multichain-testnet-partner-${count.index}"
  network    = var.network
  subnetwork = var.subnetwork

  instance_template = module.ig_template[count.index].self_link_unique

}

#####################################################################
# Firewall and loadbalancer template
#####################################################################
resource "google_compute_instance_group" "multichain_group" {
  name      = "multichain-partner-instance-group"
  instances = module.instances[*].self_links[0]

  zone = var.zone
  named_port {
    name = "http"
    port = 3000
  }
}
resource "google_compute_firewall" "app_port" {
  name    = "allow-multichain-healthcheck-access"
  network = var.network

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  source_tags   = ["multichain"]

  allow {
    protocol = "tcp"
    ports    = ["80", "3000"]
  }

}

#####################################################################
# LOAD BALANCER definition Passthrough
#####################################################################
resource "google_compute_region_health_check" "multichain_tcp_region_healthcheck" {
  check_interval_sec = 5
  description        = "Multichain-TCP-region-healthcheck-for-Loadbalancer"
  healthy_threshold  = 2
  name               = "multichain-healthcheck"
  project            = var.project_id
  region             = var.region
  http_health_check {
    port         = 3030
    proxy_header = "NONE"
    request_path = "/metrics"
  }

  timeout_sec         = 5
  unhealthy_threshold = 2
}

resource "google_compute_region_backend_service" "multichain_backend_passthrough" {
  connection_draining_timeout_sec = 300
  description                     = "Multichain backend passthrough"
  health_checks                   = [google_compute_region_health_check.multichain_tcp_region_healthcheck.id]
  load_balancing_scheme           = "EXTERNAL"
  locality_lb_policy              = "MAGLEV"

  log_config {
    sample_rate = 0
  }

  name             = "multichain-backend-passthrough"
  port_name        = "http"
  protocol         = "TCP"
  project          = var.project_id
  region           = var.region
  session_affinity = "NONE"
  timeout_sec      = 30

  backend {
    group = google_compute_instance_group.multichain_group.id
    balancing_mode = "CONNECTION"
    failover = false
  }
}

resource "google_compute_forwarding_rule" "multichain_frontend_passthrough" {
  count           = length(var.node_configs)
  all_ports       = true
  backend_service = google_compute_region_backend_service.multichain_backend_passthrough.id
  ip_address      = google_compute_address.external_ips[count.index].address
  ip_protocol     = "TCP"
  load_balancing_scheme = "EXTERNAL"
  name                  = "multichain-frontend-passthrough"
  network_tier          = "PREMIUM"
  project               = var.project_id
  region                = var.region
}
