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

  container = {
    image = var.image

    port = "3000"
    volumeMounts = [
      {
        mountPath = "/data"
        name      = "host-path"
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
        name  = "MPC_CIPHER_PK"
        value = var.node_configs["${count.index}"].cipher_pk
      },
      {
        name  = "MPC_ACCOUNT_SK"
        value = data.google_secret_manager_secret_version.account_sk_secret_id[count.index].secret_data
      },
      {
        name  = "MPC_CIPHER_SK"
        value = data.google_secret_manager_secret_version.cipher_sk_secret_id[count.index].secret_data
      },
      {
        name  = "MPC_SIGN_SK"
        value = data.google_secret_manager_secret_version.sign_sk_secret_id[count.index] != null ? data.google_secret_manager_secret_version.sign_sk_secret_id[count.index].secret_data : data.google_secret_manager_secret_version.account_sk_secret_id[count.index].secret_data
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
        value = "http://${google_compute_global_address.external_ips[count.index].address}"
      },
      {
        name  = "MPC_SK_SHARE_SECRET_ID"
        value = var.node_configs["${count.index}"].sk_share_secret_id
      },
      {
        name  = "MPC_ENV",
        value = var.env
      },
      {
        name  = "MPC_GCP_PROJECT_ID"
        value = var.project_id
      },
      {
        name  = "MPC_REDIS_URL",
        value = var.redis_url
      }
    ])
  }
  volumes = [
    {
      name = "host-path"
      hostPath = {
        path = "/var/redis"
      }
    }
  ]
}

resource "google_service_account" "service_account" {
  account_id   = "multichain-${var.env}"
  display_name = "Multichain ${var.env} Account"
}

resource "google_project_iam_member" "sa-roles" {
  for_each = toset([
    "roles/secretmanager.admin",
    "roles/storage.objectAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.logWriter"
  ])

  role    = each.key
  member  = "serviceAccount:${google_service_account.service_account.email}"
  project = var.project_id
}

resource "google_compute_global_address" "external_ips" {
  count        = length(var.node_configs)
  name         = "multichain-testnet-${count.index}"
  address_type = "EXTERNAL"
}

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
  name_prefix  = "multichain-testnet-${count.index}"
  machine_type = "n2d-standard-2"

  startup_script = "docker rm watchtower ; docker run -d --name watchtower -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --debug --interval 30"

  source_image = var.source_image
  metadata     = merge(var.additional_metadata, { "gce-container-declaration" = module.gce-container["${count.index}"].metadata_value })
  tags = [
    "multichain"
  ]
  labels = {
    "container-vm" = module.gce-container[count.index].vm_container_label,
    environment    = "prod",
    chain          = "near",
    owner          = "sig",
    network        = "testnet"
  }

  depends_on = [google_compute_global_address.external_ips]
}


module "instances" {
  count      = length(var.node_configs)
  source     = "../modules/instance-from-tpl"
  region     = var.region
  project_id = var.project_id
  hostname   = "multichain-testnet-${count.index}"
  network    = var.network
  subnetwork = var.subnetwork

  instance_template = module.ig_template[count.index].self_link_unique

}

resource "google_compute_health_check" "multichain_healthcheck" {
  name = "multichain-testnet-healthcheck"

  http_health_check {
    port         = 3000
    request_path = "/"
  }

}

resource "google_compute_global_forwarding_rule" "default" {
  count                 = length(var.node_configs)
  name                  = "multichain-testnet-rule-${count.index}"
  target                = google_compute_target_http_proxy.default[count.index].id
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL"
  ip_address            = google_compute_global_address.external_ips[count.index].address
}

resource "google_compute_target_http_proxy" "default" {
  count       = length(var.node_configs)
  name        = "multichain-testnet-target-proxy-${count.index}"
  description = "a description"
  url_map     = google_compute_url_map.default[count.index].id
}

resource "google_compute_url_map" "default" {
  count           = length(var.node_configs)
  name            = "multichain-testnet-url-map-${count.index}"
  default_service = google_compute_backend_service.multichain_backend.id
}

resource "google_compute_backend_service" "multichain_backend" {
  name                  = "multichain-testnet-backend-service"
  load_balancing_scheme = "EXTERNAL"

  backend {
    group = google_compute_instance_group.multichain_group.id
  }

  health_checks = [google_compute_health_check.multichain_healthcheck.id]
}

resource "google_compute_instance_group" "multichain_group" {
  name      = "multichain-testnet-instance-group"
  instances = module.instances[*].self_links[0]

  zone = var.zone
  named_port {
    name = "http"
    port = 3000
  }
}
