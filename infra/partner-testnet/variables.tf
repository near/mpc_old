variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
}

variable "network" {
  description = "The GCP network"
  type        = string
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
}

variable "image" {
  description = "The Docker image to deploy to GCE instances. Note: This is a public image repository used for updating your nodes, please do not change this"
  type        = string
  default     = "docker.io/nearone/mpc-node-gcp:testnet-standalone"
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
}

variable "zone" {
  type = string
}

variable "near_boot_nodes" {
  type = string
}

variable "service_account" {
  type = object({
    email  = string,
    scopes = list(string)
  })
  default = {
    email  = ""
    scopes = ["cloud-platform"]
  }
}

variable "node_configs" {
  type = list(object({
    account                            = string
    domain                             = string
    gcp_local_encryption_key_secret_id = string
    gcp_keyshare_secret_id             = string
    gcp_p2p_private_key_secret_id      = string
    gcp_account_sk_secret_id           = string
  }))
}

variable "env" {
  type    = string
  default = "dev"
}

variable "create_network" {
  default     = false
  description = "Do you want to create a new VPC network (true) or use default GCP network (false)?"
}