variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
  default     = "near-cs-dev"
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
  default     = "dev-europe-west1"
}

variable "mig_name" {
  description = "The desired name to assign to the deployed managed instance group"
  type        = string
  default     = "mpc-mig"
}

variable "source_image" {
  type    = string
  default = "projects/cos-cloud/global/images/cos-stable-117-18613-75-37"
}

variable "image" {
  description = "The Docker image to deploy to GCE instances"
  type        = string
  default     = "europe-west1-docker.pkg.dev/near-cs-dev/multichain/multichain-dev:latest"
}

variable "image_port" {
  description = "The port the image exposes for HTTP requests"
  type        = number
  default     = 3000
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
  default     = "europe-west1"
}

variable "network" {
  description = "The GCP network"
  type        = string
  default     = "dev"
}

variable "additional_metadata" {
  type        = map(any)
  description = "Additional metadata to attach to the instance"
  default     = {}
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

variable "env_variables" {
  type    = map(any)
  default = null
}

variable "node_configs" {
  type = list(object({
    account              = string
    cipher_pk            = string
    account_sk_secret_id = string
    cipher_sk_secret_id  = string
    sign_sk_secret_id    = string
    sk_share_secret_id   = string
    ip_address           = string
  }))
}

variable "env" {
  type    = string
  default = "dev"
}


variable "static_env" {
  type = list(object({
    name  = string
    value = string
  }))
  default = [
    {
      name  = "MPC_NEAR_RPC"
      value = "https://rpc.testnet.fastnear.com"
    },
    {
      name  = "MPC_CONTRACT_ID"
      value = "v1.signer-dev.testnet"
    },
    {
      name  = "MPC_INDEXER_S3_BUCKET"
      value = "near-lake-data-testnet"
    },
    {
      name  = "AWS_DEFAULT_REGION"
      value = "eu-central-1"
    },
    {
      name  = "MPC_GCP_PROJECT_ID"
      value = "near-cs-dev"
    },
    {
      name  = "MPC_WEB_PORT"
      value = "3000"
    },
    {
      name  = "RUST_LOG"
      value = "mpc_node=debug"
    },
    {
      name  = "MPC_INDEXER_S3_REGION"
      value = "eu-central-1"
    }
  ]
}

variable "redis_url" {
  type    = string
  default = "redis://127.0.0.1:6379"
}
