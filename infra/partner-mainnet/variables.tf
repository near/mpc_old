variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
}

variable "mig_name" {
  description = "The desired name to assign to the deployed managed instance group"
  type        = string
  default     = "mpc-mig"
}

variable "image" {
  description = "The Docker image to deploy to GCE instances. Note: This is a public image repository used for updating your nodes, please do not change this"
  type        = string
  default     = "us-east1-docker.pkg.dev/pagoda-discovery-platform-prod/multichain-public/multichain-mainnet:latest"
}

variable "image_port" {
  description = "The port the image exposes for HTTP requests"
  type        = number
  default     = 3000
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
}

variable "zone" {
  type = string
}

variable "network" {
  description = "The GCP network"
  type        = string
}

variable "additional_metadata" {
  type        = map(any)
  description = "Additional metadata to attach to the instance"
  default = {
    cos-update-strategy : "update_enabled"
  }
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
  default = "mainnet"
}

variable "near_boot_nodes" {
  type = string
}

variable "static_env" {
  type = list(object({
    name  = string
    value = string
  }))
  default = [
    {
      name  = "MPC_NEAR_RPC"
      value = "https://rpc.mainnet.near.org"
    },
    {
      name  = "MPC_CONTRACT_ID"
      value = "v1.signer"
    },
    {
      name  = "MPC_INDEXER_S3_BUCKET"
      value = "near-lake-data-mainnet"
    },
    {
      name  = "MPC_INDEXER_START_BLOCK_HEIGHT"
      value = 124647189
    },
    {
      name  = "AWS_DEFAULT_REGION"
      value = "eu-central-1"
    },
    {
      name  = "MPC_GCP_PROJECT_ID"
      value = "<your-project-id>"
    },
    {
      name  = "MPC_WEB_PORT"
      value = "3000"
    },
    {
      name  = "RUST_LOG"
      value = "mpc_node=info"
    },
    {
      name  = "MPC_INDEXER_S3_REGION"
      value = "eu-central-1"
    },
    {
      name  = "MPC_CLIENT_HEADER_REFERER"
      value = "https://multichain-partner-mainnet-pagoda.api.pagoda.co"
    }
  ]
}

variable "create_network" {
  default     = false
  description = "Do you want to create a new VPC network (true) or use default GCP network (false)?"
}

variable "domain" {
  description = "DNS name for your node"
  default     = ""
}
