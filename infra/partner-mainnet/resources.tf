terraform {
  backend "gcs" {
    bucket = "multichain-terraform-{your_entity_name}"
    prefix = "state/mainnet"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}