terraform {
  backend "gcs" {
    bucket = "nearone-terraform-mpc"
    prefix = "state/infra/mpc-cluster-peter-upgrade-test"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

# These data blocks grab the values from your GCP secret manager, please adjust secret names as desired
# This is the AWS access key and secret key for our public S3 bucket with Lake data
data "google_secret_manager_secret_version" "aws_access_key_secret_id" {
  secret = "multichain-indexer-aws-access-key"
}

data "google_secret_manager_secret_version" "aws_secret_key_secret_id" {
  secret = "multichain-indexer-aws-secret-key"
}
