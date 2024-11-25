env        = "mainnet"
project_id = "<your-project-id>"
network    = "default"
subnetwork = "default"
image      = "us-east1-docker.pkg.dev/pagoda-discovery-platform-prod/multichain-public/multichain-mainnet:latest"
region     = "europe-west1"
zone       = "europe-west1-b"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account   = "{your_near_account_id}"
    cipher_pk = "<your_cipher_pk>"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-mainnet-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-mainnet-0"
    sign_sk_secret_id    = "multichain-sign-sk-mainnet-0"
    sk_share_secret_id   = "multichain-sk-share-mainnet-0"
    domain               = "{your-domain-or-subdomain}"
  },
]