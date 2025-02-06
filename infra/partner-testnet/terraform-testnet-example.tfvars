env             = "testnet"
project_id      = "nearone-mpc"
network         = "default"
subnetwork      = "default"
image           = "docker.io/nearone/mpc-node-gcp:testnet-standalone"
region          = "europe-west1"
zone            = "europe-west1-b"
near_boot_nodes = "ed25519:EPH7y1nFPbtDqA3yNqpCX11JbLYT1dNbyD5axMM34fiZ@91.237.141.25:24567,ed25519:8UKENS6qMEr9ErfMyJEiDrsvrTbP9LkFcZeusy261Z5q@66.23.239.58:24568,ed25519:E319a9GQ3VmnQsNjtzDQ2XggkddnYiThmf1RUFQVQoZD@135.181.59.45:24568,ed25519:CZnYNFkwVc7puGKeVczEET3F7niQrmta9qBbrrCmQMoV@15.204.102.233:24567,ed25519:8QFAJ4kLg9rTXPkWrtZpTt6HRj4F38zfjQMcMR51QZDR@65.108.142.173:24567,ed25519:6KqNf95KiCriWByjXNJWGVYKc88Ff7vjs1LDGdqktFZD@54.184.146.36:24567,ed25519:7Bq35uKsRvoB8UAyF566LYSazdzdmwuUwAAwheBUy8iA@37.27.98.72:24567"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account      = "signer-c436b5b3-f815-4750-938d-1a4b4b87c911.testnet"
    domain       = "test.nearone.co"
    mpc_home_dir = "/data"
    # These 4 values below should match your secret names in google secrets manager
    gcp_local_encryption_key_secret_id = "multichain-local-encryption-key-0"
    gcp_keyshare_secret_id             = "multichain-sk-share-testnet-0"
    gcp_p2p_private_key_secret_id      = "multichain-sign-sk-testnet-0"
    gcp_account_sk_secret_id           = "multichain-account-sk-testnet-0"
  },
]