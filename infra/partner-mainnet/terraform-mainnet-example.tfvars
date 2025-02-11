env             = "mainnet"
project_id      = "<your-project-id>"
network         = "default"
subnetwork      = "default"
image           = "docker.io/nearone/mpc-node-gcp:mainnet-standalone"
region          = "europe-west1"
zone            = "europe-west1-b"
near_boot_nodes = "ed25519:46peZ8rcRucjVPSSjfYEzUbSpqM8VEvCFsVwVFozRK6Q@65.108.96.254:24567,ed25519:DHowcbPk8DXYbefJgy7p74rqAn1wpJweeYuWmch6DEYd@65.109.70.223:24567,ed25519:2q7pyVVqW2vqYW6KPnoVu1HaPFaTkN2mnD9o76XAy88c@198.244.165.131:24567,ed25519:bZy5XwAekxbeth8btCoNaFnRZhZA6wZY8Q6NwqAmWv6@148.113.8.54:24567,ed25519:D7KoxvdbaiGFsx6UERAqEzeS5xYNRjoPaKrM54B8JdP6@194.182.189.12:24567,ed25519:3QT2JpTNBDREUm7ez2xCU1YKEHGqm9osAbg9hCPix3Ua@54.173.255.47:24567,ed25519:B5cpwy1LX9J6HUZiyeie9FZb1m8Qw8Q9JruFrYvMj3v1@103.50.32.50:22710,ed25519:6oSQBoaLLR2ttvqbPAEVT5TKfwYUyi3qYu7CXA5B5ERV@162.55.25.119:24567,ed25519:HZfT8ypFWQLb3YT4eyDLGim8mmFyUzxHkbCogmwWX2mE@142.132.192.24:24567,ed25519:HApx4szhWVtca1KL82hLmLXtAXrSWVVQkQJcT2BBVTnD@65.21.65.102:24567,ed25519:8DMLbdvVUVaL5KikT3Lqf1tXFW7iBF2yDFtKsc79JUow@34.135.231.166:24567,ed25519:BKgRXmMYuWXwTzS9izTh1g7NYL5q2A8azywfz9i8eUg9@65.109.69.56:24567"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account = "{your_near_account_id}"
    domain  = "mpc-test.nearone.org"
    # These 4 values below should match your secret names in google secrets manager
    gcp_local_encryption_key_secret_id = "multichain-local-encryption-key-0"
    gcp_keyshare_secret_id             = "multichain-sk-share-testnet-0"
    gcp_p2p_private_key_secret_id      = "multichain-sign-sk-testnet-0"
    gcp_account_sk_secret_id           = "multichain-account-sk-testnet-0"
  },
]