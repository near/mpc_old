// TODO: FIXME: Remove this once we have a better way to handle these large errors
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::PathBuf;

use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use clap::Parser;
use curv::elliptic::curves::Ed25519;
use curv::elliptic::curves::Point;
use multi_party_eddsa::protocols::ExpandedKeyPair;
use serde::de::DeserializeOwned;
use tracing_subscriber::EnvFilter;

use near_crypto::{InMemorySigner, SecretKey};
use near_fetch::signer::KeyRotatingSigner;
use near_primitives::types::AccountId;

use crate::firewall::allowed::PartnerList;
use crate::gcp::GcpService;
use crate::sign_node::migration;

pub mod error;
pub mod firewall;
pub mod gcp;
pub mod key_recovery;
pub mod leader_node;
pub mod logging;
pub mod metrics;
pub mod msg;
pub mod nar;
pub mod oauth;
pub mod primitives;
pub mod relayer;
pub mod sign_node;
pub mod transaction;
pub mod utils;

type NodeId = u64;

pub use leader_node::run as run_leader_node;
pub use leader_node::Config as LeaderConfig;
pub use sign_node::run as run_sign_node;
pub use sign_node::Config as SignerConfig;

pub struct GenerateResult {
    pub pk_set: Vec<Point<Ed25519>>,
    pub secrets: Vec<(ExpandedKeyPair, GenericArray<u8, U32>)>,
}

#[tracing::instrument(level = "debug", skip_all, fields(n = n))]
pub fn generate(n: usize) -> GenerateResult {
    // Let's tie this up to a deterministic RNG when we can
    let sk_set: Vec<_> = (1..=n).map(|_| ExpandedKeyPair::create()).collect();
    let cipher_keys: Vec<_> = (1..=n)
        .map(|_| Aes256Gcm::generate_key(&mut OsRng))
        .collect();
    let pk_set: Vec<_> = sk_set.iter().map(|sk| sk.public_key.clone()).collect();

    GenerateResult {
        pk_set,
        secrets: sk_set.into_iter().zip(cipher_keys.into_iter()).collect(),
    }
}

#[derive(Parser, Debug)]
pub enum Cli {
    Generate {
        n: usize,
    },
    StartLeader {
        /// Environment to run in (`dev` or `prod`)
        #[arg(long, env("MPC_RECOVERY_ENV"), default_value("dev"))]
        env: String,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        /// The compute nodes to connect to
        #[arg(long, value_parser, num_args = 1.., value_delimiter = ',', env("MPC_RECOVERY_SIGN_NODES"))]
        sign_nodes: Vec<String>,
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_RECOVERY_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// NEAR root account that has linkdrop contract deployed on it
        #[arg(long, env("MPC_RECOVERY_NEAR_ROOT_ACCOUNT"), default_value("testnet"))]
        near_root_account: String,
        /// Account creator ID
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_CREATOR_ID"))]
        account_creator_id: AccountId,
        /// Account creator's secret key(s)
        #[arg(
            long,
            value_parser = parse_json_str::<Vec<SecretKey>>,
            env("MPC_RECOVERY_ACCOUNT_CREATOR_SK"),
            default_value("[]")
        )]
        account_creator_sk: ::std::vec::Vec<SecretKey>,
        /// JSON list of related items to be used to verify OIDC tokens.
        #[arg(long, env("FAST_AUTH_PARTNERS"))]
        fast_auth_partners: Option<String>,
        /// Filepath to a JSON list of related items to be used to verify OIDC tokens.
        #[arg(long, value_parser, env("FAST_AUTH_PARTNERS_FILEPATH"))]
        fast_auth_partners_filepath: Option<PathBuf>,
        /// GCP project ID
        #[arg(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
        gcp_project_id: String,
        /// GCP datastore URL
        #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
        gcp_datastore_url: Option<String>,
        /// URLs of the public keys used by all issuers
        #[arg(long, value_parser = parse_json_str::<HashMap<String, String>>, env("MPC_RECOVERY_JWT_SIGNATURE_PK_URLS"))]
        jwt_signature_pk_urls: HashMap<String, String>,
        /// Enables export of span data using opentelemetry protocol.
        #[clap(flatten)]
        logging_options: logging::Options,
    },
    StartSign {
        /// Environment to run in (`dev` or `prod`)
        #[arg(long, env("MPC_RECOVERY_ENV"), default_value("dev"))]
        env: String,
        /// Node ID
        #[arg(long, env("MPC_RECOVERY_NODE_ID"))]
        node_id: u64,
        /// Cipher key to encrypt stored user credentials, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_CIPHER_KEY"))]
        cipher_key: Option<String>,
        /// Secret key share, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_SK_SHARE"))]
        sk_share: Option<String>,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        /// GCP project ID
        #[arg(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
        gcp_project_id: String,
        /// GCP datastore URL
        #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
        gcp_datastore_url: Option<String>,
        /// URLs of the public keys used by all issuers
        #[arg(long, value_parser = parse_json_str::<HashMap<String, String>>, env("MPC_RECOVERY_JWT_SIGNATURE_PK_URLS"))]
        jwt_signature_pk_urls: HashMap<String, String>,
        /// Enables export of span data using opentelemetry protocol.
        #[clap(flatten)]
        logging_options: logging::Options,
    },
    RotateSignNodeCipher {
        /// Environment to run in (`dev` or `prod`)
        #[arg(long, env("MPC_RECOVERY_ENV"), default_value("dev"))]
        env: String,
        /// If no `new_env` is specified, the rotation will be done inplace in the current `env`.
        #[arg(long, env("MPC_RECOVERY_ROTATE_INPLACE"))]
        new_env: Option<String>,
        /// Node ID
        #[arg(long, env("MPC_RECOVERY_NODE_ID"))]
        node_id: u64,
        /// Old cipher key, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_OLD_CIPHER_KEY"))]
        old_cipher_key: Option<String>,
        /// The new cipher key to replace each encrypted record with.
        #[arg(long, env("MPC_RECOVERY_NEW_CIPHER_KEY"))]
        new_cipher_key: Option<String>,
        /// GCP project ID
        #[arg(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
        gcp_project_id: String,
        /// GCP datastore URL
        #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
        gcp_datastore_url: Option<String>,
        /// Enables export of span data using opentelemetry protocol.
        #[clap(flatten)]
        logging_options: logging::Options,
    },
}

pub async fn run(cmd: Cli) -> anyhow::Result<()> {
    match cmd {
        Cli::Generate { n } => {
            let GenerateResult { pk_set, secrets } = generate(n);
            println!("Public key set: {}", serde_json::to_string(&pk_set)?);
            for (i, (sk_share, cipher_key)) in secrets.iter().enumerate() {
                println!(
                    "Secret key share {}: {}",
                    i,
                    serde_json::to_string(sk_share)?
                );
                println!("Cipher {}: {}", i, hex::encode(cipher_key));
            }
        }
        Cli::StartLeader {
            env,
            web_port,
            sign_nodes,
            near_rpc,
            near_root_account,
            account_creator_id,
            account_creator_sk,
            fast_auth_partners: partners,
            fast_auth_partners_filepath: partners_filepath,
            gcp_project_id,
            gcp_datastore_url,
            jwt_signature_pk_urls,
            logging_options,
        } => {
            let _subscriber_guard = logging::subscribe_global(
                EnvFilter::from_default_env(),
                &logging_options,
                env.clone(),
                "leader".to_string(),
            )
            .await;
            let gcp_service =
                GcpService::new(env.clone(), gcp_project_id, gcp_datastore_url).await?;
            let account_creator_signer =
                load_account_creator(&gcp_service, &env, &account_creator_id, account_creator_sk)
                    .await?;
            let partners = PartnerList {
                entries: load_entries(&gcp_service, &env, "leader", partners, partners_filepath)
                    .await?,
            };

            let config = LeaderConfig {
                env,
                port: web_port,
                sign_nodes,
                near_rpc,
                near_root_account,
                account_creator_signer,
                partners,
                jwt_signature_pk_urls,
            };

            run_leader_node(config).await;
        }
        Cli::StartSign {
            env,
            node_id,
            sk_share,
            cipher_key,
            web_port,
            gcp_project_id,
            gcp_datastore_url,
            jwt_signature_pk_urls,
            logging_options,
        } => {
            let _subscriber_guard = logging::subscribe_global(
                EnvFilter::from_default_env(),
                &logging_options,
                env.clone(),
                node_id.to_string(),
            )
            .await;
            let gcp_service =
                GcpService::new(env.clone(), gcp_project_id, gcp_datastore_url).await?;
            let cipher_key = load_cipher_key(&gcp_service, &env, node_id, cipher_key).await?;
            let cipher_key = hex::decode(cipher_key)?;
            let cipher_key = GenericArray::<u8, U32>::clone_from_slice(&cipher_key);
            let cipher = Aes256Gcm::new(&cipher_key);

            let sk_share = load_sh_skare(&gcp_service, &env, node_id, sk_share).await?;

            // TODO Import just the private key and derive the rest
            let sk_share: ExpandedKeyPair = serde_json::from_str(&sk_share).unwrap();

            let config = SignerConfig {
                gcp_service,
                our_index: node_id,
                node_key: sk_share,
                cipher,
                port: web_port,
                jwt_signature_pk_urls,
            };
            run_sign_node(config).await;
        }
        Cli::RotateSignNodeCipher {
            env,
            new_env,
            node_id,
            old_cipher_key,
            new_cipher_key,
            gcp_project_id,
            gcp_datastore_url,
            logging_options,
        } => {
            let _subscriber_guard = logging::subscribe_global(
                EnvFilter::from_default_env(),
                &logging_options,
                env.clone(),
                node_id.to_string(),
            )
            .await;
            let gcp_service = GcpService::new(
                env.clone(),
                gcp_project_id.clone(),
                gcp_datastore_url.clone(),
            )
            .await?;

            let dest_gcp_service = if let Some(new_env) = new_env {
                GcpService::new(new_env, gcp_project_id, gcp_datastore_url).await?
            } else {
                gcp_service.clone()
            };

            let old_cipher_key =
                load_cipher_key(&gcp_service, &env, node_id, old_cipher_key).await?;
            let old_cipher_key = hex::decode(old_cipher_key)?;
            let old_cipher_key = GenericArray::<u8, U32>::clone_from_slice(&old_cipher_key);
            let old_cipher = Aes256Gcm::new(&old_cipher_key);

            let new_cipher_key =
                load_cipher_key(&gcp_service, &env, node_id, new_cipher_key).await?;
            let new_cipher_key = hex::decode(new_cipher_key)?;
            let new_cipher_key = GenericArray::<u8, U32>::clone_from_slice(&new_cipher_key);
            let new_cipher = Aes256Gcm::new(&new_cipher_key);

            migration::rotate_cipher(
                node_id as usize,
                &old_cipher,
                &new_cipher,
                &gcp_service,
                &dest_gcp_service,
            )
            .await?;
        }
    }

    Ok(())
}

async fn load_sh_skare(
    gcp_service: &GcpService,
    env: &str,
    node_id: u64,
    sk_share_arg: Option<String>,
) -> anyhow::Result<String> {
    match sk_share_arg {
        Some(sk_share) => Ok(sk_share),
        None => {
            let name = format!("mpc-recovery-secret-share-{node_id}-{env}/versions/latest");
            Ok(std::str::from_utf8(&gcp_service.load_secret(name).await?)?.to_string())
        }
    }
}

async fn load_cipher_key(
    gcp_service: &GcpService,
    env: &str,
    node_id: u64,
    cipher_key_arg: Option<String>,
) -> anyhow::Result<String> {
    match cipher_key_arg {
        Some(cipher_key) => Ok(cipher_key),
        None => {
            let name = format!("mpc-recovery-encryption-cipher-{node_id}-{env}/versions/latest");
            Ok(std::str::from_utf8(&gcp_service.load_secret(name).await?)?.to_string())
        }
    }
}

async fn load_account_creator(
    gcp_service: &GcpService,
    env: &str,
    account_creator_id: &AccountId,
    account_creator_sk: Vec<SecretKey>,
) -> anyhow::Result<KeyRotatingSigner> {
    let sks = if account_creator_sk.is_empty() {
        let name = format!("mpc-recovery-account-creator-sk-{env}/versions/latest");
        let data = gcp_service.load_secret(name).await?;
        serde_json::from_str(std::str::from_utf8(&data)?)?
    } else {
        account_creator_sk
    };

    Ok(KeyRotatingSigner::from_signers(sks.into_iter().map(|sk| {
        InMemorySigner::from_secret_key(account_creator_id.clone(), sk)
    })))
}

async fn load_entries<T>(
    gcp_service: &GcpService,
    env: &str,
    node_id: &str,
    data: Option<String>,
    path: Option<PathBuf>,
) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let entries = match (data, path) {
        (Some(data), None) => serde_json::from_str(&data)?,
        (None, Some(path)) => {
            let file = std::fs::File::open(path)?;
            let reader = std::io::BufReader::new(file);
            serde_json::from_reader(reader)?
        }
        (None, None) => {
            let name =
                format!("mpc-recovery-allowed-oidc-providers-{node_id}-{env}/versions/latest");
            let data = gcp_service.load_secret(name).await?;
            serde_json::from_str(std::str::from_utf8(&data)?)?
        }
        _ => return Err(anyhow::anyhow!("Invalid combination of data and path")),
    };

    Ok(entries)
}

impl Cli {
    pub fn into_str_args(self) -> Vec<String> {
        match self {
            Cli::Generate { n } => {
                vec!["generate".to_string(), n.to_string()]
            }
            Cli::StartLeader {
                env,
                web_port,
                sign_nodes,
                near_rpc,
                near_root_account,
                account_creator_id,
                account_creator_sk,
                fast_auth_partners,
                fast_auth_partners_filepath,
                gcp_project_id,
                gcp_datastore_url,
                jwt_signature_pk_urls,
                logging_options,
            } => {
                let mut buf = vec![
                    "start-leader".to_string(),
                    "--env".to_string(),
                    env.to_string(),
                    "--web-port".to_string(),
                    web_port.to_string(),
                    "--near-rpc".to_string(),
                    near_rpc,
                    "--near-root-account".to_string(),
                    near_root_account,
                    "--account-creator-id".to_string(),
                    account_creator_id.to_string(),
                    "--gcp-project-id".to_string(),
                    gcp_project_id,
                ];

                if let Some(partners) = fast_auth_partners {
                    buf.push("--fast-auth-partners".to_string());
                    buf.push(partners);
                }
                if let Some(partners_filepath) = fast_auth_partners_filepath {
                    buf.push("--fast-auth-partners-filepath".to_string());
                    buf.push(partners_filepath.to_str().unwrap().to_string());
                }
                if let Some(gcp_datastore_url) = gcp_datastore_url {
                    buf.push("--gcp-datastore-url".to_string());
                    buf.push(gcp_datastore_url);
                }
                for sign_node in sign_nodes {
                    buf.push("--sign-nodes".to_string());
                    buf.push(sign_node);
                }

                let jwt_signature_pk_urls = serde_json::to_string(&jwt_signature_pk_urls).unwrap();
                buf.push("--jwt-signature-pk-urls".to_string());
                buf.push(jwt_signature_pk_urls);

                let account_creator_sk = serde_json::to_string(&account_creator_sk).unwrap();
                buf.push("--account-creator-sk".to_string());
                buf.push(account_creator_sk);
                buf.extend(logging_options.into_str_args());

                buf
            }
            Cli::StartSign {
                env,
                node_id,
                web_port,
                cipher_key,
                sk_share,
                gcp_project_id,
                gcp_datastore_url,
                jwt_signature_pk_urls,
                logging_options,
            } => {
                let mut buf = vec![
                    "start-sign".to_string(),
                    "--env".to_string(),
                    env.to_string(),
                    "--node-id".to_string(),
                    node_id.to_string(),
                    "--web-port".to_string(),
                    web_port.to_string(),
                    "--gcp-project-id".to_string(),
                    gcp_project_id,
                ];
                if let Some(key) = cipher_key {
                    buf.push("--cipher-key".to_string());
                    buf.push(key);
                }
                if let Some(share) = sk_share {
                    buf.push("--sk-share".to_string());
                    buf.push(share);
                }
                if let Some(gcp_datastore_url) = gcp_datastore_url {
                    buf.push("--gcp-datastore-url".to_string());
                    buf.push(gcp_datastore_url);
                }

                let jwt_signature_pk_urls = serde_json::to_string(&jwt_signature_pk_urls).unwrap();
                buf.push("--jwt-signature-pk-urls".to_string());
                buf.push(jwt_signature_pk_urls);

                buf.extend(logging_options.into_str_args());

                buf
            }
            Cli::RotateSignNodeCipher {
                env,
                new_env,
                node_id,
                old_cipher_key,
                new_cipher_key,
                gcp_project_id,
                gcp_datastore_url,
                logging_options,
            } => {
                let mut buf = vec![
                    "rotate-sign-node-cipher".to_string(),
                    "--env".to_string(),
                    env.to_string(),
                    "--node-id".to_string(),
                    node_id.to_string(),
                    "--gcp-project-id".to_string(),
                    gcp_project_id,
                ];
                if let Some(new_env) = new_env {
                    buf.push("--new-env".to_string());
                    buf.push(new_env);
                }
                if let Some(old_cipher_key) = old_cipher_key {
                    buf.push("--old-cipher-key".to_string());
                    buf.push(old_cipher_key);
                }
                if let Some(new_cipher_key) = new_cipher_key {
                    buf.push("--new-cipher-key".to_string());
                    buf.push(new_cipher_key);
                }
                if let Some(gcp_datastore_url) = gcp_datastore_url {
                    buf.push("--gcp-datastore-url".to_string());
                    buf.push(gcp_datastore_url);
                }
                buf.extend(logging_options.into_str_args());

                buf
            }
        }
    }
}

fn parse_json_str<T>(val: &str) -> Result<T, String>
where
    for<'a> T: serde::Deserialize<'a>,
{
    serde_json::from_str(val).map_err(|e| e.to_string())
}
