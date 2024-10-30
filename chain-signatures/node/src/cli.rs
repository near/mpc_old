use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
use crate::gcp::GcpService;
use crate::protocol::{MpcSignProtocol, SignQueue};
use crate::storage::triple_storage::LockTripleNodeStorageBox;
use crate::{http_client, indexer, mesh, storage, web};
use clap::Parser;
use local_ip_address::local_ip;
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing_stackdriver::layer as stackdriver_layer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use url::Url;

use mpc_keys::hpke;

#[derive(Parser, Debug)]
pub enum Cli {
    Start {
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// MPC contract id
        #[arg(long, env("MPC_CONTRACT_ID"), default_value("v1.signer-dev.testnet"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_ACCOUNT_ID"))]
        account_id: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The web port for this server
        #[arg(long, env("MPC_WEB_PORT"))]
        web_port: u16,
        // TODO: need to add in CipherPK type for parsing.
        /// The cipher public key used to encrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_PK"))]
        cipher_pk: String,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_SK"))]
        cipher_sk: String,
        /// The secret key used to sign messages to be sent between nodes.
        #[arg(long, env("MPC_SIGN_SK"))]
        sign_sk: Option<SecretKey>,
        /// NEAR Lake Indexer options
        #[clap(flatten)]
        indexer_options: indexer::Options,
        /// Local address that other peers can use to message this node.
        #[arg(long, env("MPC_LOCAL_ADDRESS"))]
        my_address: Option<Url>,
        /// Storage options
        #[clap(flatten)]
        storage_options: storage::Options,
        /// The set of configurations that we will use to override contract configurations.
        #[arg(long, env("MPC_OVERRIDE_CONFIG"), value_parser = clap::value_parser!(OverrideConfig))]
        override_config: Option<OverrideConfig>,
        /// referer header for mainnet whitelist
        #[arg(long, env("MPC_CLIENT_HEADER_REFERER"), default_value(None))]
        client_header_referer: Option<String>,
        #[clap(flatten)]
        mesh_options: mesh::Options,
        #[clap(flatten)]
        message_options: http_client::Options,
    },
}

impl Cli {
    pub fn into_str_args(self) -> Vec<String> {
        match self {
            Cli::Start {
                near_rpc,
                account_id,
                mpc_contract_id,
                account_sk,
                web_port,
                cipher_pk,
                cipher_sk,
                sign_sk,
                indexer_options,
                my_address,
                storage_options,
                override_config,
                client_header_referer,
                mesh_options,
                message_options,
            } => {
                let mut args = vec![
                    "start".to_string(),
                    "--near-rpc".to_string(),
                    near_rpc,
                    "--mpc-contract-id".to_string(),
                    mpc_contract_id.to_string(),
                    "--account-id".to_string(),
                    account_id.to_string(),
                    "--account-sk".to_string(),
                    account_sk.to_string(),
                    "--web-port".to_string(),
                    web_port.to_string(),
                    "--cipher-pk".to_string(),
                    cipher_pk,
                    "--cipher-sk".to_string(),
                    cipher_sk,
                ];
                if let Some(sign_sk) = sign_sk {
                    args.extend(["--sign-sk".to_string(), sign_sk.to_string()]);
                }
                if let Some(my_address) = my_address {
                    args.extend(["--my-address".to_string(), my_address.to_string()]);
                }
                if let Some(override_config) = override_config {
                    args.extend([
                        "--override-config".to_string(),
                        serde_json::to_string(&override_config).unwrap(),
                    ]);
                }

                if let Some(client_header_referer) = client_header_referer {
                    args.extend(["--client-header-referer".to_string(), client_header_referer]);
                }

                args.extend(indexer_options.into_str_args());
                args.extend(storage_options.into_str_args());
                args.extend(mesh_options.into_str_args());
                args.extend(message_options.into_str_args());
                args
            }
        }
    }
}

/// This will whether this code is being ran on top of GCP or not.
fn is_running_on_gcp() -> bool {
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() {
        return true;
    }

    let resp = reqwest::blocking::Client::new()
        .get("http://metadata.google.internal/computeMetadata/v1/instance/id")
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_millis(200))
        .send();

    match resp {
        Ok(resp) => resp.status().is_success(),
        _ => false,
    }
}

pub fn run(cmd: Cli) -> anyhow::Result<()> {
    // Install global collector configured based on RUST_LOG env var.
    let base_subscriber = Registry::default().with(EnvFilter::from_default_env());

    let subscriber = if is_running_on_gcp() {
        let stackdriver = stackdriver_layer().with_writer(std::io::stderr);
        base_subscriber.with(None).with(Some(stackdriver))
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer().with_thread_ids(true);
        base_subscriber.with(Some(fmt_layer)).with(None)
    };

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    let _span = tracing::trace_span!("cli").entered();

    match cmd {
        Cli::Start {
            near_rpc,
            web_port,
            mpc_contract_id,
            account_id,
            account_sk,
            cipher_pk,
            cipher_sk,
            sign_sk,
            indexer_options,
            my_address,
            storage_options,
            override_config,
            client_header_referer,
            mesh_options,
            message_options,
        } => {
            let sign_queue = Arc::new(RwLock::new(SignQueue::new()));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let gcp_service =
                rt.block_on(async { GcpService::init(&account_id, &storage_options).await })?;
            let (indexer_handle, indexer) = indexer::run(
                &indexer_options,
                &mpc_contract_id,
                &account_id,
                &sign_queue,
                &gcp_service,
                &rt,
            )?;

            let key_storage =
                storage::secret_storage::init(Some(&gcp_service), &storage_options, &account_id);
            let triple_storage: LockTripleNodeStorageBox = Arc::new(RwLock::new(
                storage::triple_storage::init(Some(&gcp_service), &account_id),
            ));

            let sign_sk = sign_sk.unwrap_or_else(|| account_sk.clone());
            let my_address = my_address
                .map(|mut addr| {
                    addr.set_port(Some(web_port)).unwrap();
                    addr
                })
                .unwrap_or_else(|| {
                    let my_ip = local_ip().unwrap();
                    Url::parse(&format!("http://{my_ip}:{web_port}")).unwrap()
                });

            let (sender, receiver) = mpsc::channel(16384);

            tracing::info!(%my_address, "address detected");
            let mut rpc_client = near_fetch::Client::new(&near_rpc);
            if let Some(referer_param) = client_header_referer {
                let client_headers = rpc_client.inner_mut().headers_mut();
                client_headers.insert(http::header::REFERER, referer_param.parse().unwrap());
            }

            tracing::info!(rpc_addr = rpc_client.rpc_addr(), "rpc client initialized");
            let signer = InMemorySigner::from_secret_key(account_id.clone(), account_sk);
            let (protocol, protocol_state) = MpcSignProtocol::init(
                my_address,
                mpc_contract_id,
                account_id,
                rpc_client,
                signer,
                receiver,
                sign_queue,
                key_storage,
                triple_storage,
                Config::new(LocalConfig {
                    over: override_config.unwrap_or_else(Default::default),
                    network: NetworkConfig {
                        cipher_pk: hpke::PublicKey::try_from_bytes(&hex::decode(cipher_pk)?)?,
                        sign_sk,
                    },
                }),
                mesh_options,
                message_options,
            );

            rt.block_on(async {
                tracing::info!("protocol initialized");
                let protocol_handle = tokio::spawn(async move { protocol.run().await });
                tracing::info!("protocol thread spawned");
                let cipher_sk = hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?;
                let web_handle = tokio::spawn(async move {
                    web::run(web_port, sender, cipher_sk, protocol_state, indexer).await
                });
                tracing::info!("protocol http server spawned");

                protocol_handle.await??;
                web_handle.await??;
                tracing::info!("spinning down");

                indexer_handle.join().unwrap()?;
                anyhow::Ok(())
            })?;
        }
    }

    Ok(())
}
