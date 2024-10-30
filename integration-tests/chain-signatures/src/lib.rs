pub mod containers;
pub mod execute;
pub mod local;
pub mod utils;

use deadpool_redis::Pool;
use std::collections::HashMap;

use self::local::NodeConfig;
use crate::containers::DockerClient;
use crate::containers::LocalStack;

use anyhow::Context as _;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use mpc_contract::config::{PresignatureConfig, ProtocolConfig, TripleConfig};
use mpc_contract::primitives::CandidateInfo;
use mpc_node::gcp::GcpService;
use mpc_node::http_client;
use mpc_node::mesh;
use mpc_node::storage;
use mpc_node::storage::triple_storage::TripleRedisStorage;
use near_crypto::KeyFile;
use near_workspaces::network::{Sandbox, ValidatorKey};
use near_workspaces::types::{KeyType, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::json;
use testcontainers::{Container, GenericImage};

const NETWORK: &str = "mpc_it_network";

#[derive(Clone, Debug)]
pub struct MultichainConfig {
    pub nodes: usize,
    pub threshold: usize,
    pub protocol: ProtocolConfig,
}

impl Default for MultichainConfig {
    fn default() -> Self {
        Self {
            nodes: 3,
            threshold: 2,
            protocol: ProtocolConfig {
                triple: TripleConfig {
                    min_triples: 8,
                    max_triples: 80,
                    ..Default::default()
                },
                presignature: PresignatureConfig {
                    min_presignatures: 2,
                    max_presignatures: 20,
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }
}

pub enum Nodes<'a> {
    Local {
        ctx: Context<'a>,
        nodes: Vec<local::Node>,
    },
    Docker {
        ctx: Context<'a>,
        nodes: Vec<containers::Node<'a>>,
    },
}

impl Nodes<'_> {
    pub fn len(&self) -> usize {
        match self {
            Nodes::Local { nodes, .. } => nodes.len(),
            Nodes::Docker { nodes, .. } => nodes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn ctx(&self) -> &Context {
        match self {
            Nodes::Local { ctx, .. } => ctx,
            Nodes::Docker { ctx, .. } => ctx,
        }
    }

    pub fn url(&self, id: usize) -> &str {
        match self {
            Nodes::Local { nodes, .. } => &nodes[id].address,
            Nodes::Docker { nodes, .. } => &nodes[id].address,
        }
    }

    pub fn near_accounts(&self) -> Vec<&Account> {
        match self {
            Nodes::Local { nodes, .. } => nodes.iter().map(|node| &node.account).collect(),
            Nodes::Docker { nodes, .. } => nodes.iter().map(|node| &node.account).collect(),
        }
    }

    pub async fn start_node(
        &mut self,
        cfg: &MultichainConfig,
        new_account: &Account,
    ) -> anyhow::Result<()> {
        tracing::info!(id = %new_account.id(), "adding one more node");
        match self {
            Nodes::Local { ctx, nodes } => {
                nodes.push(local::Node::run(ctx, cfg, new_account).await?)
            }
            Nodes::Docker { ctx, nodes } => {
                nodes.push(containers::Node::run(ctx, cfg, new_account).await?)
            }
        }

        Ok(())
    }

    pub async fn kill_node(&mut self, account_id: &AccountId) -> NodeConfig {
        let killed_node_config = match self {
            Nodes::Local { nodes, .. } => {
                let index = nodes
                    .iter()
                    .position(|node| node.account.id() == account_id)
                    .unwrap();
                nodes.remove(index).kill()
            }
            Nodes::Docker { nodes, .. } => {
                let index = nodes
                    .iter()
                    .position(|node| node.account.id() == account_id)
                    .unwrap();
                nodes.remove(index).kill()
            }
        };

        // wait for the node to be removed from the network
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        killed_node_config
    }

    pub async fn restart_node(&mut self, config: NodeConfig) -> anyhow::Result<()> {
        tracing::info!(node_account_id = %config.account.id(), "restarting node");
        match self {
            Nodes::Local { ctx, nodes } => nodes.push(local::Node::spawn(ctx, config).await?),
            Nodes::Docker { ctx, nodes } => nodes.push(containers::Node::spawn(ctx, config).await?),
        }
        // wait for the node to be added to the network
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(())
    }

    pub async fn triple_storage(
        &self,
        redis_pool: &Pool,
        account_id: &AccountId,
    ) -> TripleRedisStorage {
        storage::triple_storage::init(redis_pool, account_id)
    }

    pub async fn gcp_services(&self) -> anyhow::Result<Vec<GcpService>> {
        let mut gcp_services = Vec::new();
        match self {
            Nodes::Local { nodes, .. } => {
                for node in nodes {
                    gcp_services.push(
                        GcpService::init(node.account.id(), &self.ctx().storage_options).await?,
                    );
                }
            }
            Nodes::Docker { nodes, .. } => {
                for node in nodes {
                    gcp_services.push(
                        GcpService::init(node.account.id(), &self.ctx().storage_options).await?,
                    );
                }
            }
        }
        Ok(gcp_services)
    }

    pub fn proxy_name_for_node(&self, id: usize) -> String {
        let account_id = self.near_accounts();
        format!("rpc_from_node_{}", account_id[id].id())
    }

    pub fn contract(&self) -> &Contract {
        &self.ctx().mpc_contract
    }
}

pub struct Context<'a> {
    pub docker_client: &'a DockerClient,
    pub docker_network: String,
    pub release: bool,

    pub localstack: crate::containers::LocalStack<'a>,
    pub lake_indexer: crate::containers::LakeIndexer<'a>,
    pub worker: Worker<Sandbox>,
    pub mpc_contract: Contract,
    pub datastore: crate::containers::Datastore<'a>,
    pub redis: crate::containers::Redis<'a>,
    pub storage_options: storage::Options,
    pub mesh_options: mesh::Options,
    pub message_options: http_client::Options,
}

pub async fn setup(docker_client: &DockerClient) -> anyhow::Result<Context<'_>> {
    let release = true;
    let docker_network = NETWORK;
    docker_client.create_network(docker_network).await?;

    let LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    } = initialize_lake_indexer(docker_client, docker_network).await?;

    let mpc_contract = worker
        .dev_deploy(&std::fs::read(
            execute::target_dir()
                .context("could not find target dir")?
                .join("wasm32-unknown-unknown/release/mpc_contract.wasm"),
        )?)
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    let gcp_project_id = "multichain-integration";
    let datastore =
        crate::containers::Datastore::run(docker_client, docker_network, gcp_project_id).await?;

    let redis = crate::containers::Redis::run(docker_client, docker_network).await?;
    let redis_url = redis.internal_address.clone();

    let sk_share_local_path = "multichain-integration-secret-manager".to_string();
    let storage_options = mpc_node::storage::Options {
        env: "local-test".to_string(),
        gcp_project_id: "multichain-integration".to_string(),
        sk_share_secret_id: None,
        gcp_datastore_url: Some(datastore.local_address.clone()),
        sk_share_local_path: Some(sk_share_local_path),
        redis_url,
    };

    let mesh_options = mpc_node::mesh::Options {
        fetch_participant_timeout: 1000,
        refresh_active_timeout: 1000,
    };

    let message_options = http_client::Options { timeout: 1000 };

    Ok(Context {
        docker_client,
        docker_network: docker_network.to_string(),
        release,
        localstack,
        lake_indexer,
        worker,
        mpc_contract,
        datastore,
        redis,
        storage_options,
        mesh_options,
        message_options,
    })
}

pub async fn docker(cfg: MultichainConfig, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let accounts =
        futures::future::join_all((0..cfg.nodes).map(|_| ctx.worker.dev_create_account()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
    let mut node_futures = Vec::new();
    for account in &accounts {
        let node = containers::Node::run(&ctx, &cfg, account);
        node_futures.push(node);
    }
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let candidates: HashMap<AccountId, CandidateInfo> = accounts
        .iter()
        .cloned()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_pk.to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": candidates
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(Nodes::Docker { ctx, nodes })
}

pub async fn dry_host(
    cfg: MultichainConfig,
    docker_client: &DockerClient,
) -> anyhow::Result<Context> {
    let ctx = setup(docker_client).await?;

    let accounts =
        futures::future::join_all((0..cfg.nodes).map(|_| ctx.worker.dev_create_account()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
    let mut node_cfgs = Vec::new();
    for account in accounts.iter().take(cfg.nodes) {
        node_cfgs.push(local::Node::dry_run(&ctx, account, &cfg).await?);
    }

    let candidates: HashMap<AccountId, CandidateInfo> = accounts
        .iter()
        .cloned()
        .zip(&node_cfgs)
        .map(|(account, node_cfg)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: format!("http://127.0.0.1:{0}", node_cfg.web_port),
                    cipher_pk: node_cfg.cipher_pk.to_bytes(),
                    sign_pk: node_cfg.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();

    println!("\nPlease call below to update localnet:\n");
    let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
    println!("near config add-connection --network-name local --connection-name local --rpc-url {} --wallet-url http://127.0.0.1/ --explorer-transaction-url http://127.0.0.1:6666/", near_rpc);
    println!("\nAfter run the nodes, please call the following command to init contract: ");
    let args = json!({
        "threshold": cfg.threshold,
        "candidates": candidates
    })
    .to_string();
    let sk = SecretKey::from_seed(KeyType::ED25519, "testificate");

    println!("near contract call-function as-transaction {} init json-args '{}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as {} network-config local sign-with-plaintext-private-key --signer-public-key {} --signer-private-key {} send",
             ctx.mpc_contract.id(),
             args,
             ctx.mpc_contract.id(),
             sk.public_key(),
             sk
    );
    println!();

    Ok(ctx)
}

pub async fn host(cfg: MultichainConfig, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let accounts =
        futures::future::join_all((0..cfg.nodes).map(|_| ctx.worker.dev_create_account()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
    let mut node_futures = Vec::with_capacity(cfg.nodes);
    for account in &accounts {
        node_futures.push(local::Node::run(&ctx, &cfg, account));
    }
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let candidates: HashMap<AccountId, CandidateInfo> = accounts
        .iter()
        .cloned()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_pk.to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": candidates
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(Nodes::Local { ctx, nodes })
}

pub async fn run(cfg: MultichainConfig, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    #[cfg(feature = "docker-test")]
    return docker(cfg, docker_client).await;

    #[cfg(not(feature = "docker-test"))]
    return host(cfg, docker_client).await;
}

pub async fn dry_run(
    cfg: MultichainConfig,
    docker_client: &DockerClient,
) -> anyhow::Result<Context> {
    #[cfg(feature = "docker-test")]
    unimplemented!("dry_run only works with native node");

    #[cfg(not(feature = "docker-test"))]
    return dry_host(cfg, docker_client).await;
}

async fn fetch_from_validator(
    docker_client: &containers::DockerClient,
    container: &Container<'_, GenericImage>,
    path: &str,
) -> anyhow::Result<Vec<u8>> {
    tracing::info!(path, "fetching data from validator");
    let create_result = docker_client
        .docker
        .create_exec(
            container.id(),
            CreateExecOptions::<&str> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec!["cat", path]),
                ..Default::default()
            },
        )
        .await?;

    let start_result = docker_client
        .docker
        .start_exec(&create_result.id, None)
        .await?;

    match start_result {
        StartExecResults::Attached { mut output, .. } => {
            let mut stream_contents = Vec::new();
            while let Some(chunk) = output.next().await {
                stream_contents.extend_from_slice(&chunk?.into_bytes());
            }

            tracing::info!("data fetched");
            Ok(stream_contents)
        }
        StartExecResults::Detached => unreachable!("unexpected detached output"),
    }
}

async fn fetch_validator_keys(
    docker_client: &containers::DockerClient,
    container: &Container<'_, GenericImage>,
) -> anyhow::Result<KeyFile> {
    let _span = tracing::info_span!("fetch_validator_keys");
    let key_data =
        fetch_from_validator(docker_client, container, "/root/.near/validator_key.json").await?;
    Ok(serde_json::from_slice(&key_data)?)
}

pub struct LakeIndexerCtx<'a> {
    pub localstack: containers::LocalStack<'a>,
    pub lake_indexer: containers::LakeIndexer<'a>,
    pub worker: Worker<Sandbox>,
}

pub async fn initialize_lake_indexer<'a>(
    docker_client: &'a containers::DockerClient,
    network: &str,
) -> anyhow::Result<LakeIndexerCtx<'a>> {
    let s3_bucket = "near-lake-custom";
    let s3_region = "us-east-1";
    let localstack = LocalStack::run(docker_client, network, s3_bucket, s3_region).await?;

    let lake_indexer = containers::LakeIndexer::run(
        docker_client,
        network,
        &localstack.s3_address,
        s3_bucket,
        s3_region,
    )
    .await?;

    let validator_key = fetch_validator_keys(docker_client, &lake_indexer.container).await?;

    tracing::info!("initializing sandbox worker");
    let worker = near_workspaces::sandbox()
        // use not proxied rpc address because workspace is used in setup (create dev account, deploy
        // contract which we can assume succeed
        .rpc_addr(&lake_indexer.rpc_host_address)
        .validator_key(ValidatorKey::Known(
            validator_key.account_id.to_string().parse()?,
            validator_key.secret_key.to_string().parse()?,
        ))
        .await?;

    Ok(LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    })
}
