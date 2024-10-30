use crate::{execute, utils, MultichainConfig};

use crate::containers::LakeIndexer;
use crate::execute::executable;
use anyhow::Context;
use async_process::Child;
use mpc_keys::hpke;
use mpc_node::config::OverrideConfig;
use near_workspaces::Account;
use shell_escape::escape;

pub struct Node {
    pub address: String,
    pub account: Account,
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    cipher_sk: hpke::SecretKey,
    cfg: MultichainConfig,
    web_port: u16,

    // process held so it's not dropped. Once dropped, process will be killed.
    process: Child,
    // near rpc address, after proxy
    pub near_rpc: String,
}

pub struct NodeConfig {
    pub web_port: u16,
    pub account: Account,
    pub cipher_pk: hpke::PublicKey,
    pub cipher_sk: hpke::SecretKey,
    pub sign_sk: near_crypto::SecretKey,
    pub cfg: MultichainConfig,
    // near rpc address, after proxy
    pub near_rpc: String,
}

impl Node {
    pub async fn dry_run(
        ctx: &super::Context<'_>,
        account: &Account,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<NodeConfig> {
        let account_id = account.id();
        let account_sk = account.secret_key();
        let web_port = utils::pick_unused_port().await?;
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");

        let indexer_options = mpc_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
            running_threshold: 120,
            behind_threshold: 120,
        };
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let cli = mpc_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            sign_sk: Some(sign_sk.clone()),
            indexer_options,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                cfg.protocol.clone(),
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        };

        let cmd = executable(ctx.release, crate::execute::PACKAGE_MULTICHAIN)
            .with_context(|| "could not find target dir for mpc-node")?;
        let args = cli.into_str_args();
        let escaped_args: Vec<_> = args
            .iter()
            .map(|arg| escape(arg.clone().into()).to_string())
            .collect();
        println!(
            "\nCommand to run node {}:\n {} {}",
            account_id,
            cmd.to_str().unwrap(),
            escaped_args.join(" ")
        );
        let node_config = NodeConfig {
            web_port,
            account: account.clone(),
            cipher_pk,
            cipher_sk,
            sign_sk,
            cfg: cfg.clone(),
            near_rpc,
        };
        Ok(node_config)
    }

    pub async fn run(
        ctx: &super::Context<'_>,
        cfg: &MultichainConfig,
        account: &Account,
    ) -> anyhow::Result<Self> {
        let web_port = utils::pick_unused_port().await?;
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();

        let proxy_name = format!("rpc_from_node_{}", account.id());
        let rpc_port_proxied = utils::pick_unused_port().await?;
        let rpc_address_proxied = format!("http://127.0.0.1:{}", rpc_port_proxied);
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!(
            "Proxy RPC address {} accessed by node@{} to {}",
            near_rpc,
            address,
            rpc_address_proxied
        );
        LakeIndexer::populate_proxy(&proxy_name, true, &rpc_address_proxied, &near_rpc).await?;

        Self::spawn(
            ctx,
            NodeConfig {
                web_port,
                account: account.clone(),
                cipher_pk,
                cipher_sk,
                sign_sk,
                cfg: cfg.clone(),
                near_rpc: rpc_address_proxied,
            },
        )
        .await
    }

    pub async fn spawn(ctx: &super::Context<'_>, config: NodeConfig) -> anyhow::Result<Self> {
        let web_port = config.web_port;
        let indexer_options = mpc_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
            running_threshold: 120,
            behind_threshold: 120,
        };
        let cli = mpc_node::cli::Cli::Start {
            near_rpc: config.near_rpc.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: config.account.id().clone(),
            account_sk: config.account.secret_key().to_string().parse()?,
            web_port,
            cipher_pk: hex::encode(config.cipher_pk.to_bytes()),
            cipher_sk: hex::encode(config.cipher_sk.to_bytes()),
            sign_sk: Some(config.sign_sk.clone()),
            indexer_options,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                config.cfg.protocol.clone(),
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        };

        let mpc_node_id = format!("multichain/{}", config.account.id());
        let process = execute::spawn_multichain(ctx.release, &mpc_node_id, cli)?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {address}");
        utils::ping_until_ok(&address, 60).await?;
        tracing::info!(node_account_id = %config.account.id(), ?address, "node started");

        Ok(Self {
            address,
            account: config.account,
            sign_sk: config.sign_sk,
            cipher_pk: config.cipher_pk,
            cipher_sk: config.cipher_sk,
            near_rpc: config.near_rpc,
            cfg: config.cfg,
            web_port,
            process,
        })
    }

    pub fn kill(self) -> NodeConfig {
        // NOTE: process gets killed after this function completes via the drop, due to taking ownership of self.

        tracing::info!(id = %self.account.id(), ?self.address, "node killed");
        NodeConfig {
            web_port: self.web_port,
            account: self.account.clone(),
            cipher_pk: self.cipher_pk.clone(),
            cipher_sk: self.cipher_sk.clone(),
            sign_sk: self.sign_sk.clone(),
            cfg: self.cfg.clone(),
            near_rpc: self.near_rpc.clone(),
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.process.kill().unwrap();
    }
}
