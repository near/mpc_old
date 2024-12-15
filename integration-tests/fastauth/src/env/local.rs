use std::collections::HashMap;

use crate::env::{LeaderNodeApi, SignerNodeApi};
use crate::mpc::{self, NodeProcess};
use crate::util;
use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use mpc_recovery::firewall::allowed::DelegateActionRelayer;
use mpc_recovery::logging;
use mpc_recovery::relayer::NearRpcAndRelayerClient;
use multi_party_eddsa::protocols::ExpandedKeyPair;

pub struct SignerNode {
    pub address: String,
    env: String,
    node_id: usize,
    sk_share: ExpandedKeyPair,
    cipher_key: GenericArray<u8, U32>,
    gcp_project_id: String,
    gcp_datastore_url: String,

    // process held so it's not dropped. Once dropped, process will be killed.
    _process: NodeProcess,
}

impl SignerNode {
    pub async fn run(
        ctx: &super::Context<'_>,
        node_id: u64,
        sk_share: &ExpandedKeyPair,
        cipher_key: &GenericArray<u8, U32>,
    ) -> anyhow::Result<Self> {
        let web_port = util::pick_unused_port().await?;
        let mut jwt_signature_pk_urls = HashMap::new();
        jwt_signature_pk_urls.insert(ctx.issuer.clone(), ctx.oidc_provider.jwt_pk_url.clone());
        let cli = mpc_recovery::Cli::StartSign {
            env: ctx.env.clone(),
            node_id,
            web_port,
            sk_share: Some(serde_json::to_string(&sk_share)?),
            cipher_key: Some(hex::encode(cipher_key)),
            gcp_project_id: ctx.gcp_project_id.clone(),
            gcp_datastore_url: Some(ctx.datastore.local_address.clone()),
            jwt_signature_pk_urls,
            logging_options: logging::Options::default(),
        };

        let sign_node_id = format!("sign-{node_id}");
        let process = mpc::spawn(ctx.release, &sign_node_id, cli).await?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("Signer node is starting at {}", address);
        util::ping_until_ok(&address, 60).await?;
        tracing::info!("Signer node started [node_id={node_id}, {address}]");

        Ok(Self {
            address,
            env: ctx.env.clone(),
            node_id: node_id as usize,
            sk_share: sk_share.clone(),
            cipher_key: *cipher_key,
            gcp_project_id: ctx.gcp_project_id.clone(),
            gcp_datastore_url: ctx.datastore.local_address.clone(),
            _process: process,
        })
    }

    pub fn api(&self) -> SignerNodeApi {
        SignerNodeApi {
            address: self.address.clone(),
            env: self.env.clone(),
            node_id: self.node_id,
            sk_share: self.sk_share.clone(),
            cipher_key: self.cipher_key,
            gcp_project_id: self.gcp_project_id.clone(),
            gcp_datastore_local_url: self.gcp_datastore_url.clone(),
        }
    }
}

pub struct LeaderNode {
    pub address: String,
    near_rpc: String,
    relayer_url: String,

    // process held so it's not dropped. Once dropped, process will be killed.
    _process: NodeProcess,
}

impl LeaderNode {
    pub async fn run(ctx: &super::Context<'_>, sign_nodes: Vec<String>) -> anyhow::Result<Self> {
        tracing::info!("Running leader node...");
        let account_creator = &ctx.relayer_ctx.creator_account;
        let web_port = util::pick_unused_port().await?;
        let mut jwt_signature_pk_urls = HashMap::new();
        jwt_signature_pk_urls.insert(ctx.issuer.clone(), ctx.oidc_provider.jwt_pk_url.clone());
        let cli = mpc_recovery::Cli::StartLeader {
            env: ctx.env.clone(),
            web_port,
            sign_nodes,
            near_rpc: ctx.relayer_ctx.sandbox.local_address.clone(),
            near_root_account: ctx.relayer_ctx.worker.root_account()?.id().to_string(),
            account_creator_id: account_creator.id().as_str().parse()?,
            account_creator_sk: ctx
                .relayer_ctx
                .creator_account_keys
                .iter()
                .map(|k| k.to_string().parse())
                .collect::<Result<Vec<_>, _>>()?,
            fast_auth_partners_filepath: None,
            fast_auth_partners: Some(
                serde_json::json!([
                    {
                        "oidc_provider": {
                            "issuer": ctx.issuer,
                            "audience": ctx.audience_id,
                        },
                        "relayer": {
                            "url": &ctx.relayer_ctx.relayer.local_address,
                            "api_key": serde_json::Value::Null,
                        },
                    },
                ])
                .to_string(),
            ),
            gcp_project_id: ctx.gcp_project_id.clone(),
            gcp_datastore_url: Some(ctx.datastore.local_address.clone()),
            jwt_signature_pk_urls,
            logging_options: logging::Options::default(),
        };

        let process = mpc::spawn(ctx.release, "leader", cli).await?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("Leader node container is starting at {}", address);
        util::ping_until_ok(&address, 60).await?;
        tracing::info!("Leader node running at {address}");

        Ok(Self {
            address,
            near_rpc: ctx.relayer_ctx.sandbox.local_address.clone(),
            relayer_url: ctx.relayer_ctx.relayer.local_address.clone(),
            _process: process,
        })
    }

    pub fn api(&self) -> LeaderNodeApi {
        LeaderNodeApi {
            address: self.address.clone(),
            client: NearRpcAndRelayerClient::connect(&self.near_rpc),
            relayer: DelegateActionRelayer {
                url: self.relayer_url.clone(),
                api_key: None,
            },
        }
    }
}
