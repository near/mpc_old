mod actions;
mod cases;

use crate::actions::wait_for;
use mpc_contract::update::{ProposeUpdateArgs, UpdateId};

use futures::future::BoxFuture;
use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::utils::{vote_join, vote_leave};
use integration_tests_chain_signatures::{run, utils, MultichainConfig, Nodes};

use near_workspaces::types::NearToken;
use near_workspaces::{Account, AccountId, Contract};

use integration_tests_chain_signatures::local::NodeConfig;
use std::collections::HashSet;

const CURRENT_CONTRACT_DEPLOY_DEPOSIT: NearToken = NearToken::from_millinear(9000);
const CURRENT_CONTRACT_FILE_PATH: &str =
    "../../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

pub struct MultichainTestContext<'a> {
    nodes: Nodes<'a>,
    rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    cfg: MultichainConfig,
}

impl MultichainTestContext<'_> {
    pub fn contract(&self) -> &Contract {
        self.nodes.contract()
    }

    pub async fn participant_accounts(&self) -> anyhow::Result<Vec<&Account>> {
        let state = wait_for::running_mpc(self, None).await?;
        let participant_ids = state.participants.keys().collect::<HashSet<_>>();
        let mut node_accounts = self.nodes.near_accounts();
        node_accounts.retain(|a| participant_ids.contains(a.id()));
        Ok(node_accounts)
    }

    pub async fn add_participant(
        &mut self,
        existing_node: Option<NodeConfig>,
    ) -> anyhow::Result<()> {
        let state = wait_for::running_mpc(self, None).await?;
        let node_account = match existing_node {
            Some(node) => {
                tracing::info!(
                    node_account_id = %node.account.id(),
                    "adding pre-existing participant"
                );
                node.account
            }
            None => {
                let account = self.nodes.ctx().worker.dev_create_account().await?;
                tracing::info!(node_account_id = %account.id(), "adding new participant");
                account
            }
        };

        self.nodes.start_node(&self.cfg, &node_account).await?;
        // Wait for new node to add itself as a candidate
        tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

        // T number of participants should vote
        let participants = self.participant_accounts().await?;
        let voting_participants = participants
            .iter()
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();
        assert!(vote_join(
            &voting_participants,
            self.contract().id(),
            node_account.id(),
        )
        .await
        .is_ok());

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        assert_eq!(new_state.participants.len(), state.participants.len() + 1);
        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(())
    }

    pub async fn remove_participant(
        &mut self,
        kick: Option<&AccountId>,
    ) -> anyhow::Result<NodeConfig> {
        let state = wait_for::running_mpc(self, None).await?;
        let participant_accounts = self.participant_accounts().await?;
        let kick = kick
            .unwrap_or_else(|| participant_accounts.last().unwrap().id())
            .clone();
        let voting_accounts = participant_accounts
            .iter()
            .filter(|account| account.id() != &kick)
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();

        tracing::info!(?voting_accounts, %kick, "kicking participant");
        let results = vote_leave(&voting_accounts, self.contract().id(), &kick).await;
        // Check if any result has failures, and return early with an error if so
        if results
            .iter()
            .any(|result| !result.as_ref().unwrap().failures().is_empty())
        {
            tracing::error!(?voting_accounts, "failed to vote");
            anyhow::bail!("failed to vote_leave");
        }

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        tracing::info!(
            "Getting new state, old {} {:?}, new {} {:?}",
            state.participants.len(),
            state.public_key,
            new_state.participants.len(),
            new_state.public_key
        );

        assert_eq!(state.participants.len(), new_state.participants.len() + 1);

        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(self.nodes.kill_node(&kick).await)
    }

    pub async fn propose_update(&self, args: ProposeUpdateArgs) -> mpc_contract::update::UpdateId {
        let accounts = self.nodes.near_accounts();
        accounts[0]
            .call(self.contract().id(), "propose_update")
            .args_borsh((args,))
            .max_gas()
            .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
            .transact()
            .await
            .unwrap()
            .json()
            .unwrap()
    }

    pub async fn propose_update_contract_default(&self) -> UpdateId {
        let same_contract_bytes = std::fs::read(CURRENT_CONTRACT_FILE_PATH).unwrap();
        self.propose_update(ProposeUpdateArgs {
            code: Some(same_contract_bytes),
            config: None,
        })
        .await
    }

    pub async fn vote_update(&self, id: UpdateId) {
        let participants = self.participant_accounts().await.unwrap();

        let mut success = 0;
        for account in participants.iter() {
            let execution = account
                .call(self.contract().id(), "vote_update")
                .args_json((id,))
                .max_gas()
                .transact()
                .await
                .unwrap()
                .into_result();

            match execution {
                Ok(_) => success += 1,
                Err(e) => tracing::warn!(?id, ?e, "Failed to vote for update"),
            }
        }

        assert!(
            success >= self.cfg.threshold,
            "did not successfully vote for update"
        );
    }
}

pub async fn with_multichain_nodes<F>(cfg: MultichainConfig, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(MultichainTestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker_client = DockerClient::default();
    let nodes = run(cfg.clone(), &docker_client).await?;

    let sk_local_path = nodes.ctx().storage_options.sk_share_local_path.clone();

    let connector = near_jsonrpc_client::JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client);
    let result = f(MultichainTestContext {
        nodes,
        rpc_client,
        http_client: reqwest::Client::default(),
        cfg,
    })
    .await;
    utils::clear_local_sk_shares(sk_local_path).await?;

    result
}
