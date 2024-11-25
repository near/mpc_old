use crate::protocol::ProtocolState;
use crate::rpc_client;
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct ContractStateUpdater {
    rpc_client: near_fetch::Client,
    mpc_contract_id: AccountId,
}

impl ContractStateUpdater {
    pub fn init(
        rpc_client: near_fetch::Client,
        mpc_contract_id: AccountId,
    ) -> (Self, Arc<RwLock<Option<ProtocolState>>>) {
        let updater = Self {
            rpc_client,
            mpc_contract_id: mpc_contract_id.clone(),
        };
        let contract_state = Arc::new(RwLock::new(None));
        (updater, contract_state)
    }

    pub async fn run(
        &self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
    ) -> anyhow::Result<()> {
        let mut last_update = Instant::now();
        loop {
            if last_update.elapsed() > Duration::from_millis(1000) {
                let mut contract_state = contract_state.write().await;
                *contract_state =
                    rpc_client::fetch_mpc_contract_state(&self.rpc_client, &self.mpc_contract_id)
                        .await
                        .ok();
                last_update = Instant::now();
            }
        }
    }
}
