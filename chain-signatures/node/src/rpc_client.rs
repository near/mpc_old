use crate::config::{Config, ContractConfig};
use crate::protocol::ProtocolState;

use near_account_id::AccountId;
use near_crypto::InMemorySigner;

use serde_json::json;

pub async fn fetch_mpc_contract_state(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<ProtocolState> {
    let contract_state: mpc_contract::ProtocolContractState = rpc_client
        .view(mpc_contract_id, "state")
        .await
        .map_err(|e| {
            tracing::warn!(%e, "failed to fetch protocol state");
            e
        })?
        .json()?;

    let protocol_state: ProtocolState = contract_state.try_into().map_err(|_| {
        let msg = "failed to parse protocol state, has it been initialized?".to_string();
        tracing::error!(msg);
        anyhow::anyhow!(msg)
    })?;

    tracing::debug!(?protocol_state, "protocol state");
    Ok(protocol_state)
}

pub async fn fetch_mpc_config(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
    original: &Config,
) -> anyhow::Result<Config> {
    let contract_config: ContractConfig = rpc_client
        .view(mpc_contract_id, "config")
        .await
        .map_err(|e| {
            tracing::warn!(%e, "failed to fetch contract config");
            e
        })?
        .json()?;
    tracing::debug!(?contract_config, "contract config");
    Config::try_from_contract(contract_config, original).ok_or_else(|| {
        let msg = "failed to parse contract config";
        tracing::error!(msg);
        anyhow::anyhow!(msg)
    })
}

pub async fn vote_for_public_key(
    rpc_client: &near_fetch::Client,
    signer: &InMemorySigner,
    mpc_contract_id: &AccountId,
    public_key: &near_crypto::PublicKey,
) -> anyhow::Result<bool> {
    tracing::info!(%public_key, %signer.account_id, "voting for public key");
    let result = rpc_client
        .call(signer, mpc_contract_id, "vote_pk")
        .args_json(json!({
            "public_key": public_key
        }))
        .max_gas()
        .retry_exponential(10, 5)
        .transact()
        .await
        .map_err(|e| {
            tracing::warn!(%e, "failed to vote for public key");
            e
        })?
        .json()?;

    Ok(result)
}

pub async fn vote_reshared(
    rpc_client: &near_fetch::Client,
    signer: &InMemorySigner,
    mpc_contract_id: &AccountId,
    epoch: u64,
) -> anyhow::Result<bool> {
    tracing::info!(%epoch, %signer.account_id, "voting for reshared");
    let result = rpc_client
        .call(signer, mpc_contract_id, "vote_reshared")
        .args_json(json!({
            "epoch": epoch
        }))
        .max_gas()
        .retry_exponential(10, 5)
        .transact()
        .await
        .map_err(|e| {
            tracing::warn!(%e, "failed to vote for reshared");
            e
        })?
        .json()?;

    Ok(result)
}
