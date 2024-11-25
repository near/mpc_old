use std::sync::PoisonError;

use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::Config;
use crate::gcp::error::SecretStorageError;
use crate::http_client::SendError;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MeshState;
use crate::protocol::MpcMessage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use async_trait::async_trait;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait::async_trait]
pub trait CryptographicCtx {
    async fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox;
    fn cfg(&self) -> &Config;

    /// Active participants is the active participants at the beginning of each protocol loop.
    fn mesh_state(&self) -> &Arc<RwLock<MeshState>>;
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("failed to send a message: {0}")]
    SendError(#[from] SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error("rpc error: {0}")]
    RpcError(#[from] near_fetch::Error),
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("more than one writing to state: {0}")]
    InvalidStateHandle(String),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

impl<T> From<PoisonError<T>> for CryptographicError {
    fn from(_: PoisonError<T>) -> Self {
        let typename = std::any::type_name::<T>();
        Self::SyncError(format!("PoisonError: {typename}"))
    }
}

#[async_trait]
pub trait CryptographicProtocol {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError>;
}

#[async_trait]
impl CryptographicProtocol for GeneratingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        mut ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        let mesh_state = ctx.mesh_state().read().await.clone();
        tracing::info!(active = ?mesh_state.active_participants.keys_vec(), "generating: progressing key generation");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh keygen protocol");
                    }
                    return Err(err)?;
                }
            };
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("generating: waiting");
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().local.network.sign_sk,
                            ctx.http_client(),
                            &mesh_state.active_participants,
                            &ctx.cfg().protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?mesh_state.active_participants.keys_vec(),
                            "generating(wait): failed to send encrypted message; {failures:?}"
                        );
                    }

                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("generating: sending a message to many participants");
                    let mut messages = self.messages.write().await;
                    for (p, info) in mesh_state.active_participants.iter() {
                        if p == &ctx.me().await {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        messages.push(
                            info.clone(),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me().await,
                                data: data.clone(),
                            }),
                        );
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    let info = self.fetch_participant(&to)?;
                    self.messages.write().await.push(
                        info.clone(),
                        MpcMessage::Generating(GeneratingMessage {
                            from: ctx.me().await,
                            data,
                        }),
                    );
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "generating: successfully completed key generation"
                    );
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: 0,
                            private_share: r.private_share,
                            public_key: r.public_key,
                        })
                        .await?;
                    // Send any leftover messages
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().local.network.sign_sk,
                            ctx.http_client(),
                            &mesh_state.active_participants,
                            &ctx.cfg().protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?mesh_state.active_participants.keys_vec(),
                            "generating(return): failed to send encrypted message; {failures:?}"
                        );
                    }
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: 0,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                        messages: self.messages,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for WaitingForConsensusState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        let mesh_state = ctx.mesh_state().read().await.clone();
        let failures = self
            .messages
            .write()
            .await
            .send_encrypted(
                ctx.me().await,
                &ctx.cfg().local.network.sign_sk,
                ctx.http_client(),
                &mesh_state.active_participants,
                &ctx.cfg().protocol,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?mesh_state.active_participants.keys_vec(),
                "waitingForConsensus: failed to send encrypted message; {failures:?}"
            );
        }

        // Wait for ConsensusProtocol step to advance state
        Ok(NodeState::WaitingForConsensus(self))
    }
}

#[async_trait]
impl CryptographicProtocol for ResharingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        mut ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        let mesh_state = ctx.mesh_state().read().await.clone();
        // TODO: we are not using active potential participants here, but we should in the future.
        // Currently resharing protocol does not timeout and restart with new set of participants.
        // So if it picks up a participant that is not active, it will never be able to send a message to it.
        let active = mesh_state
            .active_participants
            .and(&mesh_state.potential_participants);
        tracing::info!(active = ?active.keys().collect::<Vec<_>>(), "progressing key reshare");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    tracing::debug!("got action fail, {}", err);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh reshare protocol");
                    }
                    return Err(err)?;
                }
            };
            tracing::debug!("got action ok");
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("resharing: waiting");
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().local.network.sign_sk,
                            ctx.http_client(),
                            &active,
                            &ctx.cfg().protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(wait): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    let me = ctx.me().await;
                    let mut messages = self.messages.write().await;
                    for (p, info) in self.new_participants.iter() {
                        if p == &me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        messages.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: me,
                                data: data.clone(),
                            }),
                        )
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    match self.new_participants.get(&to) {
                        Some(info) => self.messages.write().await.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me().await,
                                data,
                            }),
                        ),
                        None => return Err(CryptographicError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("resharing: successfully completed key reshare");
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: self.old_epoch + 1,
                            private_share,
                            public_key: self.public_key,
                        })
                        .await?;

                    // Send any leftover messages.
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().local.network.sign_sk,
                            ctx.http_client(),
                            &active,
                            &ctx.cfg().protocol,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(return): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: self.old_epoch + 1,
                        participants: self.new_participants,
                        threshold: self.threshold,
                        private_share,
                        public_key: self.public_key,
                        messages: self.messages,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for RunningState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        let mesh_state = ctx.mesh_state().read().await.clone();
        let protocol_cfg = &ctx.cfg().protocol;
        let active = &mesh_state.active_participants;
        if active.len() < self.threshold {
            tracing::warn!(
                active = ?active.keys_vec(),
                "running: not enough participants to progress"
            );
            return Ok(NodeState::Running(self));
        }

        let mut messages = self.messages.write().await;
        let mut triple_manager = self.triple_manager.write().await;
        let my_account_id = triple_manager.my_account_id.clone();
        crate::metrics::MESSAGE_QUEUE_SIZE
            .with_label_values(&[my_account_id.as_str()])
            .set(messages.len() as i64);
        if let Err(err) = triple_manager.stockpile(active, protocol_cfg).await {
            tracing::warn!(?err, "running: failed to stockpile triples");
        }
        for (p, msg) in triple_manager.poke(protocol_cfg).await {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Triple(msg));
        }

        crate::metrics::NUM_TRIPLES_MINE
            .with_label_values(&[my_account_id.as_str()])
            .set(triple_manager.len_mine().await as i64);
        crate::metrics::NUM_TRIPLES_TOTAL
            .with_label_values(&[my_account_id.as_str()])
            .set(triple_manager.len_generated().await as i64);
        crate::metrics::NUM_TRIPLE_GENERATORS_INTRODUCED
            .with_label_values(&[my_account_id.as_str()])
            .set(triple_manager.introduced.len() as i64);
        crate::metrics::NUM_TRIPLE_GENERATORS_TOTAL
            .with_label_values(&[my_account_id.as_str()])
            .set(triple_manager.ongoing.len() as i64);

        let mut presignature_manager = self.presignature_manager.write().await;
        if let Err(err) = presignature_manager
            .stockpile(
                active,
                &self.public_key,
                &self.private_share,
                &mut triple_manager,
                protocol_cfg,
            )
            .await
        {
            tracing::warn!(?err, "running: failed to stockpile presignatures");
        }
        drop(triple_manager);
        for (p, msg) in presignature_manager.poke().await {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Presignature(msg));
        }

        crate::metrics::NUM_PRESIGNATURES_MINE
            .with_label_values(&[my_account_id.as_str()])
            .set(presignature_manager.len_mine().await as i64);
        crate::metrics::NUM_PRESIGNATURES_TOTAL
            .with_label_values(&[my_account_id.as_str()])
            .set(presignature_manager.len_generated().await as i64);
        crate::metrics::NUM_PRESIGNATURE_GENERATORS_TOTAL
            .with_label_values(&[my_account_id.as_str()])
            .set(
                presignature_manager.len_potential().await as i64
                    - presignature_manager.len_generated().await as i64,
            );

        // NOTE: signatures should only use stable and not active participants. The difference here is that
        // stable participants utilizes more than the online status of a node, such as whether or not their
        // block height is up to date, such that they too can process signature requests. If they cannot
        // then they are considered unstable and should not be a part of signature generation this round.
        let stable = mesh_state.stable_participants;
        tracing::debug!(?stable, "stable participants");

        let mut sign_queue = self.sign_queue.write().await;
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[my_account_id.as_str()])
            .set(sign_queue.len() as i64);
        let me = ctx.me().await;
        sign_queue.organize(self.threshold, &stable, me, &my_account_id);

        let my_requests = sign_queue.my_requests(me);
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[my_account_id.as_str()])
            .set(my_requests.len() as i64);

        let mut signature_manager = self.signature_manager.write().await;
        signature_manager
            .handle_requests(
                self.threshold,
                &stable,
                my_requests,
                &mut presignature_manager,
                protocol_cfg,
            )
            .await;
        drop(sign_queue);
        drop(presignature_manager);

        for (p, msg) in signature_manager.poke() {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Signature(msg));
        }
        signature_manager
            .publish(ctx.rpc_client(), ctx.signer(), ctx.mpc_contract_id())
            .await;
        drop(signature_manager);
        let failures = messages
            .send_encrypted(
                ctx.me().await,
                &ctx.cfg().local.network.sign_sk,
                ctx.http_client(),
                active,
                protocol_cfg,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?active.keys_vec(),
                "running: failed to send encrypted message; {failures:?}"
            );
        }
        drop(messages);

        Ok(NodeState::Running(self))
    }
}

#[async_trait]
impl CryptographicProtocol for NodeState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        match self {
            NodeState::Generating(state) => state.progress(ctx).await,
            NodeState::Resharing(state) => state.progress(ctx).await,
            NodeState::Running(state) => state.progress(ctx).await,
            NodeState::WaitingForConsensus(state) => state.progress(ctx).await,
            _ => Ok(self),
        }
    }
}
