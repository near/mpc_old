use super::contract::{ProtocolState, ResharingContractState};
use super::state::{
    JoiningState, NodeState, PersistentNodeData, RunningState, StartedState,
    WaitingForConsensusState,
};
use super::{Config, SignQueue};
use crate::gcp::error::DatastoreStorageError;
use crate::gcp::error::SecretStorageError;
use crate::http_client::MessageQueue;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::presignature::PresignatureManager;
use crate::protocol::signature::SignatureManager;
use crate::protocol::state::{GeneratingState, ResharingState};
use crate::protocol::triple::TripleManager;
use crate::storage::presignature_storage::PresignatureRedisStorage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::triple_storage::TripleRedisStorage;
use crate::types::{KeygenProtocol, ReshareProtocol, SecretKeyShare};
use crate::util::AffinePointExt;
use crate::{http_client, rpc_client};

use std::cmp::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use cait_sith::protocol::InitializationError;
use serde_json::json;
use tokio::sync::RwLock;
use url::Url;

use near_account_id::AccountId;
use near_crypto::InMemorySigner;

pub trait ConsensusCtx {
    fn my_account_id(&self) -> &AccountId;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn my_address(&self) -> &Url;
    fn sign_queue(&self) -> Arc<RwLock<SignQueue>>;
    fn secret_storage(&self) -> &SecretNodeStorageBox;
    fn triple_storage(&self) -> &TripleRedisStorage;
    fn presignature_storage(&self) -> &PresignatureRedisStorage;
    fn cfg(&self) -> &Config;
    fn message_options(&self) -> http_client::Options;
}

#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("contract state has been rolled back")]
    ContractStateRollback,
    #[error("contract epoch has been rolled back")]
    EpochRollback,
    #[error("mismatched public key between contract state and local state")]
    MismatchedPublicKey,
    #[error("mismatched threshold between contract state and local state")]
    MismatchedThreshold,
    #[error("mismatched participant set between contract state and local state")]
    MismatchedParticipants,
    #[error("this node has been unexpectedly kicked from the participant set")]
    HasBeenKicked,
    #[error("this node errored out during the join process: {0}")]
    CannotJoin(String),
    #[error("this node errored out while trying to vote: {0}")]
    CannotVote(String),
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("secret storage error: {0}")]
    SecretStorageError(SecretStorageError),
    #[error("datastore storage error: {0}")]
    DatastoreStorageError(DatastoreStorageError),
}

impl From<SecretStorageError> for ConsensusError {
    fn from(err: SecretStorageError) -> Self {
        ConsensusError::SecretStorageError(err)
    }
}

impl From<DatastoreStorageError> for ConsensusError {
    fn from(err: DatastoreStorageError) -> Self {
        ConsensusError::DatastoreStorageError(err)
    }
}

#[async_trait]
pub trait ConsensusProtocol {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError>;
}

#[async_trait]
impl ConsensusProtocol for StartedState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match self.persistent_node_data {
            Some(PersistentNodeData {
                epoch,
                private_share,
                public_key,
            }) => match contract_state {
                ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
                ProtocolState::Running(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    match contract_state.epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                "started(running): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                                epoch,
                                contract_state.epoch
                            );
                            Ok(NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key,
                            }))
                        }
                        Ordering::Less => Err(ConsensusError::EpochRollback),
                        Ordering::Equal => {
                            let sign_queue = ctx.sign_queue();
                            match contract_state
                                .participants
                                .find_participant(ctx.my_account_id())
                            {
                                Some(me) => {
                                    tracing::info!(
                                        "started: contract state is running and we are already a participant"
                                    );
                                    let triple_manager = Arc::new(RwLock::new(TripleManager::new(
                                        me,
                                        contract_state.threshold,
                                        epoch,
                                        ctx.my_account_id(),
                                        ctx.triple_storage(),
                                    )));

                                    let presignature_manager =
                                        Arc::new(RwLock::new(PresignatureManager::new(
                                            me,
                                            contract_state.threshold,
                                            epoch,
                                            ctx.my_account_id(),
                                            ctx.presignature_storage(),
                                        )));

                                    let signature_manager =
                                        Arc::new(RwLock::new(SignatureManager::new(
                                            me,
                                            public_key,
                                            epoch,
                                            ctx.my_account_id(),
                                        )));

                                    Ok(NodeState::Running(RunningState {
                                        epoch,
                                        participants: contract_state.participants,
                                        threshold: contract_state.threshold,
                                        private_share,
                                        public_key,
                                        sign_queue,
                                        triple_manager,
                                        presignature_manager,
                                        signature_manager,
                                        messages: Arc::new(RwLock::new(MessageQueue::new(
                                            ctx.message_options().clone(),
                                        ))),
                                    }))
                                }
                                None => Ok(NodeState::Joining(JoiningState {
                                    participants: contract_state.participants,
                                    public_key,
                                })),
                            }
                        }
                    }
                }
                ProtocolState::Resharing(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    match contract_state.old_epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                "started(resharing): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                                epoch,
                                contract_state.old_epoch
                            );
                            Ok(NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key,
                            }))
                        }
                        Ordering::Less => Err(ConsensusError::EpochRollback),
                        Ordering::Equal => {
                            tracing::info!(
                                "started(resharing): contract state is resharing with us, joining as a participant"
                            );
                            start_resharing(Some(private_share), ctx, contract_state).await
                        }
                    }
                }
            },
            None => match contract_state {
                ProtocolState::Initializing(contract_state) => {
                    let participants: Participants = contract_state.candidates.clone().into();
                    match participants.find_participant(ctx.my_account_id()) {
                        Some(me) => {
                            tracing::info!(
                                "started(initializing): starting key generation as a part of the participant set"
                            );
                            let protocol = KeygenProtocol::new(
                                &participants.keys().cloned().collect::<Vec<_>>(),
                                me,
                                contract_state.threshold,
                            )?;
                            Ok(NodeState::Generating(GeneratingState {
                                participants,
                                threshold: contract_state.threshold,
                                protocol,
                                messages: Arc::new(RwLock::new(MessageQueue::new(
                                    ctx.message_options().clone(),
                                ))),
                            }))
                        }
                        None => {
                            tracing::info!("started(initializing): we are not a part of the initial participant set, waiting for key generation to complete");
                            Ok(NodeState::Started(self))
                        }
                    }
                }
                ProtocolState::Running(contract_state) => Ok(NodeState::Joining(JoiningState {
                    participants: contract_state.participants,
                    public_key: contract_state.public_key,
                })),
                ProtocolState::Resharing(contract_state) => Ok(NodeState::Joining(JoiningState {
                    participants: contract_state.old_participants,
                    public_key: contract_state.public_key,
                })),
            },
        }
    }
}

#[async_trait]
impl ConsensusProtocol for GeneratingState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        _ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => {
                tracing::info!("generating(initializing): continuing generation, contract state has not been finalized yet");
                Ok(NodeState::Generating(self))
            }
            ProtocolState::Running(contract_state) => {
                if contract_state.epoch > 0 {
                    tracing::warn!("generating(running): contract has already changed epochs, trying to rejoin as a new participant");
                    return Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::info!("generating(running): contract state has finished key generation, trying to catch up");
                if self.participants != contract_state.participants {
                    return Err(ConsensusError::MismatchedParticipants);
                }
                if self.threshold != contract_state.threshold {
                    return Err(ConsensusError::MismatchedThreshold);
                }
                Ok(NodeState::Generating(self))
            }
            ProtocolState::Resharing(contract_state) => {
                if contract_state.old_epoch > 0 {
                    tracing::warn!("generating(resharing): contract has already changed epochs, trying to rejoin as a new participant");
                    return Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.old_participants,
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::warn!("generating(resharing): contract state is resharing without us, trying to catch up");
                if self.participants != contract_state.old_participants {
                    return Err(ConsensusError::MismatchedParticipants);
                }
                if self.threshold != contract_state.threshold {
                    return Err(ConsensusError::MismatchedThreshold);
                }
                Ok(NodeState::Generating(self))
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for WaitingForConsensusState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                tracing::info!("waiting(initializing): waiting for consensus, contract state has not been finalized yet");
                let public_key = self.public_key.into_near_public_key();
                let has_voted = contract_state
                    .pk_votes
                    .get(&public_key)
                    .map(|ps| ps.contains(ctx.my_account_id()))
                    .unwrap_or_default();
                if !has_voted {
                    tracing::info!("waiting(initializing): we haven't voted yet, voting for the generated public key");
                    rpc_client::vote_for_public_key(
                        ctx.rpc_client(),
                        ctx.signer(),
                        ctx.mpc_contract_id(),
                        &public_key,
                    )
                    .await
                    .map_err(|err| ConsensusError::CannotVote(format!("{err:?}")))?;
                }
                Ok(NodeState::WaitingForConsensus(self))
            }
            ProtocolState::Running(contract_state) => match contract_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                        "waiting(running): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                        self.epoch,
                        contract_state.epoch
                    );

                    Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::info!("waiting(running): contract state has reached consensus");
                    if contract_state.participants != self.participants {
                        return Err(ConsensusError::MismatchedParticipants);
                    }
                    if contract_state.threshold != self.threshold {
                        return Err(ConsensusError::MismatchedThreshold);
                    }
                    if contract_state.public_key != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }

                    let me = contract_state
                        .participants
                        .find_participant(ctx.my_account_id())
                        .unwrap();

                    // Clear triples from storage before starting the new epoch. This is necessary if the node has accumulated
                    // triples from previous epochs. If it was not able to clear the previous triples, we'll leave them as-is
                    if let Err(err) = ctx.triple_storage().clear().await {
                        tracing::error!(
                            ?err,
                            "failed to clear triples from storage on new epoch start"
                        );
                    }

                    if let Err(err) = ctx.presignature_storage().clear().await {
                        tracing::error!(
                            ?err,
                            "failed to clear presignatures from storage on new epoch start"
                        );
                    }

                    let triple_manager = Arc::new(RwLock::new(TripleManager::new(
                        me,
                        self.threshold,
                        self.epoch,
                        ctx.my_account_id(),
                        ctx.triple_storage(),
                    )));

                    let presignature_manager = Arc::new(RwLock::new(PresignatureManager::new(
                        me,
                        self.threshold,
                        self.epoch,
                        ctx.my_account_id(),
                        ctx.presignature_storage(),
                    )));

                    let signature_manager = Arc::new(RwLock::new(SignatureManager::new(
                        me,
                        self.public_key,
                        self.epoch,
                        ctx.my_account_id(),
                    )));

                    Ok(NodeState::Running(RunningState {
                        epoch: self.epoch,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: self.private_share,
                        public_key: self.public_key,
                        sign_queue: ctx.sign_queue(),
                        triple_manager,
                        presignature_manager,
                        signature_manager,
                        messages: self.messages,
                    }))
                }
            },
            ProtocolState::Resharing(contract_state) => {
                match (contract_state.old_epoch + 1).cmp(&self.epoch) {
                    Ordering::Greater if contract_state.old_epoch + 2 == self.epoch => {
                        tracing::info!("waiting(resharing): contract state is resharing, joining");
                        if contract_state.old_participants != self.participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.threshold != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        start_resharing(Some(self.private_share), ctx, contract_state).await
                    }
                    Ordering::Greater => {
                        tracing::warn!(
                            "waiting(resharing): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.old_epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!(
                            "waiting(resharing): waiting for resharing consensus, contract state has not been finalized yet"
                        );
                        let has_voted = contract_state.finished_votes.contains(ctx.my_account_id());
                        match contract_state
                            .old_participants
                            .find_participant(ctx.my_account_id())
                        {
                            Some(_) => {
                                if !has_voted {
                                    tracing::info!(
                                        epoch = self.epoch,
                                        "waiting(resharing): we haven't voted yet, voting for resharing to complete"
                                    );
                                    rpc_client::vote_reshared(
                                        ctx.rpc_client(),
                                        ctx.signer(),
                                        ctx.mpc_contract_id(),
                                        self.epoch,
                                    )
                                    .await
                                    .map_err(|err| {
                                        ConsensusError::CannotVote(format!("{err:?}"))
                                    })?;
                                } else {
                                    tracing::info!(
                                        epoch = self.epoch,
                                        "waiting(resharing): we have voted for resharing to complete"
                                    );
                                }
                            }
                            None => {
                                tracing::info!("waiting(resharing): we are not a part of the old participant set");
                            }
                        }
                        Ok(NodeState::WaitingForConsensus(self))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for RunningState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
            ProtocolState::Running(contract_state) => match contract_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                            "running(running): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.epoch
                        );

                    Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::debug!("running(running): continuing to run as normal");
                    if contract_state.participants != self.participants {
                        return Err(ConsensusError::MismatchedParticipants);
                    }
                    if contract_state.threshold != self.threshold {
                        return Err(ConsensusError::MismatchedThreshold);
                    }
                    if contract_state.public_key != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    Ok(NodeState::Running(self))
                }
            },
            ProtocolState::Resharing(contract_state) => {
                match contract_state.old_epoch.cmp(&self.epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "running(resharing): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.old_epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!("running(resharing): contract is resharing");
                        let is_in_old_participant_set = contract_state
                            .old_participants
                            .contains_account_id(ctx.my_account_id());
                        let is_in_new_participant_set = contract_state
                            .new_participants
                            .contains_account_id(ctx.my_account_id());
                        if !is_in_old_participant_set || !is_in_new_participant_set {
                            return Err(ConsensusError::HasBeenKicked);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        start_resharing(Some(self.private_share), ctx, contract_state).await
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for ResharingState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        _ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
            ProtocolState::Running(contract_state) => {
                match contract_state.epoch.cmp(&(self.old_epoch + 1)) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "resharing(running): expected epoch {} while contract state's is {}, trying to rejoin as a new participant",
                            self.old_epoch + 1,
                            contract_state.epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!("resharing(running): contract state has finished resharing, trying to catch up");
                        if contract_state.participants != self.new_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.threshold != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        Ok(NodeState::Resharing(self))
                    }
                }
            }
            ProtocolState::Resharing(contract_state) => {
                match contract_state.old_epoch.cmp(&self.old_epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "resharing(resharing): expected resharing from epoch {} while contract is resharing from {}, trying to rejoin as a new participant",
                            self.old_epoch,
                            contract_state.old_epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!("resharing(resharing): continue to reshare as normal");
                        if contract_state.old_participants != self.old_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.new_participants != self.new_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.threshold != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        Ok(NodeState::Resharing(self))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for JoiningState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
            ProtocolState::Running(contract_state) => {
                match contract_state
                    .candidates
                    .find_candidate(ctx.my_account_id())
                {
                    Some(_) => {
                        let votes = contract_state
                            .join_votes
                            .get(ctx.my_account_id())
                            .cloned()
                            .unwrap_or_default();
                        let participant_account_ids_to_vote = contract_state
                            .participants
                            .iter()
                            .map(|(_, info)| &info.account_id)
                            .filter(|id| !votes.contains(*id))
                            .collect::<Vec<_>>();
                        if !participant_account_ids_to_vote.is_empty() {
                            tracing::info!(
                                ?participant_account_ids_to_vote,
                                "Some participants have not voted for you to join"
                            );
                        }
                        Ok(NodeState::Joining(self))
                    }
                    None => {
                        tracing::info!(
                            "joining(running): sending a transaction to join the participant set"
                        );
                        ctx.rpc_client()
                            .call(ctx.signer(), ctx.mpc_contract_id(), "join")
                            .args_json(json!({
                                "url": ctx.my_address(),
                                "cipher_pk": ctx.cfg().local.network.cipher_pk.to_bytes(),
                                "sign_pk": ctx.cfg().local.network.sign_sk.public_key(),
                            }))
                            .max_gas()
                            .retry_exponential(10, 3)
                            .transact()
                            .await
                            .map_err(|err| {
                                tracing::error!(?err, "failed to join the participant set");
                                ConsensusError::CannotJoin(format!("{err:?}"))
                            })?;
                        Ok(NodeState::Joining(self))
                    }
                }
            }
            ProtocolState::Resharing(contract_state) => {
                if contract_state
                    .new_participants
                    .contains_account_id(ctx.my_account_id())
                {
                    tracing::info!("joining(resharing): joining as a new participant");
                    start_resharing(None, ctx, contract_state).await
                } else {
                    tracing::info!("joining(resharing): network is resharing without us, waiting for them to finish");
                    Ok(NodeState::Joining(self))
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for NodeState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match self {
            NodeState::Starting => {
                let persistent_node_data = ctx.secret_storage().load().await?;
                Ok(NodeState::Started(StartedState {
                    persistent_node_data,
                }))
            }
            NodeState::Started(state) => state.advance(ctx, contract_state).await,
            NodeState::Generating(state) => state.advance(ctx, contract_state).await,
            NodeState::WaitingForConsensus(state) => state.advance(ctx, contract_state).await,
            NodeState::Running(state) => state.advance(ctx, contract_state).await,
            NodeState::Resharing(state) => state.advance(ctx, contract_state).await,
            NodeState::Joining(state) => state.advance(ctx, contract_state).await,
        }
    }
}

async fn start_resharing<C: ConsensusCtx>(
    private_share: Option<SecretKeyShare>,
    ctx: C,
    contract_state: ResharingContractState,
) -> Result<NodeState, ConsensusError> {
    let me = contract_state
        .new_participants
        .find_participant(ctx.my_account_id())
        .unwrap();
    let protocol = ReshareProtocol::new(private_share, me, &contract_state)?;
    Ok(NodeState::Resharing(ResharingState {
        old_epoch: contract_state.old_epoch,
        old_participants: contract_state.old_participants,
        new_participants: contract_state.new_participants,
        threshold: contract_state.threshold,
        public_key: contract_state.public_key,
        protocol,
        messages: Arc::new(RwLock::new(MessageQueue::new(
            ctx.message_options().clone(),
        ))),
    }))
}
