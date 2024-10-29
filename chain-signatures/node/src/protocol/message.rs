use super::cryptography::CryptographicError;
use super::presignature::{GenerationError, PresignatureId};
use super::signature::SignRequestIdentifier;
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::triple::TripleId;
use crate::gcp::error::SecretStorageError;
use crate::http_client::SendError;
use crate::indexer::ContractSignRequest;
use crate::mesh::Mesh;
use crate::util;

use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use k256::Scalar;
use mpc_keys::hpke::{self, Ciphered};
use near_crypto::Signature;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait::async_trait]
pub trait MessageCtx {
    async fn me(&self) -> Participant;
    fn mesh(&self) -> &Mesh;
    fn cfg(&self) -> &crate::config::Config;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ResharingMessage {
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SignatureMessage {
    pub request_id: [u8; 32],
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub entropy: [u8; 32],
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage),
}

impl MpcMessage {
    pub const fn typename(&self) -> &'static str {
        match self {
            MpcMessage::Generating(_) => "Generating",
            MpcMessage::Resharing(_) => "Resharing",
            MpcMessage::Triple(_) => "Triple",
            MpcMessage::Presignature(_) => "Presignature",
            MpcMessage::Signature(_) => "Signature",
        }
    }
}

#[derive(Default)]
pub struct MpcMessageQueue {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
    triple_bins: HashMap<u64, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature_bins: HashMap<u64, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature_bins: HashMap<u64, HashMap<SignRequestIdentifier, VecDeque<SignatureMessage>>>,
}

impl MpcMessageQueue {
    pub fn push(&mut self, message: MpcMessage) {
        match message {
            MpcMessage::Generating(message) => self.generating.push_back(message),
            MpcMessage::Resharing(message) => self
                .resharing_bins
                .entry(message.epoch)
                .or_default()
                .push_back(message),
            MpcMessage::Triple(message) => self
                .triple_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Presignature(message) => self
                .presignature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Signature(message) => self
                .signature_bins
                .entry(message.epoch)
                .or_default()
                .entry(SignRequestIdentifier::new(
                    message.request_id,
                    message.epsilon,
                    message.request.payload,
                ))
                .or_default()
                .push_back(message),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MessageHandleError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error("failed to send a message: {0}")]
    SendError(SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("invalid state")]
    InvalidStateHandle(String),
    #[error("rpc error: {0}")]
    RpcError(#[from] near_fetch::Error),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

impl From<CryptographicError> for MessageHandleError {
    fn from(value: CryptographicError) -> Self {
        match value {
            CryptographicError::CaitSithInitializationError(e) => {
                Self::CaitSithInitializationError(e)
            }
            CryptographicError::CaitSithProtocolError(e) => Self::CaitSithProtocolError(e),
            CryptographicError::SyncError(e) => Self::SyncError(e),
            CryptographicError::SendError(e) => Self::SendError(e),
            CryptographicError::UnknownParticipant(e) => Self::UnknownParticipant(e),
            CryptographicError::DataConversion(e) => Self::DataConversion(e),
            CryptographicError::Encryption(e) => Self::Encryption(e),
            CryptographicError::InvalidStateHandle(e) => Self::InvalidStateHandle(e),
            CryptographicError::RpcError(e) => Self::RpcError(e),
            CryptographicError::SecretStorageError(e) => Self::SecretStorageError(e),
        }
    }
}

#[async_trait]
pub trait MessageHandler {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError>;
}

#[async_trait]
impl MessageHandler for GeneratingState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = queue.generating.pop_front() {
            tracing::debug!("handling new generating message");
            protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for ResharingState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        tracing::debug!("handling {} resharing messages", queue.resharing_bins.len());
        let q = queue.resharing_bins.entry(self.old_epoch).or_default();
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = q.pop_front() {
            protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for RunningState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        let protocol_cfg = &ctx.cfg().protocol;
        let participants = ctx.mesh().active_participants();
        let mut triple_manager = self.triple_manager.write().await;

        // remove the triple_id that has already failed or taken from the triple_bins
        // and refresh the timestamp of failed and taken
        let triple_messages = queue.triple_bins.entry(self.epoch).or_default();
        triple_messages.retain(|id, queue| {
            if queue.is_empty()
                || queue.iter().any(|msg| {
                    util::is_elapsed_longer_than_timeout(
                        msg.timestamp,
                        protocol_cfg.triple.generation_timeout,
                    )
                })
            {
                return false;
            }

            // if triple id is in GC, remove these messages because the triple is currently
            // being GC'ed, where this particular triple has previously failed or been utilized.
            !triple_manager.refresh_gc(id)
        });
        for (id, queue) in triple_messages {
            let protocol = match triple_manager.get_or_generate(*id, participants, protocol_cfg) {
                Ok(protocol) => protocol,
                Err(err) => {
                    // ignore the message since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(?err, "unable to initialize incoming triple protocol");
                    continue;
                }
            };

            if let Some(protocol) = protocol {
                while let Some(message) = queue.pop_front() {
                    protocol.message(message.from, message.data);
                }
            }
        }

        let mut presignature_manager = self.presignature_manager.write().await;
        let presignature_messages = queue.presignature_bins.entry(self.epoch).or_default();
        presignature_messages.retain(|id, queue| {
            // Skip message if it already timed out
            if queue.is_empty()
                || queue.iter().any(|msg| {
                    util::is_elapsed_longer_than_timeout(
                        msg.timestamp,
                        protocol_cfg.presignature.generation_timeout,
                    )
                })
            {
                return false;
            }

            // if presignature id is in GC, remove these messages because the presignature is currently
            // being GC'ed, where this particular presignature has previously failed or been utilized.
            !presignature_manager.refresh_gc(id)
        });
        for (id, queue) in presignature_messages {
            // SAFETY: this unwrap() is safe since we have already checked that the queue is not empty.
            let PresignatureMessage {
                triple0, triple1, ..
            } = queue.front().unwrap();

            if !queue
                .iter()
                .all(|msg| triple0 == &msg.triple0 && triple1 == &msg.triple1)
            {
                // Check that all messages in the queue have the same triple0 and triple1, otherwise this is an
                // invalid message, so we should just bin the whole entire protocol and its message for this presignature id.
                queue.clear();
                continue;
            }

            let protocol = match presignature_manager
                .get_or_generate(
                    participants,
                    *id,
                    *triple0,
                    *triple1,
                    &mut triple_manager,
                    &self.public_key,
                    &self.private_share,
                    protocol_cfg,
                )
                .await
            {
                Ok(protocol) => protocol,
                Err(GenerationError::TripleIsGenerating(_)) => {
                    // We will go back to this presignature bin later when the triple is generated.
                    continue;
                }
                Err(
                    err @ (GenerationError::AlreadyGenerated
                    | GenerationError::TripleIsGarbageCollected(_)
                    | GenerationError::TripleIsMissing(_)),
                ) => {
                    // This triple has already been generated or removed from the triple manager, so we will have to bin
                    // the entirety of the messages we received for this presignature id, and have the other nodes timeout
                    tracing::warn!(id, ?err, "presignature cannot be generated");
                    queue.clear();
                    continue;
                }
                Err(GenerationError::CaitSithInitializationError(error)) => {
                    // ignore these messages since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(
                        presignature_id = id,
                        ?error,
                        "unable to initialize incoming presignature protocol"
                    );
                    queue.clear();
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        presignature_id = id,
                        ?err,
                        "Unexpected error encounted while generating presignature"
                    );
                    queue.clear();
                    continue;
                }
            };

            while let Some(message) = queue.pop_front() {
                protocol.message(message.from, message.data);
            }
        }

        let mut signature_manager = self.signature_manager.write().await;
        let signature_messages = queue.signature_bins.entry(self.epoch).or_default();
        signature_messages.retain(|sign_request_identifier, queue| {
            // Skip message if it already timed out
            if queue.is_empty()
                || queue.iter().any(|msg| {
                    util::is_elapsed_longer_than_timeout(
                        msg.timestamp,
                        protocol_cfg.signature.generation_timeout,
                    )
                })
            {
                return false;
            }

            !signature_manager.refresh_gc(sign_request_identifier)
        });
        for (sign_request_identifier, queue) in signature_messages {
            // SAFETY: this unwrap() is safe since we have already checked that the queue is not empty.
            let SignatureMessage {
                proposer,
                presignature_id,
                request,
                epsilon,
                entropy,
                ..
            } = queue.front().unwrap();

            if !queue
                .iter()
                .all(|msg| presignature_id == &msg.presignature_id)
            {
                // Check that all messages in the queue have the same triple0 and triple1, otherwise this is an
                // invalid message, so we should just bin the whole entire protocol and its message for this presignature id.
                queue.clear();
                continue;
            }

            // if !self
            //     .sign_queue
            //     .read()
            //     .await
            //     .contains(message.proposer, receipt_id.clone())
            // {
            //     leftover_messages.push(message);
            //     continue;
            // };
            // TODO: Validate that the message matches our sign_queue
            let protocol = match signature_manager.get_or_generate(
                participants,
                sign_request_identifier.request_id,
                *proposer,
                *presignature_id,
                request,
                *epsilon,
                *entropy,
                &mut presignature_manager,
                protocol_cfg,
            ) {
                Ok(protocol) => protocol,
                Err(GenerationError::PresignatureIsGenerating(_)) => {
                    // We will revisit this this signature request later when the presignature has been generated.
                    continue;
                }
                Err(
                    err @ (GenerationError::AlreadyGenerated
                    | GenerationError::PresignatureIsGarbageCollected(_)
                    | GenerationError::PresignatureIsMissing(_)),
                ) => {
                    // We will have to remove the entirety of the messages we received for this signature request,
                    // and have the other nodes timeout in the following cases:
                    // - If a presignature is in GC, then it was used already or failed to be produced.
                    // - If a presignature is missing, that means our system cannot process this signature.
                    tracing::warn!(
                        ?sign_request_identifier,
                        ?err,
                        "signature cannot be generated"
                    );
                    queue.clear();
                    continue;
                }
                Err(GenerationError::CaitSithInitializationError(error)) => {
                    // ignore the whole of the messages since the generation had bad parameters. Also have the other node who
                    // initiated the protocol resend the message or have it timeout on their side.
                    tracing::warn!(
                        ?sign_request_identifier,
                        presignature_id,
                        ?error,
                        "unable to initialize incoming signature protocol"
                    );
                    queue.clear();
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        ?sign_request_identifier,
                        ?err,
                        "Unexpected error encounted while generating signature"
                    );
                    queue.clear();
                    continue;
                }
            };

            while let Some(message) = queue.pop_front() {
                protocol.message(message.from, message.data);
            }
        }
        triple_manager.garbage_collect(protocol_cfg);
        presignature_manager.garbage_collect(protocol_cfg);
        signature_manager.garbage_collect(protocol_cfg);
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for NodeState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        match self {
            NodeState::Generating(state) => state.handle(ctx, queue).await,
            NodeState::Resharing(state) => state.handle(ctx, queue).await,
            NodeState::Running(state) => state.handle(ctx, queue).await,
            _ => {
                tracing::debug!("skipping message processing");
                Ok(())
            }
        }
    }
}

/// A signed message that can be encrypted. Note that the message's signature is included
/// in the encrypted message to avoid from it being tampered with without first decrypting.
#[derive(Serialize, Deserialize)]
pub struct SignedMessage<T> {
    /// The message with all it's related info.
    pub msg: T,
    /// The signature used to verify the authenticity of the encrypted message.
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: Participant,
}

impl<T> SignedMessage<T> {
    pub const ASSOCIATED_DATA: &'static [u8] = b"";
}

impl<T> SignedMessage<T>
where
    T: Serialize,
{
    pub fn encrypt(
        msg: &T,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, CryptographicError> {
        let msg = serde_json::to_vec(msg)?;
        let sig = sign_sk.sign(&msg);
        let msg = SignedMessage { msg, sig, from };
        let msg = serde_json::to_vec(&msg)?;
        let ciphered = cipher_pk
            .encrypt(&msg, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|e| {
                tracing::error!(error = ?e, "failed to encrypt message");
                CryptographicError::Encryption(e.to_string())
            })?;
        Ok(ciphered)
    }
}

impl<T> SignedMessage<T>
where
    T: for<'a> Deserialize<'a>,
{
    pub async fn decrypt(
        cipher_sk: &hpke::SecretKey,
        protocol_state: &Arc<RwLock<NodeState>>,
        encrypted: Ciphered,
    ) -> Result<T, CryptographicError> {
        let message = cipher_sk
            .decrypt(&encrypted, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|err| {
                tracing::error!(error = ?err, "failed to decrypt message");
                CryptographicError::Encryption(err.to_string())
            })?;
        let SignedMessage::<Vec<u8>> { msg, sig, from } = serde_json::from_slice(&message)?;
        if !sig.verify(
            &msg,
            &protocol_state
                .read()
                .await
                .fetch_participant(&from)?
                .sign_pk,
        ) {
            tracing::error!(from = ?from, "signed message erred out with invalid signature");
            return Err(CryptographicError::Encryption(
                "invalid signature while verifying authenticity of encrypted protocol message"
                    .to_string(),
            ));
        }

        Ok(serde_json::from_slice(&msg)?)
    }
}
