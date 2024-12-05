use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
use crate::protocol::message::SignedMessage;
use crate::protocol::MpcMessage;
use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::Ciphered;
use reqwest::{Client, IntoUrl};
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::Utf8Error;
use std::time::{Duration, Instant};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use near_account_id::AccountId;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "message_options")]
pub struct Options {
    #[clap(long, env("MPC_MESSAGE_TIMEOUT"), default_value = "1000")]
    pub timeout: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec!["--timeout".to_string(), self.timeout.to_string()]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("http request was unsuccessful: {0}")]
    Unsuccessful(String),
    #[error("serialization unsuccessful: {0}")]
    DataConversionError(serde_json::Error),
    #[error("http client error: {0}")]
    ReqwestClientError(#[from] reqwest::Error),
    #[error("http response could not be parsed: {0}")]
    ReqwestBodyError(reqwest::Error),
    #[error("http response body is not valid utf-8: {0}")]
    MalformedResponse(Utf8Error),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("http request timeout: {0}")]
    Timeout(String),
    #[error("participant is not alive: {0}")]
    ParticipantNotAlive(String),
}

pub async fn send_encrypted<U: IntoUrl>(
    from: Participant,
    client: Client,
    url: U,
    message: Vec<Ciphered>,
    request_timeout: Duration,
) -> Result<(), SendError> {
    let _span = tracing::info_span!("message_request");
    let mut url = url.into_url()?;
    url.set_path("msg");
    tracing::debug!(?from, to = %url, "making http request: sending encrypted message");
    let action = || async {
        let response = tokio::time::timeout(
            request_timeout,
            client
                .post(url.clone())
                .header("content-type", "application/json")
                .json(&message)
                .send(),
        )
        .await
        .map_err(|_| SendError::Timeout(format!("send encrypted from {from:?} to {url}")))?
        .map_err(SendError::ReqwestClientError)?;

        let status = response.status();
        let response_bytes = response
            .bytes()
            .await
            .map_err(SendError::ReqwestBodyError)?;
        let response_str =
            std::str::from_utf8(&response_bytes).map_err(SendError::MalformedResponse)?;
        if status.is_success() {
            Ok(())
        } else {
            tracing::warn!(
                "failed to send a message to {} with code {}: {}",
                url,
                status,
                response_str
            );
            Err(SendError::Unsuccessful(response_str.into()))
        }
    };

    let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
    Retry::spawn(retry_strategy, action).await
}

// TODO: add in retry logic either in struct or at call site.
// TODO: add check for participant list to see if the messages to be sent are still valid.
pub struct MessageQueue {
    deque: VecDeque<(ParticipantInfo, MpcMessage, Instant)>,
    seen_counts: HashSet<String>,
    account_id: AccountId,
    message_options: Options,
}

impl MessageQueue {
    pub fn new(id: &AccountId, options: Options) -> Self {
        Self {
            deque: VecDeque::new(),
            seen_counts: HashSet::new(),
            account_id: id.clone(),
            message_options: options,
        }
    }

    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn push(&mut self, info: ParticipantInfo, msg: MpcMessage) {
        self.deque.push_back((info, msg, Instant::now()));
    }

    pub async fn send_encrypted(
        &mut self,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        client: &Client,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Vec<SendError> {
        let mut failed = VecDeque::new();
        let mut errors = Vec::new();
        let mut participant_counter = HashMap::new();

        let outer = Instant::now();
        let uncompacted = self.deque.len();
        let mut encrypted = HashMap::new();
        while let Some((info, msg, instant)) = self.deque.pop_front() {
            if instant.elapsed() > timeout(&msg, cfg) {
                errors.push(SendError::Timeout(format!(
                    "{} message has timed out: {info:?}",
                    msg.typename(),
                )));
                continue;
            }

            if !participants.contains_key(&Participant::from(info.id)) {
                let counter = participant_counter.entry(info.id).or_insert(0);
                *counter += 1;
                failed.push_back((info, msg, instant));
                continue;
            }
            let encrypted_msg = match SignedMessage::encrypt(&msg, from, sign_sk, &info.cipher_pk) {
                Ok(encrypted) => encrypted,
                Err(err) => {
                    errors.push(SendError::EncryptionError(err.to_string()));
                    continue;
                }
            };
            let encrypted = encrypted.entry(info.id).or_insert_with(Vec::new);
            encrypted.push((encrypted_msg, (info, msg, instant)));
        }

        let mut tasks = tokio::task::JoinSet::new();
        for (id, encrypted) in encrypted {
            for partition in partition_ciphered_256kb(encrypted) {
                let (encrypted_partition, _msgs): (Vec<_>, Vec<_>) = partition.into_iter().unzip();
                // guaranteed to unwrap due to our previous loop check:
                let id = Participant::from(id);
                let info = participants.get(&id).unwrap();
                let account_id = &info.account_id;

                crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                    .with_label_values(&[account_id.as_str()])
                    .inc();

                tasks.spawn(send_encrypted(
                    from,
                    client.clone(),
                    info.url.clone(),
                    encrypted_partition,
                    Duration::from_millis(self.message_options.timeout),
                ));
            }
        }

        let mut compacted = 0;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(result) => {
                    let Err(err) = result else {
                        compacted += 1;
                        continue;
                    };
                    errors.push(err);
                }
                Err(err) => {
                    tracing::error!(?err, "message queue task failure");
                }
            }
        }

        let elapsed = outer.elapsed();
        if uncompacted > 0 {
            tracing::debug!(
                uncompacted,
                compacted,
                "{from:?} sent messages in {elapsed:?}",
            );
        }
        crate::metrics::SEND_ENCRYPTED_LATENCY
            .with_label_values(&[self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        // only add the participant count if it hasn't been seen before.
        let counts = format!("{participant_counter:?}");
        if !participant_counter.is_empty() && self.seen_counts.insert(counts.clone()) {
            errors.push(SendError::ParticipantNotAlive(format!(
                "participants not responding: {counts:?}",
            )));
        }

        // Add back the failed attempts for next time.
        self.deque = failed;
        if !errors.is_empty() {
            tracing::warn!("got errors when sending encrypted messages: {errors:?}");
        }
        errors
    }
}

/// Encrypted message with a reference to the old message. Only the ciphered portion of this
/// type will be sent over the wire, while the original message is kept just in case things
/// go wrong somewhere and the message needs to be requeued to be sent later.
type EncryptedMessage = (Ciphered, (ParticipantInfo, MpcMessage, Instant));

fn partition_ciphered_256kb(encrypted: Vec<EncryptedMessage>) -> Vec<Vec<EncryptedMessage>> {
    let mut result = Vec::new();
    let mut current_partition = Vec::new();
    let mut current_size: usize = 0;

    for ciphered in encrypted {
        let bytesize = ciphered.0.text.len();
        if current_size + bytesize > 256 * 1024 {
            // If adding this byte vector exceeds 256kb, start a new partition
            result.push(current_partition);
            current_partition = Vec::new();
            current_size = 0;
        }
        current_partition.push(ciphered);
        current_size += bytesize;
    }

    if !current_partition.is_empty() {
        // Add the last partition
        result.push(current_partition);
    }

    result
}

fn timeout(msg: &MpcMessage, cfg: &ProtocolConfig) -> Duration {
    match msg {
        MpcMessage::Generating(_) => Duration::from_millis(cfg.message_timeout),
        MpcMessage::Resharing(_) => Duration::from_millis(cfg.message_timeout),
        MpcMessage::Triple(_) => Duration::from_millis(cfg.triple.generation_timeout),
        MpcMessage::Presignature(_) => Duration::from_millis(cfg.presignature.generation_timeout),
        MpcMessage::Signature(_) => Duration::from_millis(cfg.signature.generation_timeout),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::message::GeneratingMessage;
    use crate::protocol::MpcMessage;

    #[test]
    fn test_sending_encrypted_message() {
        let associated_data = b"";
        let (sk, pk) = mpc_keys::hpke::generate();
        let starting_message = MpcMessage::Generating(GeneratingMessage {
            from: cait_sith::protocol::Participant::from(0),
            data: vec![],
        });

        let message = serde_json::to_vec(&starting_message).unwrap();
        let message = pk.encrypt(&message, associated_data).unwrap();

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = sk.decrypt(&cipher, associated_data).unwrap();
        let message: MpcMessage = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }
}
