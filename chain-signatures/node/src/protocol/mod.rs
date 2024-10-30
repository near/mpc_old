mod cryptography;

pub mod consensus;
pub mod contract;
pub mod message;
pub mod presignature;
pub mod signature;
pub mod state;
pub mod triple;

pub use consensus::ConsensusError;
pub use contract::primitives::ParticipantInfo;
pub use contract::ProtocolState;
pub use cryptography::CryptographicError;
pub use message::MpcMessage;
pub use signature::SignQueue;
pub use signature::SignRequest;
pub use state::NodeState;
pub use sysinfo::{Components, CpuRefreshKind, Disks, RefreshKind, System};

use self::consensus::ConsensusCtx;
use self::cryptography::CryptographicCtx;
use self::message::MessageCtx;
use crate::config::Config;
use crate::http_client;
use crate::mesh;
use crate::mesh::Mesh;
use crate::protocol::consensus::ConsensusProtocol;
use crate::protocol::cryptography::CryptographicProtocol;
use crate::protocol::message::{MessageHandler, MpcMessageQueue};
use crate::rpc_client;
use crate::storage::presignature_storage::PresignatureRedisStorage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::triple_storage::TripleRedisStorage;

use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use reqwest::IntoUrl;
use std::path::Path;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::sync::RwLock;
use url::Url;

struct Ctx {
    my_address: Url,
    account_id: AccountId,
    mpc_contract_id: AccountId,
    signer: InMemorySigner,
    rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    sign_queue: Arc<RwLock<SignQueue>>,
    secret_storage: SecretNodeStorageBox,
    triple_storage: TripleRedisStorage,
    presignature_storage: PresignatureRedisStorage,
    cfg: Config,
    mesh: Mesh,
    message_options: http_client::Options,
}

impl ConsensusCtx for &mut MpcSignProtocol {
    fn my_account_id(&self) -> &AccountId {
        &self.ctx.account_id
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.ctx.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.ctx.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.ctx.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn my_address(&self) -> &Url {
        &self.ctx.my_address
    }

    fn sign_queue(&self) -> Arc<RwLock<SignQueue>> {
        self.ctx.sign_queue.clone()
    }

    fn secret_storage(&self) -> &SecretNodeStorageBox {
        &self.ctx.secret_storage
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }

    fn triple_storage(&self) -> &TripleRedisStorage {
        &self.ctx.triple_storage
    }

    fn presignature_storage(&self) -> &PresignatureRedisStorage {
        &self.ctx.presignature_storage
    }

    fn message_options(&self) -> http_client::Options {
        self.ctx.message_options.clone()
    }
}

#[async_trait::async_trait]
impl CryptographicCtx for &mut MpcSignProtocol {
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.ctx.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.ctx.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.ctx.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox {
        &mut self.ctx.secret_storage
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }

    fn mesh(&self) -> &Mesh {
        &self.ctx.mesh
    }
}

#[async_trait::async_trait]
impl MessageCtx for &MpcSignProtocol {
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn mesh(&self) -> &Mesh {
        &self.ctx.mesh
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }
}

pub struct MpcSignProtocol {
    ctx: Ctx,
    receiver: mpsc::Receiver<MpcMessage>,
    state: Arc<RwLock<NodeState>>,
}

impl MpcSignProtocol {
    #![allow(clippy::too_many_arguments)]
    pub fn init<U: IntoUrl>(
        my_address: U,
        mpc_contract_id: AccountId,
        account_id: AccountId,
        rpc_client: near_fetch::Client,
        signer: InMemorySigner,
        receiver: mpsc::Receiver<MpcMessage>,
        sign_queue: Arc<RwLock<SignQueue>>,
        secret_storage: SecretNodeStorageBox,
        triple_storage: TripleRedisStorage,
        presignature_storage: PresignatureRedisStorage,
        cfg: Config,
        mesh_options: mesh::Options,
        message_options: http_client::Options,
    ) -> (Self, Arc<RwLock<NodeState>>) {
        let my_address = my_address.into_url().unwrap();
        let rpc_url = rpc_client.rpc_addr();
        let signer_account_id: AccountId = signer.clone().account_id;
        tracing::info!(
            ?my_address,
            ?mpc_contract_id,
            ?account_id,
            ?rpc_url,
            ?signer_account_id,
            ?cfg,
            "initializing protocol with parameters"
        );
        let state = Arc::new(RwLock::new(NodeState::Starting));
        let ctx = Ctx {
            my_address,
            account_id,
            mpc_contract_id,
            rpc_client,
            http_client: reqwest::Client::new(),
            sign_queue,
            signer,
            secret_storage,
            triple_storage,
            presignature_storage,
            cfg,
            mesh: Mesh::new(mesh_options),
            message_options,
        };
        let protocol = MpcSignProtocol {
            ctx,
            receiver,
            state: state.clone(),
        };
        (protocol, state)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let my_account_id = self.ctx.account_id.to_string();
        let _span = tracing::info_span!("running", my_account_id);
        crate::metrics::NODE_RUNNING
            .with_label_values(&[my_account_id.as_str()])
            .set(1);
        crate::metrics::NODE_VERSION
            .with_label_values(&[my_account_id.as_str()])
            .set(node_version());
        let mut queue = MpcMessageQueue::default();
        let mut last_state_update = Instant::now();
        let mut last_config_update = Instant::now();
        let mut last_hardware_pull = Instant::now();
        let mut last_pinged = Instant::now();

        // Sets the latest configurations from the contract:
        if let Err(err) = self
            .ctx
            .cfg
            .fetch_inplace(&self.ctx.rpc_client, &self.ctx.mpc_contract_id)
            .await
        {
            tracing::error!("could not fetch contract's config on startup: {err:?}");
        }

        loop {
            let protocol_time = Instant::now();
            tracing::debug!("trying to advance chain signatures protocol");
            // Hardware metric refresh
            if last_hardware_pull.elapsed() > Duration::from_secs(5) {
                update_system_metrics(&my_account_id);
                last_hardware_pull = Instant::now();
            }

            crate::metrics::PROTOCOL_ITER_CNT
                .with_label_values(&[my_account_id.as_str()])
                .inc();
            loop {
                let msg_result = self.receiver.try_recv();
                match msg_result {
                    Ok(msg) => {
                        tracing::debug!("received a new message");
                        queue.push(msg);
                    }
                    Err(TryRecvError::Empty) => {
                        tracing::debug!("no new messages received");
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        tracing::warn!("communication was disconnected, no more messages will be received, spinning down");
                        return Ok(());
                    }
                }
            }

            let contract_state = if last_state_update.elapsed() > Duration::from_secs(1) {
                let contract_state = match rpc_client::fetch_mpc_contract_state(
                    &self.ctx.rpc_client,
                    &self.ctx.mpc_contract_id,
                )
                .await
                {
                    Ok(contract_state) => contract_state,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                // Establish the participants for this current iteration of the protocol loop. This will
                // set which participants are currently active in the protocol and determines who will be
                // receiving messages.
                self.ctx.mesh.establish_participants(&contract_state).await;

                last_state_update = Instant::now();
                Some(contract_state)
            } else {
                None
            };

            if last_config_update.elapsed() > Duration::from_secs(5 * 60) {
                // Sets the latest configurations from the contract:
                if let Err(err) = self
                    .ctx
                    .cfg
                    .fetch_inplace(&self.ctx.rpc_client, &self.ctx.mpc_contract_id)
                    .await
                {
                    tracing::warn!("could not fetch contract's config: {err:?}");
                }
                last_config_update = Instant::now();
            }

            if last_pinged.elapsed() > Duration::from_millis(300) {
                self.ctx.mesh.ping().await;
                last_pinged = Instant::now();
            }

            let state = {
                let guard = self.state.read().await;
                guard.clone()
            };

            let crypto_time = Instant::now();
            let mut state = match state.progress(&mut self).await {
                Ok(state) => {
                    tracing::debug!("progress ok: {state}");
                    state
                }
                Err(err) => {
                    tracing::warn!("protocol unable to progress: {err:?}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            crate::metrics::PROTOCOL_LATENCY_ITER_CRYPTO
                .with_label_values(&[my_account_id.as_str()])
                .observe(crypto_time.elapsed().as_secs_f64());

            let consensus_time = Instant::now();
            if let Some(contract_state) = contract_state {
                let from_state = format!("{state}");
                state = match state.advance(&mut self, contract_state).await {
                    Ok(state) => {
                        tracing::debug!("advance ok: {from_state} => {state}");
                        state
                    }
                    Err(err) => {
                        tracing::warn!("protocol unable to advance: {err:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
            }
            crate::metrics::PROTOCOL_LATENCY_ITER_CONSENSUS
                .with_label_values(&[my_account_id.as_str()])
                .observe(consensus_time.elapsed().as_secs_f64());

            let message_time = Instant::now();
            if let Err(err) = state.handle(&self, &mut queue).await {
                tracing::warn!("protocol unable to handle messages: {err:?}");
            }
            crate::metrics::PROTOCOL_LATENCY_ITER_MESSAGE
                .with_label_values(&[my_account_id.as_str()])
                .observe(message_time.elapsed().as_secs_f64());

            let sleep_ms = match state {
                NodeState::Generating(_) => 500,
                NodeState::Resharing(_) => 500,
                NodeState::Running(_) => 100,

                NodeState::Starting => 1000,
                NodeState::Started(_) => 1000,
                NodeState::WaitingForConsensus(_) => 1000,
                NodeState::Joining(_) => 1000,
            };

            let mut guard = self.state.write().await;
            *guard = state;
            drop(guard);

            crate::metrics::PROTOCOL_LATENCY_ITER_TOTAL
                .with_label_values(&[my_account_id.as_str()])
                .observe(protocol_time.elapsed().as_secs_f64());
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }
}

async fn get_my_participant(protocol: &MpcSignProtocol) -> Participant {
    let my_near_acc_id = &protocol.ctx.account_id;
    let state = protocol.state.read().await;
    let participant_info = state
        .find_participant_info(my_near_acc_id)
        .unwrap_or_else(|| {
            tracing::error!("could not find participant info for {my_near_acc_id}");
            panic!("could not find participant info for {my_near_acc_id}");
        });
    participant_info.id.into()
}

/// our release versions take the form of "1.0.0-rc.2"
fn node_version() -> i64 {
    let version = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    let rc_num = if let Some(rc_str) = version.pre.split('.').nth(1) {
        rc_str.parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    (rc_num + version.patch * 1000 + version.minor * 1000000 + version.major * 1000000000) as i64
}

fn update_system_metrics(node_account_id: &str) {
    let mut system = System::new_all();

    // Refresh only the necessary components
    system.refresh_all();

    let mut s =
        System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::everything()));
    // Wait a bit because CPU usage is based on diff.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    // Refresh CPUs again to get actual value.
    s.refresh_cpu_specifics(CpuRefreshKind::everything());

    // Update CPU usage metric
    let cpu_usage = s.global_cpu_usage() as i64;
    crate::metrics::CPU_USAGE_PERCENTAGE
        .with_label_values(&["global", node_account_id])
        .set(cpu_usage);

    // Update available memory metric
    let available_memory = system.available_memory() as i64;
    crate::metrics::AVAILABLE_MEMORY_BYTES
        .with_label_values(&["available_mem", node_account_id])
        .set(available_memory);

    // Update used memory metric
    let used_memory = system.used_memory() as i64;
    crate::metrics::USED_MEMORY_BYTES
        .with_label_values(&["used", node_account_id])
        .set(used_memory);

    let root_mount_point = Path::new("/");
    // Update available disk space metric
    let available_disk_space = Disks::new_with_refreshed_list()
        .iter()
        .find(|d| d.mount_point() == root_mount_point)
        .expect("No disk found mounted at '/'")
        .available_space() as i64;
    crate::metrics::AVAILABLE_DISK_SPACE_BYTES
        .with_label_values(&["available_disk", node_account_id])
        .set(available_disk_space);

    // Update total disk space metric
    let total_disk_space = Disks::new_with_refreshed_list()
        .iter()
        .find(|d| d.mount_point() == root_mount_point)
        .expect("No disk found mounted at '/'")
        .total_space() as i64;
    crate::metrics::TOTAL_DISK_SPACE_BYTES
        .with_label_values(&["total_disk", node_account_id])
        .set(total_disk_space);
}
