use std::time::{Duration, Instant};

use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod connection;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "mesh_options")]
pub struct Options {
    #[clap(
        long,
        env("MPC_MESH_FETCH_PARTICIPANT_TIMEOUT"),
        default_value = "1000"
    )]
    pub fetch_participant_timeout: u64,
    #[clap(long, env("MPC_MESH_REFRESH_ACTIVE_TIMEOUT"), default_value = "1000")]
    pub refresh_active_timeout: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--fetch-participant-timeout".to_string(),
            self.fetch_participant_timeout.to_string(),
            "--refresh-active-timeout".to_string(),
            self.refresh_active_timeout.to_string(),
        ]
    }
}

#[derive(Clone)]
pub struct MeshState {
    /// Participants that are active at the beginning of each protocol loop.
    pub active_participants: Participants,

    /// Potential participants that are active at the beginning of each protocol loop. This
    /// includes participants belonging to the next epoch.
    pub active_potential_participants: Participants,

    pub potential_participants: Participants,

    pub stable_participants: Participants,
}

pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,

    /// Participants that are active at the beginning of each protocol loop.
    active_participants: Participants,

    /// Potential participants that are active at the beginning of each protocol loop. This
    /// includes participants belonging to the next epoch.
    active_potential_participants: Participants,
}

impl Mesh {
    pub fn init(options: Options) -> (Self, Arc<RwLock<MeshState>>) {
        let mesh = Self {
            connections: connection::Pool::new(
                Duration::from_millis(options.fetch_participant_timeout),
                Duration::from_millis(options.refresh_active_timeout),
            ),
            active_participants: Participants::default(),
            active_potential_participants: Participants::default(),
        };
        let mesh_state = Arc::new(RwLock::new(MeshState {
            active_participants: Participants::default(),
            active_potential_participants: Participants::default(),
            potential_participants: Participants::default(),
            stable_participants: Participants::default(),
        }));
        (mesh, mesh_state)
    }

    /// Participants that are active at the beginning of each protocol loop.
    pub fn active_participants(&self) -> &Participants {
        &self.active_participants
    }

    /// Potential participants that are active at the beginning of each protocol loop. This will
    /// be empty if not in resharing state for the protocol
    pub fn active_potential_participants(&self) -> &Participants {
        &self.active_potential_participants
    }

    /// Get all pontential participants, but they may not necessarily be active.
    pub async fn potential_participants(&self) -> Participants {
        self.connections.potential_participants().await
    }

    pub fn all_active_participants(&self) -> Participants {
        let mut participants = self.active_participants.clone();
        let active = self.active_potential_participants.keys_vec();
        tracing::info!(?active, "Getting potentially active participants");
        for (participant, info) in self.active_potential_participants.iter() {
            if !participants.contains_key(participant) {
                participants.insert(participant, info.clone());
            }
        }
        participants
    }

    /// Get active participants that have a stable connection. This is useful for arbitrary metrics to
    /// say whether or not a node is stable, such as a node being on track with the latest block height.
    ///
    /// NOTE: ping() will also ping our own node since everyone, including us, is stored in the contract state
    /// or `ProtocolState`, which eventually leads to checking our own stablitity.
    pub async fn stable_participants(&self) -> Participants {
        let mut stable = Participants::default();
        for (participant, info) in self.active_participants().iter() {
            if self.connections.is_participant_stable(participant).await {
                stable.insert(participant, info.clone());
            }
        }
        stable
    }

    async fn establish_participants(&mut self, contract_state: &ProtocolState) {
        self.connections
            .establish_participants(contract_state)
            .await;
        self.ping().await;

        tracing::debug!(
            active = ?self.active_participants.account_ids(),
            active_potential = ?self.active_potential_participants.account_ids(),
            "mesh pinging",
        );
    }

    /// Ping the active participants such that we can see who is alive.
    async fn ping(&mut self) {
        self.active_participants = self.connections.ping().await;
        self.active_potential_participants = self.connections.ping_potential().await;
    }

    pub async fn run(
        mut self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        mesh_state: Arc<RwLock<MeshState>>,
    ) -> anyhow::Result<()> {
        let mut last_pinged = Instant::now();
        loop {
            if last_pinged.elapsed() > Duration::from_millis(300) {
                if let Some(state) = contract_state.read().await.clone() {
                    self.establish_participants(&state).await;
                    let mut mesh_state = mesh_state.write().await;
                    *mesh_state = MeshState {
                        active_participants: self.active_participants().clone(),
                        active_potential_participants: self.active_potential_participants().clone(),
                        potential_participants: self.potential_participants().await.clone(),
                        stable_participants: self.potential_participants().await.clone(),
                    };
                    last_pinged = Instant::now();
                }
            }
        }
    }
}
