pub mod primitives;

use crate::util::NearPublicKeyExt;
use crypto_shared::PublicKey;
use mpc_contract::ProtocolContractState;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};

use self::primitives::{Candidates, Participants, PkVotes, Votes};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

impl From<mpc_contract::InitializingContractState> for InitializingContractState {
    fn from(value: mpc_contract::InitializingContractState) -> Self {
        InitializingContractState {
            candidates: value.candidates.into(),
            threshold: value.threshold,
            pk_votes: value.pk_votes.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

impl From<mpc_contract::RunningContractState> for RunningContractState {
    fn from(value: mpc_contract::RunningContractState) -> Self {
        RunningContractState {
            epoch: value.epoch,
            participants: value.participants.into(),
            threshold: value.threshold,
            public_key: value.public_key.into_affine_point(),
            candidates: value.candidates.into(),
            join_votes: value.join_votes.into(),
            leave_votes: value.leave_votes.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
}

impl From<mpc_contract::ResharingContractState> for ResharingContractState {
    fn from(contract_state: mpc_contract::ResharingContractState) -> Self {
        ResharingContractState {
            old_epoch: contract_state.old_epoch,
            old_participants: contract_state.old_participants.into(),
            new_participants: contract_state.new_participants.into(),
            threshold: contract_state.threshold,
            public_key: contract_state.public_key.into_affine_point(),
            finished_votes: contract_state
                .finished_votes
                .into_iter()
                .map(|acc_id| AccountId::from_str(acc_id.as_ref()).unwrap())
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ProtocolState {
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolState {
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ProtocolState::Initializing { .. } => None,
            ProtocolState::Running(RunningContractState { public_key, .. }) => Some(public_key),
            ProtocolState::Resharing(ResharingContractState { public_key, .. }) => Some(public_key),
        }
    }

    pub fn threshold(&self) -> usize {
        match self {
            ProtocolState::Initializing(InitializingContractState { threshold, .. }) => *threshold,
            ProtocolState::Running(RunningContractState { threshold, .. }) => *threshold,
            ProtocolState::Resharing(ResharingContractState { threshold, .. }) => *threshold,
        }
    }
}

impl TryFrom<ProtocolContractState> for ProtocolState {
    type Error = ();

    fn try_from(value: ProtocolContractState) -> Result<Self, Self::Error> {
        match value {
            ProtocolContractState::Initializing(state) => {
                Ok(ProtocolState::Initializing(state.into()))
            }
            ProtocolContractState::Running(state) => Ok(ProtocolState::Running(state.into())),
            ProtocolContractState::Resharing(state) => Ok(ProtocolState::Resharing(state.into())),
            ProtocolContractState::NotInitialized => Err(()),
        }
    }
}
