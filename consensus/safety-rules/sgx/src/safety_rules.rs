use libra_types::{
    validator_signer::ValidatorSigner,
    epoch_change::EpochChangeProof,
    waypoint::Waypoint,
};
use consensus_types::{
    block_data::BlockData,
    timeout::Timeout,
    vote::Vote,
    vote_proposal::MaybeSignedVoteProposal,
    common::Round,
};
use std::io::prelude::*;
use std::io::{BufReader};
use std::net::{TcpStream};

use crate::consensus_state::ConsensusState;
use crate::storage_proxy::StorageProxy;

pub struct SafetyRules {
    validator_signer: ValidatorSigner,
    storage_proxy: StorageProxy,
}

impl SafetyRules {

    pub fn new() -> Self {
        Self {
            validator_signer: ValidatorSigner::from_int(1),
            storage_proxy: StorageProxy::new(None),
        }
    }


    pub fn set_storage_proxy(&mut self, proxy: TcpStream) {
        self.storage_proxy = StorageProxy::new(Some(proxy));
    }

    pub fn initialize(&mut self, proof: &EpochChangeProof) {
    }

    pub fn construct_and_sign_proposal(&mut self, vote_proposal: &MaybeSignedVoteProposal) {
    }

    pub fn sign_proposal(&mut self, block_data: BlockData) {
    }

    pub fn sign_timeout(&mut self, timeout: &Timeout) {
    }

    pub fn consensus_state(&mut self, mut stream: TcpStream) -> Option<ConsensusState> {
        eprintln!("Handling req:consensus_state!");
        let epoch = self.storage_proxy.epoch();
        let last_voted_round = self.storage_proxy.last_voted_round();
        let preferred_round = self.storage_proxy.preferred_round();
        let waypoint = self.storage_proxy.waypoint();
        Some(ConsensusState::new(
                epoch,
                last_voted_round,
                preferred_round,
                waypoint,
                true
            )
         )
    }
}

