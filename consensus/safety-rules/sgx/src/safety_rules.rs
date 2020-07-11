use anyhow::Result;
use libra_types::{
    validator_signer::ValidatorSigner,
    epoch_change::EpochChangeProof,
    epoch_state::EpochState,
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

use crate::{
    consensus_state::ConsensusState,
    storage_proxy::StorageProxy,
    error::Error,
};

pub struct SafetyRules {
    validator_signer: ValidatorSigner,
    storage_proxy: StorageProxy,
    epoch_state: Option<EpochState>,
}

impl SafetyRules {

    pub fn new() -> Self {
        Self {
            validator_signer: ValidatorSigner::from_int(1),
            storage_proxy: StorageProxy::new(None),
            epoch_state: None,
        }
    }


    pub fn set_storage_proxy(&mut self, proxy: TcpStream) {
        self.storage_proxy = StorageProxy::new(Some(proxy));
    }

    pub fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        eprintln!("Initializing...");

        let waypoint = self.storage_proxy.waypoint();
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
        let ledger_info = last_li.ledger_info();
        let epoch_state = ledger_info
            .next_epoch_state()
            .cloned().
            ok_or(Error::InvalidLedgerInfo)?;

        let author = self.storage_proxy.author();
        if let Some(expected_key) = epoch_state.verifier.get_public_key(&author) {
            // TODO:reconcile key
        }
        let current_epoch = self.storage_proxy.epoch();

        if current_epoch < epoch_state.epoch {
            self.storage_proxy.set_waypoint(&Waypoint::new_epoch_boundary(ledger_info)?)?;
            self.storage_proxy.set_last_voted_round(0)?;
            self.storage_proxy.set_preferred_round(0)?;
            self.storage_proxy.set_last_vote(None)?;
            self.storage_proxy.set_epoch(epoch_state.epoch)?;
        }
        self.epoch_state = Some(epoch_state);
        Ok(())
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

