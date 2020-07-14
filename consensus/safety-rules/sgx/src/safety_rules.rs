use anyhow::Result;
use consensus_types::{
    block::Block,
    block_data::BlockData,
    common::Author,
    quorum_cert::QuorumCert,
    timeout::Timeout,
    vote::Vote,
    vote_data::VoteData,
    vote_proposal::{MaybeSignedVoteProposal, VoteProposal},
};
use libra_crypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    hash::HashValue,
    traits::Signature,
};
use libra_types::{
    block_info::BlockInfo, epoch_change::EpochChangeProof, epoch_state::EpochState,
    ledger_info::LedgerInfo, validator_signer::ValidatorSigner, waypoint::Waypoint,
};
use std::cmp::Ordering;

use std::io::{BufReader};
use std::net::{TcpStream};

use crate::{
    consensus_state::ConsensusState,
    t_safety_rules::TSafetyRules,
    storage_proxy::StorageProxy,
    error::Error,
};

#[macro_use]
macro_rules! sgx_print {
    (@preamble) => {{
        let file: Vec<&str> = file!().split("/").collect();
        let file_name: &str = file.last().unwrap();
        print!("LSR_SGX[{}:{}] ", file_name, line!());
    }};

    () => {
        sgx_print!(@preamble);
        println!();
    };

    ($first:expr $(, $rest:expr)* $(,)*) => {
       sgx_print!(@preamble);
       println!($first, $($rest),*);
    };
}

pub struct SafetyRules {
    validator_signer: ValidatorSigner,
    storage_proxy: StorageProxy,
    epoch_state: Option<EpochState>,
}

impl SafetyRules {

    pub fn new() -> Self {
        Self {
            validator_signer: ValidatorSigner::from_int(0),
            storage_proxy: StorageProxy::new(None),
            epoch_state: None,
        }
    }

    fn signer(&self) -> &ValidatorSigner {
        &self.validator_signer
    }

    fn epoch_state(&self) -> Result<&EpochState, Error>  {
        self.epoch_state
            .as_ref()
            .ok_or_else(|| Error::NotInitialized("epoch_state".into()))
    }

    /// Check if the executed result extends the parent result.
    fn extension_check(&self, vote_proposal: &VoteProposal) -> Result<VoteData, Error> {
        let proposed_block = vote_proposal.block();
        let new_tree = vote_proposal
            .accumulator_extension_proof()
            .verify(
                proposed_block
                    .quorum_cert()
                    .certified_block()
                    .executed_state_id(),
            )
            .map_err(|e| Error::InvalidAccumulatorExtension(e.to_string()))?;
        Ok(VoteData::new(
            proposed_block.gen_block_info(
                new_tree.root_hash(),
                new_tree.version(),
                vote_proposal.next_epoch_state().cloned(),
            ),
            proposed_block.quorum_cert().certified_block().clone(),
        ))
    }

    /// Produces a LedgerInfo that either commits a block based upon the 3-chain
    /// commit rule or an empty LedgerInfo for no commit. The 3-chain commit rule is: B0 and its
    /// prefixes can be committed if there exist certified blocks B1 and B2 that satisfy:
    /// 1) B0 <- B1 <- B2 <--
    /// 2) round(B0) + 1 = round(B1), and
    /// 3) round(B1) + 1 = round(B2).
    pub fn construct_ledger_info(&self, proposed_block: &Block) -> LedgerInfo {
        let block2 = proposed_block.round();
        let block1 = proposed_block.quorum_cert().certified_block().round();
        let block0 = proposed_block.quorum_cert().parent_block().round();

        let commit = block0 + 1 == block1 && block1 + 1 == block2;
        if commit {
            LedgerInfo::new(
                proposed_block.quorum_cert().parent_block().clone(),
                HashValue::zero(),
            )
        } else {
            LedgerInfo::new(BlockInfo::empty(), HashValue::zero())
        }
    }

    /// Second voting rule
    fn verify_and_update_preferred_round(&mut self, quorum_cert: &QuorumCert) -> Result<(), Error> {
        let preferred_round = self.storage_proxy.preferred_round();
        let one_chain_round = quorum_cert.certified_block().round();
        let two_chain_round = quorum_cert.parent_block().round();

        if one_chain_round < preferred_round {
            sgx_print!(
                "QC round does not match preferred round {} < {}",
                one_chain_round, preferred_round
            );
            return Err(Error::IncorrectPreferredRound(
                one_chain_round,
                preferred_round,
            ));
        }

        match two_chain_round.cmp(&preferred_round) {
            Ordering::Greater => self
                .storage_proxy
                .set_preferred_round(two_chain_round)?,
            Ordering::Less => eprintln!(
                "2-chain round {} is lower than preferred round {} but 1-chain round {} is higher.",
                two_chain_round, preferred_round, one_chain_round
            ),
            Ordering::Equal => (),
        }
        Ok(())
    }

    /// This verifies whether the author of one proposal is the validator signer
    fn verify_author(&self, author: Option<Author>) -> Result<(), Error> {
        let validator_signer_author = &self.signer().author();
        let author = author
            .ok_or_else(|| Error::InvalidProposal("No author found in the proposal".into()))?;
        if validator_signer_author != &author {
            return Err(Error::InvalidProposal(
                "Proposal author is not validator signer!".into(),
            ));
        }
        Ok(())
    }

    /// This verifies the epoch given against storage for consistent verification
    fn verify_epoch(&self, epoch: u64) -> Result<(), Error> {
        let expected_epoch = self.storage_proxy.epoch();
        if epoch != expected_epoch {
            Err(Error::IncorrectEpoch(epoch, expected_epoch))
        } else {
            Ok(())
        }
    }

    /// First voting rule
    fn verify_last_vote_round(&self, proposed_block: &BlockData) -> Result<(), Error> {
        let last_voted_round = self.storage_proxy.last_voted_round();
        if proposed_block.round() > last_voted_round {
            return Ok(());
        }

        sgx_print!(
            "Vote proposal is old {} <= {}",
            proposed_block.round(),
            last_voted_round
        );
        Err(Error::IncorrectLastVotedRound(
            proposed_block.round(),
            last_voted_round,
        ))
    }

    /// This verifies a QC has valid signatures.
    fn verify_qc(&self, qc: &QuorumCert) -> Result<(), Error> {
        let epoch_state = self.epoch_state()?;

        qc.verify(&epoch_state.verifier)
            .map_err(|e| Error::InvalidQuorumCertificate(e.to_string()))?;
        Ok(())
    }

    pub fn set_storage_proxy(&mut self, proxy: TcpStream) {
        self.storage_proxy = StorageProxy::new(Some(proxy));
    }

}

impl TSafetyRules for SafetyRules {

    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        sgx_print!("Initializing...");

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

    fn construct_and_sign_vote(&mut self, vote_proposal: &MaybeSignedVoteProposal) -> Result<Vote, Error> {
        return Err(Error::NotInitialized("tsafety_rules".into()));
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        sgx_print!("Incoming proposal to sign.");

        self.signer();
        self.verify_author(block_data.author())?;
        self.verify_epoch(block_data.epoch())?;
        self.verify_last_vote_round(&block_data)?;
        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert())?;

        Ok(Block::new_proposal_from_block_data(
                block_data,
                self.signer(),
        ))
    }

    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        sgx_print!("Incoming timeout message for round {}", timeout.round());

        self.signer();
        self.verify_epoch(timeout.epoch())?;

        let preferred_round = self.storage_proxy.preferred_round();
        if timeout.round() <= preferred_round {
            return Err(Error::IncorrectPreferredRound(
                timeout.round(),
                preferred_round,
            ));
        }

        let last_voted_round = self.storage_proxy.last_voted_round();
        if timeout.round() < last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                last_voted_round,
            ));
        }
        if timeout.round() > last_voted_round {
            self.storage_proxy
                .set_last_voted_round(timeout.round())?;
        }

        let validator_signer = self.signer();
        let signature = timeout.sign(&validator_signer);

        sgx_print!("Successfully signed timeout message.");
        Ok(signature)
    }

    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        sgx_print!("Handling req:consensus_state!");
        let epoch = self.storage_proxy.epoch();
        let last_voted_round = self.storage_proxy.last_voted_round();
        let preferred_round = self.storage_proxy.preferred_round();
        let waypoint = self.storage_proxy.waypoint();
        Ok(ConsensusState::new(
                epoch,
                last_voted_round,
                preferred_round,
                waypoint,
                true
            )
         )
    }

}
