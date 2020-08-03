// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    consensus_state::ConsensusState,
    error::Error,
    logging::{self, LogEntry, LogEvent, LogField},
    persistent_safety_storage::PersistentSafetyStorage,
    t_safety_rules::TSafetyRules,
    COUNTERS,
};
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
use libra_logger::prelude::*;
use libra_trace::prelude::*;
use libra_types::{
    block_info::BlockInfo, epoch_change::EpochChangeProof, epoch_state::EpochState,
    ledger_info::LedgerInfo, validator_signer::ValidatorSigner, waypoint::Waypoint,
};
use std::cmp::Ordering;
use std::time::{SystemTime, Duration};

/// @TODO consider a cache of verified QCs to cut down on verification costs
pub struct SafetyRules {
    persistent_storage: PersistentSafetyStorage,
    execution_public_key: Option<Ed25519PublicKey>,
    validator_signer: Option<ValidatorSigner>,
    epoch_state: Option<EpochState>,
}

impl SafetyRules {
    /// Constructs a new instance of SafetyRules with the given persistent storage and the
    /// consensus private keys
    pub fn new(
        persistent_storage: PersistentSafetyStorage,
        verify_vote_proposal_signature: bool,
    ) -> Self {
        let execution_public_key = if verify_vote_proposal_signature {
            Some(
                persistent_storage
                    .execution_public_key()
                    .expect("Unable to retrieve execution public key"),
            )
        } else {
            None
        };
        Self {
            persistent_storage,
            execution_public_key,
            validator_signer: None,
            epoch_state: None,
        }
    }

    fn signer(&self) -> Result<&ValidatorSigner, Error> {
        self.validator_signer
            .as_ref()
            .ok_or_else(|| Error::NotInitialized("validator_signer".into()))
    }

    fn epoch_state(&self) -> Result<&EpochState, Error> {
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
    pub fn construct_ledger_info(&self, proposed_block: &Block) -> Result<LedgerInfo, Error> {
        let block2 = proposed_block.round();
        let block1 = proposed_block.quorum_cert().certified_block().round();
        let block0 = proposed_block.quorum_cert().parent_block().round();

        // verify 3-chain rule
        let next_round =
            |round: u64| u64::checked_add(round, 1).ok_or(Error::IncorrectRound(round));
        let commit = next_round(block0)? == block1 && next_round(block1)? == block2;

        // create a ledger info
        let ledger_info = if commit {
            LedgerInfo::new(
                proposed_block.quorum_cert().parent_block().clone(),
                HashValue::zero(),
            )
        } else {
            LedgerInfo::new(BlockInfo::empty(), HashValue::zero())
        };

        Ok(ledger_info)
    }

    /// Second voting rule
    fn verify_and_update_preferred_round(&mut self, quorum_cert: &QuorumCert) -> Result<(), Error> {
        let preferred_round = self.persistent_storage.preferred_round()?;
        let one_chain_round = quorum_cert.certified_block().round();
        let two_chain_round = quorum_cert.parent_block().round();

        if one_chain_round < preferred_round {
            return Err(Error::IncorrectPreferredRound(
                one_chain_round,
                preferred_round,
            ));
        }

        match two_chain_round.cmp(&preferred_round) {
            Ordering::Greater => self
                .persistent_storage
                .set_preferred_round(two_chain_round)?,
            Ordering::Less => {
                trace!(
                "2-chain round {} is lower than preferred round {} but 1-chain round {} is higher.",
                two_chain_round, preferred_round, one_chain_round
            )
            }
            Ordering::Equal => (),
        }
        Ok(())
    }

    /// This verifies whether the author of one proposal is the validator signer
    fn verify_author(&self, author: Option<Author>) -> Result<(), Error> {
        let validator_signer_author = &self.signer()?.author();
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
        let expected_epoch = self.persistent_storage.epoch()?;
        if epoch != expected_epoch {
            Err(Error::IncorrectEpoch(epoch, expected_epoch))
        } else {
            Ok(())
        }
    }

    /// First voting rule
    fn verify_last_vote_round(&self, proposed_block: &BlockData) -> Result<(), Error> {
        let last_voted_round = self.persistent_storage.last_voted_round()?;
        if proposed_block.round() > last_voted_round {
            return Ok(());
        }

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

    // Internal functions mapped to the public interface to enable exhaustive logging and metrics

    fn guarded_consensus_state(&mut self) -> Result<ConsensusState, Error> {
        trace_code_block!("safety_rules::guarded_consensus_state", {"req", 0u32});
        Ok(ConsensusState::new(
            self.persistent_storage.epoch()?,
            self.persistent_storage.last_voted_round()?,
            self.persistent_storage.preferred_round()?,
            self.persistent_storage.waypoint()?,
            self.signer().is_ok(),
        ))
    }

    fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let waypoint = self.persistent_storage.waypoint()?;
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
        let ledger_info = last_li.ledger_info();
        let epoch_state = ledger_info
            .next_epoch_state()
            .cloned()
            .ok_or(Error::InvalidLedgerInfo)?;

        let author = self.persistent_storage.author()?;
        if let Some(expected_key) = epoch_state.verifier.get_public_key(&author) {
            let curr_key = self.signer().ok().map(|s| s.public_key());
            if curr_key != Some(expected_key.clone()) {
                let consensus_key = self
                    .persistent_storage
                    .consensus_key_for_version(expected_key)
                    .ok()
                    .ok_or_else(|| {
                        send_struct_log!(logging::safety_log(
                            LogEntry::KeyReconciliation,
                            LogEvent::Error
                        )
                        .data(LogField::Message.as_str(), "Validator key not found"));

                        self.validator_signer = None;
                        Error::InternalError("Validator key not found".into())
                    })?;

                self.validator_signer = Some(ValidatorSigner::new(author, consensus_key));
            }

            send_struct_log!(
                logging::safety_log(LogEntry::KeyReconciliation, LogEvent::Success)
                    .data(LogField::Message.as_str(), "in set")
            );
        } else {
            send_struct_log!(
                logging::safety_log(LogEntry::KeyReconciliation, LogEvent::Success)
                    .data(LogField::Message.as_str(), "not in set")
            );
            self.validator_signer = None;
        }

        let current_epoch = self.persistent_storage.epoch()?;

        if current_epoch < epoch_state.epoch {
            // This is ordered specifically to avoid configuration issues:
            // * First set the waypoint to lock in the minimum restarting point,
            // * set the round information,
            // * finally, set the epoch information because once the epoch is set, this `if`
            // statement cannot be re-entered.
            self.persistent_storage
                .set_waypoint(&Waypoint::new_epoch_boundary(ledger_info)?)?;
            self.persistent_storage.set_last_voted_round(0)?;
            self.persistent_storage.set_preferred_round(0)?;
            self.persistent_storage.set_last_vote(None)?;
            self.persistent_storage.set_epoch(epoch_state.epoch)?;
        }
        self.epoch_state = Some(epoch_state);

        Ok(())
    }

    fn guarded_construct_and_sign_vote(
        &mut self,
        maybe_signed_vote_proposal: &MaybeSignedVoteProposal,
    ) -> Result<Vote, Error> {
        // Exit early if we cannot sign
        self.signer()?;

        let (vote_proposal, execution_signature) = (
            &maybe_signed_vote_proposal.vote_proposal,
            maybe_signed_vote_proposal.signature.as_ref(),
        );

        if let Some(public_key) = self.execution_public_key.as_ref() {
            execution_signature
                .ok_or_else(|| Error::VoteProposalSignatureNotFound)?
                .verify(vote_proposal, public_key)?
        }

        let proposed_block = vote_proposal.block();
        self.verify_epoch(proposed_block.epoch())?;
        self.verify_qc(proposed_block.quorum_cert())?;
        proposed_block.validate_signature(&self.epoch_state()?.verifier)?;

        self.verify_and_update_preferred_round(proposed_block.quorum_cert())?;
        // if already voted on this round, send back the previous vote.
        let last_vote = self.persistent_storage.last_vote()?;
        if let Some(vote) = last_vote {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                self.persistent_storage
                    .set_last_voted_round(proposed_block.round())?;
                return Ok(vote);
            }
        }
        self.verify_last_vote_round(proposed_block.block_data())?;

        let vote_data = self.extension_check(vote_proposal)?;
        self.persistent_storage
            .set_last_voted_round(proposed_block.round())?;

        let validator_signer = self.signer()?;
        let vote = Vote::new(
            vote_data,
            validator_signer.author(),
            self.construct_ledger_info(proposed_block)?,
            validator_signer,
        );
        self.persistent_storage.set_last_vote(Some(vote.clone()))?;
        self.persistent_storage
            .set_last_voted_round(proposed_block.round())?;

        Ok(vote)
    }

    fn guarded_sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        self.signer()?;
        self.verify_author(block_data.author())?;
        self.verify_epoch(block_data.epoch())?;
        self.verify_last_vote_round(&block_data)?;
        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert())?;

        Ok(Block::new_proposal_from_block_data(
            block_data,
            self.signer()?,
        ))
    }

    fn guarded_sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        self.signer()?;
        self.verify_epoch(timeout.epoch())?;

        let preferred_round = self.persistent_storage.preferred_round()?;
        if timeout.round() <= preferred_round {
            return Err(Error::IncorrectPreferredRound(
                timeout.round(),
                preferred_round,
            ));
        }

        let last_voted_round = self.persistent_storage.last_voted_round()?;
        if timeout.round() < last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                last_voted_round,
            ));
        }
        if timeout.round() > last_voted_round {
            self.persistent_storage
                .set_last_voted_round(timeout.round())?;
        }

        let validator_signer = self.signer()?;
        let signature = timeout.sign(&validator_signer);

        Ok(signature)
    }
}

impl TSafetyRules for SafetyRules {
    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        // lwg: this is to understand vault overhead
        //trace_code_block!("safety_rules::consensus_state", {"req", 0u32});
        let log_cb = |log: StructuredLogEntry| log;
        let cb = || self.guarded_consensus_state();


        run_and_log(
            cb,
            &COUNTERS.consensus_state_request,
            &COUNTERS.consensus_state_success,
            &COUNTERS.consensus_state_error,
            log_cb,
            LogEntry::ConsensusState,
        )
    }

    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let log_cb = |log: StructuredLogEntry| log;
        let cb = || self.guarded_initialize(proof);
        run_and_log(
            cb,
            &COUNTERS.initialize_request,
            &COUNTERS.initialize_success,
            &COUNTERS.initialize_error,
            log_cb,
            LogEntry::Initialize,
        )
    }

    fn construct_and_sign_vote(
        &mut self,
        maybe_signed_vote_proposal: &MaybeSignedVoteProposal,
    ) -> Result<Vote, Error> {
        // lwg: hack
        let round = maybe_signed_vote_proposal.vote_proposal.block().round();
        trace_code_block!("safety_rules::construct_and_sign_vote", {"round", round});
        let log_cb = |log: StructuredLogEntry| log.data(LogField::Round.as_str(), round);
        let cb = || self.guarded_construct_and_sign_vote(maybe_signed_vote_proposal);
        // lwg: this marks the end
        run_and_log(
            cb,
            &COUNTERS.construct_and_sign_vote_request,
            &COUNTERS.construct_and_sign_vote_success,
            &COUNTERS.construct_and_sign_vote_error,
            log_cb,
            LogEntry::ConstructAndSignVote,
        )
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        let round = block_data.round();
        trace_code_block!("safety_rules::sign_proposal", {"round", round});
        let log_cb = |log: StructuredLogEntry| log.data(LogField::Round.as_str(), round);
        let cb = || self.guarded_sign_proposal(block_data);
        run_and_log(
            cb,
            &COUNTERS.sign_proposal_request,
            &COUNTERS.sign_proposal_success,
            &COUNTERS.sign_proposal_error,
            log_cb,
            LogEntry::SignProposal,
        )
    }

    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        trace_code_block!("safety_rules::sign_timeout", {"round", 0});
        let log_cb = |log: StructuredLogEntry| log.data(LogField::Round.as_str(), timeout.round());
        let cb = || self.guarded_sign_timeout(timeout);
        run_and_log(
            cb,
            &COUNTERS.sign_timeout_request,
            &COUNTERS.sign_timeout_success,
            &COUNTERS.sign_timeout_error,
            log_cb,
            LogEntry::SignTimeout,
        )
    }
}

fn run_and_log<F, L, R>(
    callback: F,
    entry_counter: &libra_secure_push_metrics::Counter,
    success_counter: &libra_secure_push_metrics::Counter,
    error_counter: &libra_secure_push_metrics::Counter,
    log_cb: L,
    log_entry: LogEntry,
) -> Result<R, Error>
where
    F: FnOnce() -> Result<R, Error>,
    L: Fn(StructuredLogEntry) -> StructuredLogEntry,
{
    send_struct_log!(log_cb(logging::safety_log(log_entry, LogEvent::Request)));
    entry_counter.inc();
    let now = SystemTime::now();
    let ret = callback()
        .map(|v| {
            send_struct_log!(log_cb(logging::safety_log(log_entry, LogEvent::Success)));
            success_counter.inc();
            v
        })
        .map_err(|err| {
            send_struct_log!(log_cb(logging::safety_log(log_entry, LogEvent::Error))
                .data(LogField::Message.as_str(), &err));
            error_counter.inc();
            err
        });
    let duration = now.duration_since(now).unwrap().as_nanos();
    send_struct_log!(
            logging::ts_log(
                LogEntry::ConsensusState,
                LogEvent::TS)
            .data(LogField::Message.as_str(), duration.to_string().as_str())
    );
    ret
}
