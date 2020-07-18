// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{ConsensusState, Error, safety_rules_sgx_runner, t_safety_rules::TSafetyRules,
    persistent_safety_storage::PersistentSafetyStorage
};
use consensus_types::{
        block::Block, block_data::BlockData, timeout::Timeout, vote::Vote,
        vote_proposal::MaybeSignedVoteProposal,
};
use libra_crypto::ed25519::{Ed25519Signature};
use libra_types::{
    epoch_change::EpochChangeProof,
    sgx_types::{LSR_SGX_ADDRESS, SgxReq, SgxMsg},
};
use std::io::{self, Write};
use std::net::{TcpStream, Shutdown};

pub struct SafetyRulesSGX {
    persistent_storage: PersistentSafetyStorage,
}

impl SafetyRulesSGX {
    fn connect_sgx() -> TcpStream {
        TcpStream::connect(LSR_SGX_ADDRESS).unwrap()
    }

    fn send_req_to_sgx(&self, req: &SgxMsg) -> TcpStream {
        let mut stream = SafetyRulesSGX::connect_sgx();
        stream.write(req.to_bytes().as_ref()).unwrap();
        stream
    }

    fn shutdown_sgx_stream(&self, stream: &mut TcpStream) {
        stream.shutdown(Shutdown::Both).unwrap();
    }

    // Although current impl of LSR persistent storage uniformly returns Ok(()) on
    // any ``set'', we still want some assurance that the command hits the storage by
    // the time we go back to SGX. Hence we return the exact content being written to
    // SGX for SGX to read.
    fn handle_set(&mut self, command: &str, payload: &[u8]) -> Vec<u8> {
        self.persistent_storage.set(command, payload).unwrap();
        let msg = SgxMsg::new(SgxReq::Set, Some(command.into()), payload.to_vec());
        msg.to_bytes()
    }

    fn handle_get(&self, command: &str) -> Vec<u8> {
        self.persistent_storage.get(command)
    }

    fn handle_storage_reqs(&mut self, stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = [0u8; 256];
        stream.set_nonblocking(true).expect("Cannot set nonblocking..Boom");
        loop {
            match stream.peek(&mut buf) {
                Ok(_len) => {
                    let msg = SgxMsg::from_stream(stream);
                    match msg.req() {
                        SgxReq::Get => {
                            let key = msg.key();
                            let payload = self.handle_get(&key);
                            let msg = SgxMsg::new(SgxReq::Get, None, payload);
                            stream.write(msg.to_bytes().as_ref()).unwrap();
                        }
                        SgxReq::Set => {
                            let key = msg.key();
                            let payload = msg.payload();
                            let reply = self.handle_set(&key, &payload);
                            let msg = SgxMsg::new(SgxReq::Set, Some(key), reply);
                            stream.write(msg.to_bytes().as_ref()).unwrap();
                        }
                        SgxReq::Terminate => {
                            println!("storage services finished. about to close.");
                            let payload = msg.payload().to_vec();
                            stream.shutdown(Shutdown::Both)
                                .expect("cannot shutdown stream with SGX...");
                            return payload;
                        }
                        _ => {
                        }
                    }
               }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    //println!("keep waiting....");
                }
                Err(_) => {
                }
            }
        }
    }

    pub fn new(persistent_storage: PersistentSafetyStorage) -> Self {
        // If SGX is already running but we are trying to instantiate a new safety rule instance
        // simple tell SGX to reset its internal states
        if let Ok(mut stream) = TcpStream::connect(LSR_SGX_ADDRESS) {
           let msg= SgxMsg::new(SgxReq::Reset, None, vec![0]);
           stream.write(msg.to_bytes().as_ref()).unwrap();
           stream.shutdown(Shutdown::Write).unwrap();
           println!("The address {} has already been used! LSR-SGX is supposed to be running.",
               LSR_SGX_ADDRESS);
        } else {
            safety_rules_sgx_runner::start_lsr_enclave();
        }
        Self {
            persistent_storage,
        }
    }
}

impl TSafetyRules for SafetyRulesSGX {
    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let msg = SgxMsg::new(SgxReq::Initialize, None, lcs::to_bytes(&proof).unwrap());
        let mut stream = self.send_req_to_sgx(&msg);
        let result = self.handle_storage_reqs(&mut stream);
        self.shutdown_sgx_stream(&mut stream);
        let result: Result<(), Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        let msg = SgxMsg::new(SgxReq::ConsensusState, None, vec![0]);
       let mut stream = self.send_req_to_sgx(&msg);
        let result = self.handle_storage_reqs(&mut stream);
        self.shutdown_sgx_stream(&mut stream);
        let result: Result<ConsensusState, Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn construct_and_sign_vote(&mut self, maybe_signed_vote_proposal: &MaybeSignedVoteProposal) -> Result<Vote, Error> {
        let msg = SgxMsg::new(SgxReq::ConstructAndSignVote, None, lcs::to_bytes(&maybe_signed_vote_proposal).unwrap());
        let mut stream = self.send_req_to_sgx(&msg);
        let result = self.handle_storage_reqs(&mut stream);
        self.shutdown_sgx_stream(&mut stream);
        let result: Result<Vote, Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        let msg= SgxMsg::new(SgxReq::SignProposal, None, lcs::to_bytes(&block_data).unwrap());
        let mut stream = self.send_req_to_sgx(&msg);
        let result = self.handle_storage_reqs(&mut stream);
        self.shutdown_sgx_stream(&mut stream);
        let result: Result<Block, Error>  = lcs::from_bytes(&result).unwrap();
        result
    }

    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        let msg= SgxMsg::new(SgxReq::SignTimeout, None, lcs::to_bytes(timeout).unwrap());
        let mut stream = self.send_req_to_sgx(&msg);
        let result = self.handle_storage_reqs(&mut stream);
        self.shutdown_sgx_stream(&mut stream);
        let result: Result<Ed25519Signature, Error> = lcs::from_bytes(&result).unwrap();
        result
    }
}
