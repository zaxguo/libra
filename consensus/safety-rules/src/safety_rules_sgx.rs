/* lwg: safetyrule that leverages sgx */

/* from t_safety_rules */
#[allow(dead_code)]
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
};
use std::io::{self, Write, Read, BufReader, BufRead};
use std::net::{TcpStream, Shutdown};
use std::str;

pub struct SafetyRulesSGX {
    persistent_storage: PersistentSafetyStorage,
}

// TODO: move below to a common create used by SGX and untrusted LSR
const CONSENSUS_STATE: &str = "req:consensus_state";
const INITIALIZE: &str = "req:init";
const CONSTRUCT_AND_SIGN_VOTE: &str = "req:construct_and_sign_vote";
const SIGN_PROPOSAL: &str = "req:sign_proposal";
const SIGN_TIMEOUT: &str = "req:sign_timeout";
const RESET: &str = "req:reset";

macro_rules! prepare_req {
    ($req: expr) => {{
        let mut msg: Vec<u8> = $req.as_bytes().iter().cloned().collect();
        msg.extend("\n".as_bytes());
        msg
    }};
    ($req: expr, $payload: expr) => {{
        let mut msg: Vec<u8> = $req.as_bytes().iter().cloned().collect();
        msg.extend("\n".as_bytes());
        msg.extend(lcs::to_bytes($payload).unwrap());
        msg
    }};
}

impl SafetyRulesSGX {

    fn connect_sgx(&self) -> TcpStream {
        TcpStream::connect(safety_rules_sgx_runner::LSR_SGX_ADDRESS).unwrap()
    }

    fn prepare_storage_reply(&self, reply: Vec<u8>) -> Vec<u8> {
        let len: i32 = reply.len() as i32;
        let mut msg = lcs::to_bytes(&len).unwrap();
        msg.extend(reply);
        msg
    }

    fn get_sgx_payload(&self, stream: &mut BufReader<TcpStream>) -> Vec<u8> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        let len: i32 = lcs::from_bytes(&buf).unwrap();
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    // Although current impl of LSR persistent storage uniformly returns Ok(()) on
    // any ``set'', we still want some assurance that the command hits the storage by
    // the time we go back to SGX. Hence we return the exact content being written to
    // SGX.
    fn handle_set(&mut self, command: &str, payload: &[u8]) -> Vec<u8> {
        let key: Vec<&str> = command.split(":").collect();
        self.persistent_storage.set(key.last().unwrap(), payload).unwrap();
        payload.to_vec()
    }

    fn handle_get(&self, command: &str) -> Vec<u8> {
        let key: Vec<&str> = command.split(":").collect();
        self.persistent_storage.get(key.last().unwrap())
    }

    fn handle_storage_reqs(&mut self, mut stream: TcpStream) -> Vec<u8> {
        let mut buf = [0u8; 256];
        stream.set_nonblocking(true).expect("Cannot set nonblocking..Boom");
        loop {
            match stream.peek(&mut buf) {
                Ok(len) => {
                    let mut req = String::new();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    // read the command, consume the bytes
                    reader.read_line(&mut req).unwrap();
                    let req = req.as_str().trim();
                    if len == 0 {
                        continue;
                    }
                    if req == "done" {
                        println!("storage services finished. about to close.");
                        let payload = self.get_sgx_payload(&mut reader);
                        stream.shutdown(Shutdown::Both)
                            .expect("cannot shutdown stream with SGX...");
                        return payload;
                    } else if req.contains("get") {
                        let reply = self.handle_get(req);
                        let reply = self.prepare_storage_reply(reply);
                        stream.write(&reply).unwrap();
                    } else if req.contains("set") {
                        let payload = self.get_sgx_payload(&mut reader);
                        let reply = self.handle_set(req, &payload);
                        let reply = self.prepare_storage_reply(reply);
                        stream.write(&reply).unwrap();
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
        if let Ok(mut stream) = TcpStream::connect(safety_rules_sgx_runner::LSR_SGX_ADDRESS) {
           let req = prepare_req!(RESET);
           stream.write(req.as_ref()).unwrap();
           stream.shutdown(Shutdown::Write).unwrap();
           println!("The address {} has already been used! LSR-SGX is supposed to be running.",
               safety_rules_sgx_runner::LSR_SGX_ADDRESS);
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
        let msg = prepare_req!(INITIALIZE, proof);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<(), Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        let msg = prepare_req!(CONSENSUS_STATE);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<ConsensusState, Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn construct_and_sign_vote(&mut self, maybe_signed_vote_proposal: &MaybeSignedVoteProposal) -> Result<Vote, Error> {
        let msg = prepare_req!(CONSTRUCT_AND_SIGN_VOTE, maybe_signed_vote_proposal);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<Vote, Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        let msg = prepare_req!(SIGN_PROPOSAL, &block_data);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<Block, Error>  = lcs::from_bytes(&result).unwrap();
        result
    }

    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        let msg = prepare_req!(SIGN_TIMEOUT, timeout);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<Ed25519Signature, Error> = lcs::from_bytes(&result).unwrap();
        result
    }
}


