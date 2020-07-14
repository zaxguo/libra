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
use libra_crypto::ed25519::Ed25519Signature;
use libra_types::{
    epoch_change::EpochChangeProof,
    waypoint::Waypoint
};
use std::io::{self, Write, Read, BufReader, BufRead};
use std::net::{TcpStream, Shutdown};
use std::str;
use serde::{Serialize, Deserialize};

pub struct SafetyRulesSGX {
    persistent_storage: PersistentSafetyStorage,
}

// TODO: move this to a separate package for SGX to use as well
#[derive(Serialize, Deserialize)]
struct StorageCommand {
    // only get and set
    command: u8,
    // payload size
    size: u64,
    // payload bytestream
    payload: Vec<u8>,
}

macro_rules! prepare_msg {
    ($req: expr, $arg: expr) => {{
        let mut msg:Vec<u8> = $req.as_bytes().iter().cloned().collect();
        msg.extend(lcs::to_bytes($arg).unwrap());
        msg
    }}
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
        match command {
            "set:waypoint" => {
                let waypoint: Waypoint = lcs::from_bytes(payload).unwrap();
                self.persistent_storage.set_waypoint(&waypoint).unwrap();
                lcs::to_bytes(&waypoint).unwrap()
            }
            _ => {
                Vec::new()
            }
        }
    }

    fn handle_get(&self, command: &str) -> Vec<u8> {
        match command {
            "get:epoch" => {
                let epoch = self.persistent_storage.epoch().unwrap();
                println!("epoch = {}", epoch);
                lcs::to_bytes(&epoch).unwrap()
            }
            "get:preferred_round" => {
                let round = self.persistent_storage.preferred_round().unwrap();
                println!("preferred round = {}", round);
                lcs::to_bytes(&round).unwrap()
            }
            "get:last_voted_round" => {
                let round = self.persistent_storage.last_voted_round().unwrap();
                println!("last round = {}", round);
                lcs::to_bytes(&round).unwrap()
            }
            "get:waypoint" => {
               let waypoint = self.persistent_storage.waypoint().unwrap();
               println!("waypoint = {}", waypoint);
               lcs::to_bytes(&waypoint).unwrap()
            }
            "get:author" => {
                let author = self.persistent_storage.author().unwrap();
                println!("author = {}", author);
                lcs::to_bytes(&author).unwrap()
            }
            _ => {
               println!("I am not supposed to be here :(");
               Vec::new()
            }
        }
    }

    fn handle_storage_reqs(&mut self, mut stream: TcpStream) -> Vec<u8> {
        let mut buf = [0u8; 256];
        println!("waiting for storage reqs...local_addr = {:?}, peer_addr = {:?}",
            stream.local_addr(),
            stream.peer_addr());
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
                        return payload;
                    } else if req.contains("get") {
                        // handle storage command (i.e. ocall)
                        println!("requested get services: {}", req);
                        let reply = self.handle_get(req);
                        let reply = self.prepare_storage_reply(reply);
                        //println!("reply = {:#?}", reply);
                        stream.write(&reply).unwrap();
                    } else if req.contains("set") {
                        println!("requested set services: {}", req);
                        //let payload = self.get_sgx_payload(stream.try_clone().unwrap());
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
        if let Ok(mut stream) = TcpStream::connect(safety_rules_sgx_runner::LSR_SGX_ADDRESS) {
           stream.write("hello...".as_bytes()).unwrap();
           stream.shutdown(Shutdown::Write).unwrap();
        } else {
            safety_rules_sgx_runner::start_lsr_enclave();
        }
        Self { persistent_storage }
    }
}

impl TSafetyRules for SafetyRulesSGX {

    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let msg = prepare_msg!("req:init\n", proof);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        self.handle_storage_reqs(stream.try_clone().unwrap());
        Ok(())
    }

    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        let msg: Vec<u8> = "req:consensus_state\n".as_bytes().iter().cloned().collect();
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<ConsensusState, Error> = lcs::from_bytes(&result).unwrap();
        result
    }

    fn construct_and_sign_vote(&mut self, maybe_signed_vote_proposal: &MaybeSignedVoteProposal) -> Result<Vote, Error> {
        let msg = prepare_msg!("req:construct_and_sign_vote\n", maybe_signed_vote_proposal);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        self.handle_storage_reqs(stream.try_clone().unwrap());
        Err(Error::NotInitialized("Unimplemented".into()))
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        let msg = prepare_msg!("req:sign_proposal\n", &block_data);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<Block, Error>  = lcs::from_bytes(&result).unwrap();
        result
    }

    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        let msg = prepare_msg!("req:sign_timeout\n", timeout);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        self.handle_storage_reqs(stream.try_clone().unwrap());
        Err(Error::NotInitialized("Unimplemented".into()))
    }
}


