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
use libra_types::epoch_change::EpochChangeProof;
use std::io::{self, Write, Read, BufReader, BufRead};
use std::net::{TcpStream, Shutdown};
use std::str;
use serde::{Serialize, Deserialize};

pub struct SafetyRulesSGX {
    stream: TcpStream,
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

    fn handle_storage_command(&self, command: &str) -> Vec<u8> {
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
            _ => {
               println!("I am not supposed to be here :(");
               Vec::new()
            }
        }
    }

    fn handle_storage_reqs(&self, mut stream: TcpStream) {
        let mut buf = [0u8; 256];
        println!("waiting for storage reqs...local_addr = {:?}, peer_addr = {:?}",
            stream.local_addr(),
            stream.peer_addr());
        stream.set_nonblocking(true).expect("Cannot set nonblocking..Boom");
        loop {
            match stream.peek(&mut buf) {
                Ok(len) => {
                    // consume the bytes
                    let mut req = String::new();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let _reply = reader.read_line(&mut req).unwrap();
                    let req = req.as_str().trim();
                    if len == 0 {
                        continue;
                    }
                    if req == "done" {
                        println!("storage services finished. about to close.");
                        break;
                    } else {
                        // handle storage command (i.e. ocall)
                        // TODO: separate get and set
                        println!("requested storage services: {}", req);
                        let reply = self.handle_storage_command(req);
                        let reply = self.prepare_storage_reply(reply);
                        println!("reply = {:#?}", reply);
                        // reply.extend("\n".as_bytes());
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
        safety_rules_sgx_runner::start_lsr_enclave();
        let mut stream = TcpStream::connect(safety_rules_sgx_runner::LSR_SGX_ADDRESS).unwrap();
        stream.write("hello...".as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        Self { stream, persistent_storage }
    }
}

impl TSafetyRules for SafetyRulesSGX {

    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let msg = prepare_msg!("req:init\n", proof);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        //self.send(msg.as_ref());
        Ok(())
    }

    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        let msg: Vec<u8> = "req:consensus_state\n".as_bytes().iter().cloned().collect();
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        self.handle_storage_reqs(stream.try_clone().unwrap());
        Err(Error::NotInitialized("Unimplemented".into()))
    }

    fn construct_and_sign_vote(&mut self, maybe_signed_vote_proposal: &MaybeSignedVoteProposal) -> Result<Vote, Error> {
        let msg = prepare_msg!("req:construct_and_sign_vote\n", maybe_signed_vote_proposal);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        Err(Error::NotInitialized("Unimplemented".into()))
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        let msg = prepare_msg!("req:sign_proposal\n", &block_data);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        Err(Error::NotInitialized("Unimplemented".into()))
    }

    fn sign_timeout(&mut self, timeout: &Timeout) -> Result<Ed25519Signature, Error> {
        let msg = prepare_msg!("req:sign_timeout\n", timeout);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        Err(Error::NotInitialized("Unimplemented".into()))
    }
}


