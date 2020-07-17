/* lwg: safetyrule that leverages sgx */

/* from t_safety_rules */
#[allow(dead_code)]
use crate::{ConsensusState, Error, safety_rules_sgx_runner, t_safety_rules::TSafetyRules,
    persistent_safety_storage::PersistentSafetyStorage
};
use consensus_types::{
        block::Block, block_data::BlockData, timeout::Timeout, vote::Vote,
        vote_proposal::MaybeSignedVoteProposal, common::Round,
};
use libra_crypto::ed25519::{Ed25519Signature, Ed25519PublicKey};
use libra_types::{
    epoch_change::EpochChangeProof,
    waypoint::Waypoint
};
use std::io::{self, Write, Read, BufReader, BufRead};
use std::net::{TcpStream, Shutdown};
use std::str;
use serde::{Serialize, Deserialize};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, NewAead, generic_array::GenericArray},
};

pub struct SafetyRulesSGX {
    persistent_storage: PersistentSafetyStorage,
    cipher: Aes256Gcm,
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

    // This is the shared secret we assumed between SGX and storage, which is
    // needed for intializing the storage with ENCRYPTED data in the first place
    fn generate_cipher_for_testing() -> Aes256Gcm {
        let key = GenericArray::from_slice(&[0u8; 32]);
        Aes256Gcm::new(key)
    }

    #[allow(dead_code)]
    fn test_cipher(&self, payload: &[u8]) {
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let ciphertext = self.cipher.encrypt(nonce, payload).unwrap();
        let plaintext = self.cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        println!("orig: len = {}, data = {:?}", payload.len(), payload);
        println!("cipher text: len = {}, data = {:?}", ciphertext.len(), ciphertext);
        println!("plain text: len = {}, data = {:?}", plaintext.len(), plaintext);
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
                self.persistent_storage.set_waypoint_bytes(payload.to_vec()).unwrap();
                payload.to_vec()
            }
            "set:last_voted_round" => {
                self.persistent_storage.set_last_voted_round_bytes(payload.to_vec()).unwrap();
                payload.to_vec()
            }
            "set:preferred_round" => {
                self.persistent_storage.set_preferred_round_bytes(payload.to_vec()).unwrap();
                payload.to_vec()
            }
            "set:last_vote" => {
                self.persistent_storage.set_last_vote_bytes(payload.to_vec()).unwrap();
                payload.to_vec()
            }
            "set:epoch" => {
                self.persistent_storage.set_epoch_bytes(payload.to_vec()).unwrap();
                payload.to_vec()
            }
            _ => {
                println!("LSR: unrecognized set command! [{}]", command);
                Vec::new()
            }
        }
    }

    fn handle_get(&self, command: &str) -> Vec<u8> {
        match command {
            "get:epoch" => {
                self.persistent_storage.epoch_bytes().unwrap()
            }
            "get:preferred_round" => {
                self.persistent_storage.preferred_round_bytes().unwrap()
            }
            "get:last_voted_round" => {
                self.persistent_storage.last_voted_round_bytes().unwrap()
            }
            "get:waypoint" => {
               self.persistent_storage.waypoint_bytes().unwrap()
            }
            "get:author" => {
               self.persistent_storage.author_bytes().unwrap()
            }
            "get:last_vote" => {
               self.persistent_storage.last_vote_bytes().unwrap()
            }
            "get:curr_consensus_key" => {
                self.persistent_storage.curr_consensus_key_bytes().unwrap()
            }
            "get:prev_consensus_key" => {
                self.persistent_storage.prev_consensus_key_bytes()
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
                        stream.shutdown(Shutdown::Both).expect("cannot shutdown stream with SGX...");
                        return payload;
                    } else if req.contains("get") {
                        // handle storage command (i.e. ocall)
                        println!("requested get services: {}", req);
                        let reply = self.handle_get(req);
                        let reply = self.prepare_storage_reply(reply);
                        println!("reply = {:?}", reply);
                        stream.write(&reply).unwrap();
                    } else if req.contains("set") {
                        println!("requested set services: {}", req);
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
        // SGX is already running but we are trying to instantiate a new safety rule instance
        // Tell SGX to reset its internal states
        if let Ok(mut stream) = TcpStream::connect(safety_rules_sgx_runner::LSR_SGX_ADDRESS) {
           stream.write("req:reset\n".as_bytes()).unwrap();
           stream.shutdown(Shutdown::Write).unwrap();
           println!("The address {} has already been used! LSR-SGX is supposed to be running.",
               safety_rules_sgx_runner::LSR_SGX_ADDRESS);
        } else {
            safety_rules_sgx_runner::start_lsr_enclave();
        }
        Self {
            persistent_storage,
            cipher: Self::generate_cipher_for_testing(),
        }
    }
}

impl TSafetyRules for SafetyRulesSGX {

    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let msg = prepare_msg!("req:init\n", proof);
        let mut stream = self.connect_sgx();
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<(), Error> = lcs::from_bytes(&result).unwrap();
        result
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
        println!("----- sending {} bytes...", msg.len());
        stream.write(msg.as_ref()).unwrap();
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<Vote, Error> = lcs::from_bytes(&result).unwrap();
        result
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
        let result = self.handle_storage_reqs(stream.try_clone().unwrap());
        let result: Result<Ed25519Signature, Error> = lcs::from_bytes(&result).unwrap();
        result
    }
}


