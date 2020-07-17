use std::net::{TcpStream};
use anyhow::Result;
use std::io::prelude::*;
use consensus_types::{
    common::{Round, Author},
    vote::Vote,
};
use libra_crypto::{
    ed25519::{Ed25519PublicKey, Ed25519PrivateKey},
    PrivateKey,
};
use libra_global_constants::{
    CONSENSUS_KEY, EPOCH, LAST_VOTE, LAST_VOTED_ROUND,
    OPERATOR_ACCOUNT, PREFERRED_ROUND, WAYPOINT,
};
use libra_types::{
    waypoint::Waypoint,
};
use std::str::FromStr;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, NewAead, generic_array::GenericArray},
};

pub struct StorageProxy {
    internal: Option<TcpStream>,
    cipher: Aes256Gcm,
}

impl StorageProxy {
    pub fn new(stream: Option<TcpStream>) -> Self {
        Self {
            internal: stream,
            cipher: Self::generate_cipher_for_testing(),
        }
    }
    pub fn set_stream(&mut self, stream: TcpStream) {
        self.internal = Some(stream);
    }

     fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        let nonce = GenericArray::from_slice(&[0u8;12]);
        self.cipher.encrypt(nonce, payload).unwrap()
    }

    fn decrypt(&self, payload: &[u8]) -> Vec<u8> {
        let nonce =  GenericArray::from_slice(&[0u8;12]);
        // Decryption fail due to persistent storage cannot provide
        // valid encrypted bytes, which can be trying to get the data
        // of non-existing keys
        match self.cipher.decrypt(nonce, payload) {
            Ok(value) => value,
            Err(_) => Vec::new(),
        }
     }

    fn generate_cipher_for_testing() -> Aes256Gcm {
        // 256 bit
        let key = GenericArray::from_slice(&[0u8; 32]);
        Aes256Gcm::new(key)
    }

    fn get(&self, key: &str) -> Vec<u8> {
        // send out get command
        let prefix: String = "get:".to_owned();
        let cmd = prefix + key;
        let cmd = cmd + "\n".into();
        let mut stream = self.internal.as_ref().unwrap();
        stream.write(cmd.as_bytes()).unwrap();

        // read reply, message format:
        // first 4 bytes: payload length (len)
        // following (len) bytes: payload
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        let len: i32 = lcs::from_bytes(&buf).unwrap();
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        // decrypt the payload
        let result = self.decrypt(payload.as_ref());
        result
    }

    fn set(&self, key: &str, payload: &[u8]) {
        let prefix: String = "set:".to_owned();
        let cmd = prefix + key;
        let cmd = cmd + "\n".into();
        let mut stream = self.internal.as_ref().unwrap();

        // send out payload in one-shot. Message format is the same --
        // Stringified command (ending w/ \n) + len (i32) + payload
        let mut cmd = cmd.as_bytes().to_vec();
        let e_payload = self.encrypt(payload);
        let len = e_payload.len() as i32;
        let len = lcs::to_bytes(&len).unwrap();
        cmd.extend(len);
        cmd.extend(e_payload);
        stream.write(&cmd).unwrap();

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).unwrap();
        let len: i32 = lcs::from_bytes(&reply).unwrap();
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).unwrap();
    }

    pub fn epoch(&self) -> u64 {
        let payload = self.get(EPOCH);
        let ret: u64 = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn last_voted_round(&self) -> Round {
        let payload = self.get(LAST_VOTED_ROUND);
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn last_vote(&self) -> Option<Vote> {
        let payload = self.get(LAST_VOTE);
        let ret: Option<Vote> = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn preferred_round(&self) -> Round {
        let payload = self.get(PREFERRED_ROUND);
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }
    pub fn waypoint(&self) -> Waypoint {
        let payload = self.get(WAYPOINT);
        let waypoint = String::from_utf8(payload).unwrap();
        let ret: Waypoint = Waypoint::from_str(&waypoint).unwrap();
        ret
    }

    pub fn author(&self) -> Author {
        // decrypted Vec<u8> => Str
        let payload = self.get(OPERATOR_ACCOUNT);
        let payload = String::from_utf8(payload).unwrap();
        std::str::FromStr::from_str(&payload).unwrap()
    }

    pub fn set_waypoint(&self, waypoint: &Waypoint) -> Result<()> {
        let payload = lcs::to_bytes(waypoint).unwrap();
        self.set(WAYPOINT, &payload);
        Ok(())
    }

    pub fn set_last_voted_round(&self, last_voted_round: Round) -> Result<()> {
        let payload = lcs::to_bytes(&last_voted_round).unwrap();
        self.set(LAST_VOTED_ROUND, &payload);
        Ok(())
    }

    pub fn set_preferred_round(&self, preferred_round: Round) -> Result<()> {
        let payload = lcs::to_bytes(&preferred_round).unwrap();
        self.set(PREFERRED_ROUND, &payload);
        Ok(())
    }

    pub fn set_last_vote(&self, vote: Option<Vote>) -> Result<()> {
        let payload = lcs::to_bytes(&vote).unwrap();
        self.set(LAST_VOTE, &payload);
        Ok(())
    }

    pub fn set_epoch(&self, epoch: u64) -> Result<()> {
        let payload = lcs::to_bytes(&epoch).unwrap();
        self.set(EPOCH, &payload);
        Ok(())
    }

    // Rewritten to fit get/set semantics
    pub fn consensus_key_for_version(
        &self,
        version: Ed25519PublicKey,
        ) -> Option<Ed25519PrivateKey> {

        let payload = self.get(CONSENSUS_KEY);
        let curr_key = lcs::from_bytes::<Ed25519PrivateKey>(&payload);
        match curr_key {
            Ok(curr_key) => {
                if curr_key.public_key().eq(&version) {
                    return Some(curr_key);
                }
            }
            Err(_) => {
                return None;
            }
        }
        // note this is hard coded
        let payload = self.get("consensus_previous");
        let prev_key = lcs::from_bytes::<Ed25519PrivateKey>(&payload);
        match prev_key {
            Ok(prev_key) => {
                if prev_key.public_key().eq(&version) {
                    Some(prev_key)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
 }
