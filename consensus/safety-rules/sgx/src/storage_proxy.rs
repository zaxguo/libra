use std::net::{TcpStream};
use anyhow::Result;
use std::io::prelude::*;
use consensus_types::{
    common::{Round, Author},
    vote::Vote,
};
use libra_types::{
    waypoint::Waypoint,
};

pub struct StorageProxy {
    internal: Option<TcpStream>,
}

impl StorageProxy {
    pub fn new(stream: Option<TcpStream>) -> Self {
        Self {
            internal: stream
        }
    }
    pub fn set_stream(&mut self, stream: TcpStream) {
        self.internal = Some(stream);
    }

    fn get(&self, key: &str) -> Vec<u8> {
        // send out get command
        let prefix: String = "get:".to_owned();
        let cmd = prefix + key;
        let mut stream = self.internal.as_ref().unwrap();
        stream.write(cmd.as_bytes()).unwrap();
        println!("cmd: {}", cmd);

        // read reply, message format:
        // first 4 bytes: payload length (len)
        // following (len) bytes: payload
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        let len: i32 = lcs::from_bytes(&buf).unwrap();
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    fn set(&self, key: &str, payload: &[u8]) {
        // send out set command
        let prefix: String = "set:".to_owned();
        let cmd = prefix + key;
        let mut stream = self.internal.as_ref().unwrap();
        stream.write(cmd.as_bytes()).unwrap();

        // send out payload, message format is the same --
        // first 4 bytes indicate the size of the payload,
        // followed by payload.
        let len = payload.len() as i32;
        let len = lcs::to_bytes(&len).unwrap();
        stream.write(&len).unwrap();
        stream.write(payload).unwrap();

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).unwrap();
        let len: i32 = lcs::from_bytes(&reply).unwrap();
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).unwrap();
    }

    pub fn epoch(&self) -> u64 {
        let payload = self.get("epoch\n");
        let ret: u64 = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn last_voted_round(&self) -> Round {
        let payload = self.get("last_voted_round\n");
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn preferred_round(&self) -> Round {
        let payload = self.get("preferred_round\n");
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }
    pub fn waypoint(&self) -> Waypoint {
        let payload = self.get("waypoint\n");
        let ret: Waypoint = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn author(&self) -> Author {
        let payload = self.get("author\n");
        let ret: Author = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn set_waypoint(&self, waypoint: &Waypoint) -> Result<()> {
        let payload = lcs::to_bytes(waypoint).unwrap();
        self.set("waypoint\n", &payload);
        Ok(())
    }

    pub fn set_last_voted_round(&self, last_voted_round: Round) -> Result<()> {
        let payload = lcs::to_bytes(&last_voted_round).unwrap();
        self.set("last_voted_round\n", &payload);
        Ok(())
    }

    pub fn set_preferred_round(&self, preferred_round: Round) -> Result<()> {
        let payload = lcs::to_bytes(&preferred_round).unwrap();
        self.set("last_voted_round\n", &payload);
        Ok(())
    }

    pub fn set_last_vote(&self, vote: Option<Vote>) -> Result<()> {
        let payload = lcs::to_bytes(&vote.unwrap()).unwrap();
        self.set("last_vote\n", &payload);
        Ok(())
    }

    pub fn set_epoch(&self, epoch: u64) -> Result<()> {
        let payload = lcs::to_bytes(&epoch).unwrap();
        self.set("epoch\n", &payload);
        Ok(())
    }
}
