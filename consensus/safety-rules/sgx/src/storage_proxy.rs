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

    fn get(&mut self, key: &str) -> Vec<u8> {
        let prefix: String = "get:".to_owned();
        let cmd = prefix + key;
        let mut stream = self.internal.as_ref().unwrap();
        stream.write(cmd.as_bytes()).unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        let len: i32 = lcs::from_bytes(&buf).unwrap();
        println!("msg len = {}", len);
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        println!("payload = {:#?}", payload);
        payload
    }

    fn set(&mut self, key: &str, payload: &[u8]) {
        let prefix: String = "set:".to_owned();
        let cmd = prefix + key;
        let mut stream = self.internal.as_ref().unwrap();
        stream.write(cmd.as_bytes()).unwrap();

        let len = payload.len() as i32;
        let len = lcs::to_bytes(&len).unwrap();
        stream.write(&len).unwrap();
        println!("msg len = {}", payload.len());

        stream.write(payload).unwrap();
    }


    pub fn epoch(&mut self) -> u64 {
        let payload = self.get("epoch\n");
        let ret: u64 = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn last_voted_round(&mut self) -> Round {
        let payload = self.get("last_voted_round\n");
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn preferred_round(&mut self) -> Round {
        let payload = self.get("preferred_round\n");
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }
    pub fn waypoint(&mut self) -> Waypoint {
        let payload = self.get("waypoint\n");
        let ret: Waypoint = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn author(&self) -> Author {
        Author::random()
    }

    pub fn set_waypoint(&mut self, waypoint: &Waypoint) -> Result<()> {
        let payload = lcs::to_bytes(waypoint).unwrap();
        self.set("waypoint\n", &payload);
        Ok(())
    }

    pub fn set_last_voted_round(&mut self, last_voteed_round: Round) -> Result<()> {
        Ok(())
    }

    pub fn set_preferred_round(&mut self, preferred_round: Round) -> Result<()> {
        Ok(())
    }

    pub fn set_last_vote(&mut self, vote: Option<Vote>) -> Result<()> {
        Ok(())
    }

    pub fn set_epoch(&mut self, epoch: u64) -> Result<()> {
        Ok(())
    }
}
