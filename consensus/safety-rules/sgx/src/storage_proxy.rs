use std::net::{TcpStream};
use std::io::prelude::*;
use consensus_types::{
    common::Round,
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
        let mut stream = self.internal.as_ref().unwrap();
        stream.write(key.as_bytes()).unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        let len: i32 = lcs::from_bytes(&buf).unwrap();
        println!("msg len = {}", len);
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        println!("payload = {:#?}", payload);
        payload
    }


    pub fn epoch(&mut self) -> u64 {
        let payload = self.get("get:epoch\n");
        let ret: u64 = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn last_voted_round(&mut self) -> Round {
        let payload = self.get("get:last_voted_round\n");
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }

    pub fn preferred_round(&mut self) -> Round {
        let payload = self.get("get:preferred_round\n");
        let ret: Round = lcs::from_bytes(&payload).unwrap();
        ret
    }
    pub fn waypoint(&mut self) -> Waypoint {
        let payload = self.get("get:waypoint\n");
        let ret: Waypoint = lcs::from_bytes(&payload).unwrap();
        ret
    }
}
