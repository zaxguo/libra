// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0
use serde::{Serialize, Deserialize};
use std::io::{Read};
use std::net::{TcpStream};
use std::fmt::{Display, Formatter};
use std::str;

// Constants
pub const LSR_SGX_ADDRESS: &str = "localhost:8888";
pub const CONSENSUS_STATE: &str = "req:consensus_state";
pub const INITIALIZE: &str = "req:init";
pub const CONSTRUCT_AND_SIGN_VOTE: &str = "req:construct_and_sign_vote";
pub const SIGN_PROPOSAL: &str = "req:sign_proposal";
pub const SIGN_TIMEOUT: &str = "req:sign_timeout";
pub const RESET: &str = "req:reset";

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum SgxReq {
    // Safety Rules Req
    ConsensusState,
    Initialize,
    ConstructAndSignVote,
    SignProposal,
    SignTimeout,
    Reset,
    // Storage cmds
    Get,
    Set,
    Terminate,
}

#[derive(Serialize,Deserialize)]
pub struct SgxMsg {
    req: SgxReq,
    private: Option<String>,
    payload: Vec<u8>,
}

impl SgxMsg {
    pub fn new(req: SgxReq, private: Option<String>, payload: Vec<u8>) -> Self {
        Self {
            req,
            private,
            payload,
        }
    }

    /// Read one SgxMsg from stream following the msg format
    pub fn from_stream(stream: &mut TcpStream) -> Self {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        let len: i32 = lcs::from_bytes(&buf).unwrap();
        let mut msg = vec![0u8; len as usize];
        stream.read_exact(&mut msg).unwrap();
        let sgx_msg: SgxMsg = lcs::from_bytes(&msg).unwrap();
        sgx_msg
    }

    /// Before sending to/out SGX, the function must be used to
    /// transforms the msg into the correct format:
    /// |len (4B)| SgxMsg (len Bytes)|
    pub fn to_bytes(&self) -> Vec<u8> {
        let msg = lcs::to_bytes(&self).unwrap();
        let len: i32 = msg.len() as i32;
        let mut payload = lcs::to_bytes(&len).unwrap();
        payload.extend(msg);
        payload
    }

    pub fn req(&self) -> SgxReq {
        self.req.clone()
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn key(&self) -> String {
        let key = self.private.as_ref().unwrap();
        key.clone()
    }
}

impl Display for SgxMsg {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f,
                "SgxMsg:{{req = {:?}, key = {:?}, payload = {:?}\n",
                self.req, self.private, self.payload
              )
    }

}
