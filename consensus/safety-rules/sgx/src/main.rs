use std::io::{BufRead, BufReader, Write, Result};
use std::net::{TcpStream, TcpListener, Shutdown};
use libra_types::{epoch_change::EpochChangeProof};
use consensus_types::{
    block_data::BlockData,
    vote_proposal::{MaybeSignedVoteProposal},
    timeout::Timeout,
};

use crate::{
    safety_rules::SafetyRules,
    t_safety_rules::*,
};

#[macro_use]
mod safety_rules;

mod consensus_state;
mod storage_proxy;
mod error;
mod t_safety_rules;
mod seal;

pub const LSR_SGX_ADDRESS: &str = "localhost:8888";

#[allow(dead_code)]
fn test_mem_alloc() {
    let mut mem = Vec::new();
    loop {
        mem.push(0u8);
        // This crashed at 65536, meaning 64KB is allowed. Crap
        println!("Pushing {}", mem.len());
    }
}

fn prepare_safety_rules_result(ret: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = "done\n".as_bytes().to_vec();
    let len = ret.len() as i32;
    let mut payload = lcs::to_bytes(&len).unwrap();
    payload.extend(ret.to_vec());
    result.extend(payload);
    result
}

fn process_safety_rules_reqs(lsr: &mut SafetyRules, mut stream: TcpStream) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    sgx_print!(
        "receiving LSR reqs from {:?}, stream = {:?}",
        peer_addr, stream
    );
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    let _read_bytes = reader.read_line(&mut request).unwrap();
    let buf = reader.buffer();
    let ret;
    match request.as_str().trim() {
        // TSafetyRules
        INITIALIZE => {
            // fill the read of buf
            let input: EpochChangeProof = lcs::from_bytes(buf).unwrap();
            let result = lsr.initialize(&input);
            let response = lcs::to_bytes(&result).unwrap();
            ret = response;
        }
        CONSENSUS_STATE => {
            let consensus_state = lsr.consensus_state();
            let response = lcs::to_bytes(&consensus_state).unwrap();
            ret = response;
        }
        CONSTRUCT_AND_SIGN_VOTE => {
            let input: MaybeSignedVoteProposal = lcs::from_bytes(buf).unwrap();
            let vote = lsr.construct_and_sign_vote(&input);
            let response = lcs::to_bytes(&vote).unwrap();
            ret = response;
        }
        SIGN_PROPOSAL => {
            let input: BlockData = lcs::from_bytes(buf).unwrap();
            let proposal = lsr.sign_proposal(input);
            let response = lcs::to_bytes(&proposal).unwrap();
            ret = response;
        }
        SIGN_TIMEOUT => {
            let input: Timeout = lcs::from_bytes(buf).unwrap();
            let timeout = lsr.sign_timeout(&input);
            let response = lcs::to_bytes(&timeout).unwrap();
            ret = response;
        }
        RESET => {
            lsr.reset();
            ret = vec![0u8;4]
        }
        _ => {
            sgx_print!("invalid req...{}", request);
            ret = vec![0u8;4];
        }
    }
    let result = prepare_safety_rules_result(&ret);
    stream.write(&result).unwrap();
    Ok(())
}

fn main() -> Result<()> {
    //test_mem_alloc();
    let mut safety_rules = SafetyRules::new();
    let listener = TcpListener::bind(LSR_SGX_ADDRESS)?;
    sgx_print!(" listening to {}...ready to accept LSR requests...", LSR_SGX_ADDRESS);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                safety_rules.set_storage_proxy(stream.try_clone().unwrap());
                process_safety_rules_reqs(&mut safety_rules, stream.try_clone().unwrap())?;
                stream.shutdown(Shutdown::Both).expect("Shutdown failed..");
            }
            Err(_) => {
                sgx_print!("unable to connect...");
            }
        }
    }
    sgx_print!(
        "Wohoo! LSR_CORE about to terminate",
    );
    Ok(())
}
