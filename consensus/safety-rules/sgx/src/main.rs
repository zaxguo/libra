use std::io::{BufRead, BufReader, Write, ErrorKind, Result, Error};
use std::net::{TcpStream, TcpListener, Shutdown};
use libra_types::{validator_signer::ValidatorSigner, epoch_change::EpochChangeProof};
use consensus_types::{
    block_data::BlockData,
    vote::Vote,
    vote_data::VoteData,
    vote_proposal::{MaybeSignedVoteProposal, VoteProposal},
    timeout::Timeout,
};

use crate::{
    safety_rules::SafetyRules,
    t_safety_rules::TSafetyRules,
};

#[macro_use]
mod safety_rules;

mod consensus_state;
mod storage_proxy;
mod error;
mod t_safety_rules;

pub const LSR_SGX_ADDRESS: &str = "localhost:8888";

#[allow(dead_code)]
fn respond(payload: &[u8], mut stream: TcpStream) {
    let len = payload.len() as i32;
    stream.write(&lcs::to_bytes(&len).unwrap()).unwrap();
    stream.write(payload).unwrap();
}

#[allow(dead_code)]
fn test_mem_alloc() {
    let mut mem = Vec::new();
    let mut counter = 0;
    loop {
        mem.push(0u8);
        counter += 1;
        // This crashed at 65536, meaning 64KB is allowed. Crap
        println!("Pushing {}", counter);
    }
}

fn process_safety_rules_reqs(lsr: &mut SafetyRules, mut stream: TcpStream) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    sgx_print!(
        "accept meesage from local {:?}, peer {:?}, stream = {:?}",
        local_addr, peer_addr, stream
    );
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    let _read_bytes = reader.read_line(&mut request).unwrap();
    let buf = reader.buffer();
    let ret;
    match request.as_str().trim() {
        "req:init" => {
            // fill the read of buf
            let input: EpochChangeProof = lcs::from_bytes(buf).unwrap();
            let result = lsr.initialize(&input);
            let response = lcs::to_bytes(&result).unwrap();
            ret = response;
        }
        "req:consensus_state" => {
            let consensus_state = lsr.consensus_state();
            let response = lcs::to_bytes(&consensus_state).unwrap();
            sgx_print!("consensus_state:  {:#?}", consensus_state);
            ret = response;
        }
        "req:construct_and_sign_vote" => {
            sgx_print!("buf size = {}", buf.len());
            let input: MaybeSignedVoteProposal = lcs::from_bytes(buf).unwrap();
            sgx_print!();
            let vote = lsr.construct_and_sign_vote(&input);
            let response = lcs::to_bytes(&vote).unwrap();
            sgx_print!("construct_and_sign_vote:  {:#?}", vote);
            ret = response;
        }
        "req:sign_proposal" => {
            let input: BlockData = lcs::from_bytes(buf).unwrap();
            let proposal = lsr.sign_proposal(input);
            let response = lcs::to_bytes(&proposal).unwrap();
            sgx_print!("sign_proposal:  {:#?}", proposal);
            ret = response;
        }
        "req:sign_timeout" => {
            let input: Timeout = lcs::from_bytes(buf).unwrap();
            let timeout = lsr.sign_timeout(&input);
            let response = lcs::to_bytes(&timeout).unwrap();
            sgx_print!("sign_timeout:  {:#?}", timeout);
            ret = response;
        }
        _ => {
            sgx_print!("invalid req...{}", request);
            ret = vec![0u8;4];
        }
    }

    let len = ret.len() as i32;
    let mut payload = lcs::to_bytes(&len).unwrap();
    payload.extend(ret);
    let mut ret: Vec<u8> = "done\n".as_bytes().to_vec();
    ret.extend(payload);
    stream.write(&ret).unwrap();
    Ok(())
}

fn main() -> Result<()> {
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
