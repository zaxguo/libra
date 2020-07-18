// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::io::{Write, Result};
use std::net::{TcpListener};
use libra_types::{
    epoch_change::EpochChangeProof,
    sgx_types::{
        LSR_SGX_ADDRESS,
        SgxMsg,
        SgxReq,
    },
};
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
    let msg = SgxMsg::new(SgxReq::Terminate, None, ret.to_vec());
    msg.to_bytes()
}

fn process_safety_rules_reqs(lsr: &mut SafetyRules) -> Result<()> {
    let mut stream = lsr.get_storage_proxy();
    let peer_addr = stream.peer_addr()?;
    sgx_print!(
        "receiving LSR reqs from {:?}, stream = {:?}",
        peer_addr, stream
    );
    let msg = SgxMsg::from_stream(&mut stream);
    let payload = msg.payload();
    let ret;
    match msg.req() {
        // TSafetyRules
        SgxReq::Initialize => {
            let input: EpochChangeProof = lcs::from_bytes(payload).unwrap();
            let result = lsr.initialize(&input);
            let response = lcs::to_bytes(&result).unwrap();
            ret = response;
        }
        SgxReq::ConsensusState => {
            let consensus_state = lsr.consensus_state();
            let response = lcs::to_bytes(&consensus_state).unwrap();
            ret = response;
        }
        SgxReq::ConstructAndSignVote => {
            let input: MaybeSignedVoteProposal = lcs::from_bytes(payload).unwrap();
            let vote = lsr.construct_and_sign_vote(&input);
            let response = lcs::to_bytes(&vote).unwrap();
            ret = response;
        }
        SgxReq::SignProposal => {
            let input: BlockData = lcs::from_bytes(payload).unwrap();
            let proposal = lsr.sign_proposal(input);
            let response = lcs::to_bytes(&proposal).unwrap();
            ret = response;
        }
        SgxReq::SignTimeout => {
            let input: Timeout = lcs::from_bytes(payload).unwrap();
            let timeout = lsr.sign_timeout(&input);
            let response = lcs::to_bytes(&timeout).unwrap();
            ret = response;
        }
        SgxReq::Reset => {
            lsr.reset();
            ret = vec![0u8;4]
        }
        _ => {
            sgx_print!("invalid req...");
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
                let stream = stream.try_clone().unwrap();
                safety_rules.set_storage_proxy(stream);
                process_safety_rules_reqs(&mut safety_rules)?;
                safety_rules.clear_storage_proxy();
            }
            Err(_) => {
                sgx_print!("unable to connect...");
            }
        }
    }
    sgx_print!(
        "Wohoo! LSR_SGX about to terminate",
    );
    Ok(())
}
