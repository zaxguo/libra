use std::io::{BufRead, BufReader, Write, ErrorKind, Result, Error};
use std::net::{TcpStream, TcpListener};
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
mod safety_rules;
mod consensus_state;
mod storage_proxy;
mod error;
mod t_safety_rules;

pub const LSR_SGX_ADDRESS: &str = "localhost:8888";

fn respond(payload: &[u8], mut stream: TcpStream) {
    let len = payload.len() as i32;
    stream.write(&lcs::to_bytes(&len).unwrap()).unwrap();
    stream.write(payload).unwrap();
}

fn process_safety_rules_reqs(lsr: &mut SafetyRules, mut stream: TcpStream) -> Result<()> {
    eprintln!("LSR_CORE: received a new incoming req...");
    let peer_addr = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    eprintln!(
        "LSR_CORE: accept meesage from local {:?}, peer {:?}, stream = {:?}",
        local_addr, peer_addr, stream
    );
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    let _read_bytes = reader.read_line(&mut request).unwrap();
    // fill the read of buf
    //let buf = reader.fill_buf().unwrap();
    let buf = reader.buffer();
    let ret;
    match request.as_str().trim() {
        "req:init" => {
            // fill the read of buf
            let input: EpochChangeProof = lcs::from_bytes(buf).unwrap();
            lsr.initialize(&input).unwrap();
            ret = vec![0u8;4];
        }
        "req:consensus_state" => {
            let consensus_state = lsr.consensus_state();
            let response = lcs::to_bytes(&consensus_state).unwrap();
            eprintln!("consensus_state:  {:#?}", consensus_state);
            ret = response;
        }
        "req:construct_and_sign_vote" => {
            let input: MaybeSignedVoteProposal = lcs::from_bytes(buf).unwrap();
            eprintln!("{} -- {}", request, input.vote_proposal);
            ret = vec![0u8;4];
        }
        "req:sign_proposal" => {
            let input: BlockData = lcs::from_bytes(buf).unwrap();
            let proposal = lsr.sign_proposal(input);
            let response = lcs::to_bytes(&proposal).unwrap();
            eprintln!("sign_proposal:  {:#?}", proposal);
            //eprintln!("reply:  {:#?}", response);
            ret = response;
        }
        "req:sign_timeout" => {
            let input: Timeout = lcs::from_bytes(buf).unwrap();
            eprintln!("{} -- {:#?}", request, input);
            ret = vec![0u8;4];
        }
        _ => {
            eprintln!("invalid req...{}", request);
            ret = vec![0u8;4];
        }
    }

    let len = ret.len() as i32;
    let mut payload = lcs::to_bytes(&len).unwrap();
    payload.extend(ret);
    let mut ret: Vec<u8> = "done\n".as_bytes().to_vec();
    ret.extend(payload);
    //eprintln!("LSR_CORE: returning {:#?}",ret);
    stream.write(&ret).unwrap();
    Ok(())
}

fn main() -> Result<()> {
    let mut safety_rules = SafetyRules::new();
    let listener = TcpListener::bind(LSR_SGX_ADDRESS)?;
    eprintln!("Ready to accept LSR requests...");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                safety_rules.set_storage_proxy(stream.try_clone().unwrap());
                let resp = process_safety_rules_reqs(&mut safety_rules, stream.try_clone().unwrap())?;
            }
            Err(_) => {
                eprintln!("unable to connect...");
            }
        }
    }
    eprintln!(
        "Wohoo! LSR_CORE about to terminate",
    );
    Ok(())
}
