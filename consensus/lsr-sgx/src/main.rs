use std::io::{BufRead, BufReader, Write, Error, ErrorKind, Result};
use std::net::{TcpStream, TcpListener};
use libra_types::{validator_signer::ValidatorSigner, epoch_change::EpochChangeProof};
use consensus_types::{
    block_data::BlockData,
    vote::Vote,
    vote_data::VoteData,
    vote_proposal::{MaybeSignedVoteProposal, VoteProposal},
    timeout::Timeout,
};

use crate::{safety_rules::SafetyRules};
mod safety_rules;
mod consensus_state;
mod storage_proxy;

pub const LSR_SGX_ADDRESS: &str = "localhost:8888";

/* this works for using ValidatorSigner */
fn test_validator_signer() {
    let a = ValidatorSigner::from_int(1);
    println!("signer = {:#?}", a);
}


fn test_data_types() {
    test_validator_signer();
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
    let read_bytes = reader.read_line(&mut request).unwrap();
    // fill the read of buf
    //let buf = reader.fill_buf().unwrap();
    let buf = reader.buffer();
    match request.as_str().trim() {
        "req:init" => {
            // fill the read of buf
            let input: EpochChangeProof = lcs::from_bytes(buf).unwrap();
            eprintln!("{} -- {:#?}", request, input);
        }
        "req:consensus_state" => {
            let response = lsr.consensus_state(stream.try_clone().unwrap());
            println!("{:#?}", response);
        }
        "req:construct_and_sign_vote" => {
            let input: MaybeSignedVoteProposal = lcs::from_bytes(buf).unwrap();
            eprintln!("{} -- {}", request, input.vote_proposal);
        }
        "req:sign_proposal" => {
            let input: BlockData = lcs::from_bytes(buf).unwrap();
            eprintln!("{} -- {:#?}", request, input);
        }
        "req:sign_timeout" => {
            let input: Timeout = lcs::from_bytes(buf).unwrap();
            eprintln!("{} -- {:#?}", request, input);
        }
        _ => {
            eprintln!("invalid req...{}", request);
        }
    }
    //let mut stream = BufReader::new(stream.try_clone().unwrap());
    //stream.get_mut().write_all("done".as_bytes()).unwrap();
    stream.write("done\n".as_bytes()).unwrap();
    Ok(())
}

fn main() -> Result<()> {
    test_data_types();
    let mut safety_rules = SafetyRules::new();
    let listener = TcpListener::bind(LSR_SGX_ADDRESS)?;
    eprintln!("Ready to accept...");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                safety_rules.set_storage_proxy(stream.try_clone().unwrap());
                process_safety_rules_reqs(&mut safety_rules, stream.try_clone().unwrap())?;
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
