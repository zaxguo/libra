use std::prelude::v1::*;

use libra_types::{
    validator_signer::ValidatorSigner,
};

pub fn test_validator_signer() {
    let signer = ValidatorSigner::random(None);
    println!("signer : {:#}", signer);
}
