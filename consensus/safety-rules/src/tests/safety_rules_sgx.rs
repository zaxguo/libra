// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{test_utils, tests::suite, SafetyRulesSGX};
use libra_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use libra_types::validator_signer::ValidatorSigner;
use libra_secure_storage::{InMemoryStorage, Storage, KVStorage};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, NewAead, generic_array::GenericArray},
};

#[test]
fn test() {
    suite::run_test_suite(&safety_rules_sgx());
}

fn generate_aes_cipher_for_testing() -> Aes256Gcm {
    let key = GenericArray::from_slice(&[0u8; 32]);
    Aes256Gcm::new(key)
}

fn safety_rules_sgx() -> suite::Callback {
    Box::new(move || {
        let signer = ValidatorSigner::from_int(0);
        let mut storage = test_utils::test_storage(&signer);
        let store = storage.internal_store();
        store.encrypt_and_convert_all().unwrap();
        let safety_rules = Box::new(SafetyRulesSGX::new(storage));
        (
            safety_rules,
            signer,
            Some(Ed25519PrivateKey::generate_for_testing()),
        )
    })
}
