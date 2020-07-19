// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{CryptoKVStorage, Error, GetResponse, KVStorage, Value};
use libra_secure_time::{RealTimeService, TimeService};
use std::collections::HashMap;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, NewAead, generic_array::GenericArray},
};

/// InMemoryStorage represents a key value store that is purely in memory and intended for single
/// threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission checks and simply
/// is a proof of concept to unblock building of applications without more complex data stores.
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the Libra code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
pub type InMemoryStorage = InMemoryStorageInternal<RealTimeService>;

#[derive(Default)]
pub struct InMemoryStorageInternal<T> {
    data: HashMap<String, GetResponse>,
    time_service: T,
}

impl InMemoryStorageInternal<RealTimeService> {
    pub fn new() -> Self {
        Self::new_with_time_service(RealTimeService::new())
    }


}

impl<T: TimeService> InMemoryStorageInternal<T> {
    pub fn new_with_time_service(time_service: T) -> Self {
        Self {
            data: HashMap::new(),
            time_service,
        }
    }
}

impl<T: Send + Sync + TimeService> KVStorage for InMemoryStorageInternal<T> {
    fn available(&self) -> Result<(), Error> {
        Ok(())
    }

    fn get(&self, key: &str) -> Result<GetResponse, Error> {
        let response = self
            .data
            .get(key)
            .ok_or_else(|| Error::KeyNotSet(key.to_string()))?;

        let value = match &response.value {
            Value::Bytes(value) => Value::Bytes(value.clone()),
            Value::Ed25519PrivateKey(value) => {
                // Hack because Ed25519PrivateKey does not support clone / copy
                let bytes = lcs::to_bytes(&value)?;
                let key = lcs::from_bytes(&bytes)?;
                Value::Ed25519PrivateKey(key)
            }
            Value::Ed25519PublicKey(value) => Value::Ed25519PublicKey(value.clone()),
            Value::HashValue(value) => Value::HashValue(*value),
            Value::String(value) => Value::String(value.clone()),
            Value::Transaction(value) => Value::Transaction(value.clone()),
            Value::U64(value) => Value::U64(*value),
        };

        let last_update = response.last_update;
        Ok(GetResponse { value, last_update })
    }

    fn set(&mut self, key: &str, value: Value) -> Result<(), Error> {
        self.data.insert(
            key.to_string(),
            GetResponse::new(value, self.time_service.now()),
        );
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error> {
        self.data.clear();
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    fn encrypt_and_convert_all(&mut self) -> Result<(), Error> {
        let key = GenericArray::from_slice(&[0u8; 32]);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        // the data safety rules care about
        let keys = ["consensus", "execution", "epoch",
                    "last_voted_round", "operator_account", "preferred_round",
                    "waypoint", "last_vote"];
        for key in keys.iter() {
            let response = self.get(key).unwrap();
            // unwrap the Value enum type so lcs only serializes the "Raw" type
            // (e.g. U64 instead of Value::U64)
            let value = match &response.value {
                Value::Bytes(value) => value.clone(),
                Value::U64(value) => lcs::to_bytes(&value.clone()).unwrap(),
                Value::String(value) => value.as_str().as_bytes().to_vec(),
                Value::Ed25519PublicKey(value) => lcs::to_bytes(&value.clone()).unwrap(),
                Value::Ed25519PrivateKey(value) => lcs::to_bytes(&value.clone()).unwrap(),
                Value::HashValue(value) => lcs::to_bytes(&value.clone()).unwrap(),
                _ => {
                    return Err(Error::InternalError("Incompatible type!".into()));
                }
            };
            println!("encrypting {}...", key);
            let e_bytes = cipher.encrypt(nonce, value.as_ref()).unwrap();
            let bytes = cipher.decrypt(nonce, e_bytes.as_ref()).unwrap();
            self.set(key, Value::Bytes(e_bytes)).unwrap();
        }
        Ok(())
    }
}

impl<T: TimeService + Send + Sync> CryptoKVStorage for InMemoryStorageInternal<T> {}
