// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! A library supplying various cryptographic primitives
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_trts;

pub mod ed25519;
pub mod error;
pub mod hash;
pub mod hkdf;
pub mod multi_ed25519;
pub mod noise;
pub mod test_utils;
pub mod traits;
pub mod x25519;

#[cfg(test)]
mod unit_tests;

pub use self::traits::*;
pub use hash::HashValue;

// Reexport once_cell and serde_name for use in CryptoHasher Derive implementation.
#[doc(hidden)]
pub use once_cell as _once_cell;
#[doc(hidden)]
pub use serde_name as _serde_name;
