// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

//! `Nibble` represents a four-bit unsigned integer.

#[macro_use]
extern crate sgx_tstd as std;

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Nibble(u8);

impl From<u8> for Nibble {
    fn from(nibble: u8) -> Self {
        assert!(nibble < 16, "Nibble out of range: {}", nibble);
        Self(nibble)
    }
}

impl From<Nibble> for u8 {
    fn from(nibble: Nibble) -> Self {
        nibble.0
    }
}

impl fmt::LowerHex for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}


