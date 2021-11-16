#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[macro_use]
pub extern crate bitcoin_hashes as hashes;

pub mod error;
pub mod mast;
pub mod pmt;

pub use crate::mast::*;

#[cfg(feature = "std")]
use std::io;

#[cfg(not(feature = "std"))]
use core2::io;

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
};

use hashes::{hash_newtype, sha256d, Hash};

hash_newtype!(
    LeafNode,
    sha256d::Hash,
    32,
    doc = "The leaf node of Merkle tree.",
    false
);
hash_newtype!(
    MerkleNode,
    sha256d::Hash,
    32,
    doc = "The node of Merkle tree, include leaf node.",
    false
);
