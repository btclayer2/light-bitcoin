#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub extern crate bitcoin_hashes as hashes;

pub mod error;
pub mod key;
pub mod mast;
pub mod p2sh;
pub mod pmt;
pub mod signature;
pub mod taggedhash;

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
