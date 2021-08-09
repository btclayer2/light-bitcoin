#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod error;
pub mod keypair;
pub mod private;
pub mod schnorrsig;
pub mod signature;
pub mod taggedhash;
pub mod xonly;
