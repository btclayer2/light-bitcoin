//! This package is prepared for taproot upgrade and is mainly used to implement BIP340.
//! More specifically, implement schnorr signatures based on secp256k1 elliptic curves.
//!
//! [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
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
