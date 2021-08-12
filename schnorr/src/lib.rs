//! This package is prepared for taproot upgrade and is mainly used to implement BIP340.
//! More specifically, implement schnorr signatures based on secp256k1 elliptic curves.
//!
//! [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
//!
//! rand_hack from:
//! [`schnorrkel`]: https://github.com/w3f/schnorrkel/blob/master/src/lib.rs
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "getrandom")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "getrandom")]
fn rand_hack() -> impl RngCore + CryptoRng {
    rand_core::OsRng
}

pub mod error;
pub mod private;
pub mod schnorrsig;
pub mod signature;
pub mod taggedhash;
pub mod xonly;
