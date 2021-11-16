//! Bitcoin keys.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod address;
mod display;
mod error;
mod keypair;
mod private;
mod public;
mod schnorr;
mod signature;
mod tagged;

use light_bitcoin_primitives::*;

pub use self::address::{Address, AddressTypes, Network, Type};
pub use self::display::DisplayLayout;
pub use self::error::Error;
pub use self::keypair::KeyPair;
pub use self::private::Private;
pub use self::public::{Public, XOnly};
pub use self::schnorr::*;
pub use self::signature::{CompactSignature, SchnorrSignature, Signature};
pub use self::tagged::*;

/// 20 bytes long hash derived from public `ripemd160(sha256(public))`
pub type AddressHash = H160;
/// 32 bytes long secret key
pub type Secret = H256;
/// 32 bytes long signable message
pub type Message = H256;
