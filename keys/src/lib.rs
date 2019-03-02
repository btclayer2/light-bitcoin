//! Bitcoin keys.

#![cfg_attr(not(feature = "std"), no_std)]

mod address;
mod display;
mod error;
mod keypair;
mod private;
mod public;
mod signature;

use primitives::*;

pub use self::address::{Address, Network, Type};
pub use self::display::DisplayLayout;
pub use self::error::Error;
pub use self::keypair::KeyPair;
pub use self::private::Private;
pub use self::public::Public;
pub use self::signature::{CompactSignature, Signature};

/// 20 bytes long hash derived from public `ripemd160(sha256(public))`
pub type AddressHash = H160;
/// 32 bytes long secret key
pub type Secret = H256;
/// 32 bytes long signable message
pub type Message = H256;
