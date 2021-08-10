//! This is 64-byte schnorr signature.
//!
//! More details:
//! [`BIP340`]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#design
use core::convert::{TryFrom, TryInto};
use core::fmt;

use secp256k1::curve::Scalar;

use crate::{error::Error, xonly::XOnly};

/// A standard for 64-byte Schnorr signatures over the elliptic curve secp256k1
#[derive(Eq, PartialEq, Clone)]
pub struct Signature {
    pub rx: XOnly,
    pub s: Scalar,
}

impl TryFrom<&str> for Signature {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut s_slice = [0u8; 64];
        s_slice.copy_from_slice(&hex::decode(value)?[..]);
        s_slice.try_into()
    }
}

impl TryFrom<[u8; 64]> for Signature {
    type Error = Error;

    fn try_from(bytes: [u8; 64]) -> Result<Self, Self::Error> {
        let mut rx_bytes = [0u8; 32];
        rx_bytes.copy_from_slice(&bytes[0..32]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let mut s = Scalar::default();
        let _ = s.set_b32(&s_bytes);
        let rx = rx_bytes.try_into()?;
        Ok(Signature { rx, s })
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.rx.0[..]);
        bytes[32..64].copy_from_slice(&self.s.b32());
        hex::encode(bytes).fmt(f)
    }
}
