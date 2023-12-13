//! This is 64-byte schnorr signature.
//!
//! More details:
//! [`BIP340`]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#design
use super::{error::MastError, key::PrivateKey};
use codec::{Decode, Encode};
use core::convert::{TryFrom, TryInto};

/// A standard for 64-byte Schnorr signatures over the elliptic curve secp256k1
#[derive(
    Eq,
    PartialEq,
    Clone,
    Debug,
    Decode,
    Encode,
    scale_info::TypeInfo,
    serde::Serialize,
    serde::Deserialize
)]
pub struct Signature {
    pub rx: PrivateKey,
    pub s: PrivateKey,
}

impl Signature {
    pub fn serialize(&self) -> [u8; 64] {
        let mut keys = [0u8; 64];
        keys.copy_from_slice(&[self.rx.serialize().to_vec(), self.s.serialize().to_vec()].concat());
        keys
    }
    pub fn parse(k: &[u8]) -> Result<Signature, MastError> {
        if k.len() != 64 {
            return Err(MastError::InvalidInputLength);
        }
        let mut r_slice = [0u8; 32];
        r_slice.copy_from_slice(&k[0..32]);
        let mut s_slice = [0u8; 32];
        s_slice.copy_from_slice(&k[32..64]);
        Ok(Signature {
            rx: PrivateKey::parse(&r_slice)?,
            s: PrivateKey::parse(&s_slice)?,
        })
    }
}

impl TryFrom<&str> for Signature {
    type Error = MastError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut s_slice = [0u8; 64];
        s_slice.copy_from_slice(&hex::decode(value)?[..]);
        s_slice.try_into()
    }
}

impl TryFrom<[u8; 64]> for Signature {
    type Error = MastError;

    fn try_from(bytes: [u8; 64]) -> Result<Self, Self::Error> {
        let mut rx_bytes = [0u8; 32];
        rx_bytes.copy_from_slice(&bytes[0..32]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);

        let rx = PrivateKey::parse(&rx_bytes)?;
        let s = PrivateKey::parse(&s_bytes)?;
        Ok(Signature { rx, s })
    }
}
