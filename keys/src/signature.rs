//! Bitcoin signatures.
//!
//! http://bitcoin.stackexchange.com/q/12554/40688

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{
    convert::{TryFrom, TryInto},
    fmt, ops, str,
};
use secp256k1::curve::Scalar;

use light_bitcoin_primitives::H520;

use crate::{error::Error, public::XOnly};

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Default, scale_info::TypeInfo)]
pub struct Signature(Vec<u8>);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl ops::Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// mainly use for test
impl str::FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bytes = if s.starts_with("0x") {
            hex::decode(&s.as_bytes()[2..]).map_err(|_| Error::InvalidSignature)?
        } else {
            hex::decode(s).map_err(|_| Error::InvalidSignature)?
        };
        Ok(Signature(bytes))
    }
}

impl From<Vec<u8>> for Signature {
    fn from(v: Vec<u8>) -> Self {
        Signature(v)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(s: Signature) -> Self {
        s.0
    }
}

impl Signature {
    pub fn check_low_s(&self) -> bool {
        unimplemented!();
    }
}

impl<'a> From<&'a [u8]> for Signature {
    fn from(v: &'a [u8]) -> Self {
        Signature(v.to_vec())
    }
}

/// Recovery ID (1 byte) + Compact signature (64 bytes)
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Default, scale_info::TypeInfo)]
pub struct CompactSignature(H520);

impl fmt::Debug for CompactSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for CompactSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ops::Deref for CompactSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

// mainly use for test
impl str::FromStr for CompactSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bytes = if s.starts_with("0x") {
            if s.len() != H520::len_bytes() * 2 + 2 {
                return Err(Error::InvalidSignature);
            }
            hex::decode(&s.as_bytes()[2..]).map_err(|_| Error::InvalidSignature)?
        } else {
            if s.len() != H520::len_bytes() * 2 {
                return Err(Error::InvalidSignature);
            }
            hex::decode(s).map_err(|_| Error::InvalidSignature)?
        };
        Ok(CompactSignature(H520::from_slice(&bytes)))
    }
}

impl From<H520> for CompactSignature {
    fn from(h: H520) -> Self {
        CompactSignature(h)
    }
}

impl From<CompactSignature> for H520 {
    fn from(s: CompactSignature) -> Self {
        s.0
    }
}

/// This is 64-byte schnorr signature.
///
/// More details:
/// [`BIP340`]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#design
/// A standard for 64-byte Schnorr signatures over the elliptic curve secp256k1
#[derive(Eq, PartialEq, Clone)]
pub struct SchnorrSignature {
    pub rx: XOnly,
    pub s: Scalar,
}

impl TryFrom<&str> for SchnorrSignature {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut s_slice = [0u8; 64];
        s_slice.copy_from_slice(&hex::decode(value)?[..]);
        s_slice.try_into()
    }
}

impl TryFrom<[u8; 64]> for SchnorrSignature {
    type Error = Error;

    fn try_from(bytes: [u8; 64]) -> Result<Self, Self::Error> {
        let mut rx_bytes = [0u8; 32];
        rx_bytes.copy_from_slice(&bytes[0..32]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let mut s = Scalar::default();
        let _ = s.set_b32(&s_bytes);
        let rx = rx_bytes.try_into()?;
        Ok(SchnorrSignature { rx, s })
    }
}
impl From<SchnorrSignature> for [u8; 64] {
    fn from(sig: SchnorrSignature) -> Self {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&sig.rx.0[..]);
        bytes[32..64].copy_from_slice(&sig.s.b32()[..]);
        bytes
    }
}

impl TryFrom<&[u8]> for SchnorrSignature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let mut keys = [0u8; 64];
        keys.copy_from_slice(bytes);

        let mut rx_bytes = [0u8; 32];
        rx_bytes.copy_from_slice(&keys[0..32]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&keys[32..64]);
        let mut s = Scalar::default();
        let _ = s.set_b32(&s_bytes);
        let rx = rx_bytes.try_into()?;
        Ok(SchnorrSignature { rx, s })
    }
}

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.rx.0[..]);
        bytes[32..64].copy_from_slice(&self.s.b32());
        hex::encode(bytes).fmt(f)
    }
}
