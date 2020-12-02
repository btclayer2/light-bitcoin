//! Bitcoin signatures.
//!
//! http://bitcoin.stackexchange.com/q/12554/40688

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{fmt, ops, str};

use light_bitcoin_primitives::H520;

use crate::error::Error;

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Default)]
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
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Default)]
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
