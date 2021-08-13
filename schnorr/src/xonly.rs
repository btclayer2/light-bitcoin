//! This is the public key used for schnorr signatures.
//!
//! This is the official document description:
//! [`BIP340`]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-generation
//!
//! Here are some references:
//! [`secp256kfun`]: https://github.com/LLFourn/secp256kfun/blob/master/secp256kfun/src/xonly.rs
//! [`libsecp256k1`]: https://github.com/paritytech/libsecp256k1/blob/master/src/lib.rs
use core::convert::{TryFrom, TryInto};

use rand_core::{CryptoRng, RngCore};
use secp256k1::{
    curve::{Affine, Field},
    util::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD},
    Message, PublicKey,
};

use crate::{error::Error, schnorrsig, signature::Signature, taggedhash::HashInto};

/// An [`XOnly`] is the compressed representation of a [`PublicKey`] which
/// only stores the x-coordinate of the point.
///
/// X-only public keys become equivalent to a compressed public key
/// that is the X-only key prefixed by the byte 0x02
#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub struct XOnly(pub [u8; 32]);

/// Implementing signature verification using [`XOnly`]
///
/// It should be possible to use the public key for
/// signature verification directly, which is more convenient.
impl XOnly {
    pub fn verify(self, sig: &Signature, msg: &Message) -> Result<bool, Error> {
        let pubkey = self.try_into()?;
        schnorrsig::verify(sig, msg, pubkey)
    }

    pub fn on_curve(&self) -> Result<bool, Error> {
        let mut elem = Field::default();
        let mut affine_coords = Affine::default();
        if elem.set_b32(&self.0) && affine_coords.set_xquad(&elem) {
            Ok(true)
        } else {
            Err(Error::XCoordinateNotExist)
        }
    }

    pub fn generate_with<R>(mut csprng: R) -> XOnly
    where
        R: CryptoRng + RngCore,
    {
        let mut key: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut key);
        Self(key)
    }

    #[cfg(feature = "getrandom")]
    pub fn generate() -> XOnly {
        Self::generate_with(super::rand_hack())
    }
}

/// Convert [`Field`] to [`XOnly`]
impl From<&mut Field> for XOnly {
    fn from(field: &mut Field) -> Self {
        field.normalize();
        let slice = field.b32();
        Self(slice)
    }
}

impl TryFrom<&[u8]> for XOnly {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

/// Parse [`XOnly`] from 32 bytes
impl TryFrom<[u8; 32]> for XOnly {
    type Error = Error;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let mut elem = Field::default();
        let mut affine_coords = Affine::default();
        if elem.set_b32(&value) && affine_coords.set_xquad(&elem) {
            Ok(Self(value))
        } else {
            Err(Error::XCoordinateNotExist)
        }
    }
}

/// Parse [`XOnly`] from hex
impl TryFrom<&str> for XOnly {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let x_bytes = hex::decode(value)?;
        if x_bytes.len() != 32 {
            return Err(Error::InvalidStringLength);
        }
        x_bytes[..].try_into()
    }
}

/// Convert [`PublicKey`] to [`XOnly`]
///
/// The public keys constructed by such an algorithm (assuming they use the 33-byte compressed encoding)
/// need to be converted by dropping the first byte.
///
/// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-conversion
impl TryFrom<PublicKey> for XOnly {
    type Error = Error;

    fn try_from(pubkey: PublicKey) -> Result<Self, Self::Error> {
        let conmpressed = pubkey.serialize_compressed();
        let (_, right) = conmpressed.split_at(1);
        right.try_into()
    }
}

/// Convert [`XOnly`] to [`PublicKey`]
impl TryInto<PublicKey> for XOnly {
    type Error = Error;

    fn try_into(self) -> Result<PublicKey, Self::Error> {
        let mut f = Field::default();
        let _ = f.set_b32(&self.0);
        f.normalize();
        // determine the first byte of the compressed format public key
        let tag = if f.is_odd() {
            TAG_PUBKEY_EVEN
        } else {
            TAG_PUBKEY_ODD
        };
        // construct compressed public key
        let mut c = [0u8; 33];
        for (i, byte) in c.iter_mut().enumerate() {
            if i == 0 {
                *byte = tag;
                continue;
            }
            *byte = f.b32()[i - 1];
        }
        let p = PublicKey::parse_compressed(&c)?;
        Ok(p)
    }
}

impl HashInto for XOnly {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.0)
    }
}
