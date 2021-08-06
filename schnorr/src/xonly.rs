use secp256k1::{
    curve::{Affine, Field},
    util::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD},
    PublicKey,
};

use crate::{error::Error, taggedhash::HashInto};
/// An [`XOnly`] is the compressed representation of a [`PublicKey`] which
/// only stores the x-coordinate of the point.
///
/// X-only public keys become equivalent to a compressed public key
/// that is the X-only key prefixed by the byte 0x02
#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub struct XOnly([u8; 32]);

/// A number of methods to load [`XOnly`]
impl XOnly {
    /// Convert [`Field`] to [`XOnly`]
    pub fn from_field(field: &mut Field) -> Option<Self> {
        field.normalize();
        let slice = field.b32();
        Some(Self(slice))
    }
    /// Parse [`XOnly`] from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }
    /// Parse [`XOnly`] from 32 bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut elem = Field::default();
        let mut affine_coords = Affine::default();
        if elem.set_b32(&bytes) && affine_coords.set_xquad(&elem) {
            Some(Self(bytes))
        } else {
            None
        }
    }
    /// Parse [`XOnly`] from hex string
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let x_bytes = hex::decode(s)?;
        match Self::from_slice(&x_bytes[..]) {
            Some(x) => Ok(x),
            None => Err(Error::InvalidXOnly),
        }
    }

    /// Convert [`XOnly`] to [u8; 32]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Implementing conversions to and from public keys
///
/// I think this implementation is much clearer than implementing [`From<T>`]
impl XOnly {
    /// Convert [`XOnly`] to [`PublicKey`]
    pub fn to_public(self) -> Result<PublicKey, Error> {
        let mut f = Field::default();
        let _ = f.set_b32(self.as_bytes());
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
    /// Convert [`PublicKey`] to [`XOnly`]
    ///
    /// The public keys constructed by such an algorithm (assuming they use the 33-byte compressed encoding)
    /// need to be converted by dropping the first byte.
    ///
    /// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-conversion
    pub fn from_public(pubkey: &PublicKey) -> Result<Self, Error> {
        let conmpressed = pubkey.serialize_compressed();
        let (_, right) = conmpressed.split_at(1);
        match Self::from_slice(right) {
            Some(xonly) => Ok(xonly),
            None => Err(Error::InvalidPublic),
        }
    }
}

impl HashInto for XOnly {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.as_bytes())
    }
}
