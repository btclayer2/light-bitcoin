use secp256k1::curve::{Affine, Field, Scalar};

use crate::taggedhash::HashInto;

#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub struct XOnly([u8; 32]);

impl XOnly {
    pub fn from_field(field: &mut Field) -> Option<Self> {
        field.normalize();
        let slice = field.b32();
        Some(Self(slice))
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut elem = Field::default();
        let mut affine_coords = Affine::default();
        if elem.set_b32(&bytes) && affine_coords.set_xquad(&elem) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl HashInto for XOnly {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.as_bytes())
    }
}

impl Into<Scalar> for XOnly {
    fn into(self) -> Scalar {
        let mut scalar = Scalar::default();
        let _ = scalar.set_b32(self.as_bytes());
        scalar
    }
}
