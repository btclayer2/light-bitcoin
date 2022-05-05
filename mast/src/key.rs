//! Wrap [`Affine`] and [`Scalar`] into public key and private key
//!
//! The libsecp256k1 library is still available,
//! but for ease of use, further encapsulation.

use super::{error::MastError, taggedhash::HashInto, taggedhash::*};
use arrayref::{array_mut_ref, array_ref};
use codec::{Decode, Encode};
use core::{cmp::Ordering, convert::TryFrom, ops::Neg};

#[cfg(feature = "std")]
use core::fmt::Formatter;

use digest::Digest;

#[cfg(feature = "getrandom")]
use rand_core::{OsRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar},
    util::{COMPRESSED_PUBLIC_KEY_SIZE, TAG_PUBKEY_EVEN, TAG_PUBKEY_FULL, TAG_PUBKEY_ODD},
};
#[cfg(feature = "std")]
use serde::{
    de::{Error as SerdeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

lazy_static::lazy_static! {
    /// A static ECMult context.
    pub static ref ECMULT_CONTEXT: Box<ECMultContext> = ECMultContext::new_boxed();

    /// A static ECMultGen context.
    pub static ref ECMULT_GEN_CONTEXT: Box<ECMultGenContext> = ECMultGenContext::new_boxed();
}

#[derive(Debug, Clone, Eq, PartialEq, Decode, Encode, scale_info::TypeInfo)]
pub struct PublicKey(pub Affine);

#[derive(Debug, Clone, Eq, PartialEq, Decode, Encode, scale_info::TypeInfo)]
pub struct PrivateKey(pub Scalar);

#[cfg(feature = "std")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.serialize()))
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;
        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
                formatter.write_str("struct PublicKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                let v = hex::decode(v).map_err(|_| SerdeError::custom("struct PublicKey"))?;
                let mut keys = [0u8; 65];
                keys.copy_from_slice(&v);
                PublicKey::parse(&keys).map_err(|_| SerdeError::custom("struct PublicKey"))
            }
        }
        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

impl PartialOrd<Self> for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.serialize().partial_cmp(&other.serialize())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.serialize().cmp(&other.serialize())
    }
}

#[cfg(feature = "std")]
impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.serialize()))
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrivateKeyVisitor;
        impl<'de> Visitor<'de> for PrivateKeyVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
                formatter.write_str("struct PrivateKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                let v = hex::decode(v).map_err(|_| SerdeError::custom("struct PrivateKey"))?;
                let mut keys = [0u8; 32];
                keys.copy_from_slice(&v);
                PrivateKey::parse(&keys).map_err(|_| SerdeError::custom("struct PrivateKey"))
            }
        }
        deserializer.deserialize_str(PrivateKeyVisitor)
    }
}

/// Public key multiplication and addition calculations
impl PublicKey {
    pub fn add_point(&self, rhs: &Self) -> Result<PublicKey, MastError> {
        let mut qj = Jacobian::default();
        qj.set_infinity();
        qj = qj.add_ge(&self.0);
        qj = qj.add_ge(&rhs.0);

        if qj.is_infinity() {
            return Err(MastError::InvalidPublicKey);
        }
        let q = Affine::from_gej(&qj);
        Ok(PublicKey(q))
    }

    pub fn mul_scalar(&self, rhs: &PrivateKey) -> Result<PublicKey, MastError> {
        if rhs.0.is_zero() {
            return Err(MastError::InvalidPrivateKey);
        }
        let mut r = Jacobian::default();
        let zero = Scalar::from_int(0);
        let pt = Jacobian::from_ge(&self.0);
        ECMULT_CONTEXT.ecmult(&mut r, &pt, &rhs.0, &zero);

        Ok(PublicKey(Affine::from_gej(&r)))
    }
}

/// Secret key multiplication and addition calculations
impl PrivateKey {
    pub fn add_scalar(&self, rhs: &Self) -> Result<Self, MastError> {
        let v = self.0 + rhs.0;
        if v.is_zero() {
            return Err(MastError::InvalidPrivateKey);
        }
        Ok(PrivateKey(v))
    }

    pub fn mul_scalar(&self, rhs: &Self) -> Result<Self, MastError> {
        let v = self.0 * rhs.0;
        if v.is_zero() {
            return Err(MastError::InvalidPrivateKey);
        }
        Ok(PrivateKey(v))
    }

    pub fn mul_point(&self, rhs: &PublicKey) -> Result<PublicKey, MastError> {
        if self.0.is_zero() {
            return Err(MastError::InvalidPrivateKey);
        }
        let mut r = Jacobian::default();
        let zero = Scalar::from_int(0);
        let pt = Jacobian::from_ge(&rhs.0);

        ECMULT_CONTEXT.ecmult(&mut r, &pt, &self.0, &zero);

        Ok(PublicKey(Affine::from_gej(&r)))
    }
}

impl From<Affine> for PublicKey {
    fn from(p: Affine) -> Self {
        PublicKey(p)
    }
}

impl From<PublicKey> for Affine {
    fn from(p: PublicKey) -> Self {
        p.0
    }
}

impl From<Scalar> for PrivateKey {
    fn from(s: Scalar) -> Self {
        PrivateKey(s)
    }
}

impl From<PrivateKey> for Scalar {
    fn from(s: PrivateKey) -> Self {
        s.0
    }
}

impl TryFrom<&str> for PrivateKey {
    type Error = MastError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(x_bytes) = hex::decode(value) {
            if x_bytes.len() != 32 {
                return Err(MastError::InvalidInputLength);
            }
            Self::parse_slice(&x_bytes[..])
        } else {
            Err(MastError::InvalidHexCharacter)
        }
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = MastError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let x_bytes = hex::decode(value)?;
        if x_bytes.len() != 32 {
            return Err(MastError::InvalidStringLength);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&x_bytes);
        PublicKey::parse_x_coor(&k)
    }
}

impl HashInto for PrivateKey {
    fn hash_into(&self, hash: &mut impl Digest) {
        hash.update(self.0.b32())
    }
}

impl PublicKey {
    pub fn serialize_compressed(&self) -> [u8; 33] {
        debug_assert!(!self.0.is_infinity());

        let mut ret = [0u8; 33];
        let mut elem = self.0;

        elem.x.normalize_var();
        elem.y.normalize_var();
        elem.x.fill_b32(array_mut_ref!(ret, 1, 32));
        ret[0] = if elem.y.is_odd() {
            TAG_PUBKEY_ODD
        } else {
            TAG_PUBKEY_EVEN
        };

        ret
    }

    pub fn serialize(&self) -> [u8; 65] {
        debug_assert!(!self.0.is_infinity());

        let mut ret = [0u8; 65];
        let mut elem = self.0;

        elem.x.normalize_var();
        elem.y.normalize_var();
        elem.x.fill_b32(array_mut_ref!(ret, 1, 32));
        elem.y.fill_b32(array_mut_ref!(ret, 33, 32));
        ret[0] = TAG_PUBKEY_FULL;

        ret
    }

    pub fn x_coor(&self) -> [u8; 32] {
        let mut x = self.0.x;
        x.normalize();
        x.b32()
    }

    pub fn y_coor(&self) -> [u8; 32] {
        let mut y = self.0.y;
        y.normalize();
        y.b32()
    }

    pub fn is_odd_y(&self) -> bool {
        let mut y = self.0.y;
        y.normalize();
        y.is_odd()
    }

    pub fn create_from_private_key(s: &PrivateKey) -> PublicKey {
        let mut pj = Jacobian::default();
        ECMULT_GEN_CONTEXT.ecmult_gen(&mut pj, &s.0);
        let mut p = Affine::default();
        p.set_gej(&pj);
        PublicKey(p)
    }

    pub fn neg(&self) -> PublicKey {
        // let p: Affine = self.0;
        // let p = p.neg();
        PublicKey(self.0.neg())
    }

    pub fn parse(p: &[u8; 65]) -> Result<Self, MastError> {
        let mut x = Field::default();
        let mut y = Field::default();
        if !x.set_b32(array_ref!(p, 1, 32)) {
            return Err(MastError::InvalidPublicKey);
        }

        if !y.set_b32(array_ref!(p, 33, 32)) {
            return Err(MastError::InvalidPublicKey);
        }
        let mut elem = Affine::default();
        elem.set_xy(&x, &y);

        if elem.is_infinity() {
            return Err(MastError::InvalidPublicKey);
        }

        if !elem.is_valid_var() {
            return Err(MastError::InvalidPublicKey);
        }
        Ok(PublicKey(elem))
    }

    pub fn parse_slice(p: &[u8]) -> Result<Self, MastError> {
        if p.len() == 65 {
            let mut k = [0u8; 65];
            k.copy_from_slice(p);
            Self::parse(&k)
        } else if p.len() == 33 {
            let mut k = [0u8; 33];
            k.copy_from_slice(p);
            Self::parse_compressed(&k)
        } else if p.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(p);
            Self::parse_x_coor(&k)
        } else {
            Err(MastError::InvalidInputLength)
        }
    }

    /// Convert [`x_coor`] to [`PublicKey`]
    ///
    /// Recover the public key from the x coordinate in the schnorr signature;
    /// Reference ift_x(x): [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    pub fn parse_x_coor(x: &[u8; 32]) -> Result<Self, MastError> {
        let mut elem = Field::default();
        let mut affine = Affine::default();
        if elem.set_b32(x) && affine.set_xo_var(&elem, false) {
            Ok(Self(affine))
        } else {
            Err(MastError::XCoordinateNotExist)
        }
    }

    pub fn parse_compressed(p: &[u8; COMPRESSED_PUBLIC_KEY_SIZE]) -> Result<PublicKey, MastError> {
        if !(p[0] == TAG_PUBKEY_EVEN || p[0] == TAG_PUBKEY_ODD) {
            return Err(MastError::InvalidPublicKey);
        }
        let mut x = Field::default();
        if !x.set_b32(array_ref!(p, 1, 32)) {
            return Err(MastError::InvalidPublicKey);
        }
        let mut elem = Affine::default();
        elem.set_xo_var(&x, p[0] == TAG_PUBKEY_ODD);
        if elem.is_infinity() {
            return Err(MastError::InvalidPublicKey);
        }
        if elem.is_valid_var() {
            Ok(PublicKey(elem))
        } else {
            Err(MastError::InvalidPublicKey)
        }
    }
}

impl PrivateKey {
    pub fn serialize(&self) -> [u8; 32] {
        self.0.b32()
    }

    pub fn parse(s: &[u8; 32]) -> Result<Self, MastError> {
        let mut r = Scalar::default();
        if !bool::from(r.set_b32(s)) {
            Ok(PrivateKey(r))
        } else {
            Err(MastError::InvalidPrivateKey)
        }
    }

    pub fn parse_slice(s: &[u8]) -> Result<Self, MastError> {
        if s.len() != 32 {
            return Err(MastError::InvalidInputLength);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(s);
        Self::parse(&k)
    }

    pub fn neg(&self) -> Self {
        PrivateKey(self.0.neg())
    }

    pub fn from_int(v: u32) -> Self {
        PrivateKey(Scalar::from_int(v))
    }

    #[cfg(feature = "getrandom")]
    pub fn generate_random() -> Result<Self, Error> {
        let mut key: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::parse(&key)
    }
}

/// Represents the aggregate public key and the corresponding coefficient.
#[derive(Debug, Clone, Decode, Encode, scale_info::TypeInfo)]
pub struct KeyAgg {
    /// Aggregate public key.
    pub x_tilde: PublicKey,
    /// The coefficient pf aggregate public key
    pub a_coefficients: Vec<PrivateKey>,
}

impl KeyAgg {
    pub fn key_aggregation_n(pks: &[PublicKey]) -> Result<KeyAgg, MastError> {
        if pks.is_empty() {
            return Err(MastError::InvalidPubkeysLength);
        }
        let mut pks = pks.to_vec();
        pks.sort_unstable();

        let x_coors = pks
            .iter()
            .map(|pk| PrivateKey::parse(&pk.x_coor()))
            .collect::<Result<Vec<_>, _>>()?;

        let hashs = x_coors
            .iter()
            .map(|pk| {
                let mut hnon_preimage = vec![];
                for mpz in x_coors.iter().take(pks.len()) {
                    hnon_preimage.push(mpz);
                }
                hnon_preimage.push(pk);
                let mut h = sha2::Sha256::default().tagged(b"BIP0340/aggregate");
                for v in hnon_preimage {
                    h = h.add(&v.clone());
                }
                let tagged = h.finalize();
                PrivateKey::parse_slice(tagged.as_slice())
                // the "L" part of the hash
            })
            .collect::<Result<Vec<_>, _>>()?;

        let x_tildes = pks
            .iter()
            .zip(&hashs)
            .map(|(pk, hash)| pk.mul_scalar(hash))
            .collect::<Result<Vec<_>, _>>()?;

        let sum = x_tildes.iter().skip(1).fold(
            Ok(x_tildes[0].clone()),
            |acc: Result<PublicKey, MastError>, pk| acc?.add_point(pk),
        )?;

        Ok(KeyAgg {
            x_tilde: sum,
            a_coefficients: hashs,
        })
    }
}
