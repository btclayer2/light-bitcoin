use arrayref::array_mut_ref;
use core::{
    convert::{TryFrom, TryInto},
    fmt, ops,
};

use light_bitcoin_crypto::dhash160;
use light_bitcoin_primitives::{H264, H512, H520};

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    schnorr::verify_schnorr,
    signature::{CompactSignature, SchnorrSignature, Signature},
    tagged::HashInto,
    AddressHash, Message,
};
use secp256k1::curve::{Affine, Field};

/// Secret public key
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(untagged))]
#[derive(Encode, Decode)]
pub enum Public {
    /// Normal version of public key
    Normal(H520),
    /// Compressed version of public key
    Compressed(H264),
}

impl fmt::Debug for Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Public::Normal(hash) => write!(f, "{:?}", hash),
            Public::Compressed(hash) => write!(f, "{:?}", hash),
        }
    }
}

impl fmt::Display for Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Public::Normal(hash) => write!(f, "{}", hash),
            Public::Compressed(hash) => write!(f, "{}", hash),
        }
    }
}

impl ops::Deref for Public {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Public::Normal(hash) => hash.as_bytes(),
            Public::Compressed(hash) => hash.as_bytes(),
        }
    }
}

impl Default for Public {
    fn default() -> Public {
        Public::Normal(H520::default())
    }
}

impl TryFrom<Public> for musig2::PublicKey {
    type Error = Error;
    fn try_from(p: Public) -> Result<Self, Self::Error> {
        musig2::PublicKey::parse_slice(&p.to_vec()).map_err(|_| Error::InvalidPublic)
    }
}

impl Public {
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        match data.len() {
            33 => Ok(Public::Compressed(H264::from_slice(data))),
            65 => Ok(Public::Normal(H520::from_slice(data))),
            _ => Err(Error::InvalidPublic),
        }
    }

    pub fn address_hash(&self) -> AddressHash {
        dhash160(self)
    }

    pub fn verify(&self, message: &Message, signature: &Signature) -> Result<bool, Error> {
        let public = match self {
            Public::Normal(pubkey) => secp256k1::PublicKey::parse(pubkey.as_fixed_bytes())?,
            Public::Compressed(pubkey) => {
                secp256k1::PublicKey::parse_compressed(pubkey.as_fixed_bytes())?
            }
        };
        let mut signature = secp256k1::Signature::parse_der_lax(&**signature)?;
        signature.normalize_s();
        let message = secp256k1::Message::parse(message.as_fixed_bytes());
        Ok(secp256k1::verify(&message, &signature, &public))
    }

    pub fn verify_schnorr(&self, message: &Message, signature: [u8; 64]) -> Result<bool, Error> {
        let public = match self {
            Public::Normal(pubkey) => secp256k1::PublicKey::parse(pubkey.as_fixed_bytes())?,
            Public::Compressed(pubkey) => {
                secp256k1::PublicKey::parse_compressed(pubkey.as_fixed_bytes())?
            }
        };
        let xonly = public.try_into()?;
        let signature = SchnorrSignature::try_from(signature)?;
        verify_schnorr(&signature, message, xonly)
    }

    pub fn verify_compact(&self, message: &Message, signature: &[u8; 64]) -> Result<bool, Error> {
        let public = match self {
            Public::Normal(pubkey) => secp256k1::PublicKey::parse(pubkey.as_fixed_bytes())?,
            Public::Compressed(pubkey) => {
                secp256k1::PublicKey::parse_compressed(pubkey.as_fixed_bytes())?
            }
        };
        let signature = secp256k1::Signature::parse(signature);
        let message = secp256k1::Message::parse(message.as_fixed_bytes());
        Ok(secp256k1::verify(&message, &signature, &public))
    }

    pub fn recover_compact(message: &Message, signature: &CompactSignature) -> Result<Self, Error> {
        let recovery_id = (signature[0] - 27) & 3;
        let compressed = (signature[0] - 27) & 4 != 0;
        let recovery_id = secp256k1::RecoveryId::parse(recovery_id)?;
        let sign = H512::from_slice(&signature[1..65]);
        let signature = secp256k1::Signature::parse(sign.as_fixed_bytes());
        let message = secp256k1::Message::parse(message.as_fixed_bytes());
        let pub_key = secp256k1::recover(&message, &signature, &recovery_id)?;

        let public = if compressed {
            let public = H264::from_slice(&pub_key.serialize_compressed());
            Public::Compressed(public)
        } else {
            let public = H520::from_slice(&pub_key.serialize());
            Public::Normal(public)
        };
        Ok(public)
    }
}

/// An [`XOnly`] is the compressed representation of a [`PublicKey`] which
/// only stores the x-coordinate of the point.
///
/// X-only public keys become equivalent to a compressed public key
/// that is the X-only key prefixed by the byte 0x02
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode)]
pub struct XOnly(pub [u8; 32]);

impl XOnly {
    pub fn on_curve(&self) -> Result<bool, Error> {
        let mut elem = secp256k1::curve::Field::default();
        let mut affine_coords = secp256k1::curve::Affine::default();
        if elem.set_b32(&self.0) && affine_coords.set_xquad(&elem) {
            Ok(true)
        } else {
            Err(Error::XCoordinateNotExist)
        }
    }

    pub fn verify(&self, message: &Message, signature: [u8; 64]) -> Result<bool, Error> {
        let signature = SchnorrSignature::try_from(signature)?;

        verify_schnorr(&signature, message, *self)
    }
}

/// Convert [`Field`] to [`XOnly`]
impl From<&mut secp256k1::curve::Field> for XOnly {
    fn from(field: &mut secp256k1::curve::Field) -> Self {
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

/// Parse [`XOnly`] from 32 bytes
impl TryFrom<[u8; 32]> for XOnly {
    type Error = Error;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let mut elem = secp256k1::curve::Field::default();
        let mut affine_coords = secp256k1::curve::Affine::default();
        if elem.set_b32(&value) && affine_coords.set_xquad(&elem) {
            Ok(Self(value))
        } else {
            Err(Error::XCoordinateNotExist)
        }
    }
}

/// Convert [`PublicKey`] to [`XOnly`]
///
/// The public keys constructed by such an algorithm (assuming they use the 33-byte compressed encoding)
/// need to be converted by dropping the first byte.
///
/// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-conversion
impl TryFrom<secp256k1::PublicKey> for XOnly {
    type Error = Error;

    fn try_from(pubkey: secp256k1::PublicKey) -> Result<Self, Self::Error> {
        let conmpressed = pubkey.serialize_compressed();
        let (_, right) = conmpressed.split_at(1);
        right.try_into()
    }
}

/// Convert [`XOnly`] to [`PublicKey`]
impl TryInto<secp256k1::PublicKey> for XOnly {
    type Error = Error;

    fn try_into(self) -> Result<secp256k1::PublicKey, Self::Error> {
        let mut elem = Field::default();
        let mut affine = Affine::default();
        if elem.set_b32(&self.0) && affine.set_xo_var(&elem, false) {
            let mut ret = [0u8; 65];
            ret[0] = 0x04;
            affine.x.normalize_var();
            affine.y.normalize_var();
            affine.x.fill_b32(array_mut_ref!(ret, 1, 32));
            affine.y.fill_b32(array_mut_ref!(ret, 33, 32));
            Ok(secp256k1::PublicKey::parse(&ret)?)
        } else {
            Err(Error::XCoordinateNotExist)
        }

        // let mut x = secp256k1::curve::Field::default();
        // let _ = x.set_b32(&self.0);
        // x.normalize();
        //
        // let mut elem = secp256k1::curve::Affine::default();
        // elem.set_xquad(&x);
        // elem.y.normalize();
        // // determine the first byte of the compressed format public key
        // let tag = if elem.y.is_odd() {
        //     // need to convert y to an even number
        //     secp256k1::util::TAG_PUBKEY_EVEN
        // } else {
        //     secp256k1::util::TAG_PUBKEY_ODD
        // };
        // // construct compressed public key
        // let mut c = [0u8; 33];
        // for (i, byte) in c.iter_mut().enumerate() {
        //     if i == 0 {
        //         *byte = tag;
        //         continue;
        //     }
        //     *byte = x.b32()[i - 1];
        // }
        // let p = secp256k1::PublicKey::parse_compressed(&c)?;
        // Ok(p)
    }
}

impl HashInto for XOnly {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.0)
    }
}

#[test]
fn test_serde_public() {
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    struct Test(Public);

    let pubkey = Test(Public::Compressed(H264::from([1u8; 33])));
    let ser = serde_json::to_string(&pubkey).unwrap();
    assert_eq!(
        ser,
        "\"0x010101010101010101010101010101010101010101010101010101010101010101\""
    );
    let de = serde_json::from_str::<Test>(&ser).unwrap();
    assert_eq!(de, pubkey);
}
