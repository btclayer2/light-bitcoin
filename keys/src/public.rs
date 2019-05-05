use ustd::{fmt, ops, prelude::*};

use crypto::dhash160;
use primitives::{H264, H512, H520};

use parity_codec_derive::{Decode, Encode};
#[cfg(feature = "std")]
use serde_derive::{Deserialize, Serialize};

use super::error::Error;
use super::signature::{CompactSignature, Signature};
use super::{AddressHash, Message};

/// Secret public key
#[derive(Ord, PartialOrd, Eq, Copy, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Public {
    /// Normal version of public key
    Normal(H520),
    /// Compressed version of public key
    Compressed(H264),
}

impl PartialEq for Public {
    fn eq(&self, other: &Self) -> bool {
        let s_slice: &[u8] = self;
        let o_slice: &[u8] = other;
        s_slice == o_slice
    }
}

impl fmt::Debug for Public {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Public::Normal(ref hash) => writeln!(f, "normal: {}", hash),
            Public::Compressed(ref hash) => writeln!(f, "compressed: {}", hash),
        }
    }
}

impl fmt::Display for Public {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Public::Normal(ref hash) => writeln!(f, "normal: {}", hash),
            Public::Compressed(ref hash) => writeln!(f, "compressed: {}", hash),
        }
    }
}

impl ops::Deref for Public {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match *self {
            Public::Normal(ref hash) => hash.as_bytes(),
            Public::Compressed(ref hash) => hash.as_bytes(),
        }
    }
}

impl Default for Public {
    fn default() -> Public {
        Public::Normal(H520::default())
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
        let public_key: &[u8] = self;
        dhash160(public_key)
    }

    pub fn verify(&self, message: &Message, signature: &Signature) -> Result<bool, Error> {
        let public = match self {
            Public::Normal(_) => secp256k1::PublicKey::parse_slice(self, None)?,
            Public::Compressed(_) => secp256k1::PublicKey::parse_slice(self, None)?,
        };
        let mut signature = secp256k1::Signature::parse_der_lax(&**signature)?;
        signature.normalize_s();
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
