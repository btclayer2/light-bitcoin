use core::{fmt, ops};

use light_bitcoin_crypto::dhash160;
use light_bitcoin_primitives::{H264, H512, H520};

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::signature::{CompactSignature, Signature};
use crate::{AddressHash, Message};

/// Secret public key
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
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
