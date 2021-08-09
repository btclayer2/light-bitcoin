//！ Wrapped the [`SecretKey`]
//！
//！ The private key from the libsecp256k1 library is still available,
//！ but I think I'll have to add the schnorr signature to it.

use core::fmt;

use secp256k1::{Message, PublicKey, SecretKey};

use crate::{error::Error, schnorrsig::sign_no_aux, signature::Signature};

#[derive(Clone, PartialEq, Eq)]
pub struct Private(SecretKey);

/// Convenient use of private key signatures
impl Private {
    pub fn sign(&self, msg: &Message) -> Result<Signature, Error> {
        let pubkey = PublicKey::from_secret_key(&self.0);
        sign_no_aux(msg.clone(), self.0.clone(), pubkey)
    }
}

/// Convert [`Private`] to [u8; 32]
impl Private {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.serialize()
    }
}

impl fmt::Debug for Private {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.to_bytes()).fmt(f)
    }
}
