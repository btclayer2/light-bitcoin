//! Wrapped the [`SecretKey`]
//!
//! The private key from the libsecp256k1 library is still available,
//! but I think I'll have to add the schnorr signature to it.
//!
//! Currently it is useless, leave it for subsequent optimization.

use secp256k1::{Message, PublicKey, SecretKey};

use crate::{error::Error, schnorrsig::sign_no_aux, signature::Signature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Private(pub SecretKey);

/// Convenient use of private key signatures
impl Private {
    pub fn sign(&self, msg: &Message) -> Result<Signature, Error> {
        let pubkey = PublicKey::from_secret_key(&self.0);
        sign_no_aux(msg.clone(), self.0.clone(), pubkey)
    }
}
