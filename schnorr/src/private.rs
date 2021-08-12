//! Wrapped the [`SecretKey`]
//!
//! The private key from the libsecp256k1 library is still available,
//! but I think I'll have to add the schnorr signature to it.
//!
//! Currently, the purpose is more to test
//!
//! Random key generation reference:
//! [`schnorrkel`]: https://github.com/w3f/schnorrkel/blob/master/src/keys.rs
#[cfg(feature = "getrandom")]
use crate::schnorrsig::sign_with_rand_aux;

use core::convert::TryFrom;

use rand_core::{CryptoRng, RngCore};
use secp256k1::{curve::Scalar, Message, PublicKey, SecretKey};

use crate::{error::Error, schnorrsig::sign_no_aux, signature::Signature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Private(pub SecretKey);

/// Convenient use of private key signatures
impl Private {
    pub fn sign_no_aux(&self, msg: &Message) -> Result<Signature, Error> {
        let pubkey = PublicKey::from_secret_key(&self.0);
        sign_no_aux(msg.clone(), self.0.clone(), pubkey)
    }

    #[cfg(feature = "getrandom")]
    pub fn sign_with_rand(&self, msg: &Message) -> Result<Signature, Error> {
        let pubkey = PublicKey::from_secret_key(&self.0);
        sign_with_rand_aux(msg.clone(), self.0.clone(), pubkey)
    }

    pub fn generate_with<R>(mut csprng: R) -> Scalar
    where
        R: CryptoRng + RngCore,
    {
        let mut key: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut key);
        let mut s = Scalar::default();
        let _ = s.set_b32(&key);
        s
    }

    #[cfg(feature = "getrandom")]
    pub fn generate_nonce() -> Scalar {
        Self::generate_with(super::rand_hack())
    }

    #[cfg(feature = "getrandom")]
    pub fn generate() -> Result<Private, Error> {
        let s = Self::generate_with(super::rand_hack());
        let sk = SecretKey::try_from(s)?;
        Ok(Self(sk))
    }
}

impl From<SecretKey> for Private {
    fn from(s: SecretKey) -> Self {
        Self(s)
    }
}

impl TryFrom<&str> for Private {
    type Error = Error;

    fn try_from(secret: &str) -> Result<Self, Self::Error> {
        let mut sec_slice = [0u8; 32];
        sec_slice.copy_from_slice(&hex::decode(secret)?[..]);
        let seckey = SecretKey::parse_slice(&sec_slice)?;
        Ok(seckey.into())
    }
}
