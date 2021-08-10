//! The current is of little use, leaving room for subsequent development.
use secp256k1::{PublicKey, SecretKey};

use crate::error::Error;

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn from_secret_key(secret: SecretKey) -> Self {
        let public = PublicKey::from_secret_key(&secret);
        Self { secret, public }
    }

    pub fn from_secret_hex(secret: &str) -> Result<Self, Error> {
        let mut sec_slice = [0u8; 32];
        sec_slice.copy_from_slice(&hex::decode(secret)?[..]);
        let seckey = SecretKey::parse_slice(&sec_slice)?;
        Ok(KeyPair::from_secret_key(seckey))
    }
}
