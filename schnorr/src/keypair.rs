use secp256k1::{PublicKey, SecretKey};

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

    pub fn from_secret_str(secret: &str) -> Self {
        let mut sec_slice = [0u8; 32];
        sec_slice.copy_from_slice(&hex::decode(secret).unwrap()[..]);
        let seckey = SecretKey::parse_slice(&sec_slice).unwrap();
        KeyPair::from_secret_key(seckey)
    }
}
