use core::fmt;

use secp256k1::curve::Scalar;

use crate::{error::Error, xonly::XOnly};

/// A standard for 64-byte Schnorr signatures over the elliptic curve secp256k1
#[derive(Eq, PartialEq, Clone)]
pub struct Signature {
    pub rx: XOnly,
    pub s: Scalar,
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(self.rx.as_bytes());
        bytes[32..64].copy_from_slice(&self.s.b32());
        bytes
    }

    pub fn as_tuple(&self) -> (&XOnly, &Scalar) {
        (&self.rx, &self.s)
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let mut rx_bytes = [0u8; 32];
        rx_bytes.copy_from_slice(&bytes[0..32]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let mut s = Scalar::default();
        let _ = s.set_b32(&s_bytes);

        XOnly::from_bytes(rx_bytes).map(|rx| Signature { rx, s })
    }

    pub fn from_hex_str(str: &str) -> Result<Option<Self>, Error> {
        let mut s_slice = [0u8; 64];
        s_slice.copy_from_slice(&hex::decode(str)?[..]);
        Ok(Signature::from_bytes(s_slice))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.to_bytes()).fmt(f)
    }
}
