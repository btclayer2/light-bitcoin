//! Secret with additional network identifier and format type

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{fmt, str};

use crypto::checksum;
use primitives::H520;

use crate::address::Network;
use crate::display::DisplayLayout;
use crate::error::Error;
use crate::signature::{CompactSignature, Signature};
use crate::{Message, Secret};

/// Secret with additional network identifier and format type
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Default)]
pub struct Private {
    /// The network on which this key should be used.
    pub network: Network,
    /// ECDSA key.
    pub secret: Secret,
    /// True if this private key represents a compressed address.
    pub compressed: bool,
}

impl fmt::Debug for Private {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "network: {:?}", self.network)?;
        writeln!(f, "secret: {}", self.secret)?;
        writeln!(f, "compressed: {}", self.compressed)
    }
}

impl fmt::Display for Private {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bs58::encode(self.layout().as_slice()).into_string().fmt(f)
    }
}

impl str::FromStr for Private {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let hex = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::InvalidPrivate)?;
        Private::from_layout(&hex)
    }
}

impl From<&'static str> for Private {
    fn from(s: &'static str) -> Self {
        s.parse().unwrap()
    }
}

impl Private {
    pub fn sign(&self, message: &Message) -> Result<Signature, Error> {
        let secret = secp256k1::SecretKey::parse(self.secret.as_fixed_bytes())?;
        let message = secp256k1::Message::parse(message.as_fixed_bytes());
        let (signature, _recovery_id) = secp256k1::sign(&message, &secret)?;
        // let (signature, _recovery_id) = secp256k1::sign(&message, &secret);
        Ok(signature.serialize_der().as_ref().to_vec().into())
    }

    pub fn sign_compact(&self, message: &Message) -> Result<CompactSignature, Error> {
        let secret = secp256k1::SecretKey::parse(self.secret.as_fixed_bytes())?;
        let message = secp256k1::Message::parse(message.as_fixed_bytes());
        let (signature, recovery_id) = secp256k1::sign(&message, &secret)?;
        // let (signature, recovery_id) = secp256k1::sign(&message, &secret);
        let recovery_id = recovery_id.serialize();
        let data = signature.serialize();

        let mut compact_signature = [0u8; 65];
        compact_signature[0] = if self.compressed {
            27 + recovery_id + 4
        } else {
            27 + recovery_id
        };
        compact_signature[1..65].copy_from_slice(&data);
        Ok(H520::from(compact_signature).into())
    }
}

impl DisplayLayout for Private {
    type Target = Vec<u8>;

    fn layout(&self) -> Self::Target {
        let mut result = vec![];
        let network_byte = match self.network {
            Network::Mainnet => 128,
            Network::Testnet => 239,
        };

        result.push(network_byte);
        result.extend(self.secret.as_bytes());
        if self.compressed {
            result.push(1);
        }
        let cs = checksum(&result);
        result.extend_from_slice(cs.as_bytes());
        result
    }

    fn from_layout(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let compressed = match data.len() {
            37 => false,
            38 => true,
            _ => return Err(Error::InvalidPrivate),
        };

        if compressed && data[data.len() - 5] != 1 {
            return Err(Error::InvalidPrivate);
        }

        let cs = checksum(&data[0..data.len() - 4]);
        if &data[data.len() - 4..] != cs.as_bytes() {
            return Err(Error::InvalidChecksum);
        }

        let network = match data[0] {
            128 => Network::Mainnet,
            239 => Network::Testnet,
            _ => return Err(Error::InvalidPrivate),
        };

        let secret = Secret::from_slice(&data[1..33]);

        Ok(Private {
            network,
            secret,
            compressed,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;
    use primitives::h256_from_rev_str;

    use super::*;

    #[test]
    fn test_private_to_string() {
        let private = Private {
            network: Network::Mainnet,
            secret: h256_from_rev_str(
                "063377054c25f98bc538ac8dd2cf9064dd5d253a725ece0628a34e2f84803bd5",
            ),
            compressed: false,
        };

        assert_eq!(
            private.to_string(),
            "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu".to_string(),
        );
    }

    #[test]
    fn test_private_from_str() {
        let private = Private {
            network: Network::Mainnet,
            secret: h256_from_rev_str(
                "063377054c25f98bc538ac8dd2cf9064dd5d253a725ece0628a34e2f84803bd5",
            ),
            compressed: false,
        };

        assert_eq!(
            private,
            "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu".into()
        );
    }
}
