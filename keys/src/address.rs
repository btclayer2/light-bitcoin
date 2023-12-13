//! `AddressHash` with network identifier and format type
//!
//! A Bitcoin address, or simply address, is an identifier of 26-35 alphanumeric characters, beginning with the number 1
//! or 3, that represents a possible destination for a bitcoin payment.
//!
//! https://en.bitcoin.it/wiki/Address

extern crate alloc;
use alloc::string::{String, ToString};
use core::{convert::TryFrom, fmt, ops, str, str::FromStr};

use bitcoin_bech32::constants::Network as Bech32Network;
use bitcoin_bech32::{u5, WitnessProgram};
use light_bitcoin_crypto::checksum;
use light_bitcoin_primitives::{io, H160, H256};
use light_bitcoin_serialization::{Deserializable, Reader, Serializable, Stream};

use codec::{Decode, Encode};

use crate::display::DisplayLayout;
use crate::error::Error;
use crate::{AddressHash, XOnly};

/// There are two address formats currently in use.
/// https://bitcoin.org/en/developer-reference#address-conversion
#[derive(
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Debug,
    Decode,
    Encode,
    scale_info::TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum Type {
    /// Pay to PubKey Hash
    /// Common P2PKH which begin with the number 1, eg: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
    /// https://bitcoin.org/en/glossary/p2pkh-address
    P2PKH,
    /// Pay to Script Hash
    /// Newer P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
    /// https://bitcoin.org/en/glossary/p2sh-address
    P2SH,
    /// Pay to Witness PubKey Hash
    P2WPKH,
    /// Pay to Witness Script Hash
    P2WSH,
    /// Pay to Witness Taproot
    P2TR,
}

impl Default for Type {
    fn default() -> Type {
        Type::P2PKH
    }
}

impl Type {
    pub fn from(v: u32) -> Option<Self> {
        match v {
            0 => Some(Type::P2PKH),
            1 => Some(Type::P2SH),
            2 => Some(Type::P2WPKH),
            3 => Some(Type::P2WSH),
            4 => Some(Type::P2TR),
            _ => None,
        }
    }
}

impl Serializable for Type {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            Type::P2PKH => s.append(&Type::P2PKH),
            Type::P2SH => s.append(&Type::P2SH),
            Type::P2WPKH => s.append(&Type::P2WPKH),
            Type::P2WSH => s.append(&Type::P2WSH),
            Type::P2TR => s.append(&Type::P2TR),
        };
    }
}

impl Deserializable for Type {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let t: u32 = reader.read()?;
        Type::from(t).ok_or(io::Error::ReadMalformedData)
    }
}

#[derive(
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Debug,
    Decode,
    Encode,
    scale_info::TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum Network {
    // Bitcoin Mainnet
    Mainnet,
    // Bitcoin Testnet
    Testnet,
    // Dogecoin Mainnet
    DogeCoinMainnet,
    // Dogecoin Testnet
    DogeCoinTestnet,
}

impl ToString for Network {
    fn to_string(&self) -> String {
        match self {
            Network::Mainnet => "Mainnet".to_string(),
            Network::Testnet => "Testnet".to_string(),
            Network::DogeCoinMainnet => "Dogecoin Mainnet".to_string(),
            Network::DogeCoinTestnet => "Dogecoin Testnet".to_string(),
        }
    }
}

impl Default for Network {
    fn default() -> Network {
        Network::Mainnet
    }
}

impl Network {
    pub fn from(v: u32) -> Option<Self> {
        match v {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            2 => Some(Network::DogeCoinMainnet),
            3 => Some(Network::DogeCoinTestnet),
            _ => None,
        }
    }
}

impl Serializable for Network {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            Network::Mainnet => s.append(&Network::Mainnet),
            Network::Testnet => s.append(&Network::Testnet),
            Network::DogeCoinMainnet => s.append(&Network::DogeCoinMainnet),
            Network::DogeCoinTestnet => s.append(&Network::DogeCoinTestnet),
        };
    }
}

impl Deserializable for Network {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let t: u32 = reader.read()?;
        Network::from(t).ok_or(io::Error::ReadMalformedData)
    }
}

#[derive(
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Debug,
    Decode,
    Encode,
    scale_info::TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum AddressTypes {
    Legacy(AddressHash),
    WitnessV0ScriptHash(H256),
    WitnessV0KeyHash(H160),
    WitnessV1Taproot(XOnly),
}

impl Default for AddressTypes {
    fn default() -> Self {
        AddressTypes::Legacy(AddressHash::default())
    }
}

impl Serializable for AddressTypes {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            AddressTypes::Legacy(h) => s.append(&0).append(&h),
            AddressTypes::WitnessV0ScriptHash(h) => s.append(&1).append(&h),
            AddressTypes::WitnessV0KeyHash(h) => s.append(&2).append(&h),
            AddressTypes::WitnessV1Taproot(h) => s.append(&3).append_slice(&h.0),
        };
    }
}

impl Deserializable for AddressTypes {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let t: u32 = reader.read()?;
        match t {
            0 => {
                let h: H160 = reader.read()?;
                Ok(AddressTypes::Legacy(h))
            }
            1 => {
                let h: H256 = reader.read()?;
                Ok(AddressTypes::WitnessV0ScriptHash(h))
            }
            2 => {
                let h: H160 = reader.read()?;
                Ok(AddressTypes::WitnessV0KeyHash(h))
            }
            3 => {
                let mut keys = [0u8; 32];
                reader.read_slice(&mut keys)?;

                Ok(AddressTypes::WitnessV1Taproot(XOnly(keys)))
            }
            _ => Err(io::Error::ReadMalformedData),
        }
    }
}

/// `AddressHash` with network identifier and format type
#[derive(
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Debug,
    Default,
    Decode,
    Encode,
    scale_info::TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
#[derive(Serializable, Deserializable)]
pub struct Address {
    /// The type of the address.
    pub kind: Type,
    /// The network of the address.
    pub network: Network,
    /// Public key hash.
    pub hash: AddressTypes,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let network = match self.network {
            Network::Mainnet => Bech32Network::Bitcoin,
            _ => Bech32Network::Testnet,
        };
        match self.hash {
            AddressTypes::Legacy(_) => bs58::encode(self.layout().0).into_string().fmt(f),
            AddressTypes::WitnessV0ScriptHash(h) => {
                let witness = WitnessProgram::new(
                    u5::try_from_u8(0).map_err(|_| fmt::Error)?,
                    h.0.to_vec(),
                    network,
                )
                .map_err(|_| fmt::Error)?;
                witness.to_string().fmt(f)
            }
            AddressTypes::WitnessV0KeyHash(h) => {
                let witness = WitnessProgram::new(
                    u5::try_from_u8(0).map_err(|_| fmt::Error)?,
                    h.0.to_vec(),
                    network,
                )
                .map_err(|_| fmt::Error)?;
                witness.to_string().fmt(f)
            }
            AddressTypes::WitnessV1Taproot(h) => {
                let witness = WitnessProgram::new(
                    u5::try_from_u8(1).map_err(|_| fmt::Error)?,
                    h.0.to_vec(),
                    network,
                )
                .map_err(|_| fmt::Error)?;
                witness.to_string().fmt(f)
            }
        }
    }
}

fn bs58_decode(s: &str) -> Result<Address, Error> {
    let hex = bs58::decode(s)
        .into_vec()
        .map_err(|_| Error::InvalidAddress)?;
    Address::from_layout(&hex)
}

fn bech32_decode(s: &str) -> Result<Address, Error> {
    let witness = WitnessProgram::from_str(s).map_err(|_| Error::InvalidAddress)?;
    let version = witness.version().to_u8();
    let network = match witness.network() {
        Bech32Network::Bitcoin => Network::Mainnet,
        _ => Network::Testnet,
    };
    let (kind, hash) = if version == 1 {
        (
            Type::P2TR,
            AddressTypes::WitnessV1Taproot(XOnly::try_from(witness.program())?),
        )
    } else if witness.program().len() == 20 {
        (
            Type::P2WPKH,
            AddressTypes::WitnessV0KeyHash(H160::from_slice(witness.program())),
        )
    } else {
        (
            Type::P2WSH,
            AddressTypes::WitnessV0ScriptHash(H256::from_slice(witness.program())),
        )
    };
    Ok(Address {
        kind,
        network,
        hash,
    })
}

impl str::FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let data = bs58_decode(s);
        if data.is_ok() {
            data
        } else {
            bech32_decode(s)
        }
    }
}

#[derive(
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Debug,
    Default,
    Decode,
    Encode,
    scale_info::TypeInfo
)]
pub struct AddressDisplayLayout([u8; 25]);

impl ops::Deref for AddressDisplayLayout {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DisplayLayout for Address {
    type Target = AddressDisplayLayout;

    fn layout(&self) -> Self::Target {
        let mut result = [0u8; 25];

        result[0] = match (self.network, self.kind) {
            (Network::Mainnet, Type::P2PKH) => 0,
            (Network::Mainnet, Type::P2SH) => 5,
            (Network::Testnet, Type::P2PKH) => 111,
            (Network::Testnet, Type::P2SH) => 196,
            (Network::DogeCoinMainnet, Type::P2PKH) => 30,
            (Network::DogeCoinMainnet, Type::P2SH) => 22,
            (Network::DogeCoinTestnet, Type::P2PKH) => 113,
            (Network::DogeCoinTestnet, Type::P2SH) => 196,
            _ => todo!(),
        };

        match self.hash {
            AddressTypes::Legacy(h) => result[1..21].copy_from_slice(h.as_bytes()),
            _ => todo!(),
        };
        let cs = checksum(&result[0..21]);
        result[21..25].copy_from_slice(cs.as_bytes());
        AddressDisplayLayout(result)
    }

    fn from_layout(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if data.len() != 25 {
            return Err(Error::InvalidAddress);
        }

        let cs = checksum(&data[0..21]);
        if &data[21..] != cs.as_bytes() {
            return Err(Error::InvalidChecksum);
        }

        let (network, kind) = match data[0] {
            0 => (Network::Mainnet, Type::P2PKH),
            5 => (Network::Mainnet, Type::P2SH),
            111 => (Network::Testnet, Type::P2PKH),
            30 => (Network::DogeCoinMainnet, Type::P2PKH),
            22 => (Network::DogeCoinMainnet, Type::P2SH),
            113 => (Network::DogeCoinTestnet, Type::P2PKH),
            196 => (Network::DogeCoinTestnet, Type::P2SH),
            _ => return Err(Error::InvalidAddress),
        };

        let hash = AddressHash::from_slice(&data[1..21]);
        Ok(Address {
            kind,
            network,
            hash: AddressTypes::Legacy(hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use light_bitcoin_primitives::h160;

    #[test]
    fn test_address_to_string() {
        let address = Address {
            kind: Type::P2PKH,
            network: Network::DogeCoinMainnet,
            hash: AddressTypes::Legacy(h160("4ecd07e6f2683d43e82c8191b5414d1387eeb1dd")),
        };
        assert_eq!(
            address.to_string(),
            "DCKks1rtZnCHJMvpHTqQTDvYs6sah7K6J1".to_string(),
        );

        let address = Address {
            kind: Type::P2SH,
            network: Network::DogeCoinMainnet,
            hash: AddressTypes::Legacy(h160("38a2935dbb241efa8144dc10559a7ac9bba33664")),
        };
        assert_eq!(
            address.to_string(),
            "9wbjG5xnc1MPEZX5kK7YQPqx9t8GVvYq6G".to_string(),
        );
    }

    #[test]
    fn test_address_from_str() {
        let address = Address {
            kind: Type::P2PKH,
            network: Network::DogeCoinMainnet,
            hash: AddressTypes::Legacy(h160("4ecd07e6f2683d43e82c8191b5414d1387eeb1dd")),
        };
        assert_eq!(
            address,
            "DCKks1rtZnCHJMvpHTqQTDvYs6sah7K6J1".parse().unwrap()
        );

        let address = Address {
            kind: Type::P2SH,
            network: Network::DogeCoinMainnet,
            hash: AddressTypes::Legacy(h160("38a2935dbb241efa8144dc10559a7ac9bba33664")),
        };
        assert_eq!(
            address,
            "9wbjG5xnc1MPEZX5kK7YQPqx9t8GVvYq6G".parse().unwrap()
        );
    }
}
