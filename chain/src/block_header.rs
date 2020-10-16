#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{fmt, str};

use light_bitcoin_crypto::dhash256;
use light_bitcoin_primitives::{hash_rev, Compact, H256};
use light_bitcoin_serialization::{deserialize, serialize, Deserializable, Reader, Serializable};

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// A block header, which contains all the block's information except
/// the actual transactions
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Serializable, Deserializable)]
pub struct BlockHeader {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    ///
    /// Indicating user-visible serializations of this hash should be backward.
    pub previous_header_hash: H256,
    /// The root hash of the merkle tree of transactions in the block
    ///
    /// Indicating user-visible serializations of this hash should be backward.
    pub merkle_root_hash: H256,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    /// The target value below which the block hash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: Compact,
    /// The nonce, selected to obtain a low enough block hash
    pub nonce: u32,
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockHeader")
            .field("version", &self.version)
            .field("previous_header_hash", &hash_rev(self.previous_header_hash))
            .field("merkle_root_hash", &hash_rev(self.merkle_root_hash))
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}

// mainly use for test
impl str::FromStr for BlockHeader {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| "hex decode error")?;
        deserialize(bytes.as_slice()).map_err(|_| "deserialize error")
    }
}

impl BlockHeader {
    /// Compute hash of the block header.
    ///
    /// Indicating user-visible serializations of this hash should be backward.
    /// For some reason Satoshi decided this for `Double Sha256 Hash`.
    pub fn hash(&self) -> H256 {
        dhash256(&serialize(self))
    }
}

impl codec::Encode for BlockHeader {
    fn encode(&self) -> Vec<u8> {
        let value = serialize::<BlockHeader>(&self);
        value.encode()
    }
}

impl codec::EncodeLike for BlockHeader {}

impl codec::Decode for BlockHeader {
    fn decode<I: codec::Input>(value: &mut I) -> Result<Self, codec::Error> {
        let value: Vec<u8> = codec::Decode::decode(value)?;
        deserialize(Reader::new(&value)).map_err(|_| "deserialize BlockHeader error".into())
    }
}

#[cfg(test)]
mod tests {
    use light_bitcoin_primitives::{h256_rev, io, Bytes};
    use light_bitcoin_serialization::{Reader, Stream};

    use super::*;

    #[test]
    fn test_block_header_stream() {
        let block_header = BlockHeader {
            version: 1,
            previous_header_hash: [2; 32].into(),
            merkle_root_hash: [3; 32].into(),
            time: 4,
            bits: 5.into(),
            nonce: 6,
        };

        let mut stream = Stream::default();
        stream.append(&block_header);

        assert_eq!(
            format!("{:?}", stream.out()),
            "01000000\
            0202020202020202020202020202020202020202020202020202020202020202\
            0303030303030303030303030303030303030303030303030303030303030303\
            04000000\
            05000000\
            06000000"
        );

        // Block 80000
        // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
        // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6?format=hex
        let block_header = BlockHeader {
            version: 1,
            previous_header_hash: h256_rev(
                "00000000001937917bd2caba204bb1aa530ec1de9d0f6736e5d85d96da9c8bba",
            ),
            merkle_root_hash: h256_rev(
                "8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719",
            ),
            time: 1284613427,
            bits: 459009510.into(),
            nonce: 1462756097,
        };

        let mut stream = Stream::default();
        stream.append(&block_header);

        assert_eq!(
            format!("{:?}", stream.out()),
            "01000000\
            ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000\
            190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f\
            33a5914c\
            e6ed5b1b\
            01e32f57"
        );
    }

    #[test]
    fn test_block_header_reader() {
        let buffer = "\
        01000000\
        0202020202020202020202020202020202020202020202020202020202020202\
        0303030303030303030303030303030303030303030303030303030303030303\
        04000000\
        05000000\
        06000000\
        "
        .parse::<Bytes>()
        .unwrap();

        let mut reader = Reader::new(&buffer);
        let got = reader.read::<BlockHeader>().unwrap();
        let expected = BlockHeader {
            version: 1,
            previous_header_hash: [2; 32].into(),
            merkle_root_hash: [3; 32].into(),
            time: 4,
            bits: 5.into(),
            nonce: 6,
        };
        assert_eq!(got, expected);

        let got = reader.read::<BlockHeader>().unwrap_err();
        assert_eq!(got, io::Error::UnexpectedEof);

        // Block 80000
        // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
        // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6?format=hex
        let buffer = "\
        01000000\
        ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000\
        190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f\
        33a5914c\
        e6ed5b1b\
        01e32f57\
        "
        .parse::<Bytes>()
        .unwrap();
        let mut reader = Reader::new(&buffer);
        let got = reader.read::<BlockHeader>().unwrap();
        let expected = BlockHeader {
            version: 1,
            previous_header_hash: h256_rev(
                "00000000001937917bd2caba204bb1aa530ec1de9d0f6736e5d85d96da9c8bba",
            ),
            merkle_root_hash: h256_rev(
                "8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719",
            ),
            time: 1284613427,
            bits: 459009510.into(),
            nonce: 1462756097,
        };
        assert_eq!(got, expected);

        let got = reader.read::<BlockHeader>().unwrap_err();
        assert_eq!(got, io::Error::UnexpectedEof);
    }
}
