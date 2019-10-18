#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::fmt;

use crypto::dhash256;
use primitives::{Compact, H256};
use serialization::{deserialize, serialize, Deserializable, Reader, Serializable};

use rustc_hex::FromHex;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Default, Serializable, Deserializable)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlockHeader {
    pub version: u32,
    pub previous_header_hash: H256,
    pub merkle_root_hash: H256,
    pub time: u32,
    pub bits: Compact,
    pub nonce: u32,
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let reverse_hash = |hash: &H256| {
            let mut res = H256::from_slice(hash.as_bytes());
            let bytes = res.as_bytes_mut();
            bytes.reverse();
            res
        };
        f.debug_struct("BlockHeader")
            .field("version", &self.version)
            .field(
                "previous_header_hash",
                &reverse_hash(&self.previous_header_hash),
            )
            .field("merkle_root_hash", &reverse_hash(&self.merkle_root_hash))
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl From<&'static str> for BlockHeader {
    fn from(s: &'static str) -> Self {
        deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
    }
}

impl BlockHeader {
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

impl codec::Decode for BlockHeader {
    fn decode<I: codec::Input>(value: &mut I) -> Option<Self> {
        let value: Option<Vec<u8>> = codec::Decode::decode(value);
        if let Some(value) = value {
            deserialize(Reader::new(&value)).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use serialization::{Reader, Stream};

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

        let expected = vec![
            1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0,
        ]
        .into();

        assert_eq!(stream.out(), expected);
    }

    #[test]
    fn test_block_header_reader() {
        let buffer = vec![
            1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0,
        ];

        let mut reader = Reader::new(&buffer);

        let expected = BlockHeader {
            version: 1,
            previous_header_hash: [2; 32].into(),
            merkle_root_hash: [3; 32].into(),
            time: 4,
            bits: 5.into(),
            nonce: 6,
        };

        assert_eq!(expected, reader.read().unwrap());
        assert_eq!(
            primitives::io::Error::UnexpectedEof,
            reader.read::<BlockHeader>().unwrap_err()
        );
    }
}
