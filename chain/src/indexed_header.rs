use rstd::{fmt, prelude::*};

use primitives::{io, H256};
use serialization::{Deserializable, Error as ReaderError, Reader};

use super::block_header::BlockHeader;
use super::read_and_hash::ReadAndHash;

#[derive(Ord, PartialOrd, Eq, Copy, Clone, Default)]
pub struct IndexedBlockHeader {
    pub hash: H256,
    pub raw: BlockHeader,
}

impl IndexedBlockHeader {
    pub fn new(hash: H256, header: BlockHeader) -> Self {
        IndexedBlockHeader { hash, raw: header }
    }
}

impl fmt::Debug for IndexedBlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let reverse_hash = |hash: &H256| {
            let mut res = H256::from_slice(hash.as_bytes());
            let bytes = res.as_bytes_mut();
            bytes.reverse();
            res
        };
        f.debug_struct("IndexedBlockHeader")
            .field("hash", &reverse_hash(&self.hash))
            .field("raw", &self.raw)
            .finish()
    }
}

impl PartialEq for IndexedBlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl From<BlockHeader> for IndexedBlockHeader {
    fn from(header: BlockHeader) -> Self {
        IndexedBlockHeader {
            hash: header.hash(),
            raw: header,
        }
    }
}

impl Deserializable for IndexedBlockHeader {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, ReaderError>
    where
        T: io::Read,
    {
        let data = reader.read_and_hash::<BlockHeader>()?;
        // TODO: use len
        Ok(IndexedBlockHeader {
            raw: data.data,
            hash: data.hash,
        })
    }
}
