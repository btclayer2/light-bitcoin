use core::fmt;

use primitives::{h256_reverse, io, H256};
use serialization::{Deserializable, Reader};

use crate::block_header::{block_header_hash, BlockHeader};
use crate::read_and_hash::ReadAndHash;

#[derive(Ord, PartialOrd, Eq, Copy, Clone, Default)]
pub struct IndexedBlockHeader {
    pub hash: H256,
    pub raw: BlockHeader,
}

impl PartialEq for IndexedBlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl fmt::Debug for IndexedBlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IndexedBlockHeader")
            .field("hash", &h256_reverse(self.hash))
            .field("raw", &self.raw)
            .finish()
    }
}

impl From<BlockHeader> for IndexedBlockHeader {
    fn from(header: BlockHeader) -> Self {
        Self::from_raw(header)
    }
}

impl IndexedBlockHeader {
    pub fn new(hash: H256, header: BlockHeader) -> Self {
        IndexedBlockHeader { hash, raw: header }
    }

    /// Explicit conversion of the raw BlockHeader into IndexedBlockHeader.
    ///
    /// Hashes the contents of block header.
    pub fn from_raw(header: BlockHeader) -> Self {
        IndexedBlockHeader::new(block_header_hash(&header), header)
    }
}

impl Deserializable for IndexedBlockHeader {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
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
