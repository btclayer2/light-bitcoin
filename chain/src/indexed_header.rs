use core::fmt;

use light_bitcoin_primitives::{hash_rev, io, H256};
use light_bitcoin_serialization::{Deserializable, Reader};

use crate::block_header::BlockHeader;
use crate::read_and_hash::ReadAndHash;

#[derive(Ord, PartialOrd, Eq, Copy, Clone, Default, scale_info::TypeInfo)]
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexedBlockHeader")
            .field("hash", &hash_rev(self.hash))
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
        IndexedBlockHeader::new(header.hash(), header)
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
