#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::str;

use light_bitcoin_primitives::H256;
use light_bitcoin_serialization::{
    deserialize, serialized_list_size, serialized_list_size_with_flags, Deserializable,
    Serializable, SERIALIZE_TRANSACTION_WITNESS,
};

use crate::block::Block;
use crate::indexed_header::IndexedBlockHeader;
use crate::indexed_transaction::IndexedTransaction;
use crate::merkle_root::merkle_root;
use crate::transaction::Transaction;

#[derive(Ord, PartialOrd, Eq, Clone, Debug, Default, Deserializable)]
pub struct IndexedBlock {
    pub header: IndexedBlockHeader,
    pub transactions: Vec<IndexedTransaction>,
}

impl PartialEq for IndexedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.header.hash == other.header.hash
    }
}

impl From<Block> for IndexedBlock {
    fn from(block: Block) -> Self {
        Self::from_raw(block)
    }
}

// mainly use for test
impl str::FromStr for IndexedBlock {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| "hex decode error")?;
        deserialize(bytes.as_slice()).map_err(|_| "deserialize error")
    }
}

impl IndexedBlock {
    pub fn new(header: IndexedBlockHeader, transactions: Vec<IndexedTransaction>) -> Self {
        IndexedBlock {
            header,
            transactions,
        }
    }

    /// Explicit conversion of the raw Block into IndexedBlock.
    ///
    /// Hashes block header + transactions.
    pub fn from_raw(block: Block) -> Self {
        let Block {
            header: block_header,
            transactions,
        } = block;
        Self::new(
            IndexedBlockHeader::from_raw(block_header),
            transactions
                .into_iter()
                .map(IndexedTransaction::from_raw)
                .collect(),
        )
    }

    pub fn hash(&self) -> &H256 {
        &self.header.hash
    }

    pub fn raw_block(self) -> Block {
        Block::new(
            self.header.raw,
            self.transactions.into_iter().map(|tx| tx.raw).collect(),
        )
    }

    pub fn size(&self) -> usize {
        let header_size = self.header.raw.serialized_size();
        let transactions = self
            .transactions
            .iter()
            .map(|tx| &tx.raw)
            .collect::<Vec<_>>();
        let txs_size = serialized_list_size::<Transaction, &Transaction>(&transactions);
        header_size + txs_size
    }

    pub fn size_with_witness(&self) -> usize {
        let header_size = self.header.raw.serialized_size();
        let transactions = self
            .transactions
            .iter()
            .map(|tx| &tx.raw)
            .collect::<Vec<_>>();
        let txs_size = serialized_list_size_with_flags::<Transaction, &Transaction>(
            &transactions,
            SERIALIZE_TRANSACTION_WITNESS,
        );
        header_size + txs_size
    }

    pub fn merkle_root(&self) -> H256 {
        merkle_root(
            self.transactions
                .iter()
                .map(|tx| tx.hash)
                .collect::<Vec<H256>>()
                .as_slice(),
        )
    }

    pub fn witness_merkle_root(&self) -> H256 {
        let hashes = match self.transactions.split_first() {
            None => vec![],
            Some((_, rest)) => {
                let mut hashes = vec![H256::zero()];
                hashes.extend(rest.iter().map(|tx| tx.raw.witness_hash()));
                hashes
            }
        };
        merkle_root(&hashes)
    }

    pub fn is_final(&self, height: u32) -> bool {
        self.transactions
            .iter()
            .all(|tx| tx.raw.is_final_in_block(height, self.header.raw.time))
    }
}

#[cfg(test)]
mod tests {
    use super::IndexedBlock;

    #[test]
    fn size_with_witness_not_equal_to_size() {
        let block_without_witness: IndexedBlock = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
        assert_eq!(
            block_without_witness.size(),
            block_without_witness.size_with_witness()
        );

        // bip143 block
        let block_with_witness: IndexedBlock = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000000".parse().unwrap();
        assert_ne!(
            block_with_witness.size(),
            block_with_witness.size_with_witness()
        );
    }
}
