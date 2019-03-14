use ustd::prelude::*;

use primitives::{io, H256};
use serialization::{
    deserialize, serialized_list_size, serialized_list_size_with_flags, Deserializable, Reader,
    Serializable, SERIALIZE_TRANSACTION_WITNESS,
};

use rustc_hex::FromHex;

use super::block::Block;
use super::indexed_header::IndexedBlockHeader;
use super::indexed_transaction::IndexedTransaction;
use super::merkle_root::merkle_root;
use super::transaction::Transaction;

#[derive(Ord, PartialOrd, Eq, Clone, Debug, Default)]
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
        let Block {
            block_header,
            transactions,
        } = block;

        IndexedBlock {
            header: block_header.into(),
            transactions: transactions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&'static str> for IndexedBlock {
    fn from(s: &'static str) -> Self {
        deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
    }
}

impl IndexedBlock {
    pub fn new(header: IndexedBlockHeader, transactions: Vec<IndexedTransaction>) -> Self {
        IndexedBlock {
            header,
            transactions,
        }
    }

    pub fn hash(&self) -> &H256 {
        &self.header.hash
    }

    pub fn to_raw_block(&self) -> Block {
        Block::new(
            self.header.raw,
            self.transactions.iter().map(|tx| tx.raw.clone()).collect(),
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

impl Deserializable for IndexedBlock {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        Ok(IndexedBlock {
            header: reader.read()?,
            transactions: reader.read_list()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::IndexedBlock;

    #[test]
    fn size_with_witness_not_equal_to_size() {
        let block_without_witness: IndexedBlock = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
        assert_eq!(
            block_without_witness.size(),
            block_without_witness.size_with_witness()
        );

        // bip143 block
        let block_with_witness: IndexedBlock = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000000".into();
        assert_ne!(
            block_with_witness.size(),
            block_with_witness.size_with_witness()
        );
    }
}
