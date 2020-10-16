#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::str;

use light_bitcoin_primitives::H256;
use light_bitcoin_serialization::{deserialize, Deserializable, Serializable};

use crate::block_header::BlockHeader;
use crate::merkle_root::merkle_root;
use crate::transaction::Transaction;

/// A Bitcoin block, which is a collection of transactions with an attached proof of work.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Default)]
#[derive(Serializable, Deserializable)]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// List of transactions contained in the block
    pub transactions: Vec<Transaction>,
}

// mainly use for test
impl str::FromStr for Block {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| "hex decode error")?;
        deserialize(bytes.as_slice()).map_err(|_| "deserialize error")
    }
}

impl Block {
    /// Create a new Block.
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
        }
    }

    /// Return the block hash.
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }

    /// Returns block's merkle root.
    pub fn merkle_root(&self) -> H256 {
        let hashes = self
            .transactions
            .iter()
            .map(Transaction::hash)
            .collect::<Vec<H256>>();
        merkle_root(&hashes)
    }

    /// Returns block's witness merkle root.
    pub fn witness_merkle_root(&self) -> H256 {
        let hashes = match self.transactions.split_first() {
            None => vec![],
            Some((_, rest)) => {
                // Replace the first hash with zeroes.
                let mut hashes = vec![H256::zero()];
                hashes.extend(rest.iter().map(Transaction::witness_hash));
                hashes
            }
        };
        merkle_root(&hashes)
    }

    /// Return the block header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Return the transactions in the block.
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

#[cfg(test)]
mod tests {
    use light_bitcoin_primitives::h256_rev;

    use super::Block;

    // Block 80000
    // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
    // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6?format=hex
    #[test]
    fn test_block_merkle_root_and_hash() {
        let block: Block = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".parse().unwrap();
        let root = h256_rev("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719");
        assert_eq!(block.merkle_root(), root);
        let hash = h256_rev("000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6");
        assert_eq!(block.hash(), hash);
    }
}
