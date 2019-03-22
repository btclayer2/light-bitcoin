use ustd::prelude::*;

use primitives::{io, H256};
use serialization::{deserialize, Deserializable, Reader, Serializable, Stream};

use rustc_hex::FromHex;

use super::block_header::BlockHeader;
use super::merkle_root::merkle_root;
use super::transaction::Transaction;

pub trait RepresentH256 {
    fn h256(&self) -> H256;
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Default)]
pub struct Block {
    pub block_header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl From<&'static str> for Block {
    fn from(s: &'static str) -> Self {
        deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
    }
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            block_header: header,
            transactions,
        }
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
                let mut hashes = vec![H256::zero()];
                hashes.extend(rest.iter().map(Transaction::witness_hash));
                hashes
            }
        };
        merkle_root(&hashes)
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn header(&self) -> &BlockHeader {
        &self.block_header
    }

    pub fn hash(&self) -> H256 {
        self.block_header.hash()
    }
}

impl RepresentH256 for Block {
    fn h256(&self) -> H256 {
        self.hash()
    }
}

impl Serializable for Block {
    fn serialize(&self, stream: &mut Stream) {
        stream
            .append(&self.block_header)
            .append_list(&self.transactions);
    }
}

impl Deserializable for Block {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        Ok(Block {
            block_header: reader.read()?,
            transactions: reader.read_list()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::h256_from_rev_str;

    // Block 80000
    // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
    // https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6?format=hex
    #[test]
    fn test_block_merkle_root_and_hash() {
        let block: Block = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
        let merkle_root =
            h256_from_rev_str("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719");
        let hash =
            h256_from_rev_str("000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6");
        assert_eq!(block.merkle_root(), merkle_root);
        assert_eq!(block.hash(), hash);
    }
}
