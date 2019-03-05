use rstd::{fmt, prelude::*};

use primitives::{io, H256};
use serialization::{Deserializable, Error as ReaderError, Reader};

use super::read_and_hash::ReadAndHash;
use super::transaction::Transaction;

#[derive(Ord, PartialOrd, Eq, Clone, Default)]
pub struct IndexedTransaction {
    pub hash: H256,
    pub raw: Transaction,
}

impl IndexedTransaction {
    pub fn new(hash: H256, transaction: Transaction) -> Self {
        IndexedTransaction {
            hash,
            raw: transaction,
        }
    }
}

impl fmt::Debug for IndexedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let reverse_hash = |hash: &H256| {
            let mut res = H256::from_slice(hash.as_bytes());
            let bytes = res.as_bytes_mut();
            bytes.reverse();
            res
        };
        f.debug_struct("IndexedTransaction")
            .field("hash", &reverse_hash(&self.hash))
            .field("raw", &self.raw)
            .finish()
    }
}

impl PartialEq for IndexedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<T> From<T> for IndexedTransaction
where
    Transaction: From<T>,
{
    fn from(other: T) -> Self {
        let tx = Transaction::from(other);
        IndexedTransaction {
            hash: tx.hash(),
            raw: tx,
        }
    }
}

impl Deserializable for IndexedTransaction {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, ReaderError>
    where
        T: io::Read,
    {
        let data = reader.read_and_hash::<Transaction>()?;
        // TODO: use len
        let tx = IndexedTransaction {
            raw: data.data,
            hash: data.hash,
        };

        Ok(tx)
    }
}
