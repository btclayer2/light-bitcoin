use core::fmt;

use light_bitcoin_primitives::{h256_conv_endian, io, H256};
use light_bitcoin_serialization::{Deserializable, Reader};

use crate::read_and_hash::ReadAndHash;
use crate::transaction::{transaction_hash, Transaction};

#[derive(Ord, PartialOrd, Eq, Clone, Default)]
pub struct IndexedTransaction {
    pub hash: H256,
    pub raw: Transaction,
}

impl PartialEq for IndexedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl fmt::Debug for IndexedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IndexedTransaction")
            .field("hash", &h256_conv_endian(self.hash))
            .field("raw", &self.raw)
            .finish()
    }
}

impl<T> From<T> for IndexedTransaction
where
    Transaction: From<T>,
{
    fn from(other: T) -> Self {
        Self::from_raw(other)
    }
}

impl IndexedTransaction {
    pub fn new(hash: H256, transaction: Transaction) -> Self {
        IndexedTransaction {
            hash,
            raw: transaction,
        }
    }

    /// Explicit conversion of the raw Transaction into IndexedTransaction.
    ///
    /// Hashes transaction contents.
    pub fn from_raw<T>(transaction: T) -> Self
    where
        Transaction: From<T>,
    {
        let transaction = Transaction::from(transaction);
        Self::new(transaction_hash(&transaction), transaction)
    }
}

impl Deserializable for IndexedTransaction {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
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
