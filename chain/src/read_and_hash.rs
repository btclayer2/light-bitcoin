use light_bitcoin_crypto::{DHash256, Digest};
use light_bitcoin_primitives::{io, H256};
use light_bitcoin_serialization::{Deserializable, Reader};

pub struct HashedData<T> {
    pub size: usize,
    pub hash: H256,
    pub data: T,
}

pub trait ReadAndHash {
    fn read_and_hash<T>(&mut self) -> Result<HashedData<T>, io::Error>
    where
        T: Deserializable;
}

impl<R> ReadAndHash for Reader<R>
where
    R: io::Read,
{
    fn read_and_hash<T>(&mut self) -> Result<HashedData<T>, io::Error>
    where
        T: Deserializable,
    {
        let mut size = 0usize;
        let mut hasher = DHash256::new();
        let data = self.read_with_proxy(|bytes| {
            size += bytes.len();
            hasher.update(bytes);
        })?;

        Ok(HashedData {
            hash: hasher.finish(),
            data,
            size,
        })
    }
}
