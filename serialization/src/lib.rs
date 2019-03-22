#![cfg_attr(not(feature = "std"), no_std)]

mod compact_integer;
mod impls;
mod list;
mod reader;
mod stream;

pub use primitives::{io::Error, Bytes, Compact, H160, H256, H264, H32, H48, H512, H520};

pub use self::compact_integer::CompactInteger;
pub use self::list::List;
pub use self::reader::{deserialize, deserialize_iterator, Deserializable, ReadIterator, Reader};
pub use self::stream::{
    serialize, serialize_list, serialize_with_flags, serialized_list_size,
    serialized_list_size_with_flags, Serializable, Stream, SERIALIZE_TRANSACTION_WITNESS,
};
