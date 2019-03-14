#![cfg_attr(not(feature = "std"), no_std)]

pub mod constants;

mod block;
mod block_header;
mod merkle_root;
mod transaction;

mod indexed_block;
mod indexed_header;
mod indexed_transaction;
/// `IndexedBlock` extension
mod read_and_hash;

pub use primitives::*;

pub use self::block::{Block, RepresentH256};
pub use self::block_header::BlockHeader;
pub use self::merkle_root::{merkle_node_hash, merkle_root};
pub use self::transaction::{OutPoint, Transaction, TransactionInput, TransactionOutput};

pub use self::indexed_block::IndexedBlock;
pub use self::indexed_header::IndexedBlockHeader;
pub use self::indexed_transaction::IndexedTransaction;
pub use self::read_and_hash::{HashedData, ReadAndHash};

pub type ShortTransactionID = H48;
