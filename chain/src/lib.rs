#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

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

pub use light_bitcoin_primitives::*;

pub use self::block::Block;
pub use self::block_header::BlockHeader;
pub use self::merkle_root::{merkle_node_hash, merkle_root};
pub use self::transaction::{
    OutPoint, Transaction, TransactionInput, TransactionOutput, TransactionOutputArray,
};

pub use self::indexed_block::IndexedBlock;
pub use self::indexed_header::IndexedBlockHeader;
pub use self::indexed_transaction::IndexedTransaction;

pub use self::read_and_hash::{HashedData, ReadAndHash};
