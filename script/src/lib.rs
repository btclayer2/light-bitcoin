#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod builder;
mod error;
mod flags;
mod interpreter;
mod num;
mod opcode;
mod script;
mod sign;
mod stack;
mod verify;

pub use light_bitcoin_primitives::*;

pub use self::builder::Builder;
pub use self::error::Error;
pub use self::flags::VerificationFlags;
pub use self::interpreter::{eval_script, verify_script};
pub use self::num::Num;
pub use self::opcode::Opcode;
pub use self::script::{
    is_witness_commitment_script, Script, ScriptAddress, ScriptType, ScriptWitness,
};
pub use self::sign::{SignatureVersion, TransactionInputSigner, UnsignedTransactionInput};
pub use self::stack::Stack;
pub use self::verify::{NoopSignatureChecker, SignatureChecker, TransactionSignatureChecker};
