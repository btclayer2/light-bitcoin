//! Bitcoin transaction.
//! https://en.bitcoin.it/wiki/Protocol_documentation#tx

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{fmt, str};

use light_bitcoin_crypto::dhash256;
use light_bitcoin_primitives::{hash_rev, io, Bytes, H256};
use light_bitcoin_serialization::{
    deserialize, serialize, serialize_with_flags, Deserializable, Reader, Serializable, Stream,
    SERIALIZE_TRANSACTION_WITNESS,
};

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::constants::{LOCKTIME_THRESHOLD, SEQUENCE_FINAL};

/// Must be zero.
const WITNESS_MARKER: u8 = 0;
/// Must be nonzero.
const WITNESS_FLAG: u8 = 1;

/// A reference to a transaction output
#[derive(Ord, PartialOrd, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Serializable, Deserializable)]
pub struct OutPoint {
    /// The referenced transaction's txid
    ///
    /// Indicating user-visible serializations of this hash should be backward.
    pub txid: H256,
    /// The index of the referenced output in its transaction's vout
    pub index: u32,
}

impl fmt::Debug for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutPoint")
            .field("txid", &hash_rev(self.txid))
            .field("index", &self.index)
            .finish()
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        Self::null()
    }
}

impl OutPoint {
    /// Create a new [OutPoint].
    pub fn new(txid: H256, index: u32) -> Self {
        Self { txid, index }
    }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    pub fn null() -> Self {
        OutPoint {
            txid: H256::default(),
            index: u32::max_value(),
        }
    }

    /// Checks if an `OutPoint` is "null".
    pub fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct TransactionInput {
    /// The reference to the previous output that is being used an an input
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    pub script_sig: Bytes,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    pub script_witness: Vec<Bytes>,
}

impl TransactionInput {
    pub fn coinbase(script_sig: Bytes) -> Self {
        TransactionInput {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: SEQUENCE_FINAL,
            script_witness: vec![],
        }
    }

    pub fn is_final(&self) -> bool {
        self.sequence == SEQUENCE_FINAL
    }

    pub fn has_witness(&self) -> bool {
        !self.script_witness.is_empty()
    }
}

impl Serializable for TransactionInput {
    fn serialize(&self, stream: &mut Stream) {
        stream
            .append(&self.previous_output)
            .append(&self.script_sig)
            .append(&self.sequence);
    }
}

impl Deserializable for TransactionInput {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        Ok(TransactionInput {
            previous_output: reader.read()?,
            script_sig: reader.read()?,
            sequence: reader.read()?,
            script_witness: vec![],
        })
    }
}

/// A transaction output, which defines new coins to be created from old ones.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Serializable, Deserializable)]
pub struct TransactionOutput {
    /// The value of the output, in satoshis
    pub value: u64,
    /// The script which must satisfy for the output to be spent
    pub script_pubkey: Bytes,
}

impl Default for TransactionOutput {
    fn default() -> Self {
        TransactionOutput {
            value: 0xffff_ffff_ffff_ffffu64,
            script_pubkey: Bytes::default(),
        }
    }
}

/// A Bitcoin transaction, which describes an authenticated movement of coins.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: i32,
    /// List of inputs
    pub inputs: Vec<TransactionInput>,
    /// List of outputs
    pub outputs: Vec<TransactionOutput>,
    /// Block number before which this transaction is valid, or 0 for
    /// valid immediately.
    pub lock_time: u32,
}

// mainly use for test
impl str::FromStr for Transaction {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| "hex decode error")?;
        deserialize(bytes.as_slice()).map_err(|_| "deserialize error")
    }
}

impl Transaction {
    /// Compute hash of the transaction.
    ///
    /// Indicating user-visible serializations of this hash should be backward.
    /// For some reason Satoshi decided this for `Double Sha256 Hash`.
    pub fn hash(&self) -> H256 {
        dhash256(&serialize(self))
    }

    /// Compute witness hash of the transaction.
    ///
    /// Indicating user-visible serializations of this hash should be backward.
    /// For some reason Satoshi decided this for `Double Sha256 Hash`.
    pub fn witness_hash(&self) -> H256 {
        dhash256(&serialize_with_flags(self, SERIALIZE_TRANSACTION_WITNESS))
    }

    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs
    }

    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() || self.outputs.is_empty()
    }

    pub fn is_null(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| input.previous_output.is_null())
    }

    /// Is this a coin base transaction?
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
    }

    pub fn is_final(&self) -> bool {
        // if lock_time is 0, transaction is final
        if self.lock_time == 0 {
            return true;
        }
        // setting all sequence numbers to 0xffffffff disables the time lock, so if you want to use locktime,
        // at least one input must have a sequence number below the maximum.
        self.inputs.iter().all(TransactionInput::is_final)
    }

    pub fn is_final_in_block(&self, block_height: u32, block_time: u32) -> bool {
        if self.lock_time == 0 {
            return true;
        }

        let max_lock_time = if self.lock_time < LOCKTIME_THRESHOLD {
            block_height
        } else {
            block_time
        };

        if self.lock_time < max_lock_time {
            return true;
        }

        self.inputs.iter().all(TransactionInput::is_final)
    }

    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(TransactionInput::has_witness)
    }

    pub fn total_spends(&self) -> u64 {
        let mut result = 0u64;
        for output in self.outputs.iter() {
            if u64::max_value() - result < output.value {
                return u64::max_value();
            }
            result += output.value;
        }
        result
    }
}

impl Serializable for Transaction {
    fn serialize(&self, stream: &mut Stream) {
        let include_transaction_witness =
            stream.include_transaction_witness() && self.has_witness();
        if include_transaction_witness {
            stream
                .append(&self.version)
                .append(&WITNESS_MARKER)
                .append(&WITNESS_FLAG)
                .append_list(&self.inputs)
                .append_list(&self.outputs);
            for input in &self.inputs {
                stream.append_list(&input.script_witness);
            }
            stream.append(&self.lock_time);
        } else {
            stream
                .append(&self.version)
                .append_list(&self.inputs)
                .append_list(&self.outputs)
                .append(&self.lock_time);
        }
    }
}

impl Deserializable for Transaction {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let version = reader.read()?;
        let mut inputs: Vec<TransactionInput> = reader.read_list()?;
        let read_witness = if inputs.is_empty() {
            let witness_flag: u8 = reader.read()?;
            if witness_flag != WITNESS_FLAG {
                return Err(io::Error::ReadMalformedData);
            }

            inputs = reader.read_list()?;
            true
        } else {
            false
        };
        let outputs = reader.read_list()?;
        if read_witness {
            for input in inputs.iter_mut() {
                input.script_witness = reader.read_list()?;
            }
        }

        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time: reader.read()?,
        })
    }
}

impl codec::Encode for Transaction {
    fn encode(&self) -> Vec<u8> {
        let value = serialize::<Transaction>(&self);
        value.encode()
    }
}

impl codec::EncodeLike for Transaction {}

impl codec::Decode for Transaction {
    fn decode<I: codec::Input>(value: &mut I) -> Result<Self, codec::Error> {
        let value: Vec<u8> = codec::Decode::decode(value)?;
        deserialize(Reader::new(&value)).map_err(|_| "deserialize Transaction error".into())
    }
}

#[cfg(test)]
mod tests {
    use light_bitcoin_primitives::{h256, h256_rev};

    use super::*;

    // real transaction from block 80000
    // https://blockchain.info/rawtx/5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2
    // https://blockchain.info/rawtx/5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2?format=hex
    #[test]
    fn test_transaction_reader() {
        let t: Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".parse().unwrap();
        assert_eq!(t.version, 1);
        assert_eq!(t.lock_time, 0);
        assert_eq!(t.inputs.len(), 1);
        assert_eq!(t.outputs.len(), 1);
        let tx_input = &t.inputs[0];
        assert_eq!(tx_input.sequence, 4294967295);
        assert_eq!(tx_input.script_sig, "48304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501".parse().unwrap());
        let tx_output = &t.outputs[0];
        assert_eq!(tx_output.value, 5000000000);
        assert_eq!(
            tx_output.script_pubkey,
            "76a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac"
                .parse()
                .unwrap()
        );
        assert!(!t.has_witness());
    }

    #[test]
    fn test_transaction_hash() {
        let t: Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".parse().unwrap();
        let hash = h256_rev("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2");
        assert_eq!(t.hash(), hash);
    }

    #[test]
    fn test_transaction_serialized_len() {
        let raw_tx: &str = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000";
        let tx: Transaction = raw_tx.parse().unwrap();
        assert_eq!(tx.serialized_size(), raw_tx.len() / 2);
    }

    // test case from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
    #[test]
    fn test_transaction_reader_with_witness() {
        let actual: Transaction = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000".parse().unwrap();
        let expected = Transaction {
			version: 1,
			inputs: vec![TransactionInput {
				previous_output: OutPoint {
					txid: h256("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"),
					index: 0,
				},
				script_sig: "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01".parse().unwrap(),
				sequence: 0xffffffee,
				script_witness: vec![],
			}, TransactionInput {
				previous_output: OutPoint {
                    txid: h256("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"),
					index: 1,
				},
				script_sig: "".parse().unwrap(),
				sequence: 0xffffffff,
				script_witness: vec![
					"304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01".parse().unwrap(),
					"025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357".parse().unwrap(),
				],
			}],
			outputs: vec![TransactionOutput {
				value: 0x0000000006b22c20,
				script_pubkey: "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac".parse().unwrap(),
			}, TransactionOutput {
				value: 0x000000000d519390,
				script_pubkey: "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac".parse().unwrap(),
			}],
			lock_time: 0x00000011,
		};
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_serialization_with_flags() {
        let transaction_without_witness: Transaction = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
        assert_eq!(
            serialize_with_flags(&transaction_without_witness, 0),
            serialize_with_flags(&transaction_without_witness, SERIALIZE_TRANSACTION_WITNESS)
        );

        let transaction_with_witness: Transaction = "0000000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000000".parse().unwrap();
        assert_ne!(
            serialize_with_flags(&transaction_with_witness, 0),
            serialize_with_flags(&transaction_with_witness, SERIALIZE_TRANSACTION_WITNESS)
        );
    }

    #[test]
    fn test_witness_hash_differs() {
        let transaction_without_witness: Transaction = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
        assert_eq!(
            transaction_without_witness.hash(),
            transaction_without_witness.witness_hash()
        );

        let transaction_with_witness: Transaction = "0000000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000000".parse().unwrap();
        assert_ne!(
            transaction_with_witness.hash(),
            transaction_with_witness.witness_hash()
        );
    }
}
