// Copyright 2018 Chainpool

#![cfg_attr(not(feature = "std"), no_std)]

use ustd::{cmp, prelude::*};

use chain::merkle_node_hash;
use primitives::{io, H256};
use serialization::{deserialize, serialize, Deserializable, Reader, Serializable, Stream};

pub use bit_vec::BitVec;
use parity_codec::{Decode, Encode, Input};

#[derive(Debug)]
pub enum Error {
    NoTx,
    SurplusHash,
    NotMatch,
    AllUsed,
    SameHash,
}

/// Partial merkle tree
#[derive(PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PartialMerkleTree {
    /// Total number of transactions
    pub tx_count: u32,
    /// Nodes hashes
    pub hashes: Vec<H256>,
    /// Match flags
    pub flags: BitVec,
}

impl PartialMerkleTree {
    /// Create new merkle tree with given data
    pub fn new(tx_count: u32, hashes: Vec<H256>, flags: BitVec) -> Self {
        PartialMerkleTree {
            tx_count,
            hashes,
            flags,
        }
    }

    /// Build partial merkle tree
    pub fn build(tx_hashes: Vec<H256>, tx_matches: BitVec) -> Self {
        PartialMerkleTreeBuilder::build(tx_hashes, tx_matches)
    }

    /// Parse partial merkle tree
    pub fn parse(self) -> Result<ParsedPartialMerkleTree, Error> {
        PartialMerkleTreeBuilder::parse(self)
    }
}

impl Serializable for PartialMerkleTree {
    fn serialize(&self, stream: &mut Stream) {
        stream
            .append(&self.tx_count)
            .append_list(&self.hashes)
            // to_bytes() converts [true, false, true] to 0b10100000
            // while protocol requires [true, false, true] to be serialized as 0x00000101
            .append_list(
                &self
                    .flags
                    .to_bytes()
                    .into_iter()
                    .map(|b| {
                        ((b & 0b1000_0000) >> 7)
                            | ((b & 0b0100_0000) >> 5)
                            | ((b & 0b0010_0000) >> 3)
                            | ((b & 0b0001_0000) >> 1)
                            | ((b & 0b0000_1000) << 1)
                            | ((b & 0b0000_0100) << 3)
                            | ((b & 0b0000_0010) << 5)
                            | ((b & 0b0000_0001) << 7)
                    })
                    .collect::<Vec<u8>>(),
            );
    }
}

impl Deserializable for PartialMerkleTree {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        Ok(PartialMerkleTree {
            tx_count: reader.read()?,
            hashes: reader.read_list()?,
            flags: {
                let flags_bytes: Vec<u8> = reader.read_list()?;
                BitVec::from_bytes(
                    &(flags_bytes
                        .into_iter()
                        .map(|b| {
                            ((b & 0b1000_0000) >> 7)
                                | ((b & 0b0100_0000) >> 5)
                                | ((b & 0b0010_0000) >> 3)
                                | ((b & 0b0001_0000) >> 1)
                                | ((b & 0b0000_1000) << 1)
                                | ((b & 0b0000_0100) << 3)
                                | ((b & 0b0000_0010) << 5)
                                | ((b & 0b0000_0001) << 7)
                        })
                        .collect::<Vec<u8>>()),
                )
            },
        })
    }
}

impl Encode for PartialMerkleTree {
    fn encode(&self) -> Vec<u8> {
        let value = serialize::<PartialMerkleTree>(&self);
        value.encode()
    }
}

impl Decode for PartialMerkleTree {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let value: Vec<u8> = Decode::decode(input).unwrap();
        if let Ok(tree) = deserialize(Reader::new(&value)) {
            Some(tree)
        } else {
            None
        }
    }
}

/// Partial merkle tree parse result
#[cfg_attr(feature = "std", derive(Debug))]
pub struct ParsedPartialMerkleTree {
    /// Merkle root
    pub root: H256,
    /// Matched hashes
    pub hashes: Vec<H256>,
    /// Match flags
    pub flags: BitVec,
}

impl ParsedPartialMerkleTree {
    pub fn new(root: H256, hashes: Vec<H256>, flags: BitVec) -> Self {
        ParsedPartialMerkleTree {
            root,
            hashes,
            flags,
        }
    }
}

/// Service structure to construct `merkleblock` message.
struct PartialMerkleTreeBuilder {
    /// All transactions length.
    all_len: u32,
    /// All transactions hashes.
    all_hashes: Vec<H256>,
    /// Match flags for all transactions.
    all_matches: BitVec,
    /// Partial hashes.
    hashes: Vec<H256>,
    /// Partial match flags.
    matches: BitVec,
}

impl PartialMerkleTreeBuilder {
    /// Build partial merkle tree as described here:
    /// https://bitcoin.org/en/developer-reference#creating-a-merkleblock-message
    pub fn build(all_hashes: Vec<H256>, all_matches: BitVec) -> PartialMerkleTree {
        let mut partial_merkle_tree = PartialMerkleTreeBuilder {
            all_len: all_hashes.len() as u32,
            all_hashes,
            all_matches,
            hashes: Vec::new(),
            matches: BitVec::new(),
        };
        partial_merkle_tree.build_tree();
        PartialMerkleTree::new(
            partial_merkle_tree.all_len,
            partial_merkle_tree.hashes,
            partial_merkle_tree.matches,
        )
    }

    fn build_tree(&mut self) {
        let tree_height = self.tree_height();
        self.build_branch(tree_height, 0)
    }

    fn build_branch(&mut self, height: usize, pos: usize) {
        // determine whether this node is the parent of at least one matched txid
        let transactions_begin = pos << height;
        let transactions_end = cmp::min(self.all_len as usize, (pos + 1) << height);
        let flag = (transactions_begin..transactions_end).any(|idx| self.all_matches[idx]);
        // remember flag
        self.matches.push(flag);
        // proceeed with descendants
        if height == 0 || !flag {
            // we're at the leaf level || there is no match
            let hash = self.branch_hash(height, pos);
            self.hashes.push(hash);
        } else {
            // proceed with left child
            self.build_branch(height - 1, pos << 1);
            // proceed with right child if any
            if (pos << 1) + 1 < self.level_width(height - 1) {
                self.build_branch(height - 1, (pos << 1) + 1);
            }
        }
    }

    /// Parse partial merkle tree as described here:
    /// https://bitcoin.org/en/developer-reference#parsing-a-merkleblock-message
    pub fn parse(tree: PartialMerkleTree) -> Result<ParsedPartialMerkleTree, Error> {
        let mut partial_merkle_tree = PartialMerkleTreeBuilder {
            all_len: tree.tx_count,
            all_hashes: Vec::new(),
            all_matches: BitVec::from_elem(tree.tx_count as usize, false),
            hashes: tree.hashes,
            matches: tree.flags,
        };

        let merkle_root = partial_merkle_tree.parse_tree()?;
        Ok(ParsedPartialMerkleTree::new(
            merkle_root,
            partial_merkle_tree.all_hashes,
            partial_merkle_tree.all_matches,
        ))
    }

    fn parse_tree(&mut self) -> Result<H256, Error> {
        if self.all_len == 0 {
            return Err(Error::NoTx);
        }
        if self.hashes.len() > self.all_len as usize {
            return Err(Error::SurplusHash);
        }
        if self.matches.len() < self.hashes.len() {
            return Err(Error::NotMatch);
        }

        // parse tree
        let mut matches_used = 0usize;
        let mut hashes_used = 0usize;
        let tree_height = self.tree_height();
        let merkle_root = self.parse_branch(tree_height, 0, &mut matches_used, &mut hashes_used)?;
        if matches_used != self.matches.len() && {
            let mut found_true = false;
            for i in matches_used..self.matches.len() {
                if self.matches[i] {
                    found_true = true;
                }
            }
            found_true
        } {
            return Err(Error::NotMatch);
        }
        if hashes_used != self.hashes.len() {
            return Err(Error::AllUsed);
        }
        Ok(merkle_root)
    }

    fn parse_branch(
        &mut self,
        height: usize,
        pos: usize,
        matches_used: &mut usize,
        hashes_used: &mut usize,
    ) -> Result<H256, Error> {
        if *matches_used >= self.matches.len() {
            return Err(Error::AllUsed);
        }

        let flag = self.matches[*matches_used];
        *matches_used += 1;

        if height == 0 || !flag {
            // we're at the leaf level || there is no match
            if *hashes_used > self.hashes.len() {
                return Err(Error::AllUsed);
            }

            // get node hash
            let hash = self.hashes[*hashes_used];
            *hashes_used += 1;

            // on leaf level && matched flag set => mark transaction as matched
            if height == 0 && flag {
                self.all_hashes.push(hash);
                self.all_matches.set(pos, true);
            }

            Ok(hash)
        } else {
            // proceed with left child
            let left = self.parse_branch(height - 1, pos << 1, matches_used, hashes_used)?;
            // proceed with right child if any
            let has_right_child = self.has_right_child(height, pos);
            let right = if has_right_child {
                self.parse_branch(height - 1, (pos << 1) + 1, matches_used, hashes_used)?
            } else {
                left
            };

            if has_right_child && left == right {
                Err(Error::SameHash)
            } else {
                Ok(merkle_node_hash(&left, &right))
            }
        }
    }

    fn tree_height(&self) -> usize {
        let mut height = 0usize;
        while self.level_width(height) > 1 {
            height += 1;
        }
        height
    }

    fn has_right_child(&self, height: usize, pos: usize) -> bool {
        (pos << 1) + 1 < self.level_width(height - 1)
    }

    fn level_width(&self, height: usize) -> usize {
        (self.all_len as usize + (1 << height) - 1) >> height
    }

    fn branch_hash(&self, height: usize, pos: usize) -> H256 {
        if height == 0 {
            self.all_hashes[pos]
        } else {
            let left = self.branch_hash(height - 1, pos << 1);
            let has_right_child = self.has_right_child(height, pos);
            let right = if has_right_child {
                self.branch_hash(height - 1, (pos << 1) + 1)
            } else {
                left
            };
            merkle_node_hash(&left, &right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::dhash256;

    #[test]
    fn test_parse_partial_merkle_tree() {
        let values = vec!["one", "two", "three", "four"];
        let hashes = vec![
            dhash256(&values[0].as_bytes()),
            dhash256(&values[1].as_bytes()),
            dhash256(&values[2].as_bytes()),
            dhash256(&values[3].as_bytes()),
        ];
        let tree = PartialMerkleTree::build(hashes, BitVec::from_elem(4, true))
            .parse()
            .unwrap();
        //        println!("tree: {:?}", tree);

        let h01 = vec![
            dhash256(&values[0].as_bytes()),
            dhash256(&values[1].as_bytes()),
        ];
        let tree01 = PartialMerkleTree::build(h01, BitVec::from_elem(2, true))
            .parse()
            .unwrap();
        //        println!("tree01: {:?}", tree01);

        let h23 = vec![
            dhash256(&values[2].as_bytes()),
            dhash256(&values[3].as_bytes()),
        ];
        let tree23 = PartialMerkleTree::build(h23, BitVec::from_elem(2, true))
            .parse()
            .unwrap();
        //        println!("tree23: {:?}", tree23);

        let tree0123 =
            PartialMerkleTree::build(vec![tree01.root, tree23.root], BitVec::from_elem(2, true))
                .parse()
                .unwrap();
        //        println!("tree0123: {:?}", tree0123);
        assert_eq!(tree.root, tree0123.root);
    }
}
