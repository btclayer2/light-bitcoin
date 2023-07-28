#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use light_bitcoin_crypto::dhash256;
use light_bitcoin_primitives::{H256, H512};

#[inline]
fn concat(a: &H256, b: &H256) -> H512 {
    let mut result = H512::default();
    result[0..32].copy_from_slice(a.as_bytes());
    result[32..64].copy_from_slice(b.as_bytes());
    result
}

/// Calculates the root of the merkle tree
/// https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
///
/// Indicating user-visible serializations of this hash should be backward.
/// For some reason Satoshi decided this for `Double Sha256 Hash`.
pub fn merkle_root(hashes: &[H256]) -> H256 {
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut row = Vec::with_capacity(hashes.len() / 2);
    let mut i = 0;
    while i + 1 < hashes.len() {
        row.push(merkle_node_hash(&hashes[i], &hashes[i + 1]));
        i += 2
    }

    // duplicate the last element if len is not even
    if hashes.len() % 2 == 1 {
        let last = &hashes[hashes.len() - 1];
        row.push(merkle_node_hash(last, last));
    }

    merkle_root(&row)
}

/// Calculate merkle tree node hash
///
/// Indicating user-visible serializations of this hash should be backward.
/// For some reason Satoshi decided this for `Double Sha256 Hash`.
pub fn merkle_node_hash(left: &H256, right: &H256) -> H256 {
    dhash256(concat(left, right).as_bytes())
}

#[cfg(test)]
mod tests {
    use light_bitcoin_primitives::h256_rev;

    use super::*;

    // block 80_000
    // https://blockchain.info/block/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
    // block 80_001
    // https://blockchain.info/block/00000000000036312a44ab7711afa46f475913fbd9727cf508ed4af3bc933d16
    #[test]
    fn test_merkle_root() {
        let cases = vec![
            (
                vec![
                    h256_rev("c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25"),
                    h256_rev("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2"),
                ],
                h256_rev("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719"),
            ),
            (
                vec![
                    h256_rev("fd859b8a041591c4a759fc5e0a1eba3776739eef2066823a15fa3c2f2f0eb15e"),
                    h256_rev("10b6fe7a18750cd43c847ed1d82daf8f3ee19f885da2b770ecfa22e961a5b829"),
                    h256_rev("73496b488e2fccace327a81c6887ca08c3551c42f9adfe3984104390859bd794"),
                ],
                h256_rev("876ec557b3686aec47a98587420373a29f36c1fbc119a7bc6807163164a5fb8a"),
            ),
        ];
        for (txs, expected) in cases {
            let got = merkle_root(&txs);
            assert_eq!(got, expected);
        }
    }
}
