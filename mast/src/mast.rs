#![allow(dead_code)]
#![allow(clippy::module_inception)]

use core::cmp::min;

use bitcoin_bech32::{constants::Network, u5, WitnessProgram};
use light_bitcoin_script::{Builder, Opcode};
use light_bitcoin_serialization::Stream;

use super::{
    error::{MastError, Result},
    pmt::PartialMerkleTree,
    LeafNode, MerkleNode,
};

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use digest::Digest;
use hashes::{
    hex::{FromHex, ToHex},
    Hash,
};
use light_bitcoin_keys::{HashAdd, Tagged};
use musig2::{
    key::{PrivateKey, PublicKey},
    musig2::KeyAgg,
};

#[cfg(feature = "std")]
use rayon::prelude::*;

const DEFAULT_TAPSCRIPT_VER: u8 = 0xc0;

/// Data structure that represents a partial mast tree
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Mast {
    /// The threshold aggregate public key
    pubkeys: Vec<PublicKey>,
    /// The pubkey of all person
    inner_pubkey: PublicKey,
}

impl Mast {
    /// Create a mast instance
    pub fn new(person_pubkeys: Vec<PublicKey>, threshold: usize) -> Result<Self> {
        let inner_pubkey = KeyAgg::key_aggregation_n(&person_pubkeys)?.X_tilde;
        Ok(Mast {
            pubkeys: generate_combine_pubkey(person_pubkeys, threshold)?,
            inner_pubkey,
        })
    }

    /// calculate merkle root
    pub fn calc_root(&self) -> Result<MerkleNode> {
        let leaf_nodes = self
            .pubkeys
            .iter()
            .map(tagged_leaf)
            .collect::<Result<Vec<_>>>()?;
        let mut matches = vec![true];

        // if self.pubkeys.len() < 2 {
        //     return Err(MastError::MastBuildError);
        // }
        matches.extend(&vec![false; self.pubkeys.len() - 1]);
        let pmt = PartialMerkleTree::from_leaf_nodes(&leaf_nodes, &matches)?;
        let mut matches_vec: Vec<LeafNode> = vec![];
        let mut indexes_vec: Vec<u32> = vec![];
        pmt.extract_matches(&mut matches_vec, &mut indexes_vec)
    }

    /// generate merkle proof
    pub fn generate_merkle_proof(&self, pubkey: &PublicKey) -> Result<Vec<u8>> {
        if !self.pubkeys.iter().any(|s| *s == *pubkey) {
            return Err(MastError::MastGenProofError);
        }

        let mut matches = vec![];
        let mut index = 9999;
        for (i, s) in self.pubkeys.iter().enumerate() {
            if *s == *pubkey {
                matches.push(true);
                index = i;
            } else {
                matches.push(false)
            }
        }
        let leaf_nodes = self
            .pubkeys
            .iter()
            .map(tagged_leaf)
            .collect::<Result<Vec<_>>>()?;
        let filter_proof = MerkleNode::from_inner(leaf_nodes[index].into_inner());
        let pmt = PartialMerkleTree::from_leaf_nodes(&leaf_nodes, &matches)?;
        let mut matches_vec: Vec<LeafNode> = vec![];
        let mut indexes_vec: Vec<u32> = vec![];
        let root = pmt.extract_matches(&mut matches_vec, &mut indexes_vec)?;
        let tweak = tweak_pubkey(&self.inner_pubkey, &root)?;
        let first_bytes: u8 = DEFAULT_TAPSCRIPT_VER | if tweak.is_odd_y() { 0x01 } else { 0x00 };
        Ok([
            vec![first_bytes],
            self.inner_pubkey.x_coor().to_vec(),
            pmt.collected_hashes(filter_proof).concat(),
        ]
        .concat())
    }

    /// generate threshold signature tweak pubkey
    pub fn generate_tweak_pubkey(&self) -> Result<PublicKey> {
        let root = self.calc_root()?;
        tweak_pubkey(&self.inner_pubkey, &root)
    }

    /// generate threshold signature address
    pub fn generate_address(&self, network: &str) -> Result<String> {
        let network = match network.to_lowercase().as_str() {
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            "mainnet" => Network::Bitcoin,
            "signet" => Network::Signet,
            _ => Network::Bitcoin,
        };
        let root = self.calc_root()?;
        let tweak = tweak_pubkey(&self.inner_pubkey, &root)?;
        let witness = WitnessProgram::new(
            u5::try_from_u8(1).map_err(|_| MastError::EncodeToBech32Error)?,
            tweak.x_coor().to_vec(),
            network,
        )
        .map_err(|_| MastError::EncodeToBech32Error)?;
        Ok(witness.to_string())
    }
}

/// Calculate the leaf nodes from the pubkey
///
/// tagged_hash("TapLeaf", bytes([leaf_version]) + ser_size(pubkey))
pub fn tagged_leaf(pubkey: &PublicKey) -> Result<LeafNode> {
    let mut stream = Stream::default();

    let version = DEFAULT_TAPSCRIPT_VER & 0xfe;

    let script = Builder::default()
        .push_bytes(&pubkey.x_coor().to_vec())
        .push_opcode(Opcode::OP_CHECKSIG)
        .into_script();
    stream.append(&version);
    stream.append_list(&script);
    let out = stream.out();

    let hash = sha2::Sha256::default()
        .tagged(b"TapLeaf")
        .add(&out[..])
        .finalize();
    Ok(LeafNode::from_hex(&hash.to_hex())?)
}

/// Calculate branch nodes from left and right children
///
/// tagged_hash("TapBranch", left + right)). The left and right nodes are lexicographic order
pub fn tagged_branch(left_node: MerkleNode, right_node: MerkleNode) -> Result<MerkleNode> {
    // If the hash of the left and right leaves is the same, it means that the total number of leaves is odd
    //
    // In this case, the parent hash is computed without copying
    // Note: `TapLeafHash` will replace the `TapBranchHash`
    if left_node != right_node {
        let mut x: Vec<u8> = vec![];
        let (left_node, right_node) = lexicographical_compare(left_node, right_node);

        x.extend(left_node.to_vec().iter());
        x.extend(right_node.to_vec().iter());
        let hash = sha2::Sha256::default()
            .tagged(b"TapBranch")
            .add(&x[..])
            .finalize();
        Ok(MerkleNode::from_hex(&hash.to_hex())?)
    } else {
        Ok(left_node)
    }
}

/// Lexicographic order of left and right nodes
fn lexicographical_compare(
    left_node: MerkleNode,
    right_node: MerkleNode,
) -> (MerkleNode, MerkleNode) {
    if right_node.to_hex() < left_node.to_hex() {
        (right_node, left_node)
    } else {
        (left_node, right_node)
    }
}

/// Compute tweak public key
pub fn tweak_pubkey(inner_pubkey: &PublicKey, root: &MerkleNode) -> Result<PublicKey> {
    // P + hash_tweak(P||root)G
    let mut stream = Stream::default();
    stream.append_slice(&inner_pubkey.x_coor().to_vec());
    stream.append_slice(&root.to_vec());
    let out = stream.out();

    let hash = sha2::Sha256::default()
        .tagged(b"TapTweak")
        .add(&out[..])
        .finalize();
    let tweak_key = hash.as_slice();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(tweak_key);
    let point = PublicKey::create_from_private_key(&PrivateKey::parse(&bytes)?);
    if inner_pubkey.is_odd_y() {
        Ok(point.add_point(&inner_pubkey.neg())?)
    } else {
        Ok(point.add_point(inner_pubkey)?)
    }
}

pub fn generate_combine_index(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut temp: Vec<usize> = vec![];
    let mut ans: Vec<Vec<usize>> = vec![];
    for i in 1..=k {
        temp.push(i)
    }
    temp.push(n + 1);

    let mut j: usize = 0;
    while j < k {
        ans.push(temp[..k as usize].to_vec());
        j = 0;

        while j < k && temp[j] + 1 == temp[j + 1] {
            temp[j] = j + 1;
            j += 1;
        }
        temp[j] += 1;
    }
    ans
}

#[cfg(feature = "std")]
pub fn generate_combine_pubkey(pubkeys: Vec<PublicKey>, k: usize) -> Result<Vec<PublicKey>> {
    let all_indexs = generate_combine_index(pubkeys.len(), k);
    let mut pks = vec![];
    for indexs in all_indexs {
        let mut temp: Vec<PublicKey> = vec![];
        for index in indexs {
            temp.push(pubkeys[index - 1].clone())
        }
        pks.push(temp);
    }
    let mut output = pks
        .par_iter()
        .map(|ps| Ok(KeyAgg::key_aggregation_n(ps)?.X_tilde))
        .collect::<Result<Vec<PublicKey>>>()?;
    output.sort_by_key(|a| a.x_coor());
    Ok(output)
}

#[cfg(not(feature = "std"))]
pub fn generate_combine_pubkey(pubkeys: Vec<PublicKey>, k: usize) -> Result<Vec<PublicKey>> {
    let all_indexs = generate_combine_index(pubkeys.len(), k);
    let mut output: Vec<PublicKey> = vec![];
    for indexs in all_indexs {
        let mut temp: Vec<PublicKey> = vec![];
        for index in indexs {
            temp.push(pubkeys[index - 1].clone())
        }
        output.push(KeyAgg::key_aggregation_n(&temp)?.X_tilde)
    }
    output.sort_by_key(|a| a.x_coor());
    Ok(output)
}

pub fn compute_combine(n: usize, m: usize) -> usize {
    let m = min(m, n - m);
    (n - m + 1..=n).product::<usize>() / (1..=m).product::<usize>()
}

pub fn compute_min_threshold(n: usize, max_value: usize) -> usize {
    if n > max_value {
        return n;
    }
    let half = n / 2;
    for i in (half..=n).rev() {
        if compute_combine(n, i) > max_value {
            return i + 1;
        }
    }
    1
}

pub fn convert_hex_to_pubkey(p: &str) -> PublicKey {
    let p = hex::decode(p).unwrap();
    if p.len() == 65 {
        let mut key = [0u8; 65];
        key.copy_from_slice(&p);
        PublicKey::parse(&key).unwrap()
    } else if p.len() == 33 {
        let mut key = [0u8; 33];
        key.copy_from_slice(&p);
        PublicKey::parse_compressed(&key).unwrap()
    } else {
        panic!("InvalidPublicKey");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashes::hex::ToHex;

    #[test]
    fn test_combine_min_threshold() {
        assert_eq!(compute_min_threshold(9, 200), 1);
        assert_eq!(compute_min_threshold(10, 200), 7);
        assert_eq!(compute_min_threshold(20, 200), 18);
    }

    #[test]
    fn test_generate_combine_pubkey() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        assert_eq!(
            generate_combine_pubkey(vec![pubkey_a, pubkey_b, pubkey_c], 2)
                .unwrap()
                .iter()
                .map(|p| hex::encode(&p.serialize()))
                .collect::<Vec<_>>(),
            vec![
                "0443498bc300426635cd1876077e3993bec1168d6c6fa1138f893ce41a5f51bf0a22a2a7a85830e1f9facf02488328be04ece354730e19ce2766d5dca1478483cd",
                "04be1979e5e167d216a1229315844990606c2aba2d582472492a9eec7c9466460a286a71973e72f8d057235855253707ba73b5436d6170e702edf2ed5df46722b2",
                "04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662",
            ]
        );
    }

    #[test]
    fn mast_generate_root_should_work() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();
        let root = mast.calc_root().unwrap();

        assert_eq!(
            "69e1de34d13d69fd894d708d656d0557cacaa18a093a6e86327a991d95c6c8e1",
            root.to_hex()
        );
    }

    #[test]
    fn mast_generate_merkle_proof_should_work() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();
        let pubkey_ab = convert_hex_to_pubkey("04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662");

        let proof = mast.generate_merkle_proof(&pubkey_ab).unwrap();

        assert_eq!(
            hex::encode(&proof),
            "c0f4152c91b2c78a3524e7858c72ffa360da59e7c3c4d67d6787cf1e3bfe1684c1e38e30c81fc61186d0ed3956b5e49bd175178a638d1410e64f7716697a7e0ccd",
        )
    }

    #[test]
    fn test_final_addr() {
        let pubkey_alice = convert_hex_to_pubkey(
            "0283f579dd2380bd31355d066086e1b4d46b518987c1f8a64d4c0101560280eae2",
        );
        let pubkey_bob = convert_hex_to_pubkey(
            "027a0868a14bd18e2e45ff3ad960f892df8d0edd1a5685f0a1dc63c7986d4ad55d",
        );
        let pubkey_charlie = convert_hex_to_pubkey(
            "02c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f",
        );
        let person_pubkeys = vec![pubkey_alice, pubkey_bob, pubkey_charlie];
        let mast = Mast::new(person_pubkeys, 2).unwrap();

        let addr = mast.generate_address("Mainnet").unwrap();
        assert_eq!(
            "bc1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwas6syxhp",
            addr
        );
    }
}
