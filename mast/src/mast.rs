#![allow(dead_code)]
#![allow(clippy::module_inception)]

use bitcoin_bech32::{constants::Network, u5, WitnessProgram};
use codec::{Decode, Encode};
use core::cmp::min;
use light_bitcoin_script::{Builder, Opcode, H256};
use light_bitcoin_serialization::Stream;

use super::{
    error::{MastError, Result},
    pmt::PartialMerkleTree,
};

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::key::{KeyAgg, PrivateKey, PublicKey};
use digest::Digest;
use hashes::hex::ToHex;
use light_bitcoin_keys::{HashAdd, Tagged};

#[cfg(feature = "std")]
use rayon::prelude::*;

const DEFAULT_TAPSCRIPT_VER: u8 = 0xc0;

/// Data structure that represents a partial mast tree
#[derive(PartialEq, Eq, Clone, Debug, Decode, Encode, scale_info::TypeInfo)]
pub struct Mast {
    /// The threshold aggregate public key
    pub pubkeys: Vec<PublicKey>,
    /// The aggregate pubkey of all person
    pub inner_pubkey: PublicKey,
    /// The personal public key
    pub person_pubkeys: Vec<PublicKey>,
    /// The index of the person_pubkeys corresponding to each pubkeys
    pub indexs: Vec<Vec<u32>>,
    /// Total number of person
    pub n: u32,
    /// Threshold number of person
    pub m: u32,
    /// Number of people in a group
    pub g: u32,
}

impl Mast {
    /// Create a mast instance
    pub fn new(mut person_pubkeys: Vec<PublicKey>, threshold: u32, group: u32) -> Result<Self> {
        person_pubkeys.sort_unstable();
        let inner_pubkey = KeyAgg::key_aggregation_n(&person_pubkeys)?.x_tilde;
        let (pubkeys, indexs): (Vec<PublicKey>, Vec<Vec<u32>>) =
            generate_combine_pubkey(person_pubkeys.clone(), threshold, group)?
                .into_iter()
                .unzip();

        let n = person_pubkeys.len() as u32;
        let m = threshold;
        let g = group;

        Ok(Mast {
            pubkeys,
            inner_pubkey,
            person_pubkeys,
            indexs,
            n,
            m,
            g,
        })
    }

    /// Obtain the mapping of aggregate public key to personal public key
    pub fn agg_pubkeys_to_personal(&self) -> Vec<(PublicKey, Vec<PublicKey>)> {
        self.pubkeys
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut person_pubkey_combine = vec![];
                for index in self.indexs[i].iter() {
                    person_pubkey_combine.push(self.person_pubkeys[*index as usize - 1].clone())
                }
                (p.clone(), person_pubkey_combine)
            })
            .collect::<Vec<_>>()
    }

    /// calculate merkle root
    pub fn calc_root(&self) -> Result<H256> {
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
        let mut matches_vec: Vec<H256> = vec![];
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
        let filter_proof = leaf_nodes[index];
        let pmt = PartialMerkleTree::from_leaf_nodes(&leaf_nodes, &matches)?;
        let mut matches_vec: Vec<H256> = vec![];
        let mut indexes_vec: Vec<u32> = vec![];
        let root = pmt.extract_matches(&mut matches_vec, &mut indexes_vec)?;
        let tweak = tweak_pubkey(&self.inner_pubkey, &root)?;
        let first_bytes: u8 = DEFAULT_TAPSCRIPT_VER | if tweak.is_odd_y() { 0x01 } else { 0x00 };
        Ok([
            vec![first_bytes],
            self.inner_pubkey.x_coor().to_vec(),
            pmt.collected_hashes(filter_proof)
                .iter()
                .map(|d| d.as_bytes().to_vec())
                .collect::<Vec<_>>()
                .concat(),
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
        let root = self.calc_root()?;
        let tweak = tweak_pubkey(&self.inner_pubkey, &root)?;
        generate_btc_address(&tweak, network)
    }
}

/// To generate btc address
pub fn generate_btc_address(pubkey: &PublicKey, network: &str) -> Result<String> {
    let network = match network.to_lowercase().as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => Network::Bitcoin,
    };
    let witness = WitnessProgram::new(
        u5::try_from_u8(1).map_err(|_| MastError::EncodeToBech32Error)?,
        pubkey.x_coor().to_vec(),
        network,
    )
    .map_err(|_| MastError::EncodeToBech32Error)?;
    Ok(witness.to_string())
}

/// Calculate the leaf nodes from the pubkey
///
/// tagged_hash("TapLeaf", bytes([leaf_version]) + ser_size(pubkey))
pub fn tagged_leaf(pubkey: &PublicKey) -> Result<H256> {
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
    Ok(H256::from_slice(&hash.to_vec()))
}

/// Calculate branch nodes from left and right children
///
/// tagged_hash("TapBranch", left + right)). The left and right nodes are lexicographic order
pub fn tagged_branch(left_node: H256, right_node: H256) -> Result<H256> {
    // If the hash of the left and right leaves is the same, it means that the total number of leaves is odd
    //
    // In this case, the parent hash is computed without copying
    // Note: `TapLeafHash` will replace the `TapBranchHash`
    if left_node != right_node {
        let mut x: Vec<u8> = vec![];
        let (left_node, right_node) = lexicographical_compare(left_node, right_node);

        x.extend(left_node.as_bytes().iter());
        x.extend(right_node.as_bytes().iter());
        let hash = sha2::Sha256::default()
            .tagged(b"TapBranch")
            .add(&x[..])
            .finalize();
        Ok(H256::from_slice(&hash.to_vec()))
    } else {
        Ok(left_node)
    }
}

/// Lexicographic order of left and right nodes
fn lexicographical_compare(left_node: H256, right_node: H256) -> (H256, H256) {
    if right_node.to_hex() < left_node.to_hex() {
        (right_node, left_node)
    } else {
        (left_node, right_node)
    }
}

/// Compute tweak public key
pub fn tweak_pubkey(inner_pubkey: &PublicKey, root: &H256) -> Result<PublicKey> {
    // P + hash_tweak(P||root)G
    let mut stream = Stream::default();
    stream.append_slice(&inner_pubkey.x_coor().to_vec());
    stream.append_slice(root.as_bytes());
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

pub fn ceil_divide(dividend: u32, divisor: u32) -> u32 {
    let mut result = dividend / divisor;

    if dividend % divisor != 0 {
        result += 1;
    }

    result
}

pub fn generate_combine_index(n: u32, k: u32, g: u32) -> Vec<Vec<u32>> {
    let max = n + 1;
    let n = ceil_divide(n, g);
    let k = ceil_divide(k, g);

    let mut temp: Vec<u32> = vec![];
    for i in 1..=k {
        temp.push(i as u32)
    }
    temp.push(n as u32 + 1);

    let mut ans: Vec<Vec<u32>> = vec![];
    let mut j: usize = 0;
    while j < k as usize {
        ans.push(temp[..k as usize].to_vec());
        j = 0;

        while j < k as usize && temp[j] + 1 == temp[j + 1] {
            temp[j] = j as u32 + 1;
            j += 1;
        }
        temp[j] += 1;
    }

    let mut result: Vec<Vec<u32>> = vec![];
    for i in 0..ans.len() {
        let mut r: Vec<u32> = vec![];
        for j in &ans[i] {
            let start = (j - 1) * g + 1;
            let end = (j * g + 1).min(max);
            r.extend((start..end).collect::<Vec<_>>());
        }
        result.push(r)
    }
    result
}

#[cfg(feature = "std")]
pub fn generate_combine_pubkey(
    mut pubkeys: Vec<PublicKey>,
    k: u32,
    g: u32,
) -> Result<Vec<(PublicKey, Vec<u32>)>> {
    pubkeys.sort_unstable();
    let all_indexs = generate_combine_index(pubkeys.len() as u32, k, g);
    let mut pks = vec![];
    for indexs in all_indexs {
        let mut temp: Vec<PublicKey> = vec![];
        for index in indexs.iter() {
            temp.push(pubkeys[*index as usize - 1].clone())
        }
        pks.push((temp, indexs));
    }
    let mut output = pks
        .par_iter()
        .map(|ps| Ok((KeyAgg::key_aggregation_n(&ps.0)?.x_tilde, ps.1.clone())))
        .collect::<Result<Vec<(PublicKey, Vec<u32>)>>>()?;
    output.sort_by_key(|a| a.0.x_coor());
    Ok(output)
}

#[cfg(not(feature = "std"))]
pub fn generate_combine_pubkey(
    mut pubkeys: Vec<PublicKey>,
    k: u32,
    g: u32,
) -> Result<Vec<(PublicKey, Vec<u32>)>> {
    pubkeys.sort_unstable();
    let all_indexs = generate_combine_index(pubkeys.len() as u32, k, g);
    let mut output: Vec<(PublicKey, Vec<u32>)> = vec![];
    for indexs in all_indexs {
        let mut temp: Vec<PublicKey> = vec![];
        for index in indexs.iter() {
            temp.push(pubkeys[*index as usize - 1].clone())
        }
        output.push((KeyAgg::key_aggregation_n(&temp)?.x_tilde, indexs))
    }
    output.sort_by_key(|a| a.0.x_coor());
    Ok(output)
}

pub fn compute_combine(n: u32, m: u32) -> u32 {
    let m = min(m, n - m);
    (n - m + 1..=n).product::<u32>() / (1..=m).product::<u32>()
}

pub fn compute_min_threshold(n: u32, max_value: u32) -> u32 {
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
    fn test_generate_combine_index() {
        assert_eq!(
            generate_combine_index(3, 2, 1),
            vec![vec![1, 2], vec![1, 3], vec![2, 3]]
        );

        assert_eq!(generate_combine_index(3, 2, 2), vec![vec![1, 2], vec![3]]);

        assert_eq!(
            generate_combine_index(10, 8, 2),
            vec![
                vec![1, 2, 3, 4, 5, 6, 7, 8],
                vec![1, 2, 3, 4, 5, 6, 9, 10],
                vec![1, 2, 3, 4, 7, 8, 9, 10],
                vec![1, 2, 5, 6, 7, 8, 9, 10],
                vec![3, 4, 5, 6, 7, 8, 9, 10],
            ]
        );

        assert_eq!(
            generate_combine_index(11, 7, 3),
            vec![
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
                vec![1, 2, 3, 4, 5, 6, 10, 11],
                vec![1, 2, 3, 7, 8, 9, 10, 11],
                vec![4, 5, 6, 7, 8, 9, 10, 11],
            ]
        );
    }

    #[test]
    fn test_generate_combine_pubkey() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        assert_eq!(
            generate_combine_pubkey(vec![pubkey_a, pubkey_b, pubkey_c], 2, 1)
                .unwrap()
                .iter()
                .map(|p| hex::encode(&p.0.serialize()))
                .collect::<Vec<_>>(),
            vec![
                "0443498bc300426635cd1876077e3993bec1168d6c6fa1138f893ce41a5f51bf0a22a2a7a85830e1f9facf02488328be04ece354730e19ce2766d5dca1478483cd",
                "04be1979e5e167d216a1229315844990606c2aba2d582472492a9eec7c9466460a286a71973e72f8d057235855253707ba73b5436d6170e702edf2ed5df46722b2",
                "04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662",
            ]
        );
    }

    #[test]
    fn test_agg_pubkeys_to_personal() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2, 1).unwrap();

        assert_eq!(
            mast.agg_pubkeys_to_personal()
                .iter()
                .map(|p| {
                    (
                        hex::encode(&p.0.serialize()),
                        p.1.iter()
                            .map(|q| hex::encode(&q.serialize()))
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![("0443498bc300426635cd1876077e3993bec1168d6c6fa1138f893ce41a5f51bf0a22a2a7a85830e1f9facf02488328be04ece354730e19ce2766d5dca1478483cd".to_owned(),
                  vec!["04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394".to_owned(),
                       "04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898".to_owned()]),
                 ("04be1979e5e167d216a1229315844990606c2aba2d582472492a9eec7c9466460a286a71973e72f8d057235855253707ba73b5436d6170e702edf2ed5df46722b2".to_owned(),
                  vec!["04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394".to_owned(),
                       "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672".to_owned()]),
                 ("04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662".to_owned(),
                  vec!["04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898".to_owned(),
                       "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672".to_owned()])]
        )
    }

    #[test]
    fn mast_generate_root_should_work() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2, 1).unwrap();
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
        let pubkey_d = convert_hex_to_pubkey("04c719aa9e26501c0a140c55d2976d935d014b03142f3c0abf8d5c13f5fa391001ff24561e7a07ee441cc0e5d250bb556619f66d2d4d64bd071d559a5a220743de");
        let pubkey_e = convert_hex_to_pubkey("042ecfd6a1ae3231c36f41183acd46b4c45b001d79bdaf76738096e252ee54dae16a6739888e061d07f19db4aec2bf6d7c4f75a3e748b656b572fd2c70f740cb14");
        let pubkey_f = convert_hex_to_pubkey("049198780fef91ff89034815ed6953c80f3231e857d89d742dba6e1128ebc6296ed417f8d30887017486b8d306bb517b798a6384d63649797ccbd5242eaccbd629");

        // 3/2/1
        let person_pubkeys = vec![pubkey_a.clone(), pubkey_b.clone(), pubkey_c.clone()];
        let mast = Mast::new(person_pubkeys, 2, 1).unwrap();
        let pubkey_ab = convert_hex_to_pubkey("04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662");

        let proof = mast.generate_merkle_proof(&pubkey_ab).unwrap();

        assert_eq!(
            hex::encode(&proof),
            "c0f4152c91b2c78a3524e7858c72ffa360da59e7c3c4d67d6787cf1e3bfe1684c1e38e30c81fc61186d0ed3956b5e49bd175178a638d1410e64f7716697a7e0ccd",
        );

        // 6/4/2
        let person_pubkeys = vec![
            pubkey_a.clone(),
            pubkey_b.clone(),
            pubkey_c.clone(),
            pubkey_d.clone(),
            pubkey_e.clone(),
            pubkey_f.clone(),
        ];
        let mast = Mast::new(person_pubkeys, 4, 2).unwrap();

        let pubkey_abef = KeyAgg::key_aggregation_n(&[
            pubkey_a.clone(),
            pubkey_b.clone(),
            pubkey_e.clone(),
            pubkey_f.clone(),
        ])
        .unwrap()
        .x_tilde;
        let proof = mast.generate_merkle_proof(&pubkey_abef).unwrap();
        assert_eq!(
            hex::encode(&proof),
            "c1b1194ddbb297bb0fc26d39bfaa9ac4bec4b458775e33d600edc068de31c565231651a7ddda9b73221f02f1f9ade1032c7660ed5ed17f24d6c395b769f2125d4003bb3059b56302e1d3ab177e560459a361f6eaf4ce31aea50f991d2652b964b2",
        );

        let pubkey_abcf = KeyAgg::key_aggregation_n(&[
            pubkey_a.clone(),
            pubkey_b.clone(),
            pubkey_c.clone(),
            pubkey_f.clone(),
        ])
        .unwrap()
        .x_tilde;
        let proof = mast.generate_merkle_proof(&pubkey_abcf);
        assert_eq!(proof, Err(MastError::MastGenProofError),);
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
        let mast = Mast::new(person_pubkeys, 2, 1).unwrap();

        let addr = mast.generate_address("Mainnet").unwrap();
        assert_eq!(
            "bc1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwas6syxhp",
            addr
        );
    }
}
