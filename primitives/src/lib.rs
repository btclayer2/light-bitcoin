#![cfg_attr(not(feature = "std"), no_std)]

mod bytes;
mod compact;
pub mod io;

use ustd::vec::Vec;

use fixed_hash::construct_fixed_hash;
pub use primitive_types::{H160, H256, H512, U128, U256, U512};
use rustc_hex::FromHex;

pub use self::bytes::{Bytes, TaggedBytes};
pub use self::compact::Compact;

construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 4 bytes (32 bits) size.
    pub struct H32(4);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 6 bytes (48 bits) size.
    pub struct H48(6);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 33 bytes (264 bits) size.
    pub struct H264(33);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 65 bytes (520 bits) size.
    pub struct H520(65);
}

/// `s` must be 64 chars, ex: c16a4a6a6cc43c67770cbec9dd0cc4bf7e956d6b4c9e7c15ff1a2dc8ef3afc63.
pub fn h256_from_rev_str(s: &'static str) -> H256 {
    let mut hex: Vec<u8> = FromHex::from_hex(s).unwrap();
    hex.reverse();
    H256::from_slice(&hex)
}

#[test]
fn test_h256_from_reversed_str() {
    let exp = H256::from([
        0x63, 0xfc, 0x3a, 0xef, 0xc8, 0x2d, 0x1a, 0xff, 0x15, 0x7c, 0x9e, 0x4c, 0x6b, 0x6d, 0x95,
        0x7e, 0xbf, 0xc4, 0x0c, 0xdd, 0xc9, 0xbe, 0x0c, 0x77, 0x67, 0x3c, 0xc4, 0x6c, 0x6a, 0x4a,
        0x6a, 0xc1,
    ]);
    assert_eq!(
        h256_from_rev_str("c16a4a6a6cc43c67770cbec9dd0cc4bf7e956d6b4c9e7c15ff1a2dc8ef3afc63"),
        exp
    );
}
