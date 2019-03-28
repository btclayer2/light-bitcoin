#![cfg_attr(not(feature = "std"), no_std)]

mod bytes;
mod compact;
pub mod io;

pub use primitive_types::{H160, H256, H264, H32, H48, H512, H520, U128, U256, U512};

pub use self::bytes::{Bytes, TaggedBytes};
pub use self::compact::Compact;

/// `s` must be 64 chars, ex: c16a4a6a6cc43c67770cbec9dd0cc4bf7e956d6b4c9e7c15ff1a2dc8ef3afc63.
pub fn h256_from_rev_str(s: &'static str) -> H256 {
    let mut hex: ustd::vec::Vec<u8> = rustc_hex::FromHex::from_hex(s).unwrap();
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
