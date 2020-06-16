#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod bytes;
mod compact;
mod hash;
pub mod io;

#[cfg(not(feature = "std"))]
use alloc::string::String;
pub use primitive_types::U256;

pub use self::bytes::{Bytes, TaggedBytes};
pub use self::compact::Compact;
pub use self::hash::{H160, H256, H264, H32, H512, H520};

/// `s` must be 64 chars, ex: c16a4a6a6cc43c67770cbec9dd0cc4bf7e956d6b4c9e7c15ff1a2dc8ef3afc63.
pub fn h256_conv_endian_from_str(s: &str) -> H256 {
    let hex = hex::decode(s).unwrap();
    let h256 = H256::from_slice(&hex);
    h256_conv_endian(h256)
}

pub fn h256_conv_endian(mut hash: H256) -> H256 {
    let bytes = hash.as_bytes_mut();
    bytes.reverse();
    hash
}

pub fn h256_conv_endian_and_hex(be: H256) -> String {
    let le = h256_conv_endian(be);
    hex::encode(&le)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h256_conv_endian_and_hex() {
        let hash = H256::from([
            0x63, 0xfc, 0x3a, 0xef, 0xc8, 0x2d, 0x1a, 0xff, 0x15, 0x7c, 0x9e, 0x4c, 0x6b, 0x6d,
            0x95, 0x7e, 0xbf, 0xc4, 0x0c, 0xdd, 0xc9, 0xbe, 0x0c, 0x77, 0x67, 0x3c, 0xc4, 0x6c,
            0x6a, 0x4a, 0x6a, 0xc1,
        ]);
        assert_eq!(
            h256_conv_endian_and_hex(hash),
            "c16a4a6a6cc43c67770cbec9dd0cc4bf7e956d6b4c9e7c15ff1a2dc8ef3afc63"
        );
    }

    #[test]
    fn test_h256_conv_endian() {
        let hash = H256::from([
            0x63, 0xfc, 0x3a, 0xef, 0xc8, 0x2d, 0x1a, 0xff, 0x15, 0x7c, 0x9e, 0x4c, 0x6b, 0x6d,
            0x95, 0x7e, 0xbf, 0xc4, 0x0c, 0xdd, 0xc9, 0xbe, 0x0c, 0x77, 0x67, 0x3c, 0xc4, 0x6c,
            0x6a, 0x4a, 0x6a, 0xc1,
        ]);
        let conv_hash = h256_conv_endian(hash);
        assert_eq!(
            h256_conv_endian_and_hex(conv_hash),
            "63fc3aefc82d1aff157c9e4c6b6d957ebfc40cddc9be0c77673cc46c6a4a6ac1"
        );
    }
}
