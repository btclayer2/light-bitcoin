#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod bytes;
mod compact;
mod hash;
pub mod io;

pub use primitive_types::U256;

pub use self::bytes::{Bytes, TaggedBytes};
pub use self::compact::Compact;
pub use self::hash::{H160, H256, H264, H32, H512, H520};

/// Convert the endian of hash, return the new hash.
pub fn hash_rev<T: AsMut<[u8]>>(mut hash: T) -> T {
    let bytes = hash.as_mut();
    bytes.reverse();
    hash
}

/// `s` must be 10 (with 0x prefix) or 8 (without 0x prefix) chars
pub fn h32(s: &str) -> H32 {
    let hex = if s.starts_with("0x") {
        hex::decode(&s[2..]).unwrap()
    } else {
        hex::decode(s).unwrap()
    };
    H32::from_slice(&hex)
}

/// `s` must be 42 (with 0x prefix) or 40 (without 0x prefix) chars
pub fn h160(s: &str) -> H160 {
    let hex = if s.starts_with("0x") {
        hex::decode(&s[2..]).unwrap()
    } else {
        hex::decode(s).unwrap()
    };
    H160::from_slice(&hex)
}

/// `s` must be 66 (with 0x prefix) or 64 (without 0x prefix) chars
pub fn h256(s: &str) -> H256 {
    let hex = if s.starts_with("0x") {
        hex::decode(&s[2..]).unwrap()
    } else {
        hex::decode(s).unwrap()
    };
    H256::from_slice(&hex)
}

/// `s` must be 66 (with 0x prefix) or 64 (without 0x prefix) chars
pub fn h256_rev(s: &str) -> H256 {
    hash_rev(h256(s))
}

/// `s` must be 68 (with 0x prefix) or 66 (without 0x prefix) chars
pub fn h264(s: &str) -> H264 {
    let hex = if s.starts_with("0x") {
        hex::decode(&s[2..]).unwrap()
    } else {
        hex::decode(s).unwrap()
    };
    H264::from_slice(&hex)
}

/// `s` must be 130 (with 0x prefix) or 128 (without 0x prefix) chars
pub fn h512(s: &str) -> H512 {
    let hex = if s.starts_with("0x") {
        hex::decode(&s[2..]).unwrap()
    } else {
        hex::decode(s).unwrap()
    };
    H512::from_slice(&hex)
}

/// `s` must be 132 (with 0x prefix) or 130 (without 0x prefix) chars
pub fn h520(s: &str) -> H520 {
    let hex = if s.starts_with("0x") {
        hex::decode(&s[2..]).unwrap()
    } else {
        hex::decode(s).unwrap()
    };
    H520::from_slice(&hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let hash = h32("9595c9df");
        assert_eq!(format!("{:?}", hash), "0x9595c9df");

        let hash = h160("b6a9c8c230722b7c748331a8b450f05566dc7d0f");
        assert_eq!(
            format!("{:?}", hash),
            "0xb6a9c8c230722b7c748331a8b450f05566dc7d0f"
        );

        let hash = h256("0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7");
        assert_eq!(
            format!("{:?}", hash),
            "0x0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7"
        );
        let hash = h256("0x0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7");
        assert_eq!(
            format!("{:?}", hash),
            "0x0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7"
        );

        let hash = h264("0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad712");
        assert_eq!(
            format!("{:?}", hash),
            "0x0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad712"
        );

        let hash = h512("0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad70000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7");
        assert_eq!(
            format!("{:?}", hash),
            "0x0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad70000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7"
        );

        let hash = h520("0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad70000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad712");
        assert_eq!(
            format!("{:?}", hash),
            "0x0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad70000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad712"
        );
    }

    #[test]
    fn test_hash_reverse() {
        let hash = h256("0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7");
        let hash = hash_rev(hash);
        assert_eq!(
            format!("{:?}", hash),
            "0xd7ca74801dd354b2623be0c344e4485b0580273a4b110a000000000000000000"
        );

        let hash = h512("0000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad70000000000000000000a114b3a2780055b48e444c3e03b62b254d31d8074cad7");
        let hash = hash_rev(hash);
        assert_eq!(
            format!("{:?}", hash),
            "0xd7ca74801dd354b2623be0c344e4485b0580273a4b110a000000000000000000d7ca74801dd354b2623be0c344e4485b0580273a4b110a000000000000000000"
        );
    }
}
