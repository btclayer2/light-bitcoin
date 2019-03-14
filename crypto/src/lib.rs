#![cfg_attr(not(feature = "std"), no_std)]

use ustd::{hash::Hasher, prelude::*};

use primitives::{H160, H256, H32};

pub use digest::Digest;
use digest::{
    generic_array::{
        typenum::{Unsigned, U20, U32},
        GenericArray,
    },
    Reset,
};
use ripemd160::Ripemd160;
use sha1::Sha1;
use sha2::Sha256;
use siphasher::sip::SipHasher24;

#[derive(Clone, Default)]
pub struct DHash160 {
    sha256: Sha256,
    ripemd: Ripemd160,
}

impl Digest for DHash160 {
    type OutputSize = U20;

    fn new() -> Self {
        Self::default()
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.sha256.input(data);
    }

    fn chain<B: AsRef<[u8]>>(self, data: B) -> Self
    where
        Self: Sized,
    {
        let mut tmp = self;
        tmp.input(data);
        tmp
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        let tmp = self.sha256.result();
        let mut ripemd = self.ripemd.clone();
        ripemd.input(tmp);
        ripemd.result()
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let res = self.clone().result();
        self.reset();
        res
    }

    fn reset(&mut self) {
        Reset::reset(&mut self.sha256);
    }

    fn output_size() -> usize {
        Self::OutputSize::to_usize()
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut hasher = Self::default();
        Self::input(&mut hasher, data);
        hasher.result()
    }
}

#[derive(Clone, Default)]
pub struct DHash256 {
    hasher: Sha256,
}

impl DHash256 {
    pub fn finish(self) -> H256 {
        H256::from_slice(&self.result())
    }
}

impl Digest for DHash256 {
    type OutputSize = U32;

    fn new() -> Self {
        Self::default()
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.hasher.input(data);
    }

    fn chain<B: AsRef<[u8]>>(self, data: B) -> Self
    where
        Self: Sized,
    {
        let mut tmp = self;
        tmp.input(data);
        tmp
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut tmp = self.hasher;
        let out = tmp.result_reset();
        tmp.input(&out);
        tmp.result()
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let res = self.clone().result();
        self.reset();
        res
    }

    fn reset(&mut self) {
        Reset::reset(&mut self.hasher);
    }

    fn output_size() -> usize {
        Self::OutputSize::to_usize()
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut hasher = Self::default();
        Self::input(&mut hasher, data);
        hasher.result()
    }
}

/// RIPEMD160
#[inline]
pub fn ripemd160(input: &[u8]) -> H160 {
    let mut hasher = Ripemd160::new();
    hasher.input(input);
    H160::from_slice(&hasher.result())
}

/// SHA-1
#[inline]
pub fn sha1(input: &[u8]) -> H160 {
    let mut hasher = Sha1::new();
    hasher.input(input);
    H160::from_slice(&hasher.result())
}

/// SHA-256
#[inline]
pub fn sha256(input: &[u8]) -> H256 {
    let mut hasher = Sha256::new();
    hasher.input(input);
    H256::from_slice(&hasher.result())
}

/// SHA-256 and RIPEMD160
#[inline]
pub fn dhash160(input: &[u8]) -> H160 {
    let mut hasher = DHash160::new();
    hasher.input(input);
    H160::from_slice(&hasher.result())
}

/// Double SHA-256
#[inline]
pub fn dhash256(input: &[u8]) -> H256 {
    let mut hasher = DHash256::new();
    hasher.input(input);
    H256::from_slice(&hasher.result())
}

/// SipHash-2-4
#[inline]
pub fn siphash24(key0: u64, key1: u64, input: &[u8]) -> u64 {
    let mut hasher = SipHasher24::new_with_keys(key0, key1);
    hasher.write(input);
    hasher.finish()
}

/// Data checksum
#[inline]
pub fn checksum(data: &[u8]) -> H32 {
    H32::from_slice(&dhash256(data)[0..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    use primitives::Bytes;
    use rustc_hex::FromHex;

    #[test]
    fn test_ripemd160() {
        let expected: Vec<u8> =
            FromHex::from_hex("108f07b8382412612c048d07d13f814118445acd").unwrap();
        let result = ripemd160(b"hello");
        assert_eq!(result, H160::from_slice(&expected));
    }

    #[test]
    fn test_sha1() {
        let expected: Vec<u8> =
            FromHex::from_hex("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap();
        let result = sha1(b"hello");
        assert_eq!(result, H160::from_slice(&expected));
    }

    #[test]
    fn test_sha256() {
        let expected: Vec<u8> =
            FromHex::from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        let result = sha256(b"hello");
        assert_eq!(result, H256::from_slice(&expected));
    }

    #[test]
    fn test_dhash160() {
        let expected: Vec<u8> =
            FromHex::from_hex("b6a9c8c230722b7c748331a8b450f05566dc7d0f").unwrap();
        let result = dhash160(b"hello");
        assert_eq!(result, H160::from_slice(&expected));

        let expected: Vec<u8> =
            FromHex::from_hex("865c71bfc7e314709207ab9e7e205c6f8e453d08").unwrap();
        let bytes: Bytes = "210292be03ed9475445cc24a34a115c641a67e4ff234ccb08cb4c5cea45caa526cb26ead6ead6ead6ead6eadac".into();
        let result = dhash160(bytes.as_ref());
        assert_eq!(result, H160::from_slice(&expected));
    }

    #[test]
    fn test_dhash256() {
        let expected: Vec<u8> =
            FromHex::from_hex("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50")
                .unwrap();
        let result = dhash256(b"hello");
        assert_eq!(result, H256::from_slice(&expected));
    }

    #[test]
    fn test_siphash24() {
        let expected = 0x74f839c593dc67fd_u64;
        let result = siphash24(0x0706050403020100_u64, 0x0F0E0D0C0B0A0908_u64, &[0; 1]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_checksum() {
        let expected: Vec<u8> = FromHex::from_hex("9595c9df").unwrap();
        assert_eq!(checksum(b"hello"), H32::from_slice(&expected));
    }
}
