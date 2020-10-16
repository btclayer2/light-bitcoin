#![cfg_attr(not(feature = "std"), no_std)]

use core::hash::Hasher;

use light_bitcoin_primitives::{H160, H256, H32};

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

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.sha256.update(data);
    }

    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        let mut tmp = self;
        tmp.update(data);
        tmp
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        let tmp = self.sha256.finalize();
        let mut ripemd = self.ripemd;
        ripemd.update(tmp);
        ripemd.finalize()
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let res = self.clone().finalize();
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
        Self::update(&mut hasher, data);
        hasher.finalize()
    }
}

#[derive(Clone, Default)]
pub struct DHash256 {
    hasher: Sha256,
}

impl DHash256 {
    pub fn finish(self) -> H256 {
        H256::from_slice(&self.finalize())
    }
}

impl Digest for DHash256 {
    type OutputSize = U32;

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.hasher.update(data);
    }

    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        let mut tmp = self;
        tmp.update(data);
        tmp
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        let mut tmp = self.hasher;
        let out = tmp.finalize_reset();
        tmp.update(&out);
        tmp.finalize()
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let res = self.clone().finalize();
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
        Self::update(&mut hasher, data);
        hasher.finalize()
    }
}

/// RIPEMD160
#[inline]
pub fn ripemd160(input: &[u8]) -> H160 {
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    H160::from_slice(&hasher.finalize())
}

/// SHA-1
#[inline]
pub fn sha1(input: &[u8]) -> H160 {
    let mut hasher = Sha1::new();
    hasher.update(input);
    H160::from_slice(&hasher.finalize())
}

/// SHA-256
#[inline]
pub fn sha256(input: &[u8]) -> H256 {
    let mut hasher = Sha256::new();
    hasher.update(input);
    H256::from_slice(&hasher.finalize())
}

/// SHA-256 and RIPEMD160
#[inline]
pub fn dhash160(input: &[u8]) -> H160 {
    let mut hasher = DHash160::new();
    hasher.update(input);
    H160::from_slice(&hasher.finalize())
}

/// Double SHA-256
#[inline]
pub fn dhash256(input: &[u8]) -> H256 {
    let mut hasher = DHash256::new();
    hasher.update(input);
    H256::from_slice(&hasher.finalize())
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
    use light_bitcoin_primitives::{h160, h256, h32, Bytes};

    use super::*;

    #[test]
    fn test_ripemd160() {
        let result = ripemd160(b"hello");
        assert_eq!(result, h160("108f07b8382412612c048d07d13f814118445acd"));
    }

    #[test]
    fn test_sha1() {
        let result = sha1(b"hello");
        assert_eq!(result, h160("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"));
    }

    #[test]
    fn test_sha256() {
        let result = sha256(b"hello");
        assert_eq!(
            result,
            h256("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }

    #[test]
    fn test_dhash160() {
        let result = dhash160(b"hello");
        assert_eq!(result, h160("b6a9c8c230722b7c748331a8b450f05566dc7d0f"));

        let bytes: Bytes = "210292be03ed9475445cc24a34a115c641a67e4ff234ccb08cb4c5cea45caa526cb26ead6ead6ead6ead6eadac".parse().unwrap();
        let result = dhash160(bytes.as_ref());
        assert_eq!(result, h160("865c71bfc7e314709207ab9e7e205c6f8e453d08"));
    }

    #[test]
    fn test_dhash256() {
        let result = dhash256(b"hello");
        assert_eq!(
            result,
            h256("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50")
        );
    }

    #[test]
    fn test_siphash24() {
        let expected = 0x74f839c593dc67fd_u64;
        let result = siphash24(0x0706050403020100_u64, 0x0F0E0D0C0B0A0908_u64, &[0; 1]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_checksum() {
        assert_eq!(checksum(b"hello"), h32("9595c9df"));
    }
}
