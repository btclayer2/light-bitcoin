//! Generally useful utilities related to hashing.
//!
//! In general, things in here are defined against the [`Digest`] trait from the [`RustCrypto`] project.
//!
//! [`Digest`]: digest::Digest
//! [`RustCrypto`]: https://github.com/RustCrypto/hashes
//!
//! Code from:
//! [`secp256kfun`]: https://github.com/LLFourn/secp256kfun/blob/master/secp256kfun/src/hash.rs
use digest::{
    generic_array::typenum::{PartialDiv, Unsigned},
    BlockInput, Digest,
};
use libsecp256k1::curve::Scalar;
/// Extension trait to "tag" a hash as described in [BIP-340].
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
pub trait Tagged: Default + Clone {
    /// Returns the _tagged_ (domain separated) SHA256 instance.
    /// This is meant be used on SHA256 state with an empty buffer.
    fn tagged(&self, tag: &[u8]) -> Self;
}

impl<H: BlockInput + Digest + Default + Clone> Tagged for H
where
    <H as BlockInput>::BlockSize: PartialDiv<H::OutputSize>,
    <<H as BlockInput>::BlockSize as PartialDiv<H::OutputSize>>::Output: Unsigned,
{
    fn tagged(&self, tag: &[u8]) -> Self {
        let hashed_tag = {
            let mut hash = H::default();
            hash.update(tag);
            hash.finalize()
        };
        let mut tagged_hash = self.clone();
        let fill_block =
            <<H::BlockSize as PartialDiv<H::OutputSize>>::Output as Unsigned>::to_usize();
        for _ in 0..fill_block {
            tagged_hash.update(&hashed_tag[..]);
        }
        tagged_hash
    }
}

/// Anything that can be hashed.
///
/// The implementations of this trait decide how the type will be converted into
/// bytes so that it can be included in the hash.
pub trait HashInto {
    /// Asks the item to convert itself to bytes and add itself to `hash`.
    fn hash_into(&self, hash: &mut impl digest::Digest);
}

impl HashInto for [u8] {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self)
    }
}

impl HashInto for [u8; 32] {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self)
    }
}

impl HashInto for str {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.as_bytes())
    }
}

impl HashInto for Scalar {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.b32())
    }
}

/// Extension trait for [`digest::Digest`] to make adding things to the hash convenient.
pub trait HashAdd {
    /// Converts something that implements [`HashInto`] to bytes and then incorporate the result into the digest (`self`).
    fn add<HI: HashInto + ?Sized>(self, data: &HI) -> Self;
}

impl<D: Digest> HashAdd for D {
    fn add<HI: HashInto + ?Sized>(mut self, data: &HI) -> Self {
        data.hash_into(&mut self);
        self
    }
}
