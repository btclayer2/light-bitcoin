#![cfg_attr(not(feature = "std"), no_std)]

use fixed_hash::construct_fixed_hash;
pub use primitive_types::*;

mod bytes;
mod compact;
pub mod io;

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

/*
#[cfg(feature = "impl-serde")]
mod serde {
    use super::*;
    impl_fixed_hash_serde!(H32, 4);
    impl_fixed_hash_serde!(H48, 6);
    impl_fixed_hash_serde!(H264, 33);
    impl_fixed_hash_serde!(H520, 65);
}
*/

/*
#[cfg(feature = "impl-codec")]
mod codec {
    use super::*;
    impl_fixed_hash_codec!(H32, 4);
    impl_fixed_hash_codec!(H48, 6);
    impl_fixed_hash_codec!(H264, 33);
    impl_fixed_hash_codec!(H520, 65);
}
*/
