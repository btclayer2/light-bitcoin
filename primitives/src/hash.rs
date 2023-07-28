pub use primitive_types::{H160, H256, H512};

use fixed_hash::construct_fixed_hash;
use impl_codec::impl_fixed_hash_codec;
#[cfg(feature = "std")]
use impl_serde::impl_fixed_hash_serde;

construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 4 bytes (32 bits) size.
    #[derive(scale_info::TypeInfo)]
    pub struct H32(4);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 33 bytes (264 bits) size.
    #[derive(scale_info::TypeInfo)]
    pub struct H264(33);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 65 bytes (520 bits) size.
    #[derive(scale_info::TypeInfo)]
    pub struct H520(65);
}

#[cfg(feature = "std")]
mod serde_impls {
    use super::*;

    impl_fixed_hash_serde!(H32, 4);
    impl_fixed_hash_serde!(H264, 33);
    impl_fixed_hash_serde!(H520, 65);
}

mod codec_impls {
    use super::*;

    impl_fixed_hash_codec!(H32, 4);
    impl_fixed_hash_codec!(H264, 33);
    impl_fixed_hash_codec!(H520, 65);
}
