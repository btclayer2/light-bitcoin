//! Wrapper around `Vec<u8>`

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{fmt, marker, ops, str};

/// Wrapper around `Vec<u8>`
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Default, scale_info::TypeInfo)]
pub struct Bytes(Vec<u8>);

impl<'a> From<&'a [u8]> for Bytes {
    fn from(v: &[u8]) -> Self {
        Bytes(v.into())
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(bytes: Bytes) -> Self {
        bytes.0
    }
}

impl str::FromStr for Bytes {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(Bytes)
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(hex::encode(&self.0).as_str())
    }
}

impl ops::Deref for Bytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Bytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Bytes {
    pub fn new() -> Self {
        Bytes::default()
    }

    pub fn new_with_len(len: usize) -> Self {
        Bytes(vec![0; len])
    }

    pub fn take(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn append(&mut self, other: &mut Bytes) {
        self.0.append(&mut other.0);
    }

    pub fn split_off(&mut self, at: usize) -> Bytes {
        Bytes(self.0.split_off(at))
    }
}

#[cfg(feature = "std")]
impl serde::Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex = hex::encode(&self.0);
        serializer.serialize_str(&hex)
    }
}

#[cfg(feature = "std")]
impl<'de> serde::Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(BytesVisitor)
    }
}

#[cfg(feature = "std")]
struct BytesVisitor;

#[cfg(feature = "std")]
impl<'de> serde::de::Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a 0x-prefixed hex-encoded vector of bytes")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() >= 2 {
            Ok(Bytes(
                hex::decode(v).map_err(|_| serde::de::Error::custom("invalid hex"))?,
            ))
        } else {
            Err(serde::de::Error::custom("invalid format"))
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v.as_ref())
    }
}

/// Wrapper around `Vec<u8>` which represent associated type
#[derive(Default, PartialEq, Clone, scale_info::TypeInfo)]
pub struct TaggedBytes<T> {
    bytes: Bytes,
    label: marker::PhantomData<T>,
}

impl<T> TaggedBytes<T> {
    pub fn new(bytes: Bytes) -> Self {
        TaggedBytes {
            bytes,
            label: marker::PhantomData,
        }
    }

    pub fn into_raw(self) -> Bytes {
        self.bytes
    }
}

impl<T> ops::Deref for TaggedBytes<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes.0
    }
}

impl<T> ops::DerefMut for TaggedBytes<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes.0
    }
}

impl<T> AsRef<[u8]> for TaggedBytes<T> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes.0
    }
}

impl<T> AsMut<[u8]> for TaggedBytes<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_from_hex() {
        let bytes: Bytes = "0145".parse().unwrap();
        assert_eq!(bytes, vec![0x01, 0x45].into());
    }

    #[test]
    fn test_bytes_debug_formatter() {
        let bytes: Bytes = "0145".parse().unwrap();
        assert_eq!(format!("{:?}", bytes), String::from("0145"));
    }
}
