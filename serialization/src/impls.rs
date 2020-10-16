#[cfg(not(feature = "std"))]
use alloc::string::String;

use light_bitcoin_primitives::io::{self, Error, LittleEndian, Read, Write};
use light_bitcoin_primitives::{Bytes, Compact, H160, H256, H264, H32, H512, H520};

use crate::compact_integer::CompactInteger;
use crate::reader::{Deserializable, Reader};
use crate::stream::{Serializable, Stream};

impl Serializable for bool {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_u8(*self as u8);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        1
    }
}

impl Serializable for i32 {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_i32::<LittleEndian>(*self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        4
    }
}

impl Serializable for i64 {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_i64::<LittleEndian>(*self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        8
    }
}

impl Serializable for u8 {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_u8(*self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        1
    }
}

impl Serializable for u16 {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_u16::<LittleEndian>(*self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        2
    }
}

impl Serializable for u32 {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_u32::<LittleEndian>(*self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        4
    }
}

impl Serializable for u64 {
    #[inline]
    #[allow(unused_must_use)]
    fn serialize(&self, s: &mut Stream) {
        s.write_u64::<LittleEndian>(*self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        8
    }
}

impl Deserializable for bool {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        let value = reader.read_u8()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::ReadMalformedData),
        }
    }
}

impl Deserializable for i32 {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        Ok(reader.read_i32::<LittleEndian>()?)
    }
}

impl Deserializable for i64 {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        Ok(reader.read_i64::<LittleEndian>()?)
    }
}

impl Deserializable for u8 {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        Ok(reader.read_u8()?)
    }
}

impl Deserializable for u16 {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        Ok(reader.read_u16::<LittleEndian>()?)
    }
}

impl Deserializable for u32 {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        Ok(reader.read_u32::<LittleEndian>()?)
    }
}

impl Deserializable for u64 {
    #[inline]
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        Ok(reader.read_u64::<LittleEndian>()?)
    }
}

impl Serializable for String {
    fn serialize(&self, stream: &mut Stream) {
        let bytes: &[u8] = self.as_ref();
        stream
            .append(&CompactInteger::from(bytes.len()))
            .append_slice(bytes);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        let bytes: &[u8] = self.as_ref();
        CompactInteger::from(bytes.len()).serialized_size() + bytes.len()
    }
}

impl<'a> Serializable for &'a str {
    fn serialize(&self, stream: &mut Stream) {
        let bytes: &[u8] = self.as_bytes();
        stream
            .append(&CompactInteger::from(bytes.len()))
            .append_slice(bytes);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        let bytes: &[u8] = self.as_bytes();
        CompactInteger::from(bytes.len()).serialized_size() + bytes.len()
    }
}

impl Deserializable for String {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        let bytes: Bytes = reader.read()?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

macro_rules! impl_ser_for_hash {
    ($name: ident, $size: expr) => {
        impl Serializable for $name {
            fn serialize(&self, stream: &mut Stream) {
                stream.append_slice(self.as_bytes());
            }

            #[inline]
            fn serialized_size(&self) -> usize {
                $size
            }
        }

        impl Deserializable for $name {
            fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
            where
                T: io::Read,
            {
                let mut result = Self::default();
                reader.read_slice(result.as_bytes_mut())?;
                Ok(result)
            }
        }
    };
}

impl_ser_for_hash!(H32, 4);
impl_ser_for_hash!(H160, 20);
impl_ser_for_hash!(H256, 32);
impl_ser_for_hash!(H264, 33);
impl_ser_for_hash!(H512, 64);
impl_ser_for_hash!(H520, 65);

impl Serializable for Bytes {
    fn serialize(&self, stream: &mut Stream) {
        stream
            .append(&CompactInteger::from(self.len()))
            .append_slice(self);
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        CompactInteger::from(self.len()).serialized_size() + self.len()
    }
}

impl Deserializable for Bytes {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        let len = reader.read::<CompactInteger>()?;
        let mut bytes = Bytes::new_with_len(len.into());
        reader.read_slice(&mut bytes)?;
        Ok(bytes)
    }
}

impl Serializable for Compact {
    fn serialize(&self, stream: &mut Stream) {
        stream.append(&u32::from(*self));
    }
}

impl Deserializable for Compact {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        T: io::Read,
    {
        reader.read::<u32>().map(Compact::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deserialize, deserialize_iterator, serialize};

    #[test]
    fn test_reader_read() {
        let buffer = vec![1, 2, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0];

        let mut reader = Reader::new(&buffer);
        assert!(!reader.is_finished());
        assert_eq!(1u8, reader.read().unwrap());
        assert_eq!(2u16, reader.read().unwrap());
        assert_eq!(3u32, reader.read().unwrap());
        assert_eq!(4u64, reader.read().unwrap());
        assert!(reader.is_finished());
        assert_eq!(Error::UnexpectedEof, reader.read::<u8>().unwrap_err());
    }

    #[test]
    fn test_reader_iterator() {
        let buffer = vec![1u8, 0, 2, 0, 3, 0, 4, 0];

        let result = deserialize_iterator(&buffer as &[u8])
            .collect::<Result<Vec<u16>, _>>()
            .unwrap();
        assert_eq!(result, vec![1u16, 2, 3, 4]);
    }

    #[test]
    fn test_stream_append() {
        let mut stream = Stream::default();

        stream
            .append(&1u8)
            .append(&2u16)
            .append(&3u32)
            .append(&4u64);

        let expected = vec![1u8, 2, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0].into();

        assert_eq!(stream.out(), expected);
    }

    #[test]
    fn test_bytes_deserialize() {
        let raw: Bytes = "020145".parse().unwrap();
        let expected: Bytes = "0145".parse().unwrap();
        assert_eq!(expected, deserialize(raw.as_ref()).unwrap());
    }

    #[test]
    fn test_bytes_serialize() {
        let expected: Bytes = "020145".parse().unwrap();
        let bytes: Bytes = "0145".parse().unwrap();
        assert_eq!(expected, serialize(&bytes));
    }

    #[test]
    fn test_string_serialize() {
        let expected: Bytes = "0776657273696f6e".parse().unwrap();
        let s: String = "version".into();
        assert_eq!(serialize(&s), expected);
        let expected: Bytes = "00".parse().unwrap();
        let s: String = "".into();
        assert_eq!(serialize(&s), expected);
    }

    #[test]
    fn test_string_deserialize() {
        let raw: Bytes = "0776657273696f6e".parse().unwrap();
        let expected: String = "version".into();
        assert_eq!(expected, deserialize::<_, String>(raw.as_ref()).unwrap());
        let raw: Bytes = "00".parse().unwrap();
        let expected: String = "".into();
        assert_eq!(expected, deserialize::<_, String>(raw.as_ref()).unwrap());
    }

    #[test]
    fn test_steam_append_slice() {
        let mut slice = [0u8; 4];
        slice[0] = 0x64;
        let mut stream = Stream::default();
        stream.append_slice(&slice);
        assert_eq!(stream.out(), "64000000".parse::<Bytes>().unwrap());
    }
}
