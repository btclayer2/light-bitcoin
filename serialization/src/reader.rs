#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker;

use light_bitcoin_primitives::io;

use crate::compact_integer::CompactInteger;

pub fn deserialize<R, T>(buffer: R) -> Result<T, io::Error>
where
    R: io::Read,
    T: Deserializable,
{
    let mut reader = Reader::from_read(buffer);
    let result = reader.read()?;

    if reader.is_finished() {
        Ok(result)
    } else {
        Err(io::Error::UnreadData)
    }
}

pub fn deserialize_iterator<R, T>(buffer: R) -> ReadIterator<R, T>
where
    R: io::Read,
    T: Deserializable,
{
    ReadIterator {
        reader: Reader::from_read(buffer),
        iter_type: marker::PhantomData,
    }
}

pub trait Deserializable {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read;
}

/// Bitcoin structures reader.
#[derive(Debug)]
pub struct Reader<T> {
    buffer: T,
    peeked: Option<u8>,
}

impl<'a> Reader<&'a [u8]> {
    /// Convenient way of creating for slice of bytes
    pub fn new(buffer: &'a [u8]) -> Self {
        Reader {
            buffer,
            peeked: None,
        }
    }
}

impl<T> io::Read for Reader<T>
where
    T: io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        // most of the times, there will be nothing in peeked,
        // so to make it as efficient as possible, check it
        // only once
        match self.peeked.take() {
            None => io::Read::read(&mut self.buffer, buf),
            Some(peeked) if buf.is_empty() => {
                self.peeked = Some(peeked);
                Ok(0)
            }
            Some(peeked) => {
                buf[0] = peeked;
                io::Read::read(&mut self.buffer, &mut buf[1..]).map(|x| x + 1)
            }
        }
    }
}

impl<R> Reader<R>
where
    R: io::Read,
{
    pub fn from_read(read: R) -> Self {
        Reader {
            buffer: read,
            peeked: None,
        }
    }

    pub fn read<T>(&mut self) -> Result<T, io::Error>
    where
        T: Deserializable,
    {
        T::deserialize(self)
    }

    pub fn read_with_proxy<T, F>(&mut self, proxy: F) -> Result<T, io::Error>
    where
        T: Deserializable,
        F: FnMut(&[u8]),
    {
        let mut reader = Reader::from_read(Proxy::new(self, proxy));
        T::deserialize(&mut reader)
    }

    pub fn skip_while(&mut self, predicate: &dyn Fn(u8) -> bool) -> Result<(), io::Error> {
        let mut next_buffer = [0u8];
        loop {
            let next = match self.peeked.take() {
                Some(peeked) => peeked,
                None => match self.buffer.read(&mut next_buffer)? {
                    0 => return Ok(()),
                    _ => next_buffer[0],
                },
            };

            if !predicate(next) {
                self.peeked = Some(next);
                return Ok(());
            }
        }
    }

    pub fn read_slice(&mut self, bytes: &mut [u8]) -> Result<(), io::Error> {
        io::Read::read_exact(self, bytes).map_err(|_| io::Error::UnexpectedEof)
    }

    pub fn read_list<T>(&mut self) -> Result<Vec<T>, io::Error>
    where
        T: Deserializable,
    {
        let len: usize = self.read::<CompactInteger>()?.into();
        let mut result = Vec::with_capacity(len);

        for _ in 0..len {
            result.push(self.read()?);
        }

        Ok(result)
    }

    pub fn read_list_max<T>(&mut self, max: usize) -> Result<Vec<T>, io::Error>
    where
        T: Deserializable,
    {
        let len: usize = self.read::<CompactInteger>()?.into();
        if len > max {
            return Err(io::Error::ReadMalformedData);
        }

        let mut result = Vec::with_capacity(len);

        for _ in 0..len {
            result.push(self.read()?);
        }

        Ok(result)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(clippy::wrong_self_convention))]
    pub fn is_finished(&mut self) -> bool {
        if self.peeked.is_some() {
            return false;
        }

        let peek: &mut [u8] = &mut [0u8];
        match self.read_slice(peek) {
            Ok(_) => {
                self.peeked = Some(peek[0]);
                false
            }
            Err(_) => true,
        }
    }
}

/// Should be used to iterate over structures of the same type
pub struct ReadIterator<R, T> {
    reader: Reader<R>,
    iter_type: marker::PhantomData<T>,
}

impl<R, T> Iterator for ReadIterator<R, T>
where
    R: io::Read,
    T: Deserializable,
{
    type Item = Result<T, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_finished() {
            None
        } else {
            Some(self.reader.read())
        }
    }
}

struct Proxy<F, T> {
    from: F,
    to: T,
}

impl<F, T> Proxy<F, T> {
    fn new(from: F, to: T) -> Self {
        Proxy { from, to }
    }
}

impl<F, T> io::Read for Proxy<F, T>
where
    F: io::Read,
    T: FnMut(&[u8]),
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let len = io::Read::read(&mut self.from, buf)?;
        let to = &mut self.to;
        to(&buf[..len]);
        Ok(len)
    }
}
