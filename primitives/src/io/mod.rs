mod error;

use ustd::{cmp, fmt, mem, prelude::*, ptr, str};

use byteorder::ByteOrder;
pub use byteorder::{BigEndian, LittleEndian};

pub use self::error::{Error, Result};

struct Guard<'a> {
    buf: &'a mut Vec<u8>,
    len: usize,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        unsafe {
            self.buf.set_len(self.len);
        }
    }
}

fn append_to_string<F>(buf: &mut String, f: F) -> Result<usize>
where
    F: FnOnce(&mut Vec<u8>) -> Result<usize>,
{
    unsafe {
        let mut g = Guard {
            len: buf.len(),
            buf: buf.as_mut_vec(),
        };
        let ret = f(g.buf);
        if str::from_utf8(&g.buf[g.len..]).is_err() {
            ret.and_then(|_| Err(Error::InvalidData))
        } else {
            g.len = g.buf.len();
            ret
        }
    }
}

fn read_to_end<R: Read + ?Sized>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize> {
    read_to_end_with_reservation(r, buf, 32)
}

fn read_to_end_with_reservation<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut Vec<u8>,
    reservation_size: usize,
) -> Result<usize> {
    let start_len = buf.len();
    let mut g = Guard {
        len: buf.len(),
        buf,
    };
    let ret;
    loop {
        if g.len == g.buf.len() {
            unsafe {
                g.buf.reserve(reservation_size);
                let capacity = g.buf.capacity();
                g.buf.set_len(capacity);
                r.initializer().initialize(&mut g.buf[g.len..]);
            }
        }

        match r.read(&mut g.buf[g.len..]) {
            Ok(0) => {
                ret = Ok(g.len - start_len);
                break;
            }
            Ok(n) => g.len += n,
            Err(e) => match e {
                Error::Interrupted => {}
                _ => {
                    ret = Err(e);
                    break;
                }
            },
        }
    }

    ret
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    #[inline]
    unsafe fn initializer(&self) -> Initializer {
        Initializer::zeroing()
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        read_to_end(self, buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
        append_to_string(buf, |b| read_to_end(self, b))
    }

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(e) => match e {
                    Error::Interrupted => {}
                    _ => return Err(e),
                },
            }
        }
        if !buf.is_empty() {
            Err(Error::UnexpectedEof)
        } else {
            Ok(())
        }
    }

    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }

    /*
    fn bytes(self) -> Bytes<Self>
    where
        Self: Sized,
    {
        Bytes { inner: self }
    }

    fn chain<R: Read>(self, next: R) -> Chain<Self, R>
    where
        Self: Sized,
    {
        Chain {
            first: self,
            second: next,
            done_first: false,
        }
    }

    fn take(self, limit: u64) -> Take<Self>
    where
        Self: Sized,
    {
        Take { inner: self, limit }
    }
    */

    // ReadBytesExt
    #[inline]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline]
    fn read_i8(&mut self) -> Result<i8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0] as i8)
    }

    #[inline]
    fn read_u16<T: ByteOrder>(&mut self) -> Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(&mut buf)?;
        Ok(T::read_u16(&buf))
    }

    #[inline]
    fn read_i16<T: ByteOrder>(&mut self) -> Result<i16> {
        let mut buf = [0; 2];
        self.read_exact(&mut buf)?;
        Ok(T::read_i16(&buf))
    }

    #[inline]
    fn read_u24<T: ByteOrder>(&mut self) -> Result<u32> {
        let mut buf = [0; 3];
        self.read_exact(&mut buf)?;
        Ok(T::read_u24(&buf))
    }

    #[inline]
    fn read_i24<T: ByteOrder>(&mut self) -> Result<i32> {
        let mut buf = [0; 3];
        self.read_exact(&mut buf)?;
        Ok(T::read_i24(&buf))
    }

    #[inline]
    fn read_u32<T: ByteOrder>(&mut self) -> Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(&mut buf)?;
        Ok(T::read_u32(&buf))
    }

    #[inline]
    fn read_i32<T: ByteOrder>(&mut self) -> Result<i32> {
        let mut buf = [0; 4];
        self.read_exact(&mut buf)?;
        Ok(T::read_i32(&buf))
    }

    #[inline]
    fn read_u48<T: ByteOrder>(&mut self) -> Result<u64> {
        let mut buf = [0; 6];
        self.read_exact(&mut buf)?;
        Ok(T::read_u48(&buf))
    }

    #[inline]
    fn read_i48<T: ByteOrder>(&mut self) -> Result<i64> {
        let mut buf = [0; 6];
        self.read_exact(&mut buf)?;
        Ok(T::read_i48(&buf))
    }

    #[inline]
    fn read_u64<T: ByteOrder>(&mut self) -> Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(&mut buf)?;
        Ok(T::read_u64(&buf))
    }

    #[inline]
    fn read_i64<T: ByteOrder>(&mut self) -> Result<i64> {
        let mut buf = [0; 8];
        self.read_exact(&mut buf)?;
        Ok(T::read_i64(&buf))
    }

    #[inline]
    fn read_uint<T: ByteOrder>(&mut self, nbytes: usize) -> Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(&mut buf[..nbytes])?;
        Ok(T::read_uint(&buf[..nbytes], nbytes))
    }

    #[inline]
    fn read_int<T: ByteOrder>(&mut self, nbytes: usize) -> Result<i64> {
        let mut buf = [0; 8];
        self.read_exact(&mut buf[..nbytes])?;
        Ok(T::read_int(&buf[..nbytes], nbytes))
    }

    #[inline]
    fn read_f32<T: ByteOrder>(&mut self) -> Result<f32> {
        let mut buf = [0; 4];
        self.read_exact(&mut buf)?;
        Ok(T::read_f32(&buf))
    }

    #[inline]
    fn read_f64<T: ByteOrder>(&mut self) -> Result<f64> {
        let mut buf = [0; 8];
        self.read_exact(&mut buf)?;
        Ok(T::read_f64(&buf))
    }
}

#[derive(Debug)]
pub struct Initializer(bool);

impl Initializer {
    /// Returns a new `Initializer` which will zero out buffers.
    #[inline]
    pub fn zeroing() -> Initializer {
        Initializer(true)
    }

    /// Returns a new `Initializer` which will not zero out buffers.
    ///
    /// # Safety
    ///
    /// This may only be called by `Read`ers which guarantee that they will not
    /// read from buffers passed to `Read` methods, and that the return value of
    /// the method accurately reflects the number of bytes that have been
    /// written to the head of the buffer.
    #[inline]
    pub unsafe fn nop() -> Initializer {
        Initializer(false)
    }

    /// Indicates if a buffer should be initialized.
    #[inline]
    pub fn should_initialize(&self) -> bool {
        self.0
    }

    /// Initializes a buffer if necessary.
    #[inline]
    pub fn initialize(&self, buf: &mut [u8]) {
        if self.should_initialize() {
            unsafe { ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) }
        }
    }
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    fn flush(&mut self) -> Result<()>;

    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(Error::WriteZero),
                Ok(n) => buf = &buf[n..],
                Err(e) => match e {
                    Error::Interrupted => {}
                    _ => return Err(e),
                },
            }
        }
        Ok(())
    }

    fn write_fmt(&mut self, fmt: fmt::Arguments) -> Result<()> {
        // Create a shim which translates a Write to a fmt::Write and saves
        // off I/O errors. instead of discarding them
        struct Adaptor<'a, T: ?Sized + 'a> {
            inner: &'a mut T,
            error: Result<()>,
        }

        impl<T: Write + ?Sized> fmt::Write for Adaptor<'_, T> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                match self.inner.write_all(s.as_bytes()) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.error = Err(e);
                        Err(fmt::Error)
                    }
                }
            }
        }

        let mut output = Adaptor {
            inner: self,
            error: Ok(()),
        };
        match fmt::write(&mut output, fmt) {
            Ok(()) => Ok(()),
            Err(..) => {
                // check if the error came from the underlying `Write` or not
                if output.error.is_err() {
                    output.error
                } else {
                    Err(Error::Other)
                }
            }
        }
    }

    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }

    // WriteBytesExt
    #[inline]
    fn write_u8(&mut self, n: u8) -> Result<()> {
        self.write_all(&[n])
    }

    #[inline]
    fn write_i8(&mut self, n: i8) -> Result<()> {
        self.write_all(&[n as u8])
    }

    #[inline]
    fn write_u16<T: ByteOrder>(&mut self, n: u16) -> Result<()> {
        let mut buf = [0; 2];
        T::write_u16(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_i16<T: ByteOrder>(&mut self, n: i16) -> Result<()> {
        let mut buf = [0; 2];
        T::write_i16(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_u24<T: ByteOrder>(&mut self, n: u32) -> Result<()> {
        let mut buf = [0; 3];
        T::write_u24(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_i24<T: ByteOrder>(&mut self, n: i32) -> Result<()> {
        let mut buf = [0; 3];
        T::write_i24(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_u32<T: ByteOrder>(&mut self, n: u32) -> Result<()> {
        let mut buf = [0; 4];
        T::write_u32(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_i32<T: ByteOrder>(&mut self, n: i32) -> Result<()> {
        let mut buf = [0; 4];
        T::write_i32(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_u48<T: ByteOrder>(&mut self, n: u64) -> Result<()> {
        let mut buf = [0; 6];
        T::write_u48(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_i48<T: ByteOrder>(&mut self, n: i64) -> Result<()> {
        let mut buf = [0; 6];
        T::write_i48(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_u64<T: ByteOrder>(&mut self, n: u64) -> Result<()> {
        let mut buf = [0; 8];
        T::write_u64(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_i64<T: ByteOrder>(&mut self, n: i64) -> Result<()> {
        let mut buf = [0; 8];
        T::write_i64(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_uint<T: ByteOrder>(&mut self, n: u64, nbytes: usize) -> Result<()> {
        let mut buf = [0; 8];
        T::write_uint(&mut buf, n, nbytes);
        self.write_all(&buf[0..nbytes])
    }

    #[inline]
    fn write_int<T: ByteOrder>(&mut self, n: i64, nbytes: usize) -> Result<()> {
        let mut buf = [0; 8];
        T::write_int(&mut buf, n, nbytes);
        self.write_all(&buf[0..nbytes])
    }

    #[inline]
    fn write_f32<T: ByteOrder>(&mut self, n: f32) -> Result<()> {
        let mut buf = [0; 4];
        T::write_f32(&mut buf, n);
        self.write_all(&buf)
    }

    #[inline]
    fn write_f64<T: ByteOrder>(&mut self, n: f64) -> Result<()> {
        let mut buf = [0; 8];
        T::write_f64(&mut buf, n);
        self.write_all(&buf)
    }
}

/*
pub trait Seek {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64>;
}

pub enum SeekFrom {
    /// Sets the offset to the provided number of bytes.
    Start(u64),

    /// Sets the offset to the size of this object plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    End(i64),

    /// Sets the offset to the current position plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    Current(i64),
}
*/

/*
pub struct Chain<T, U> {
    first: T,
    second: U,
    done_first: bool,
}

impl<T, U> Chain<T, U> {
    pub fn into_inner(self) -> (T, U) {
        (self.first, self.second)
    }

    pub fn get_ref(&self) -> (&T, &U) {
        (&self.first, &self.second)
    }

    pub fn get_mut(&mut self) -> (&mut T, &mut U) {
        (&mut self.first, &mut self.second)
    }
}

impl<T: fmt::Debug, U: fmt::Debug> fmt::Debug for Chain<T, U> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Chain")
            .field("t", &self.first)
            .field("u", &self.second)
            .finish()
    }
}

impl<T: Read, U: Read> Read for Chain<T, U> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.done_first {
            match self.first.read(buf)? {
                0 if !buf.is_empty() => {
                    self.done_first = true;
                }
                n => return Ok(n),
            }
        }
        self.second.read(buf)
    }

    unsafe fn initializer(&self) -> Initializer {
        let initializer = self.first.initializer();
        if initializer.should_initialize() {
            initializer
        } else {
            self.second.initializer()
        }
    }
}
*/

/*
#[derive(Debug)]
pub struct Take<T> {
    inner: T,
    limit: u64,
}

impl<T> Take<T> {
    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Read> Read for Take<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.limit == 0 {
            return Ok(0);
        }

        let max = cmp::min(buf.len() as u64, self.limit) as usize;
        let n = self.inner.read(&mut buf[..max])?;
        self.limit -= n as u64;
        Ok(n)
    }

    unsafe fn initializer(&self) -> Initializer {
        self.inner.initializer()
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let reservation_size = cmp::min(self.limit, 32) as usize;

        read_to_end_with_reservation(self, buf, reservation_size)
    }
}
*/

/*
#[derive(Debug)]
pub struct Bytes<R> {
    inner: R,
}

impl<R: Read> Iterator for Bytes<R> {
    type Item = Result<u8>;

    fn next(&mut self) -> Option<Result<u8>> {
        let mut byte = 0;
        loop {
            return match self.inner.read(slice::from_mut(&mut byte)) {
                Ok(0) => None,
                Ok(..) => Some(Ok(byte)),
                Err(e) => match e {
                    Error::Interrupted => continue,
                    _ => Some(Err(e)),
                },
            };
        }
    }
}
*/

impl<'a, R: Read + ?Sized> Read for &'a mut R {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        (**self).read(buf)
    }

    #[inline]
    unsafe fn initializer(&self) -> Initializer {
        (**self).initializer()
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        (**self).read_to_end(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        (**self).read_exact(buf)
    }
}

impl<'a, W: Write + ?Sized> Write for &'a mut W {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        (**self).write(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        (**self).write_all(buf)
    }
}

impl<'a> Read for &'a [u8] {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let amt = cmp::min(buf.len(), self.len());
        let (a, b) = self.split_at(amt);

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if amt == 1 {
            buf[0] = a[0];
        } else {
            buf[..amt].copy_from_slice(a);
        }

        *self = b;
        Ok(amt)
    }

    #[inline]
    unsafe fn initializer(&self) -> Initializer {
        Initializer::nop()
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(*self);
        let len = self.len();
        *self = &self[len..];
        Ok(len)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() > self.len() {
            return Err(Error::UnexpectedEof);
        }
        let (a, b) = self.split_at(buf.len());

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if buf.len() == 1 {
            buf[0] = a[0];
        } else {
            buf.copy_from_slice(a);
        }

        *self = b;
        Ok(())
    }
}

impl<'a> Write for &'a mut [u8] {
    #[inline]
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let amt = cmp::min(data.len(), self.len());
        let (a, b) = mem::replace(self, &mut []).split_at_mut(amt);
        a.copy_from_slice(&data[..amt]);
        *self = b;
        Ok(amt)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if self.write(data)? == data.len() {
            Ok(())
        } else {
            Err(Error::WriteZero)
        }
    }
}

impl Write for Vec<u8> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }
}
