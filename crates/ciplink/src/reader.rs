//! A bounds-checked little-endian reader over a byte slice.

use crate::{Error, Result};

/// Reads values from a byte slice, failing instead of panicking on short input.
///
/// Running out of data follows the Python driver: no bytes left at all is [`Error::BufferEmpty`] (what array
/// decoding stops on), some but too few bytes is [`Error::Data`].
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// The whole underlying buffer, read or not.
    pub fn buffer(&self) -> &'a [u8] {
        self.data
    }

    /// Bytes not read yet.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Bytes read so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// True when everything was read.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The bytes not read yet, without consuming them.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Takes `n` bytes. Fails with `BufferEmpty` when no byte is left, `Data` when fewer than `n` are.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let available = self.remaining().min(n);
        if available == 0 {
            return Err(Error::BufferEmpty);
        }
        if available < n {
            self.pos += available;
            return Err(Error::Data(format!("expected {n} bytes, got {available}")));
        }
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }

    /// Takes every byte left, `BufferEmpty` if none is.
    pub fn take_rest(&mut self) -> Result<&'a [u8]> {
        if self.is_empty() {
            return Err(Error::BufferEmpty);
        }
        let bytes = &self.data[self.pos..];
        self.pos = self.data.len();
        Ok(bytes)
    }

    /// Skips up to `n` bytes (fewer if the buffer ends first).
    pub fn skip(&mut self, n: usize) {
        self.pos += self.remaining().min(n);
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads a u8.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads an i8.
    pub fn i8(&mut self) -> Result<i8> {
        Ok(i8::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian u16.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian i16.
    pub fn i16(&mut self) -> Result<i16> {
        Ok(i16::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian i32.
    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian i64.
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian f32.
    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian f64.
    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_is_buffer_empty_and_short_buffer_is_data_error() {
        assert_eq!(Reader::new(&[]).u32(), Err(Error::BufferEmpty));
        assert!(matches!(Reader::new(&[1, 2]).u32(), Err(Error::Data(_))));
    }

    #[test]
    fn reads_little_endian_and_advances() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0xff]);
        assert_eq!(r.u16(), Ok(0x0201));
        assert_eq!(r.u16(), Ok(0x0403));
        assert_eq!(r.i8(), Ok(-1));
        assert!(r.is_empty());
    }
}
