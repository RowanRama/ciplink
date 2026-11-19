//! S7comm-plus wire encoding (spec sections 5, 7, 8, 11.7): VLQ integers, the symbol CRC, self-describing
//! values and the `72` frames. Pure, no I/O except the two frame helpers over `Read` / `Write`.

use std::io::{self, Read, Write};

/// A request that cannot be parsed; the connection is closed.
#[derive(Debug)]
pub(crate) struct WireError(#[allow(dead_code)] pub String); // read through Debug when debugging

pub(crate) type WireResult<T> = Result<T, WireError>;

fn short() -> WireError {
    WireError("PDU ends early".to_owned())
}

/// Bounds-checked reader over a PDU.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> WireResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(short)?;
        let bytes = self.data.get(self.pos..end).ok_or_else(short)?;
        self.pos = end;
        Ok(bytes)
    }

    pub(crate) fn u8(&mut self) -> WireResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> WireResult<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u16(&mut self) -> WireResult<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> WireResult<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> WireResult<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn vlq32(&mut self) -> WireResult<u32> {
        let mut value: u64 = 0;
        for _ in 0..5 {
            let b = self.u8()?;
            value = (value << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return u32::try_from(value).map_err(|_| WireError("VLQ32 too large".into()));
            }
        }
        Err(WireError("VLQ32 longer than 5 bytes".into()))
    }

    pub(crate) fn svlq32(&mut self) -> WireResult<i32> {
        let value = self.signed(5, false)?;
        i32::try_from(value).map_err(|_| WireError("SVLQ32 out of range".into()))
    }

    pub(crate) fn vlq64(&mut self) -> WireResult<u64> {
        let mut value: u64 = 0;
        for i in 0..9 {
            let b = self.u8()?;
            if i == 8 {
                return Ok((value << 8) | u64::from(b));
            }
            value = (value << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(WireError("VLQ64 too long".into()))
    }

    pub(crate) fn svlq64(&mut self) -> WireResult<i64> {
        self.signed(9, true)
    }

    /// Signed VLQ: bit 6 of the first byte is the sign; with `ninth`, a 9th byte carries 8 bits.
    fn signed(&mut self, max: usize, ninth: bool) -> WireResult<i64> {
        let mut value: i64 = 0;
        for i in 0..max {
            let b = self.u8()?;
            if ninth && i == 8 {
                return Ok((value << 8) | i64::from(b));
            }
            if i == 0 && b & 0x40 != 0 {
                value = -1;
            }
            value = (value << 7) | i64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(WireError("signed VLQ too long".into()))
    }
}

pub(crate) fn put_vlq32(out: &mut Vec<u8>, value: u32) {
    put_groups(out, u64::from(value));
}

fn put_groups(out: &mut Vec<u8>, mut value: u64) {
    let mut groups = [0u8; 10];
    let mut n = 0;
    loop {
        groups[n] = (value & 0x7f) as u8;
        n += 1;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(if i > 0 { groups[i] | 0x80 } else { groups[i] });
    }
}

pub(crate) fn put_vlq64(out: &mut Vec<u8>, value: u64) {
    if value >> 56 == 0 {
        put_groups(out, value);
        return;
    }
    let high = value >> 8;
    for i in (0..8).rev() {
        out.push(0x80 | ((high >> (7 * i)) & 0x7f) as u8);
    }
    out.push(value as u8);
}

pub(crate) fn put_svlq32(out: &mut Vec<u8>, value: i32) {
    put_signed(out, i64::from(value), 5, false);
}

pub(crate) fn put_svlq64(out: &mut Vec<u8>, value: i64) {
    put_signed(out, value, 8, true);
}

fn put_signed(out: &mut Vec<u8>, value: i64, max: u32, ninth: bool) {
    for n in 1..=max {
        let bits = 7 * n - 1;
        let fits = bits >= 64 || (value >= -(1i64 << bits) && value < (1i64 << bits));
        if fits {
            for i in (0..n).rev() {
                let group = ((value >> (7 * i)) & 0x7f) as u8;
                out.push(if i > 0 { group | 0x80 } else { group });
            }
            return;
        }
    }
    if ninth {
        let high = value >> 8;
        for i in (0..8).rev() {
            out.push(0x80 | ((high >> (7 * i)) & 0x7f) as u8);
        }
        out.push(value as u8);
    }
}

/// CRC-32, polynomial 0xF4ACFB13, init 0, MSB first, no final XOR (spec 11.7).
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in data {
        crc ^= u32::from(b) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0xF4AC_FB13
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Member CRC: name, type code, then any extra bytes (array marker, bounds).
pub(crate) fn member_crc(name: &str, code: u8, extra: &[u8]) -> u32 {
    let mut data = name.as_bytes().to_vec();
    data.push(code);
    data.extend_from_slice(extra);
    crc32(&data)
}

/// Address CRC of a path from its member CRCs (spec 11.7).
pub(crate) fn address_crc(members: &[u32]) -> u32 {
    let mut data = Vec::with_capacity(members.len() * 5);
    for (i, crc) in members.iter().enumerate() {
        if i > 0 {
            data.push(0x89);
        }
        data.extend_from_slice(&crc.to_le_bytes());
    }
    crc32(&data)
}

/// Datatype codes (spec 8.2).
pub(crate) mod dt {
    pub const NULL: u8 = 0x00;
    pub const BOOL: u8 = 0x01;
    pub const USINT: u8 = 0x02;
    pub const UINT: u8 = 0x03;
    pub const UDINT: u8 = 0x04;
    pub const ULINT: u8 = 0x05;
    pub const SINT: u8 = 0x06;
    pub const INT: u8 = 0x07;
    pub const DINT: u8 = 0x08;
    pub const LINT: u8 = 0x09;
    pub const BYTE: u8 = 0x0A;
    pub const WORD: u8 = 0x0B;
    pub const DWORD: u8 = 0x0C;
    pub const LWORD: u8 = 0x0D;
    pub const REAL: u8 = 0x0E;
    pub const LREAL: u8 = 0x0F;
    pub const TIMESTAMP: u8 = 0x10;
    pub const TIMESPAN: u8 = 0x11;
    pub const RID: u8 = 0x12;
    pub const AID: u8 = 0x13;
    pub const BLOB: u8 = 0x14;
    pub const WSTRING: u8 = 0x15;
    pub const VARIANT: u8 = 0x16;
    pub const STRUCT: u8 = 0x17;
    pub const S7STRING: u8 = 0x19;
}

/// A self-describing wire value (spec 8).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    USInt(u8),
    UInt(u16),
    UDInt(u32),
    ULInt(u64),
    SInt(i8),
    Int(i16),
    DInt(i32),
    LInt(i64),
    Byte(u8),
    Word(u16),
    DWord(u32),
    LWord(u64),
    Real(f32),
    LReal(f64),
    Timestamp(u64),
    Timespan(i64),
    Rid(u32),
    Aid(u32),
    Blob(Vec<u8>),
    WString(String),
    Variant(u32),
    S7String(u32),
    /// Normal struct: struct ID and (element ID, value) pairs.
    Struct(u32, Vec<(u32, Value)>),
    /// Packed struct (system and user types).
    Packed {
        id: u32,
        timestamp: u64,
        flags: u32,
        data: Vec<u8>,
    },
    /// An element or a whole array of packed structs: array flag, one packed struct with transport flag 0x400,
    /// the element size and the total, then the elements back to back (as a real CPU sends them; read only).
    PackedArray {
        id: u32,
        timestamp: u64,
        flags: u32,
        size: u32,
        data: Vec<u8>,
    },
    /// Array (flags 0x10) or address array (flags 0x20) of one datatype.
    Array {
        flags: u8,
        datatype: u8,
        items: Vec<Value>,
    },
    /// Sparse array (flags 0x40): (key, element) pairs.
    Sparse {
        datatype: u8,
        items: Vec<(u32, Value)>,
    },
}

fn is_packed(id: u32) -> bool {
    (0x0200_0001..=0x02FF_FFFE).contains(&id) || (0x9000_0001..=0x9FFF_FFFE).contains(&id)
}

impl Value {
    /// An array of one datatype.
    pub(crate) fn array(datatype: u8, items: Vec<Value>) -> Value {
        Value::Array {
            flags: 0x10,
            datatype,
            items,
        }
    }

    pub(crate) fn datatype(&self) -> u8 {
        match self {
            Value::Null => dt::NULL,
            Value::Bool(_) => dt::BOOL,
            Value::USInt(_) => dt::USINT,
            Value::UInt(_) => dt::UINT,
            Value::UDInt(_) => dt::UDINT,
            Value::ULInt(_) => dt::ULINT,
            Value::SInt(_) => dt::SINT,
            Value::Int(_) => dt::INT,
            Value::DInt(_) => dt::DINT,
            Value::LInt(_) => dt::LINT,
            Value::Byte(_) => dt::BYTE,
            Value::Word(_) => dt::WORD,
            Value::DWord(_) => dt::DWORD,
            Value::LWord(_) => dt::LWORD,
            Value::Real(_) => dt::REAL,
            Value::LReal(_) => dt::LREAL,
            Value::Timestamp(_) => dt::TIMESTAMP,
            Value::Timespan(_) => dt::TIMESPAN,
            Value::Rid(_) => dt::RID,
            Value::Aid(_) => dt::AID,
            Value::Blob(_) => dt::BLOB,
            Value::WString(_) => dt::WSTRING,
            Value::Variant(_) => dt::VARIANT,
            Value::S7String(_) => dt::S7STRING,
            Value::Struct(..) | Value::Packed { .. } | Value::PackedArray { .. } => dt::STRUCT,
            Value::Array { datatype, .. } | Value::Sparse { datatype, .. } => *datatype,
        }
    }

    /// Flags, datatype and payload.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Array {
                flags,
                datatype,
                items,
            } => {
                out.push(*flags);
                out.push(*datatype);
                put_vlq32(out, items.len() as u32);
                for item in items {
                    item.encode_payload(out);
                }
            }
            Value::PackedArray {
                id,
                timestamp,
                flags,
                size,
                data,
            } => {
                out.push(0x10);
                out.push(dt::STRUCT);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&timestamp.to_be_bytes());
                put_vlq32(out, *flags);
                put_vlq32(out, *size);
                put_vlq32(out, data.len() as u32);
                out.extend_from_slice(data);
            }
            Value::Sparse { datatype, items } => {
                out.push(0x40);
                out.push(*datatype);
                for (key, item) in items {
                    put_vlq32(out, *key);
                    item.encode_payload(out);
                }
                out.push(0);
            }
            _ => {
                out.push(0);
                out.push(self.datatype());
                self.encode_payload(out);
            }
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            Value::Null => {}
            Value::Bool(v) => out.push(u8::from(*v)),
            Value::USInt(v) | Value::Byte(v) => out.push(*v),
            Value::SInt(v) => out.push(*v as u8),
            Value::UInt(v) | Value::Word(v) => out.extend_from_slice(&v.to_be_bytes()),
            Value::Int(v) => out.extend_from_slice(&v.to_be_bytes()),
            Value::UDInt(v) | Value::Aid(v) | Value::Variant(v) | Value::S7String(v) => {
                put_vlq32(out, *v)
            }
            Value::ULInt(v) => put_vlq64(out, *v),
            Value::DInt(v) => put_svlq32(out, *v),
            Value::LInt(v) | Value::Timespan(v) => put_svlq64(out, *v),
            Value::DWord(v) | Value::Rid(v) => out.extend_from_slice(&v.to_be_bytes()),
            Value::LWord(v) | Value::Timestamp(v) => out.extend_from_slice(&v.to_be_bytes()),
            Value::Real(v) => out.extend_from_slice(&v.to_be_bytes()),
            Value::LReal(v) => out.extend_from_slice(&v.to_be_bytes()),
            Value::Blob(bytes) => {
                put_vlq32(out, 0);
                put_vlq32(out, bytes.len() as u32);
                out.extend_from_slice(bytes);
            }
            Value::WString(text) => {
                put_vlq32(out, text.len() as u32);
                out.extend_from_slice(text.as_bytes());
            }
            Value::Struct(id, elements) => {
                out.extend_from_slice(&id.to_be_bytes());
                for (element, value) in elements {
                    put_vlq32(out, *element);
                    value.encode(out);
                }
                out.push(0);
            }
            Value::Packed {
                id,
                timestamp,
                flags,
                data,
            } => {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&timestamp.to_be_bytes());
                put_vlq32(out, *flags);
                put_vlq32(out, data.len() as u32);
                out.extend_from_slice(data);
            }
            // arrays never nest; encode them whole if asked
            Value::Array { .. } | Value::Sparse { .. } | Value::PackedArray { .. } => {
                self.encode(out)
            }
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Decodes flags, datatype and payload.
    pub(crate) fn decode(cur: &mut Cursor<'_>) -> WireResult<Value> {
        let flags = cur.u8()?;
        let datatype = cur.u8()?;
        match flags & 0x70 {
            0 => Self::decode_payload(cur, datatype),
            0x10 | 0x20 => {
                let count = cur.vlq32()? as usize;
                // every element takes at least one byte (Null takes none, so cap it too)
                if count > cur.remaining().max(1) * 8 {
                    return Err(WireError(format!("array count {count} too large")));
                }
                let mut items = Vec::with_capacity(count.min(cur.remaining()));
                for _ in 0..count {
                    items.push(Self::decode_payload(cur, datatype)?);
                }
                Ok(Value::Array {
                    flags: flags & 0x70,
                    datatype,
                    items,
                })
            }
            0x40 => {
                let mut items = Vec::new();
                loop {
                    let key = cur.vlq32()?;
                    if key == 0 {
                        break;
                    }
                    items.push((key, Self::decode_payload(cur, datatype)?));
                }
                Ok(Value::Sparse { datatype, items })
            }
            other => Err(WireError(format!("value flags {other:#04x}"))),
        }
    }

    fn decode_payload(cur: &mut Cursor<'_>, datatype: u8) -> WireResult<Value> {
        Ok(match datatype {
            dt::NULL => Value::Null,
            dt::BOOL => Value::Bool(cur.u8()? != 0),
            dt::USINT => Value::USInt(cur.u8()?),
            dt::UINT => Value::UInt(cur.u16()?),
            dt::UDINT => Value::UDInt(cur.vlq32()?),
            dt::ULINT => Value::ULInt(cur.vlq64()?),
            dt::SINT => Value::SInt(cur.u8()? as i8),
            dt::INT => Value::Int(cur.u16()? as i16),
            dt::DINT => Value::DInt(cur.svlq32()?),
            dt::LINT => Value::LInt(cur.svlq64()?),
            dt::BYTE => Value::Byte(cur.u8()?),
            dt::WORD => Value::Word(cur.u16()?),
            dt::DWORD => Value::DWord(cur.u32()?),
            dt::LWORD => Value::LWord(cur.u64()?),
            dt::REAL => Value::Real(f32::from_bits(cur.u32()?)),
            dt::LREAL => Value::LReal(f64::from_bits(cur.u64()?)),
            dt::TIMESTAMP => Value::Timestamp(cur.u64()?),
            dt::TIMESPAN => Value::Timespan(cur.svlq64()?),
            dt::RID => Value::Rid(cur.u32()?),
            dt::AID => Value::Aid(cur.vlq32()?),
            dt::VARIANT => Value::Variant(cur.vlq32()?),
            dt::S7STRING => Value::S7String(cur.vlq32()?),
            dt::BLOB => {
                let root = cur.vlq32()?;
                if root > 1 {
                    cur.take(9)?;
                }
                let len = cur.vlq32()? as usize;
                Value::Blob(cur.take(len)?.to_vec())
            }
            dt::WSTRING => {
                let len = cur.vlq32()? as usize;
                let bytes = cur.take(len)?;
                Value::WString(String::from_utf8_lossy(bytes).into_owned())
            }
            dt::STRUCT => {
                let id = cur.u32()?;
                if is_packed(id) {
                    let timestamp = cur.u64()?;
                    let flags = cur.vlq32()?;
                    let mut count = cur.vlq32()? as usize;
                    if flags & 0x400 != 0 {
                        // the first count was the element size
                        count = cur.vlq32()? as usize;
                    }
                    Value::Packed {
                        id,
                        timestamp,
                        flags,
                        data: cur.take(count)?.to_vec(),
                    }
                } else {
                    let mut elements = Vec::new();
                    loop {
                        let element = cur.vlq32()?;
                        if element == 0 {
                            break;
                        }
                        elements.push((element, Value::decode(cur)?));
                    }
                    Value::Struct(id, elements)
                }
            }
            other => return Err(WireError(format!("datatype {other:#04x}"))),
        })
    }
}

/// Largest data part of one frame the PLC sends (spec 5).
pub(crate) const FRAME_DATA: usize = 979;
/// Cap on a reassembled request PDU.
const MAX_PDU: usize = 16 << 20;

/// Reads one PDU (version byte + concatenated data parts). None at a clean end of stream before a frame.
pub(crate) fn read_pdu(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut pdu: Vec<u8> = Vec::new();
    loop {
        let mut header = [0u8; 4];
        if pdu.is_empty() {
            // a clean close between PDUs is not an error
            let mut got = 0;
            while got < 4 {
                let n = reader.read(&mut header[got..])?;
                if n == 0 {
                    return if got == 0 {
                        Ok(None)
                    } else {
                        Err(io::ErrorKind::UnexpectedEof.into())
                    };
                }
                got += n;
            }
        } else {
            reader.read_exact(&mut header)?;
        }
        if header[0] != 0x72 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame marker {:#04x}", header[0]),
            ));
        }
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if pdu.is_empty() {
            pdu.push(header[1]);
        } else if header[1] != pdu[0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame version changed inside a PDU",
            ));
        }
        if len == 0 {
            return Ok(Some(pdu));
        }
        if pdu.len() + len > MAX_PDU {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "PDU too large"));
        }
        let start = pdu.len();
        pdu.resize(start + len, 0);
        reader.read_exact(&mut pdu[start..])?;
    }
}

/// The frames of a PDU (version byte + data): data parts of at most `chunk` bytes, the trailer after the
/// last. Each returned buffer is one frame (the last one with its trailer).
pub(crate) fn frames(pdu: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let Some((&version, data)) = pdu.split_first() else {
        return Vec::new();
    };
    let parts: Vec<&[u8]> = if data.is_empty() {
        vec![data]
    } else {
        data.chunks(chunk).collect()
    };
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let mut frame = Vec::with_capacity(part.len() + 8);
            frame.extend_from_slice(&[0x72, version]);
            frame.extend_from_slice(&(part.len() as u16).to_be_bytes());
            frame.extend_from_slice(part);
            if i == last {
                frame.extend_from_slice(&[0x72, version, 0, 0]);
            }
            frame
        })
        .collect()
}

/// Writes each frame of a PDU with its own `write_all` (over TLS: its own record).
pub(crate) fn write_pdu(writer: &mut impl Write, pdu: &[u8]) -> io::Result<()> {
    for frame in frames(pdu, FRAME_DATA) {
        writer.write_all(&frame)?;
    }
    writer.flush()
}

#[cfg(test)]
pub(crate) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|c| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        })
        .collect();
    digits
        .chunks(2)
        .map(|p| (p[0] << 4) | p.get(1).copied().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vlq32(v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        put_vlq32(&mut out, v);
        out
    }

    #[test]
    fn vlq32_matches_the_spec_table_both_ways() {
        for (value, bytes) in [
            (0u32, "00"),
            (127, "7f"),
            (300, "822c"),
            (1000, "8768"),
            (2550, "9376"),
            (0x8A0E_0005, "88d0b88005"),
            (0x7000_0A10, "87808094 10"),
        ] {
            assert_eq!(vlq32(value), hex(bytes), "{value}");
            assert_eq!(Cursor::new(&hex(bytes)).vlq32().expect("decode"), value);
        }
    }

    #[test]
    fn svlq32_matches_the_spec_table_both_ways() {
        for (value, bytes) in [
            (0i32, "00"),
            (63, "3f"),
            (64, "8040"),
            (-1, "7f"),
            (-64, "40"),
            (-65, "ff3f"),
            (-300, "fd54"),
            (-1_934_830_580, "f8e5b3a80c"),
        ] {
            let mut out = Vec::new();
            put_svlq32(&mut out, value);
            assert_eq!(out, hex(bytes), "{value}");
            assert_eq!(Cursor::new(&hex(bytes)).svlq32().expect("decode"), value);
        }
    }

    #[test]
    fn vlq64_uses_the_nine_byte_form_from_2_pow_56() {
        for (value, bytes) in [
            (1_234_567u64, "cbad07"),
            (0x6022_8000_012D_0011, "b088d0808084da8011"),
            (17_380_307_404_114_137_132, "f8cce897feb5a1902c"),
        ] {
            let mut out = Vec::new();
            put_vlq64(&mut out, value);
            assert_eq!(out, hex(bytes), "{value}");
            assert_eq!(Cursor::new(&hex(bytes)).vlq64().expect("decode"), value);
        }
        for value in [i64::MIN, -1, 0, 1 << 60, i64::MAX, -(1 << 55) - 1] {
            let mut out = Vec::new();
            put_svlq64(&mut out, value);
            assert_eq!(Cursor::new(&out).svlq64().expect("decode"), value);
        }
    }

    #[test]
    fn short_input_is_an_error() {
        assert!(Cursor::new(&hex("88")).vlq32().is_err());
        assert!(Cursor::new(&hex("8888888888")).vlq32().is_err());
        assert!(Value::decode(&mut Cursor::new(&hex("0010 05"))).is_err());
    }

    #[test]
    fn crcs_match_the_spec_examples() {
        let speed = member_crc("Speed", 8, &[]);
        assert_eq!(speed, 0x8C95_C2CE);
        assert_eq!(address_crc(&[speed]), 0x888E_C040);
        let conveyor = member_crc("Conveyor", 17, &[]);
        assert_eq!(conveyor, 0x8F17_B175);
        assert_eq!(address_crc(&[conveyor, speed]), 0x6E44_A73A);
        assert_eq!(
            address_crc(&[conveyor, member_crc("Running", 1, &[])]),
            0x2556_A63B
        );
        assert_eq!(address_crc(&[member_crc("Count", 7, &[])]), 0xDA02_6CFF);
        assert_eq!(address_crc(&[member_crc("Total", 49, &[])]), 0x646C_6642);
        assert_eq!(address_crc(&[member_crc("Recipe", 19, &[])]), 0x8C4E_AA1D);
        assert_eq!(address_crc(&[member_crc("Label", 62, &[])]), 0xA8FA_43BE);
        assert_eq!(address_crc(&[member_crc("Stamp", 67, &[])]), 0xFCA8_4867);
        assert_eq!(
            address_crc(&[member_crc("StartButton", 1, &[])]),
            0xB285_B00A
        );
        assert_eq!(member_crc("YEAR", 53, &[]), 0xD73B_9793);
        assert_eq!(member_crc("MONTH", 52, &[]), 0xD74E_7F14);
    }

    #[test]
    fn values_roundtrip() {
        let values = [
            Value::Bool(true),
            Value::Real(1.5),
            Value::DInt(-300),
            Value::ULInt(1_234_567),
            Value::array(dt::USINT, vec![Value::USInt(10), Value::USInt(4)]),
            Value::Packed {
                id: 0x0200_0043,
                timestamp: 0x10ff_4ad6_dfd5_774c,
                flags: 2,
                data: vec![7, 0xea, 11, 18],
            },
            Value::Struct(
                314,
                vec![
                    (315, Value::UDInt(897)),
                    (319, Value::WString("1;x;V3.1".into())),
                ],
            ),
            Value::Blob(vec![1, 2, 3]),
            Value::Sparse {
                datatype: dt::WSTRING,
                items: vec![(1034, Value::WString("a".into()))],
            },
            Value::Timespan(-5),
            Value::LWord(u64::MAX),
        ];
        for value in values {
            let bytes = value.to_bytes();
            let mut cur = Cursor::new(&bytes);
            assert_eq!(Value::decode(&mut cur).expect("decode"), value);
            assert_eq!(cur.remaining(), 0);
        }
        // the read example's item 5: STRING[10] "Mix1"
        let bytes = hex("10020c0a044d6978310000000000 00");
        let value = Value::decode(&mut Cursor::new(&bytes)).expect("decode");
        assert!(
            matches!(value, Value::Array { datatype: dt::USINT, ref items, .. } if items.len() == 12)
        );
    }

    #[test]
    fn frames_split_and_reassemble() {
        let mut pdu = vec![2u8];
        pdu.extend((0..2500u32).map(|i| i as u8));
        let frames = frames(&pdu, FRAME_DATA);
        assert_eq!(frames.len(), 3);
        assert_eq!(&frames[0][..4], &[0x72, 2, 0x03, 0xd3]);
        assert!(frames[2].ends_with(&[0x72, 2, 0, 0]));
        let stream: Vec<u8> = frames.concat();
        let back = read_pdu(&mut stream.as_slice())
            .expect("read")
            .expect("pdu");
        assert_eq!(back, pdu);
        assert!(read_pdu(&mut [].as_slice()).expect("eof").is_none());
    }
}
