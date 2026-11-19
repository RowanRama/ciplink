//! S7comm-plus primitive encodings (spec sections 7, 8, 11.7): a bounds-checked cursor, the VLQ integers, the
//! symbol CRC and self-describing wire values. Pure, no I/O.

use crate::{Error, Result};

/// Wire datatype codes (spec 8.2).
pub mod dt {
    #![allow(missing_docs)]
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

/// Value flag: the payload is an array (spec 8.1).
pub const FLAG_ARRAY: u8 = 0x10;
/// Value flag: an address array (same wire form as an array).
pub const FLAG_ADDRESS_ARRAY: u8 = 0x20;
/// Value flag: a sparse array of (key, element) pairs ended by key 0.
pub const FLAG_SPARSE: u8 = 0x40;

/// Deepest nesting of structs or objects a decoder follows; a hostile PDU cannot recurse further.
pub(crate) const MAX_DEPTH: usize = 64;

fn short(what: &str) -> Error {
    Error::comm(format!("S7comm-plus PDU too short ({what})"))
}

/// A bounds-checked reader over a byte slice; every read returns `Err(Comm)` on short input.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// Bytes read so far.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes left.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The unread bytes.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// The next byte without consuming it.
    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| short("bytes"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// u16 big endian.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// u32 big endian.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// u64 big endian.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// u16 little endian.
    pub fn u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// u32 little endian.
    pub fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Expects `n` zero bytes.
    pub fn zeros(&mut self, n: usize, what: &str) -> Result<()> {
        if self.take(n)?.iter().any(|&b| b != 0) {
            return Err(Error::comm(format!(
                "S7comm-plus PDU malformed: {what} not zero"
            )));
        }
        Ok(())
    }

    /// VLQ32 (spec 7.1): at most 5 bytes, the value must fit 32 bits.
    pub fn vlq32(&mut self) -> Result<u32> {
        let mut v: u64 = 0;
        for _ in 0..5 {
            let c = self.u8()?;
            v = (v << 7) | u64::from(c & 0x7F);
            if c & 0x80 == 0 {
                return u32::try_from(v).map_err(|_| Error::comm("S7comm-plus VLQ32 overflow"));
            }
        }
        Err(Error::comm("S7comm-plus VLQ32 longer than 5 bytes"))
    }

    /// SVLQ32 (spec 7.2): sign in bit 6 of the first byte.
    pub fn svlq32(&mut self) -> Result<i32> {
        let c = self.u8()?;
        let mut v = i64::from(c & 0x7F);
        if v & 0x40 != 0 {
            v -= 0x80;
        }
        let mut last = c;
        let mut n = 1;
        while last & 0x80 != 0 {
            if n == 5 {
                return Err(Error::comm("S7comm-plus SVLQ32 longer than 5 bytes"));
            }
            last = self.u8()?;
            v = v * 128 + i64::from(last & 0x7F);
            n += 1;
        }
        i32::try_from(v).map_err(|_| Error::comm("S7comm-plus SVLQ32 overflow"))
    }

    fn vlq64_raw(&mut self, signed: bool) -> Result<i128> {
        let c = self.u8()?;
        let mut v = i128::from(c & 0x7F);
        if signed && v & 0x40 != 0 {
            v -= 0x80;
        }
        let mut last = c;
        let mut n = 1;
        while last & 0x80 != 0 {
            last = self.u8()?;
            if n == 8 {
                // the 9th byte contributes all 8 bits (spec 7.3)
                return Ok(v * 256 + i128::from(last));
            }
            v = v * 128 + i128::from(last & 0x7F);
            n += 1;
        }
        Ok(v)
    }

    /// VLQ64 (spec 7.3): up to 8 groups of 7 bits, a 9th byte of 8 bits.
    pub fn vlq64(&mut self) -> Result<u64> {
        // 7 * 8 + 8 = 64 bits at most, unsigned: always fits
        Ok(self.vlq64_raw(false)? as u64)
    }

    /// SVLQ64 (spec 7.3): as VLQ64 with the sign in bit 6 of the first byte.
    pub fn svlq64(&mut self) -> Result<i64> {
        let v = self.vlq64_raw(true)?;
        // the 9-byte form carries exactly 64 bits: reinterpret them
        Ok(i64::try_from(v).unwrap_or(v as u64 as i64))
    }
}

/// Appends a VLQ32 (minimal length).
pub fn put_vlq32(out: &mut Vec<u8>, v: u32) {
    put_groups(out, u64::from(v), groups_unsigned(u64::from(v)));
}

/// Appends a VLQ64: minimal 7-bit groups below 2^56, the 9-byte form from 2^56 upwards.
pub fn put_vlq64(out: &mut Vec<u8>, v: u64) {
    if v >= 1 << 56 {
        put_nine(out, v);
    } else {
        put_groups(out, v, groups_unsigned(v));
    }
}

/// Appends an SVLQ32: the fewest bytes n such that the value fits 7n - 1 bits.
pub fn put_svlq32(out: &mut Vec<u8>, v: i32) {
    let n = groups_signed(i64::from(v));
    put_groups(out, i64::from(v) as u64, n);
}

/// Appends an SVLQ64: as SVLQ32 up to 8 bytes (55 bits), else the 9-byte form.
pub fn put_svlq64(out: &mut Vec<u8>, v: i64) {
    let n = groups_signed(v);
    if n > 8 {
        put_nine(out, v as u64);
    } else {
        put_groups(out, v as u64, n);
    }
}

fn groups_unsigned(v: u64) -> u32 {
    let bits = 64 - v.leading_zeros();
    bits.div_ceil(7).max(1)
}

fn groups_signed(v: i64) -> u32 {
    (1..=9)
        .find(|&n| {
            let bits = 7 * n - 1;
            bits >= 64 || {
                let lim = 1i128 << bits;
                (-lim..lim).contains(&i128::from(v))
            }
        })
        .unwrap_or(9)
}

/// The low `7 * n` bits of `v` as n groups, most significant first.
fn put_groups(out: &mut Vec<u8>, v: u64, n: u32) {
    for i in (0..n).rev() {
        let group = ((v >> (7 * i)) & 0x7F) as u8;
        out.push(if i == 0 { group } else { group | 0x80 });
    }
}

fn put_nine(out: &mut Vec<u8>, v: u64) {
    let high = v >> 8;
    for i in (0..8).rev() {
        out.push(((high >> (7 * i)) & 0x7F) as u8 | 0x80);
    }
    out.push(v as u8);
}

// ------------------------------------------------------------------------------------------------ CRC

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0xF4AC_FB13
            } else {
                c << 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

/// CRC-32 with polynomial 0xF4ACFB13, initial value 0, MSB first, no final XOR (spec 11.7).
pub fn crc32(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |crc, &b| {
        (crc << 8) ^ CRC_TABLE[usize::from(((crc >> 24) as u8) ^ b)]
    })
}

/// A member CRC from its name and type code (spec 11.7); browsing takes it from the vartype list instead.
pub fn member_crc(name: &str, type_code: u8) -> u32 {
    let mut data = Vec::with_capacity(name.len() + 1);
    data.extend_from_slice(name.as_bytes());
    data.push(type_code);
    crc32(&data)
}

/// The address CRC of a path: member CRC 1 little endian, then `89` + each further member CRC little endian.
pub fn address_crc(member_crcs: &[u32]) -> u32 {
    let mut data = Vec::with_capacity(member_crcs.len() * 5);
    for (i, crc) in member_crcs.iter().enumerate() {
        if i > 0 {
            data.push(0x89);
        }
        data.extend_from_slice(&crc.to_le_bytes());
    }
    crc32(&data)
}

// ------------------------------------------------------------------------------------------------ values

/// A blob payload (spec 8.4).
#[derive(Clone, Debug, PartialEq)]
pub struct Blob {
    /// Root ID; 0 in every capture.
    pub root: u32,
    /// The 9 bytes (8 zero + blob type) present when the root ID is above 1 (unverified).
    pub extra: Option<[u8; 9]>,
    /// The bytes.
    pub data: Vec<u8>,
}

/// A struct payload (spec 8.5).
#[derive(Clone, Debug, PartialEq)]
pub enum Struct {
    /// Element ID + full value pairs.
    Normal {
        /// Struct ID.
        id: u32,
        /// Elements in wire order.
        elements: Vec<(u32, WireValue)>,
    },
    /// A memory image of a system or user type.
    Packed {
        /// Struct ID: the type RID.
        id: u32,
        /// Interface timestamp (type-info attribute 529).
        timestamp: u64,
        /// Transport flags: 0x02 always, 0x01 classic layout, 0x400 an array of structs.
        flags: u32,
        /// With flag 0x400: the size of one element, sent before the total; the data holds the elements back to
        /// back (seen on a real CPU).
        element_size: Option<u32>,
        /// The data bytes.
        data: Vec<u8>,
    },
}

/// True for struct IDs whose struct is sent packed (spec 8.5).
pub fn is_packed_id(id: u32) -> bool {
    (0x0200_0001..=0x02FF_FFFE).contains(&id) || (0x9000_0001..=0x9FFF_FFFE).contains(&id)
}

/// One scalar payload; its variant is the wire datatype.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub enum Scalar {
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
    Blob(Blob),
    WString(String),
    Variant(u32),
    Struct(Box<Struct>),
    S7String(u32),
}

impl Scalar {
    /// The wire datatype code of this payload.
    pub fn datatype(&self) -> u8 {
        match self {
            Scalar::Null => dt::NULL,
            Scalar::Bool(_) => dt::BOOL,
            Scalar::USInt(_) => dt::USINT,
            Scalar::UInt(_) => dt::UINT,
            Scalar::UDInt(_) => dt::UDINT,
            Scalar::ULInt(_) => dt::ULINT,
            Scalar::SInt(_) => dt::SINT,
            Scalar::Int(_) => dt::INT,
            Scalar::DInt(_) => dt::DINT,
            Scalar::LInt(_) => dt::LINT,
            Scalar::Byte(_) => dt::BYTE,
            Scalar::Word(_) => dt::WORD,
            Scalar::DWord(_) => dt::DWORD,
            Scalar::LWord(_) => dt::LWORD,
            Scalar::Real(_) => dt::REAL,
            Scalar::LReal(_) => dt::LREAL,
            Scalar::Timestamp(_) => dt::TIMESTAMP,
            Scalar::Timespan(_) => dt::TIMESPAN,
            Scalar::Rid(_) => dt::RID,
            Scalar::Aid(_) => dt::AID,
            Scalar::Blob(_) => dt::BLOB,
            Scalar::WString(_) => dt::WSTRING,
            Scalar::Variant(_) => dt::VARIANT,
            Scalar::Struct(_) => dt::STRUCT,
            Scalar::S7String(_) => dt::S7STRING,
        }
    }

    /// The value of an integer payload (Bool as 0 / 1), None for anything else.
    pub fn as_i128(&self) -> Option<i128> {
        Some(match *self {
            Scalar::Bool(v) => v.into(),
            Scalar::USInt(v) | Scalar::Byte(v) => v.into(),
            Scalar::UInt(v) | Scalar::Word(v) => v.into(),
            Scalar::UDInt(v)
            | Scalar::DWord(v)
            | Scalar::Rid(v)
            | Scalar::Aid(v)
            | Scalar::Variant(v)
            | Scalar::S7String(v) => v.into(),
            Scalar::ULInt(v) | Scalar::LWord(v) | Scalar::Timestamp(v) => v.into(),
            Scalar::SInt(v) => v.into(),
            Scalar::Int(v) => v.into(),
            Scalar::DInt(v) => v.into(),
            Scalar::LInt(v) | Scalar::Timespan(v) => v.into(),
            _ => return None,
        })
    }

    /// Decodes one payload of datatype `datatype`.
    pub fn decode(c: &mut Cursor<'_>, datatype: u8, depth: usize) -> Result<Scalar> {
        Ok(match datatype {
            dt::NULL => Scalar::Null,
            dt::BOOL => Scalar::Bool(c.u8()? != 0),
            dt::USINT => Scalar::USInt(c.u8()?),
            dt::UINT => Scalar::UInt(c.u16()?),
            dt::UDINT => Scalar::UDInt(c.vlq32()?),
            dt::ULINT => Scalar::ULInt(c.vlq64()?),
            dt::SINT => Scalar::SInt(c.u8()? as i8),
            dt::INT => Scalar::Int(c.u16()? as i16),
            dt::DINT => Scalar::DInt(c.svlq32()?),
            dt::LINT => Scalar::LInt(c.svlq64()?),
            dt::BYTE => Scalar::Byte(c.u8()?),
            dt::WORD => Scalar::Word(c.u16()?),
            dt::DWORD => Scalar::DWord(c.u32()?),
            dt::LWORD => Scalar::LWord(c.u64()?),
            dt::REAL => Scalar::Real(f32::from_bits(c.u32()?)),
            dt::LREAL => Scalar::LReal(f64::from_bits(c.u64()?)),
            dt::TIMESTAMP => Scalar::Timestamp(c.u64()?),
            dt::TIMESPAN => Scalar::Timespan(c.svlq64()?),
            dt::RID => Scalar::Rid(c.u32()?),
            dt::AID => Scalar::Aid(c.vlq32()?),
            dt::BLOB => {
                let root = c.vlq32()?;
                let extra = if root > 1 {
                    Some(c.array::<9>()?)
                } else {
                    None
                };
                let n = c.vlq32()? as usize;
                Scalar::Blob(Blob {
                    root,
                    extra,
                    data: c.take(n)?.to_vec(),
                })
            }
            dt::WSTRING => {
                let n = c.vlq32()? as usize;
                let bytes = c.take(n)?;
                Scalar::WString(String::from_utf8_lossy(bytes).into_owned())
            }
            dt::VARIANT => Scalar::Variant(c.vlq32()?),
            dt::STRUCT => Scalar::Struct(Box::new(decode_struct(c, depth)?)),
            dt::S7STRING => Scalar::S7String(c.vlq32()?),
            other => {
                return Err(Error::comm(format!(
                    "S7comm-plus unknown datatype 0x{other:02X}"
                )));
            }
        })
    }

    /// Appends the payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Scalar::Null => {}
            Scalar::Bool(v) => out.push(u8::from(*v)),
            Scalar::USInt(v) | Scalar::Byte(v) => out.push(*v),
            Scalar::SInt(v) => out.push(*v as u8),
            Scalar::UInt(v) | Scalar::Word(v) => out.extend_from_slice(&v.to_be_bytes()),
            Scalar::Int(v) => out.extend_from_slice(&v.to_be_bytes()),
            Scalar::UDInt(v) | Scalar::Aid(v) | Scalar::Variant(v) | Scalar::S7String(v) => {
                put_vlq32(out, *v)
            }
            Scalar::ULInt(v) => put_vlq64(out, *v),
            Scalar::DInt(v) => put_svlq32(out, *v),
            Scalar::LInt(v) | Scalar::Timespan(v) => put_svlq64(out, *v),
            Scalar::DWord(v) | Scalar::Rid(v) => out.extend_from_slice(&v.to_be_bytes()),
            Scalar::LWord(v) | Scalar::Timestamp(v) => out.extend_from_slice(&v.to_be_bytes()),
            Scalar::Real(v) => out.extend_from_slice(&v.to_bits().to_be_bytes()),
            Scalar::LReal(v) => out.extend_from_slice(&v.to_bits().to_be_bytes()),
            Scalar::Blob(b) => {
                put_vlq32(out, b.root);
                if let Some(extra) = &b.extra {
                    out.extend_from_slice(extra);
                }
                put_vlq32(out, b.data.len() as u32);
                out.extend_from_slice(&b.data);
            }
            Scalar::WString(s) => {
                put_vlq32(out, s.len() as u32);
                out.extend_from_slice(s.as_bytes());
            }
            Scalar::Struct(s) => encode_struct(s, out),
        }
    }
}

fn decode_struct(c: &mut Cursor<'_>, depth: usize) -> Result<Struct> {
    if depth >= MAX_DEPTH {
        return Err(Error::comm("S7comm-plus structs nested too deep"));
    }
    let id = c.u32()?;
    if is_packed_id(id) {
        let timestamp = c.u64()?;
        let flags = c.vlq32()?;
        let first = c.vlq32()?;
        let (element_size, count) = if flags & 0x400 != 0 {
            (Some(first), c.vlq32()? as usize)
        } else {
            (None, first as usize)
        };
        let data = c.take(count)?.to_vec();
        return Ok(Struct::Packed {
            id,
            timestamp,
            flags,
            element_size,
            data,
        });
    }
    let mut elements = Vec::new();
    loop {
        let element = c.vlq32()?;
        if element == 0 {
            return Ok(Struct::Normal { id, elements });
        }
        elements.push((element, WireValue::decode_at(c, depth + 1)?));
    }
}

fn encode_struct(s: &Struct, out: &mut Vec<u8>) {
    match s {
        Struct::Normal { id, elements } => {
            out.extend_from_slice(&id.to_be_bytes());
            for (element, value) in elements {
                put_vlq32(out, *element);
                value.encode(out);
            }
            out.push(0);
        }
        Struct::Packed {
            id,
            timestamp,
            flags,
            element_size,
            data,
        } => {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&timestamp.to_be_bytes());
            put_vlq32(out, *flags);
            if let Some(size) = element_size {
                put_vlq32(out, *size);
            }
            put_vlq32(out, data.len() as u32);
            out.extend_from_slice(data);
        }
    }
}

/// The shape of a value's payload.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload {
    /// One element.
    Scalar(Scalar),
    /// Flags 0x10 / 0x20: a count, then the elements.
    Array(Vec<Scalar>),
    /// Flags 0x40: (key, element) pairs, ended by key 0.
    Sparse(Vec<(u32, Scalar)>),
}

/// A self-describing value: flags, datatype, payload (spec 8).
#[derive(Clone, Debug, PartialEq)]
pub struct WireValue {
    /// The flags byte as sent (0x10 array, 0x20 address array, 0x40 sparse).
    pub flags: u8,
    /// The wire datatype (needed for empty arrays).
    pub datatype: u8,
    /// The payload.
    pub payload: Payload,
}

impl WireValue {
    /// A scalar value with flags 0.
    pub fn scalar(value: Scalar) -> Self {
        WireValue {
            flags: 0,
            datatype: value.datatype(),
            payload: Payload::Scalar(value),
        }
    }

    /// An array value (flags 0x10) of `datatype` elements.
    pub fn array(datatype: u8, items: Vec<Scalar>) -> Self {
        WireValue {
            flags: FLAG_ARRAY,
            datatype,
            payload: Payload::Array(items),
        }
    }

    /// Decodes one value.
    pub fn decode(c: &mut Cursor<'_>) -> Result<Self> {
        Self::decode_at(c, 0)
    }

    pub(crate) fn decode_at(c: &mut Cursor<'_>, depth: usize) -> Result<Self> {
        let flags = c.u8()?;
        let datatype = c.u8()?;
        let payload = match flags & 0x70 {
            0 => Payload::Scalar(Scalar::decode(c, datatype, depth)?),
            // an element or a whole array of structs: the array flag, then one packed struct without a count
            // whose transport flag 0x400 adds the element size (seen on a real CPU)
            FLAG_ARRAY if datatype == dt::STRUCT => {
                Payload::Scalar(Scalar::decode(c, datatype, depth)?)
            }
            FLAG_ARRAY | FLAG_ADDRESS_ARRAY => {
                let n = c.vlq32()? as usize;
                // every element but Null takes at least one byte; a count beyond the PDU is malformed (and
                // would otherwise build up to 2^32 Null elements from nothing)
                if n > c.remaining() {
                    return Err(short("array count"));
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(Scalar::decode(c, datatype, depth)?);
                }
                Payload::Array(items)
            }
            FLAG_SPARSE => {
                let mut items = Vec::new();
                loop {
                    let key = c.vlq32()?;
                    if key == 0 {
                        break;
                    }
                    items.push((key, Scalar::decode(c, datatype, depth)?));
                }
                Payload::Sparse(items)
            }
            _ => {
                return Err(Error::comm(format!(
                    "S7comm-plus value flags 0x{flags:02X} combine shapes"
                )));
            }
        };
        Ok(WireValue {
            flags,
            datatype,
            payload,
        })
    }

    /// Appends flags, datatype and payload.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.push(self.datatype);
        match &self.payload {
            Payload::Scalar(s) => s.encode(out),
            Payload::Array(items) => {
                put_vlq32(out, items.len() as u32);
                for item in items {
                    item.encode(out);
                }
            }
            Payload::Sparse(items) => {
                for (key, item) in items {
                    put_vlq32(out, *key);
                    item.encode(out);
                }
                out.push(0);
            }
        }
    }

    /// The encoded bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// The scalar payload, None for arrays.
    pub fn as_scalar(&self) -> Option<&Scalar> {
        match &self.payload {
            Payload::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// The array elements, None for scalars and sparse arrays.
    pub fn as_array(&self) -> Option<&[Scalar]> {
        match &self.payload {
            Payload::Array(items) => Some(items),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn vlq32_matches_every_spec_row_both_ways() {
        for (v, bytes) in [
            (0u32, "00"),
            (127, "7f"),
            (300, "82 2c"),
            (1000, "87 68"),
            (2550, "93 76"),
            (0x8A0E_0005, "88 d0 b8 80 05"),
            (0x7000_0A10, "87 80 80 94 10"),
        ] {
            let mut out = Vec::new();
            put_vlq32(&mut out, v);
            assert_eq!(out, hex(bytes), "{v}");
            let mut c = Cursor::new(&out);
            assert_eq!(c.vlq32().expect("decode"), v);
            assert_eq!(c.remaining(), 0);
        }
    }

    #[test]
    fn svlq32_matches_every_spec_row_both_ways() {
        for (v, bytes) in [
            (0i32, "00"),
            (63, "3f"),
            (64, "80 40"),
            (-1, "7f"),
            (-64, "40"),
            (-65, "ff 3f"),
            (-300, "fd 54"),
            (-1_934_830_580, "f8 e5 b3 a8 0c"),
        ] {
            let mut out = Vec::new();
            put_svlq32(&mut out, v);
            assert_eq!(out, hex(bytes), "{v}");
            let mut c = Cursor::new(&out);
            assert_eq!(c.svlq32().expect("decode"), v);
            assert_eq!(c.remaining(), 0);
        }
        for v in [i32::MIN, i32::MAX, 8191, -8192, 8192, -8193] {
            let mut out = Vec::new();
            put_svlq32(&mut out, v);
            assert_eq!(Cursor::new(&out).svlq32().expect("decode"), v);
        }
    }

    #[test]
    fn vlq64_matches_spec_rows_including_the_nine_byte_form() {
        for (v, bytes) in [
            (1_234_567u64, "cb ad 07"),
            (0x6022_8000_012D_0011, "b0 88 d0 80 80 84 da 80 11"),
            (17_380_307_404_114_137_132, "f8 cc e8 97 fe b5 a1 90 2c"),
        ] {
            let mut out = Vec::new();
            put_vlq64(&mut out, v);
            assert_eq!(out, hex(bytes), "{v}");
            let mut c = Cursor::new(&out);
            assert_eq!(c.vlq64().expect("decode"), v);
            assert_eq!(c.remaining(), 0);
        }
        // 2^56 needs the 9-byte form although 8 groups would hold 56 bits only
        let mut out = Vec::new();
        put_vlq64(&mut out, 1 << 56);
        assert_eq!(out.len(), 9);
        let mut out = Vec::new();
        put_vlq64(&mut out, (1 << 56) - 1);
        assert_eq!(out.len(), 8);
        for v in [0u64, u64::MAX, 1 << 63, 0x00FF_FFFF_FFFF_FFFF] {
            let mut out = Vec::new();
            put_vlq64(&mut out, v);
            assert_eq!(Cursor::new(&out).vlq64().expect("decode"), v);
        }
    }

    #[test]
    fn svlq64_roundtrips_at_the_edges() {
        for v in [
            0i64,
            -1,
            63,
            -64,
            64,
            (1 << 55) - 1,
            -(1 << 55),
            1 << 55,
            -(1 << 55) - 1,
            i64::MIN,
            i64::MAX,
        ] {
            let mut out = Vec::new();
            put_svlq64(&mut out, v);
            let mut c = Cursor::new(&out);
            assert_eq!(c.svlq64().expect("decode"), v, "{v}");
            assert_eq!(c.remaining(), 0);
        }
        // the 8-byte form holds 55 bits signed
        let mut out = Vec::new();
        put_svlq64(&mut out, (1 << 55) - 1);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn short_and_over_long_vlqs_are_errors() {
        assert!(Cursor::new(&hex("88 d0")).vlq32().is_err());
        assert!(Cursor::new(&hex("80 80 80 80 80 00")).vlq32().is_err());
        assert!(Cursor::new(&hex("ff ff ff ff 7f")).vlq32().is_err()); // 35 bits
        assert!(Cursor::new(&hex("80 80 80 80 80 01")).svlq32().is_err());
        assert!(Cursor::new(&hex("80 80")).vlq64().is_err());
        assert!(Cursor::new(&[]).u8().is_err());
    }

    #[test]
    fn an_array_count_beyond_the_pdu_is_an_error() {
        // a Null array of 2^32 - 1 elements would otherwise be built element by element from no bytes
        assert!(WireValue::decode(&mut Cursor::new(&hex("10 00 8f ff ff ff 7f"))).is_err());
        assert!(WireValue::decode(&mut Cursor::new(&hex("10 02 05 01 02"))).is_err());
        let empty = WireValue::decode(&mut Cursor::new(&hex("10 00 00"))).expect("empty");
        assert_eq!(empty.as_array(), Some(&[][..]));
    }

    #[test]
    fn crc_reproduces_the_spec_member_and_address_crcs() {
        let speed = member_crc("Speed", 8);
        assert_eq!(speed, 0x8C95_C2CE);
        assert_eq!(address_crc(&[speed]), 0x888E_C040);
        let conveyor = member_crc("Conveyor", 17);
        assert_eq!(conveyor, 0x8F17_B175);
        assert_eq!(address_crc(&[conveyor, speed]), 0x6E44_A73A);
        assert_eq!(member_crc("YEAR", 53), 0xD73B_9793);
    }

    #[test]
    fn crc_of_the_read_example_paths() {
        // spec 11.4: the member CRCs of Line1 (DB 5), names invented, types from the table
        let conveyor = member_crc("Conveyor", 17);
        let running = member_crc("Running", 1);
        assert_eq!(address_crc(&[conveyor, running]), 0x2556_A63B);
        assert_eq!(address_crc(&[member_crc("Count", 7)]), 0xDA02_6CFF);
        assert_eq!(address_crc(&[member_crc("Total", 49)]), 0x646C_6642);
        assert_eq!(address_crc(&[member_crc("Recipe", 19)]), 0x8C4E_AA1D);
        assert_eq!(address_crc(&[member_crc("Label", 62)]), 0xA8FA_43BE);
        assert_eq!(address_crc(&[member_crc("Stamp", 67)]), 0xFCA8_4867);
        assert_eq!(address_crc(&[member_crc("StartButton", 1)]), 0xB285_B00A);
    }

    fn roundtrip(v: &WireValue) {
        let bytes = v.to_bytes();
        let mut c = Cursor::new(&bytes);
        assert_eq!(&WireValue::decode(&mut c).expect("decode"), v);
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn every_wire_datatype_roundtrips() {
        let scalars = [
            Scalar::Null,
            Scalar::Bool(true),
            Scalar::USInt(200),
            Scalar::UInt(65535),
            Scalar::UDInt(u32::MAX),
            Scalar::ULInt(u64::MAX),
            Scalar::SInt(-5),
            Scalar::Int(-30000),
            Scalar::DInt(i32::MIN),
            Scalar::LInt(i64::MIN),
            Scalar::Byte(0x10),
            Scalar::Word(0xBEEF),
            Scalar::DWord(0xDEAD_BEEF),
            Scalar::LWord(u64::MAX - 1),
            Scalar::Real(1.5),
            Scalar::LReal(-2.25),
            Scalar::Timestamp(1_763_483_686_100_000_000),
            Scalar::Timespan(-5_000_000_000),
            Scalar::Rid(0x9200_0005),
            Scalar::Aid(306),
            Scalar::Blob(Blob {
                root: 0,
                extra: None,
                data: vec![1, 2, 3],
            }),
            Scalar::Blob(Blob {
                root: 2,
                extra: Some([0, 0, 0, 0, 0, 0, 0, 0, 7]),
                data: vec![9],
            }),
            Scalar::WString("PLC_Line1".into()),
            Scalar::Variant(3),
            Scalar::S7String(254),
        ];
        for s in scalars {
            roundtrip(&WireValue::scalar(s));
        }
    }

    #[test]
    fn arrays_sparse_arrays_and_structs_roundtrip() {
        roundtrip(&WireValue::array(
            dt::UINT,
            vec![Scalar::UInt(4), Scalar::UInt(2)],
        ));
        roundtrip(&WireValue::array(dt::DINT, vec![]));
        roundtrip(&WireValue {
            flags: FLAG_ADDRESS_ARRAY,
            datatype: dt::UDINT,
            payload: Payload::Array(vec![Scalar::UDInt(1842)]),
        });
        roundtrip(&WireValue {
            flags: FLAG_SPARSE,
            datatype: dt::WSTRING,
            payload: Payload::Sparse(vec![
                (1034, Scalar::WString(String::new())),
                (1032, Scalar::WString("x".into())),
            ]),
        });
        roundtrip(&WireValue::scalar(Scalar::Struct(Box::new(
            Struct::Normal {
                id: 314,
                elements: vec![
                    (315, WireValue::scalar(Scalar::UDInt(1))),
                    (319, WireValue::scalar(Scalar::WString("1;x;V3.1".into()))),
                ],
            },
        ))));
        roundtrip(&WireValue::scalar(Scalar::Struct(Box::new(
            Struct::Packed {
                id: 0x0200_0043,
                timestamp: 0x10FF_4AD6_DFD5_774C,
                flags: 2,
                element_size: None,
                data: hex("07ea0b120410222e05f5e100"),
            },
        ))));
    }

    #[test]
    fn the_spec_dtl_value_decodes_as_a_packed_struct() {
        let bytes = hex("00 17 02000043 10ff4ad6dfd5774c 02 0c 07ea0b1204 10222e 05f5e100");
        let v = WireValue::decode(&mut Cursor::new(&bytes)).expect("decode");
        let Some(Scalar::Struct(s)) = v.as_scalar() else {
            panic!("not a struct")
        };
        let Struct::Packed {
            id, flags, data, ..
        } = s.as_ref()
        else {
            panic!("not packed")
        };
        assert_eq!((*id, *flags, data.len()), (0x0200_0043, 2, 12));
    }

    #[test]
    fn an_array_of_structs_is_one_packed_struct_with_the_element_size() {
        // the form a real CPU sends for `Recipes` / `Recipes[1]` (invented type and data): array flag, no count,
        // transport flags 0x403 (array, classic), 6 bytes per element, 12 in all
        let bytes = hex("10 17 91000005 1122334455667788 8803 06 0c 000100020003 000400050006");
        let v = WireValue::decode(&mut Cursor::new(&bytes)).expect("decode");
        assert_eq!(v.flags, FLAG_ARRAY);
        let Some(Scalar::Struct(s)) = v.as_scalar() else {
            panic!("not a struct")
        };
        let Struct::Packed {
            id,
            flags,
            element_size,
            data,
            ..
        } = s.as_ref()
        else {
            panic!("not packed")
        };
        assert_eq!(
            (*id, *flags, *element_size, data.len()),
            (0x9100_0005, 0x403, Some(6), 12)
        );
        roundtrip(&v);
    }

    #[test]
    fn unknown_datatype_and_mixed_shapes_are_errors() {
        assert!(WireValue::decode(&mut Cursor::new(&[0x00, 0x18])).is_err());
        assert!(WireValue::decode(&mut Cursor::new(&[0x30, 0x02, 0x00])).is_err());
        assert!(WireValue::decode(&mut Cursor::new(&[0x10, 0x03, 0x02, 0x00])).is_err());
    }

    #[test]
    fn deeply_nested_structs_stop_with_an_error() {
        let mut bytes = Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            bytes.extend_from_slice(&[0x00, 0x17, 0, 0, 1, 0x3A, 0x01]);
        }
        assert!(WireValue::decode(&mut Cursor::new(&bytes)).is_err());
    }
}
