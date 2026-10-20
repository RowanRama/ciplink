//! CIP elementary data types and their binary encoding, as the Python driver's `ciplink.cip.data_types`.

use crate::reader::Reader;
use crate::value::py_bytes_repr;
use crate::{Error, Result, Value};

/// A CIP elementary data type.
///
/// Several Logix types share a code with another type, `from_code` resolves those as the Python driver does
/// (0xCC is LDT, 0xD6 is FTIME, 0xDC is PACKED_EPATH).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Elementary {
    Bool,
    SInt,
    Int,
    DInt,
    LInt,
    USInt,
    UInt,
    UDInt,
    ULInt,
    Real,
    LReal,
    STime,
    Date,
    TimeOfDay,
    DateAndTime,
    Dt,
    Ldt,
    Time32,
    LogixString,
    String,
    Byte,
    Word,
    DWord,
    LWord,
    String2,
    FTime,
    LTime,
    ITime,
    StringN,
    ShortString,
    Time,
    PaddedEpath,
    PackedEpath,
    EngUnit,
    StringI,
}

/// Every type in the Python `DataTypes` declaration order (a later type wins a shared code).
const ALL: [Elementary; 35] = {
    use Elementary::*;
    [
        Bool,
        SInt,
        Int,
        DInt,
        LInt,
        USInt,
        UInt,
        UDInt,
        ULInt,
        Real,
        LReal,
        STime,
        Date,
        TimeOfDay,
        DateAndTime,
        Dt,
        Ldt,
        Time32,
        LogixString,
        String,
        Byte,
        Word,
        DWord,
        LWord,
        String2,
        FTime,
        LTime,
        ITime,
        StringN,
        ShortString,
        Time,
        PaddedEpath,
        PackedEpath,
        EngUnit,
        StringI,
    ]
};

/// How a value is stored, the class a type belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Repr {
    Bool,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    DateAndTime,
    /// Length-prefixed string: length type, encoding, bytes per character.
    Str(LenType, Encoding, usize),
    StringN,
    StringI,
    /// Bits of an unsigned integer of this many bytes.
    Bits(usize),
    Epath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LenType {
    U8,
    U16,
    U32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Latin1,
    Utf8,
    Utf16,
    Utf32,
}

impl Elementary {
    /// The type for a CIP type code, None if the code is not an elementary type.
    pub fn from_code(code: u8) -> Option<Self> {
        ALL.iter().rev().copied().find(|t| t.code() == code)
    }

    /// The type for a name such as `"DINT"` (case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        ALL.iter()
            .copied()
            .find(|t| t.name().eq_ignore_ascii_case(name))
    }

    /// The CIP type code.
    pub fn code(self) -> u8 {
        use Elementary::*;
        match self {
            Bool => 0xC1,
            SInt => 0xC2,
            Int => 0xC3,
            DInt => 0xC4,
            LInt => 0xC5,
            USInt => 0xC6,
            UInt => 0xC7,
            UDInt => 0xC8,
            ULInt => 0xC9,
            Real => 0xCA,
            LReal => 0xCB,
            STime => 0xCC,
            Date => 0xCD,
            TimeOfDay => 0xCE,
            DateAndTime => 0xCF,
            Dt => 0xC0,
            Ldt => 0xCC,
            Time32 => 0xD6,
            LogixString => 0x00,
            String => 0xD0,
            Byte => 0xD1,
            Word => 0xD2,
            DWord => 0xD3,
            LWord => 0xD4,
            String2 => 0xD5,
            FTime => 0xD6,
            LTime => 0xD7,
            ITime => 0xD8,
            StringN => 0xD9,
            ShortString => 0xDA,
            Time => 0xDB,
            PaddedEpath | PackedEpath => 0xDC,
            EngUnit => 0xDD,
            StringI => 0xDE,
        }
    }

    /// The type name, e.g. `"DINT"`.
    pub fn name(self) -> &'static str {
        use Elementary::*;
        match self {
            Bool => "BOOL",
            SInt => "SINT",
            Int => "INT",
            DInt => "DINT",
            LInt => "LINT",
            USInt => "USINT",
            UInt => "UINT",
            UDInt => "UDINT",
            ULInt => "ULINT",
            Real => "REAL",
            LReal => "LREAL",
            STime => "STIME",
            Date => "DATE",
            TimeOfDay => "TIME_OF_DAY",
            DateAndTime => "DATE_AND_TIME",
            Dt => "DT",
            Ldt => "LDT",
            Time32 => "TIME32",
            LogixString => "LOGIX_STRING",
            String => "STRING",
            Byte => "BYTE",
            Word => "WORD",
            DWord => "DWORD",
            LWord => "LWORD",
            String2 => "STRING2",
            FTime => "FTIME",
            LTime => "LTIME",
            ITime => "ITIME",
            StringN => "STRINGN",
            ShortString => "SHORT_STRING",
            Time => "TIME",
            PaddedEpath => "PADDED_EPATH",
            PackedEpath => "PACKED_EPATH",
            EngUnit => "ENGUNIT",
            StringI => "STRINGI",
        }
    }

    fn repr(self) -> Repr {
        use Elementary::*;
        match self {
            Bool => Repr::Bool,
            SInt => Repr::I8,
            Int | ITime => Repr::I16,
            DInt | STime | Time32 | FTime | Time => Repr::I32,
            LInt | LTime => Repr::I64,
            USInt => Repr::U8,
            UInt | Date => Repr::U16,
            UDInt | TimeOfDay => Repr::U32,
            ULInt | Dt | Ldt => Repr::U64,
            Real => Repr::F32,
            LReal => Repr::F64,
            DateAndTime => Repr::DateAndTime,
            LogixString => Repr::Str(LenType::U32, Encoding::Latin1, 1),
            String => Repr::Str(LenType::U16, Encoding::Latin1, 1),
            ShortString => Repr::Str(LenType::U8, Encoding::Latin1, 1),
            String2 => Repr::Str(LenType::U16, Encoding::Utf16, 2),
            StringN => Repr::StringN,
            StringI => Repr::StringI,
            Byte => Repr::Bits(1),
            Word | EngUnit => Repr::Bits(2),
            DWord => Repr::Bits(4),
            LWord => Repr::Bits(8),
            PaddedEpath | PackedEpath => Repr::Epath,
        }
    }

    /// Size in bytes of a fixed-size type, 0 for strings and paths.
    pub fn size(self) -> usize {
        match self.repr() {
            Repr::Bool | Repr::I8 | Repr::U8 => 1,
            Repr::I16 | Repr::U16 => 2,
            Repr::I32 | Repr::U32 | Repr::F32 => 4,
            Repr::I64 | Repr::U64 | Repr::F64 => 8,
            Repr::DateAndTime => 6,
            Repr::Bits(n) => n,
            Repr::Str(..) | Repr::StringN | Repr::StringI | Repr::Epath => 0,
        }
    }

    /// True for the bit string types (BYTE, WORD, DWORD, LWORD, ENGUNIT), whose value is one bool per bit.
    pub fn is_bit_array(self) -> bool {
        matches!(self.repr(), Repr::Bits(_))
    }

    /// True for the integer types.
    pub fn is_integer(self) -> bool {
        matches!(
            self.repr(),
            Repr::I8
                | Repr::I16
                | Repr::I32
                | Repr::I64
                | Repr::U8
                | Repr::U16
                | Repr::U32
                | Repr::U64
        )
    }

    /// Encodes a value of this type.
    pub fn encode(self, value: &Value) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.size().max(8));
        self.encode_into(value, &mut out)?;
        Ok(out)
    }

    /// Encodes a value of this type onto `out`, nothing is appended on error.
    pub fn encode_into(self, value: &Value, out: &mut Vec<u8>) -> Result<()> {
        let fail = || {
            Error::Data(format!(
                "Error packing {} as {}",
                value.py_repr(),
                self.name()
            ))
        };
        let int = |lo: i128, hi: i128| {
            value
                .as_i128()
                .filter(|v| (lo..=hi).contains(v))
                .ok_or_else(fail)
        };
        match self.repr() {
            Repr::Bool => out.push(if value.as_bool().ok_or_else(fail)? {
                0xFF
            } else {
                0x00
            }),
            Repr::I8 => out.extend((int(i8::MIN.into(), i8::MAX.into())? as i8).to_le_bytes()),
            Repr::I16 => out.extend((int(i16::MIN.into(), i16::MAX.into())? as i16).to_le_bytes()),
            Repr::I32 => out.extend((int(i32::MIN.into(), i32::MAX.into())? as i32).to_le_bytes()),
            Repr::I64 => out.extend((int(i64::MIN.into(), i64::MAX.into())? as i64).to_le_bytes()),
            Repr::U8 => out.extend((int(0, u8::MAX.into())? as u8).to_le_bytes()),
            Repr::U16 => out.extend((int(0, u16::MAX.into())? as u16).to_le_bytes()),
            Repr::U32 => out.extend((int(0, u32::MAX.into())? as u32).to_le_bytes()),
            Repr::U64 => out.extend((int(0, u64::MAX.into())? as u64).to_le_bytes()),
            Repr::F32 => {
                let x = value.as_f64().ok_or_else(fail)?;
                let f = x as f32;
                if f.is_infinite() && x.is_finite() {
                    return Err(fail()); // Python: float too large to pack with f format
                }
                out.extend(f.to_le_bytes());
            }
            Repr::F64 => out.extend(value.as_f64().ok_or_else(fail)?.to_le_bytes()),
            Repr::DateAndTime => {
                let Value::Array(parts) = value else {
                    return Err(fail());
                };
                let [time, date] = parts.as_slice() else {
                    return Err(fail());
                };
                let time = time
                    .as_i128()
                    .filter(|v| (0..=u32::MAX.into()).contains(v))
                    .ok_or_else(fail)?;
                let date = date
                    .as_i128()
                    .filter(|v| (0..=u16::MAX.into()).contains(v))
                    .ok_or_else(fail)?;
                out.extend((time as u32).to_le_bytes());
                out.extend((date as u16).to_le_bytes());
            }
            Repr::Str(len_type, encoding, char_size) => {
                let Value::String(text) = value else {
                    return Err(fail());
                };
                let data = encode_text(text, encoding).ok_or_else(fail)?;
                write_len(len_type, data.len() / char_size, out).ok_or_else(fail)?;
                out.extend(data);
            }
            Repr::StringN => {
                let Value::String(text) = value else {
                    return Err(fail());
                };
                out.extend(encode_stringn(text, 1)?);
            }
            Repr::Bits(size) => {
                let Value::Array(bits) = value else {
                    return Err(fail());
                };
                if bits.len() != size * 8 {
                    return Err(Error::Data(format!(
                        "{} needs exactly {} values, got {}",
                        self.name(),
                        size * 8,
                        bits.len()
                    )));
                }
                let mut word = 0u64;
                for (i, bit) in bits.iter().enumerate() {
                    if bit.as_bool().ok_or_else(fail)? {
                        word |= 1 << i;
                    }
                }
                out.extend(&word.to_le_bytes()[..size]);
            }
            Repr::StringI | Repr::Epath => return Err(fail()),
        }
        Ok(())
    }

    /// Decodes a value of this type.
    pub fn decode(self, reader: &mut Reader<'_>) -> Result<Value> {
        let start = reader.position();
        self.decode_inner(reader).map_err(|err| match err {
            Error::BufferEmpty => Error::BufferEmpty,
            _ => Error::Data(format!(
                "Error unpacking {} as {}",
                py_bytes_repr(&reader.buffer()[start..]),
                self.name()
            )),
        })
    }

    fn decode_inner(self, r: &mut Reader<'_>) -> Result<Value> {
        Ok(match self.repr() {
            Repr::Bool => Value::Bool(r.u8()? != 0),
            Repr::I8 => Value::SInt(r.i8()?),
            Repr::I16 => Value::Int(r.i16()?),
            Repr::I32 => Value::DInt(r.i32()?),
            Repr::I64 => Value::LInt(r.i64()?),
            Repr::U8 => Value::USInt(r.u8()?),
            Repr::U16 => Value::UInt(r.u16()?),
            Repr::U32 => Value::UDInt(r.u32()?),
            Repr::U64 => Value::ULInt(r.u64()?),
            Repr::F32 => Value::Real(r.f32()?),
            Repr::F64 => Value::LReal(r.f64()?),
            Repr::DateAndTime => Value::Array(vec![Value::UDInt(r.u32()?), Value::UInt(r.u16()?)]),
            Repr::Str(len_type, encoding, char_size) => {
                let len = read_len(len_type, r)?;
                if len == 0 {
                    return Ok(Value::String(std::string::String::new()));
                }
                let bytes = r.take(len * char_size)?;
                Value::String(decode_text(bytes, encoding)?)
            }
            Repr::StringN => {
                let char_size = r.u16()?;
                let count = usize::from(r.u16()?);
                let encoding = stringn_encoding(char_size)?;
                if count == 0 {
                    return Ok(Value::String(std::string::String::new()));
                }
                let bytes = r.take(count * usize::from(char_size))?;
                Value::String(decode_text(bytes, encoding)?)
            }
            Repr::StringI => decode_stringi(r)?,
            Repr::Bits(size) => {
                let bytes = r.take(size)?;
                let mut word = [0u8; 8];
                word[..size].copy_from_slice(bytes);
                let word = u64::from_le_bytes(word);
                Value::Array(
                    (0..size * 8)
                        .map(|i| Value::Bool(word >> i & 1 == 1))
                        .collect(),
                )
            }
            Repr::Epath => return Err(Error::data("Decoding EPATHs not supported")),
        })
    }
}

fn write_len(len_type: LenType, len: usize, out: &mut Vec<u8>) -> Option<()> {
    match len_type {
        LenType::U8 => out.push(u8::try_from(len).ok()?),
        LenType::U16 => out.extend(u16::try_from(len).ok()?.to_le_bytes()),
        LenType::U32 => out.extend(u32::try_from(len).ok()?.to_le_bytes()),
    }
    Some(())
}

fn read_len(len_type: LenType, r: &mut Reader<'_>) -> Result<usize> {
    Ok(match len_type {
        LenType::U8 => r.u8()?.into(),
        LenType::U16 => r.u16()?.into(),
        LenType::U32 => {
            usize::try_from(r.u32()?).map_err(|_| Error::data("string length too large"))?
        }
    })
}

fn encode_text(text: &str, encoding: Encoding) -> Option<Vec<u8>> {
    Some(match encoding {
        Encoding::Latin1 => text
            .chars()
            .map(|c| u8::try_from(u32::from(c)).ok())
            .collect::<Option<Vec<u8>>>()?,
        Encoding::Utf8 => text.as_bytes().to_vec(),
        Encoding::Utf16 => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        Encoding::Utf32 => text
            .chars()
            .flat_map(|c| u32::from(c).to_le_bytes())
            .collect(),
    })
}

fn decode_text(bytes: &[u8], encoding: Encoding) -> Result<String> {
    let bad = || Error::data("invalid string data");
    match encoding {
        Encoding::Latin1 => Ok(bytes.iter().map(|&b| char::from(b)).collect()),
        Encoding::Utf8 => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| bad()),
        Encoding::Utf16 => {
            if bytes.len() % 2 != 0 {
                return Err(bad());
            }
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).map_err(|_| bad())
        }
        Encoding::Utf32 => {
            if bytes.len() % 4 != 0 {
                return Err(bad());
            }
            bytes
                .chunks_exact(4)
                .map(|c| char::from_u32(u32::from_le_bytes([c[0], c[1], c[2], c[3]])))
                .collect::<Option<String>>()
                .ok_or_else(bad)
        }
    }
}

fn stringn_encoding(char_size: u16) -> Result<Encoding> {
    match char_size {
        1 => Ok(Encoding::Utf8),
        2 => Ok(Encoding::Utf16),
        4 => Ok(Encoding::Utf32),
        _ => Err(Error::Data(format!(
            "Unsupported character size: {char_size}"
        ))),
    }
}

/// Encodes a STRINGN: character size, character count, then the characters (UTF-8, UTF-16 or UTF-32).
pub fn encode_stringn(text: &str, char_size: u16) -> Result<Vec<u8>> {
    let fail = || {
        Error::Data(format!(
            "Error encoding {} as STRINGN using char. size {char_size}",
            crate::value::py_str_repr(text)
        ))
    };
    let encoding = stringn_encoding(char_size).map_err(|_| fail())?;
    let data = encode_text(text, encoding).ok_or_else(fail)?;
    let count = u16::try_from(data.len() / usize::from(char_size)).map_err(|_| fail())?;
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend(char_size.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend(data);
    Ok(out)
}

/// Decodes a STRINGI as `[[strings], [languages], [character sets]]`.
fn decode_stringi(r: &mut Reader<'_>) -> Result<Value> {
    let count = r.u8()?;
    let (mut strings, mut langs, mut char_sets) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..count {
        // the language is 3 characters, read as the Python driver does: a SHORT_STRING of length 3
        let lang_bytes: Vec<u8> = r.rest().iter().take(3).copied().collect();
        r.skip(lang_bytes.len());
        let mut prefixed = vec![3u8];
        prefixed.extend(&lang_bytes);
        langs.push(Elementary::ShortString.decode(&mut Reader::new(&prefixed))?);
        let string_type = match r.rest().first() {
            Some(0xD0) => Elementary::String,
            Some(0xD5) => Elementary::String2,
            Some(0xD9) => Elementary::StringN,
            Some(0xDA) => Elementary::ShortString,
            _ => return Err(Error::data("unknown STRINGI string type")),
        };
        r.skip(1);
        char_sets.push(Value::UInt(r.u16()?));
        strings.push(string_type.decode(r)?);
    }
    Ok(Value::Array(vec![
        Value::Array(strings),
        Value::Array(langs),
        Value::Array(char_sets),
    ]))
}

/// A Logix STRING type as uploaded from its template: a UDINT length and `size` bytes of characters, of which
/// at most `max_len` may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedString {
    /// Bytes reserved for characters (the template's structure size minus the 4-byte length).
    pub size: usize,
    /// Most characters the string holds.
    pub max_len: usize,
}

impl FixedString {
    /// Encodes `value` (a `Value::String`) padded with zeros to the full size.
    pub fn encode(&self, value: &Value) -> Result<Vec<u8>> {
        let fail = || {
            Error::Data(format!(
                "Error packing {} as FixedSizeString",
                value.py_repr()
            ))
        };
        let Value::String(text) = value else {
            return Err(fail());
        };
        let chars = text.chars().count();
        if chars > self.max_len {
            return Err(Error::Data(format!(
                "String longer than {} characters",
                self.max_len
            )));
        }
        let data = encode_text(text, Encoding::Latin1).ok_or_else(fail)?;
        let len = u32::try_from(chars).map_err(|_| fail())?;
        let mut out = Vec::with_capacity(4 + self.size.max(data.len()));
        out.extend(len.to_le_bytes());
        out.extend(&data);
        out.resize(out.len() + self.size.saturating_sub(chars), 0);
        Ok(out)
    }

    /// Decodes the length and the `size` bytes that follow it.
    pub fn decode(&self, reader: &mut Reader<'_>) -> Result<Value> {
        let start = reader.position();
        let inner = |r: &mut Reader<'_>| -> Result<Value> {
            let len = r.u32()? as usize;
            let data = r.take(self.size)?;
            Ok(Value::String(
                data[..len.min(data.len())]
                    .iter()
                    .map(|&b| char::from(b))
                    .collect(),
            ))
        };
        inner(reader).map_err(|err| match err {
            Error::BufferEmpty => Error::BufferEmpty,
            _ => Error::Data(format!(
                "Error unpacking {} as FixedSizeString",
                py_bytes_repr(&reader.buffer()[start..])
            )),
        })
    }
}

/// How many elements an array has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrayLen {
    /// A fixed element count.
    Fixed(usize),
    /// The count is read from the data as this integer type before the elements.
    Prefixed(Elementary),
    /// Every element left in the data.
    Unbounded,
}

/// Encodes array elements as the Python `Array` type: a fixed length (or `count`) needs at least that many
/// values and encodes only that many; bit string elements take 8 × size bools each.
pub fn encode_array(
    elem: Elementary,
    length: &ArrayLen,
    values: &[Value],
    count: Option<usize>,
) -> Result<Vec<u8>> {
    let fixed = count.filter(|&n| n > 0).or(match length {
        ArrayLen::Fixed(n) if *n > 0 => Some(*n),
        _ => None,
    });
    let mut n = match fixed {
        Some(n) if values.len() < n => {
            return Err(Error::Data(format!(
                "Not enough values to encode array of {}[{n}]",
                elem.name()
            )));
        }
        Some(n) => n,
        None => values.len(),
    };
    let mut out = Vec::with_capacity(n * elem.size().max(1));
    if elem.is_bit_array() {
        let chunk = elem.size() * 8;
        if values.len() % chunk != 0 {
            return Err(Error::Data(format!(
                "BOOL array values must be a multiple of {chunk}"
            )));
        }
        n = values.len() / chunk;
        for bits in values.chunks(chunk).take(n) {
            elem.encode_into(&Value::Array(bits.to_vec()), &mut out)?;
        }
    } else {
        for value in &values[..n] {
            elem.encode_into(value, &mut out)?;
        }
    }
    Ok(out)
}

/// Decodes array elements as the Python `Array` type; bit string elements are flattened to bools.
pub fn decode_array(
    elem: Elementary,
    length: &ArrayLen,
    r: &mut Reader<'_>,
    count: Option<usize>,
) -> Result<Vec<Value>> {
    let start = r.position();
    let fixed = count.filter(|&n| n > 0);
    let result = (|| {
        let n = match (fixed, length) {
            (Some(n), _) => Some(n),
            (None, ArrayLen::Fixed(n)) => Some(*n),
            (None, ArrayLen::Prefixed(t)) => {
                let len = t
                    .decode(r)?
                    .as_i128()
                    .ok_or_else(|| Error::data("array length is not an integer"))?;
                Some(usize::try_from(len).map_err(|_| Error::data("negative array length"))?)
            }
            (None, ArrayLen::Unbounded) => None,
        };
        let mut items = Vec::with_capacity(n.unwrap_or(0).min(r.remaining()));
        match n {
            Some(n) => {
                for _ in 0..n {
                    items.push(elem.decode(r)?);
                }
            }
            None => loop {
                match elem.decode(r) {
                    Ok(v) => items.push(v),
                    Err(Error::BufferEmpty) => break,
                    Err(e) => return Err(e),
                }
            },
        }
        if elem.is_bit_array() {
            items = items
                .into_iter()
                .flat_map(|word| match word {
                    Value::Array(bits) => bits,
                    other => vec![other],
                })
                .collect();
        }
        Ok(items)
    })();
    result.map_err(|err| match err {
        Error::BufferEmpty => Error::BufferEmpty,
        _ => Error::Data(format!(
            "Error unpacking into {}[...] from {}",
            elem.name(),
            py_bytes_repr(&r.buffer()[start..])
        )),
    })
}

/// The 32 bits of a DWORD, least significant first.
pub fn dword_to_bools(dword: u32) -> Vec<bool> {
    (0..32).map(|i| dword >> i & 1 == 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_codes_resolve_like_python() {
        assert_eq!(Elementary::from_code(0xCC), Some(Elementary::Ldt));
        assert_eq!(Elementary::from_code(0xD6), Some(Elementary::FTime));
        assert_eq!(Elementary::from_code(0xC4), Some(Elementary::DInt));
        assert_eq!(Elementary::from_code(0x01), None);
    }

    #[test]
    fn real_rejects_overflow_but_keeps_infinity() {
        assert!(Elementary::Real.encode(&Value::LReal(1e39)).is_err());
        assert_eq!(
            Elementary::Real.encode(&Value::LReal(f64::INFINITY)),
            Ok(f32::INFINITY.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn integers_reject_bools_and_floats() {
        assert!(Elementary::DInt.encode(&Value::Bool(true)).is_err());
        assert!(Elementary::DInt.encode(&Value::LReal(1.0)).is_err());
        assert_eq!(Elementary::DInt.encode(&Value::LInt(-1)), Ok(vec![0xff; 4]));
    }
}
