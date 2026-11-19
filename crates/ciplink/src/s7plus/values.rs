//! S7 values <-> ciplink [`Value`] (spec 11.5, 11.6, 11.8, 17.3): decode by the member's softdatatype, with a
//! generic fallback that never loses data; encode a write in the wire form a read returns.

use indexmap::IndexMap;

use super::browse::{Address, Member, SymbolTree};
use super::codec::{Payload, Scalar, Struct, WireValue, dt};
use super::types::softdatatype_name;
use crate::{ErrorKind, TagError, Value};

/// RID of the DTL system type (its packed-struct ID).
pub(crate) const DTL_RID: u32 = 0x0200_0043;

// ------------------------------------------------------------------------------------------------ dates

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// 1 = Sunday ... 7 = Saturday.
fn weekday(days: i64) -> u8 {
    ((days + 4).rem_euclid(7) + 1) as u8
}

const DAY_NS: u64 = 86_400_000_000_000;
const DATE_EPOCH_1990: i64 = 7305; // days from 1970-01-01 to 1990-01-01

fn fmt_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `HH:MM:SS` and the fraction with `digits` digits of `ns`.
fn fmt_time(ns_of_day: u64, digits: usize) -> String {
    let secs = ns_of_day / 1_000_000_000;
    let frac = ns_of_day % 1_000_000_000;
    let base = format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60);
    let frac = format!("{frac:09}");
    format!("{base}.{}", &frac[..digits])
}

fn fmt_datetime(ns_since_1970: i128, digits: usize) -> String {
    let days = ns_since_1970.div_euclid(i128::from(DAY_NS)) as i64;
    let ns = ns_since_1970.rem_euclid(i128::from(DAY_NS)) as u64;
    format!("{}T{}", fmt_date(days), fmt_time(ns, digits))
}

/// Parses `HH:MM:SS[.fffffffff]` to ns of day.
fn parse_time(s: &str) -> Option<u64> {
    let (hms, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    let parts: Vec<u64> = hms
        .split(':')
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    let [h, m, sec] = parts.as_slice() else {
        return None;
    };
    if *h > 23
        || *m > 59
        || *sec > 59
        || frac.len() > 9
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let frac_ns: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}").parse().ok()?
    };
    Some(((h * 60 + m) * 60 + sec) * 1_000_000_000 + frac_ns)
}

/// Parses `YYYY-MM-DD` to days since 1970-01-01.
fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || d == 0 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    (civil_from_days(days) == (y, m, d)).then_some(days)
}

/// Parses `YYYY-MM-DD[T| ]HH:MM:SS[.f]` (the time is optional) to ns since 1970-01-01.
fn parse_datetime(s: &str) -> Option<i128> {
    let s = s.trim();
    let (date, time) = match s.find(['T', ' ']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let days = parse_date(date)?;
    let ns = match time {
        Some(t) => parse_time(t)?,
        None => 0,
    };
    Some(i128::from(days) * i128::from(DAY_NS) + i128::from(ns))
}

fn bcd(b: u8) -> u32 {
    u32::from(b >> 4) * 10 + u32::from(b & 0x0F)
}

fn to_bcd(v: u32) -> u8 {
    (((v / 10) % 10) << 4 | (v % 10)) as u8
}

// ------------------------------------------------------------------------------------------------ decode

/// The spec name of a wire datatype (the `data_type` of a value decoded generically).
fn wire_name(datatype: u8) -> &'static str {
    match datatype {
        dt::NULL => "Null",
        dt::BOOL => "Bool",
        dt::USINT => "USInt",
        dt::UINT => "UInt",
        dt::UDINT => "UDInt",
        dt::ULINT => "ULInt",
        dt::SINT => "SInt",
        dt::INT => "Int",
        dt::DINT => "DInt",
        dt::LINT => "LInt",
        dt::BYTE => "Byte",
        dt::WORD => "Word",
        dt::DWORD => "DWord",
        dt::LWORD => "LWord",
        dt::REAL => "Real",
        dt::LREAL => "LReal",
        dt::TIMESTAMP => "Timestamp",
        dt::TIMESPAN => "Timespan",
        dt::RID => "RID",
        dt::AID => "AID",
        dt::BLOB => "Blob",
        dt::WSTRING => "WString",
        dt::VARIANT => "Variant",
        dt::STRUCT => "Struct",
        _ => "S7String",
    }
}

/// A wire scalar as a Value by its own type.
fn generic_scalar(s: &Scalar) -> Value {
    match s {
        Scalar::Null => Value::Bytes(Vec::new()),
        Scalar::Bool(v) => Value::Bool(*v),
        Scalar::USInt(v) | Scalar::Byte(v) => Value::USInt(*v),
        Scalar::UInt(v) | Scalar::Word(v) => Value::UInt(*v),
        Scalar::UDInt(v)
        | Scalar::DWord(v)
        | Scalar::Rid(v)
        | Scalar::Aid(v)
        | Scalar::Variant(v)
        | Scalar::S7String(v) => Value::UDInt(*v),
        Scalar::ULInt(v) | Scalar::LWord(v) | Scalar::Timestamp(v) => Value::ULInt(*v),
        Scalar::SInt(v) => Value::SInt(*v),
        Scalar::Int(v) => Value::Int(*v),
        Scalar::DInt(v) => Value::DInt(*v),
        Scalar::LInt(v) | Scalar::Timespan(v) => Value::LInt(*v),
        Scalar::Real(v) => Value::Real(*v),
        Scalar::LReal(v) => Value::LReal(*v),
        Scalar::Blob(b) => Value::Bytes(b.data.clone()),
        Scalar::WString(s) => Value::String(s.clone()),
        Scalar::Struct(s) => match s.as_ref() {
            Struct::Normal { elements, .. } => Value::Struct(
                elements
                    .iter()
                    .map(|(id, v)| (id.to_string(), generic(v)))
                    .collect(),
            ),
            Struct::Packed { data, .. } => Value::Bytes(data.clone()),
        },
    }
}

/// Any wire value as a Value by its own types.
pub(crate) fn generic(v: &WireValue) -> Value {
    match &v.payload {
        Payload::Scalar(s) => generic_scalar(s),
        Payload::Array(items) => Value::Array(items.iter().map(generic_scalar).collect()),
        Payload::Sparse(items) => Value::Struct(
            items
                .iter()
                .map(|(k, s)| (k.to_string(), generic_scalar(s)))
                .collect(),
        ),
    }
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// A STRING value: max length, current length, characters (spec 11.5).
fn s7_string(items: &[Scalar]) -> Option<String> {
    let bytes: Vec<u8> = items
        .iter()
        .map(|s| match s {
            Scalar::USInt(b) | Scalar::Byte(b) => Some(*b),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let len = usize::from(*bytes.get(1)?);
    Some(latin1(
        bytes.get(2..2 + len.min(bytes.len().saturating_sub(2)))?,
    ))
}

/// A WSTRING value: max length, current length, UTF-16 code units.
fn s7_wstring(items: &[Scalar]) -> Option<String> {
    let units: Vec<u16> = items
        .iter()
        .map(|s| match s {
            Scalar::UInt(u) | Scalar::Word(u) => Some(*u),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let len = usize::from(*units.get(1)?);
    let chars = units.get(2..2 + len.min(units.len().saturating_sub(2)))?;
    Some(String::from_utf16_lossy(chars))
}

fn s5time_ms(w: u16) -> i32 {
    let base = [10, 100, 1000, 10_000][usize::from((w >> 12) & 3)];
    let digits = bcd((w >> 8) as u8 & 0x0F) * 100 + bcd(w as u8);
    (digits * base) as i32
}

fn dt_string(b: &[u8]) -> Option<String> {
    if b.len() != 8 {
        return None;
    }
    let yy = bcd(b[0]) as i64;
    let year = if yy >= 90 { 1900 + yy } else { 2000 + yy };
    let days = days_from_civil(year, bcd(b[1]), bcd(b[2]));
    let ms = bcd(b[6]) * 10 + u32::from(b[7] >> 4);
    let ns = ((u64::from(bcd(b[3])) * 60 + u64::from(bcd(b[4]))) * 60 + u64::from(bcd(b[5])))
        * 1_000_000_000
        + u64::from(ms) * 1_000_000;
    Some(format!("{}T{}", fmt_date(days), fmt_time(ns, 3)))
}

fn dtl_string(b: &[u8]) -> Option<String> {
    if b.len() < 12 {
        return None;
    }
    let year = i64::from(u16::from_be_bytes([b[0], b[1]]));
    let ns = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    let tod = ((u64::from(b[5]) * 60 + u64::from(b[6])) * 60 + u64::from(b[7])) * 1_000_000_000
        + u64::from(ns);
    let days = days_from_civil(year, u32::from(b[2]), u32::from(b[3]));
    Some(format!("{}T{}", fmt_date(days), fmt_time(tod, 9)))
}

/// One scalar of softdatatype `sdt`; None if the wire type is not the expected one.
fn decode_scalar(sdt: u8, s: &Scalar) -> Option<Value> {
    Some(match (sdt, s) {
        (1 | 40, Scalar::Bool(v)) => Value::Bool(*v),
        (2, Scalar::Byte(v) | Scalar::USInt(v)) => Value::USInt(*v),
        (3, Scalar::USInt(v) | Scalar::Byte(v)) => Value::String(latin1(&[*v])),
        (4, Scalar::Word(v)) => Value::UInt(*v),
        (5, Scalar::Int(v)) => Value::Int(*v),
        (6, Scalar::DWord(v)) => Value::UDInt(*v),
        (7, Scalar::DInt(v)) => Value::DInt(*v),
        (8, Scalar::Real(v)) => Value::Real(*v),
        (9, Scalar::UInt(v)) => Value::String(fmt_date(DATE_EPOCH_1990 + i64::from(*v))),
        (10, Scalar::UDInt(v)) => Value::String(fmt_time(u64::from(*v) * 1_000_000, 3)),
        (11, Scalar::DInt(v)) => Value::DInt(*v),
        (12, Scalar::Word(v)) => Value::DInt(s5time_ms(*v)),
        (48, Scalar::LReal(v)) => Value::LReal(*v),
        (49, Scalar::ULInt(v)) => Value::ULInt(*v),
        (50, Scalar::LInt(v)) => Value::LInt(*v),
        (51, Scalar::LWord(v)) => Value::ULInt(*v),
        (52, Scalar::USInt(v)) => Value::USInt(*v),
        (53, Scalar::UInt(v)) => Value::UInt(*v),
        (54, Scalar::UDInt(v)) => Value::UDInt(*v),
        (55, Scalar::SInt(v)) => Value::SInt(*v),
        (61, Scalar::UInt(v) | Scalar::Word(v)) => Value::String(String::from_utf16_lossy(&[*v])),
        (64, Scalar::Timespan(v)) => Value::LInt(*v),
        (65, Scalar::ULInt(v)) => Value::String(fmt_time(*v % DAY_NS, 9)),
        (66, Scalar::Timestamp(v)) => Value::String(fmt_datetime(i128::from(*v), 9)),
        (144..=156, Scalar::Word(v) | Scalar::UInt(v)) => Value::UInt(*v),
        (208, Scalar::UInt(v) | Scalar::Word(v)) => Value::UInt(*v),
        _ => return None,
    })
}

/// The bytes of a one-dimensional BOOL array as Bools (element i = bit i % 8 of byte i / 8).
fn unpack_bools(items: &[Scalar], count: usize) -> Option<Vec<Value>> {
    let bytes: Vec<u8> = items
        .iter()
        .map(|s| match s {
            Scalar::Byte(b) | Scalar::USInt(b) => Some(*b),
            _ => None,
        })
        .collect::<Option<_>>()?;
    (0..count)
        .map(|i| bytes.get(i / 8).map(|b| Value::Bool(b >> (i % 8) & 1 != 0)))
        .collect()
}

/// Decodes a read value for its address; falls back to the generic form (and the wire type's name).
pub(crate) fn decode(tree: &SymbolTree, address: &Address, v: &WireValue) -> (Value, String) {
    let leaf = &address.leaf;
    let name = tree.data_type(address);
    let whole_array = leaf.layout.is_array() && !address.element;
    let decoded = if whole_array {
        decode_array(tree, leaf, v)
    } else {
        decode_one(tree, leaf, v)
    };
    match decoded {
        Some(value) => (value, name),
        None => {
            let shape = if matches!(v.payload, Payload::Scalar(_)) {
                ""
            } else {
                "[]"
            };
            (generic(v), format!("{}{shape}", wire_name(v.datatype)))
        }
    }
}

fn decode_array(tree: &SymbolTree, leaf: &Member, v: &WireValue) -> Option<Value> {
    // a whole array of structs: one packed struct holding the elements back to back (codec.rs)
    if let Some(Scalar::Struct(s)) = v.as_scalar()
        && let Struct::Packed {
            id,
            timestamp,
            flags,
            element_size: Some(size),
            data,
        } = s.as_ref()
    {
        let size = usize::try_from(*size).ok().filter(|&n| n > 0)?;
        if !leaf.layout.is_struct_array() || data.len() % size != 0 {
            return None;
        }
        return data
            .chunks(size)
            .map(|chunk| {
                let element = Struct::Packed {
                    id: *id,
                    timestamp: *timestamp,
                    flags: *flags,
                    element_size: None,
                    data: chunk.to_vec(),
                };
                decode_one(
                    tree,
                    leaf,
                    &WireValue::scalar(Scalar::Struct(Box::new(element))),
                )
            })
            .collect::<Option<Vec<_>>>()
            .map(Value::Array);
    }
    let items = v.as_array()?;
    if leaf.is_bool() {
        return if leaf.layout.counts.len() == 1 {
            Some(Value::Array(unpack_bools(
                items,
                leaf.layout.total() as usize,
            )?))
        } else {
            let bytes = items
                .iter()
                .map(|s| match s {
                    Scalar::Byte(b) | Scalar::USInt(b) => Some(*b),
                    _ => None,
                })
                .collect::<Option<Vec<u8>>>()?;
            Some(Value::Bytes(bytes))
        };
    }
    if leaf.layout.is_struct_array() {
        let values = items
            .iter()
            .map(|s| decode_one(tree, leaf, &WireValue::scalar(s.clone())))
            .collect::<Option<Vec<_>>>()?;
        return Some(Value::Array(values));
    }
    items
        .iter()
        .map(|s| decode_scalar(leaf.softdatatype, s))
        .collect::<Option<Vec<_>>>()
        .map(Value::Array)
}

/// One value (a scalar, a string, a struct, or one element of an array).
fn decode_one(tree: &SymbolTree, leaf: &Member, v: &WireValue) -> Option<Value> {
    match (&v.payload, leaf.softdatatype) {
        (Payload::Array(items), 19) => s7_string(items).map(Value::String),
        (Payload::Array(items), 62) => s7_wstring(items).map(Value::String),
        (Payload::Array(items), 14) => {
            let bytes: Vec<u8> = items
                .iter()
                .map(|s| match s {
                    Scalar::USInt(b) | Scalar::Byte(b) => Some(*b),
                    _ => None,
                })
                .collect::<Option<_>>()?;
            dt_string(&bytes).map(Value::String)
        }
        (Payload::Array(items), 96) => items
            .iter()
            .map(|s| match s {
                Scalar::USInt(b) | Scalar::Byte(b) => Some(*b),
                _ => None,
            })
            .collect::<Option<Vec<u8>>>()
            .map(Value::Bytes),
        (Payload::Scalar(Scalar::Struct(s)), _) => match s.as_ref() {
            Struct::Packed {
                id, flags, data, ..
            } => {
                if *id == DTL_RID {
                    return dtl_string(data).map(Value::String);
                }
                let rid = leaf.layout.relation.unwrap_or(*id);
                let classic = flags & 1 != 0;
                Some(
                    decode_packed(tree, rid, data, classic, 0)
                        .map_or_else(|| Value::Bytes(data.clone()), Value::Struct),
                )
            }
            Struct::Normal { .. } => None,
        },
        (Payload::Scalar(s), sdt) => decode_scalar(sdt, s),
        _ => None,
    }
}

/// The scalar a member of `sdt` occupies in a memory image, at `off` (big endian).
fn memory_scalar(sdt: u8, data: &[u8], off: usize) -> Option<Scalar> {
    let b = |n: usize| data.get(off..off.checked_add(n)?);
    Some(match sdt {
        2 => Scalar::Byte(*b(1)?.first()?),
        3 | 52 => Scalar::USInt(*b(1)?.first()?),
        55 => Scalar::SInt(*b(1)?.first()? as i8),
        4 | 12 => Scalar::Word(u16::from_be_bytes(b(2)?.try_into().ok()?)),
        61 | 144..=156 => Scalar::Word(u16::from_be_bytes(b(2)?.try_into().ok()?)),
        5 => Scalar::Int(i16::from_be_bytes(b(2)?.try_into().ok()?)),
        9 | 53 | 208 => Scalar::UInt(u16::from_be_bytes(b(2)?.try_into().ok()?)),
        6 => Scalar::DWord(u32::from_be_bytes(b(4)?.try_into().ok()?)),
        7 | 11 => Scalar::DInt(i32::from_be_bytes(b(4)?.try_into().ok()?)),
        8 => Scalar::Real(f32::from_be_bytes(b(4)?.try_into().ok()?)),
        10 | 54 => Scalar::UDInt(u32::from_be_bytes(b(4)?.try_into().ok()?)),
        48 => Scalar::LReal(f64::from_be_bytes(b(8)?.try_into().ok()?)),
        49 | 65 => Scalar::ULInt(u64::from_be_bytes(b(8)?.try_into().ok()?)),
        50 => Scalar::LInt(i64::from_be_bytes(b(8)?.try_into().ok()?)),
        51 => Scalar::LWord(u64::from_be_bytes(b(8)?.try_into().ok()?)),
        64 => Scalar::Timespan(i64::from_be_bytes(b(8)?.try_into().ok()?)),
        66 => Scalar::Timestamp(u64::from_be_bytes(b(8)?.try_into().ok()?)),
        _ => return None,
    })
}

/// One member of a packed struct (spec 11.8).
fn packed_member(
    tree: &SymbolTree,
    m: &Member,
    data: &[u8],
    classic: bool,
    depth: usize,
) -> Option<Value> {
    let off = if classic {
        m.layout.classic
    } else {
        m.layout.optimized
    } as usize;
    match m.layout.kind {
        1 => {
            if m.is_bool() {
                let byte = *data.get(off)?;
                return Some(Value::Bool(if m.softdatatype == 40 && !classic {
                    byte != 0
                } else {
                    byte >> m.bit() & 1 != 0
                }));
            }
            if m.softdatatype == 14 {
                return dt_string(data.get(off..off + 8)?).map(Value::String);
            }
            decode_scalar(m.softdatatype, &memory_scalar(m.softdatatype, data, off)?)
        }
        2 => {
            if m.softdatatype == 62 {
                let unit = |i: usize| -> Option<u16> {
                    Some(u16::from_be_bytes(
                        data.get(off + 2 * i..off + 2 * i + 2)?.try_into().ok()?,
                    ))
                };
                let len = usize::from(unit(1)?);
                let units = (0..len)
                    .map(|i| unit(2 + i))
                    .collect::<Option<Vec<u16>>>()?;
                Some(Value::String(String::from_utf16_lossy(&units)))
            } else {
                let len = usize::from(*data.get(off + 1)?);
                Some(Value::String(latin1(data.get(off + 2..off + 2 + len)?)))
            }
        }
        5 => {
            let rid = m.layout.relation?;
            let sub = data.get(off..)?;
            if rid == DTL_RID {
                return dtl_string(sub).map(Value::String);
            }
            decode_packed(tree, rid, sub, classic, depth + 1).map(Value::Struct)
        }
        6 => {
            let rid = m.layout.relation?;
            let (classic_size, optimized_size) = m.layout.struct_size?;
            let size = if classic {
                classic_size
            } else {
                optimized_size
            } as usize;
            let count = *m.layout.counts.first()? as usize;
            (0..count)
                .map(|i| {
                    let sub = data.get(off + i * size..)?;
                    decode_packed(tree, rid, sub, classic, depth + 1).map(Value::Struct)
                })
                .collect::<Option<Vec<_>>>()
                .map(Value::Array)
        }
        _ => None,
    }
}

/// A packed struct's members by name, from the struct's own type; None if a member cannot be placed.
fn decode_packed(
    tree: &SymbolTree,
    rid: u32,
    data: &[u8],
    classic: bool,
    depth: usize,
) -> Option<IndexMap<String, Value>> {
    if depth > 16 {
        return None;
    }
    let t = tree.types.get(&rid)?;
    t.members
        .iter()
        .map(|m| {
            Some((
                m.name.clone(),
                packed_member(tree, m, data, classic, depth)?,
            ))
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------ encode

fn bad_value(name: &str, value: &Value, why: &str) -> TagError {
    TagError::new(
        format!("Cannot write {} to {name}: {why}", value.py_repr()),
        ErrorKind::BadValue,
    )
}

fn int_in<T: TryFrom<i128>>(name: &str, value: &Value) -> Result<T, TagError> {
    value
        .as_i128()
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| bad_value(name, value, "not an integer in range"))
}

fn text<'a>(name: &str, value: &'a Value) -> Result<&'a str, TagError> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(bad_value(name, value, "expected a string")),
    }
}

/// One scalar of softdatatype `sdt` as the PLC returns it (spec 17.3).
fn encode_scalar(name: &str, sdt: u8, value: &Value) -> Result<Scalar, TagError> {
    let bad = |why: &str| bad_value(name, value, why);
    Ok(match sdt {
        1 | 40 => Scalar::Bool(value.as_bool().ok_or_else(|| bad("expected a BOOL"))?),
        2 => Scalar::Byte(int_in(name, value)?),
        3 => {
            let s = text(name, value)?;
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if (c as u32) < 256 => Scalar::USInt(c as u32 as u8),
                _ => return Err(bad("expected one ISO-8859-1 character")),
            }
        }
        4 => Scalar::Word(int_in(name, value)?),
        5 => Scalar::Int(int_in(name, value)?),
        6 => Scalar::DWord(int_in(name, value)?),
        7 | 11 => Scalar::DInt(int_in(name, value)?),
        8 => Scalar::Real(value.as_f64().ok_or_else(|| bad("expected a number"))? as f32),
        48 => Scalar::LReal(value.as_f64().ok_or_else(|| bad("expected a number"))?),
        49 => Scalar::ULInt(int_in(name, value)?),
        50 => Scalar::LInt(int_in(name, value)?),
        51 => Scalar::LWord(int_in(name, value)?),
        52 => Scalar::USInt(int_in(name, value)?),
        53 | 208 => Scalar::UInt(int_in(name, value)?),
        54 => Scalar::UDInt(int_in(name, value)?),
        55 => Scalar::SInt(int_in(name, value)?),
        144..=156 => Scalar::Word(int_in(name, value)?),
        64 => Scalar::Timespan(int_in(name, value)?),
        61 => {
            let s = text(name, value)?;
            let units: Vec<u16> = s.encode_utf16().collect();
            match units.as_slice() {
                [u] => Scalar::UInt(*u),
                _ => return Err(bad("expected one UTF-16 character")),
            }
        }
        12 => {
            let ms: i64 = int_in(name, value)?;
            let (base, unit) = [(0u16, 10i64), (1, 100), (2, 1000), (3, 10_000)]
                .into_iter()
                .find(|(_, unit)| ms >= 0 && ms <= 999 * unit)
                .ok_or_else(|| bad("S5TIME holds 0 to 9990 s"))?;
            let n = (ms / unit) as u32;
            let digits = u16::from(to_bcd(n / 100)) << 8 | u16::from(to_bcd(n % 100));
            Scalar::Word(base << 12 | digits)
        }
        9 => {
            let days = parse_date(text(name, value)?).ok_or_else(|| bad("expected YYYY-MM-DD"))?;
            Scalar::UInt(
                u16::try_from(days - DATE_EPOCH_1990).map_err(|_| bad("DATE out of range"))?,
            )
        }
        10 => {
            let ns = parse_time(text(name, value)?).ok_or_else(|| bad("expected HH:MM:SS.mmm"))?;
            Scalar::UDInt((ns / 1_000_000) as u32)
        }
        65 => Scalar::ULInt(
            parse_time(text(name, value)?).ok_or_else(|| bad("expected HH:MM:SS.nnnnnnnnn"))?,
        ),
        66 => {
            let ns = parse_datetime(text(name, value)?)
                .ok_or_else(|| bad("expected an ISO 8601 date and time"))?;
            Scalar::Timestamp(u64::try_from(ns).map_err(|_| bad("LDT starts in 1970"))?)
        }
        _ => {
            return Err(TagError::new(
                format!(
                    "Writing {} ({name}) is not supported",
                    softdatatype_name(sdt)
                ),
                ErrorKind::BadRequest,
            ));
        }
    })
}

fn dt_bytes(name: &str, value: &Value) -> Result<Vec<u8>, TagError> {
    let bad = |why: &str| bad_value(name, value, why);
    let ns = parse_datetime(text(name, value)?)
        .ok_or_else(|| bad("expected an ISO 8601 date and time"))?;
    let days = ns.div_euclid(i128::from(DAY_NS)) as i64;
    let tod = ns.rem_euclid(i128::from(DAY_NS)) as u64;
    let (y, m, d) = civil_from_days(days);
    if !(1990..=2089).contains(&y) {
        return Err(bad("DATE_AND_TIME holds 1990 to 2089"));
    }
    let secs = tod / 1_000_000_000;
    let ms = (tod % 1_000_000_000 / 1_000_000) as u32;
    Ok(vec![
        to_bcd((y % 100) as u32),
        to_bcd(m),
        to_bcd(d),
        to_bcd((secs / 3600) as u32),
        to_bcd((secs / 60 % 60) as u32),
        to_bcd((secs % 60) as u32),
        to_bcd(ms / 10),
        ((ms % 10) as u8) << 4 | weekday(days),
    ])
}

fn dtl_bytes(name: &str, value: &Value) -> Result<Vec<u8>, TagError> {
    let bad = |why: &str| bad_value(name, value, why);
    let ns = parse_datetime(text(name, value)?)
        .ok_or_else(|| bad("expected an ISO 8601 date and time"))?;
    let days = ns.div_euclid(i128::from(DAY_NS)) as i64;
    let tod = ns.rem_euclid(i128::from(DAY_NS)) as u64;
    let (y, m, d) = civil_from_days(days);
    let year = u16::try_from(y)
        .ok()
        .filter(|y| (1970..=2554).contains(y))
        .ok_or_else(|| bad("DTL holds 1970 to 2554"))?;
    let secs = tod / 1_000_000_000;
    let mut out = year.to_be_bytes().to_vec();
    out.extend_from_slice(&[
        m as u8,
        d as u8,
        weekday(days),
        (secs / 3600) as u8,
        (secs / 60 % 60) as u8,
        (secs % 60) as u8,
    ]);
    out.extend_from_slice(&((tod % 1_000_000_000) as u32).to_be_bytes());
    Ok(out)
}

fn byte_array(bytes: Vec<u8>) -> WireValue {
    WireValue::array(dt::USINT, bytes.into_iter().map(Scalar::USInt).collect())
}

/// Encodes a value for one string, date or scalar (no arrays).
fn encode_one(
    tree: &SymbolTree,
    name: &str,
    leaf: &Member,
    value: &Value,
) -> Result<WireValue, TagError> {
    let bad = |why: &str| bad_value(name, value, why);
    match leaf.softdatatype {
        19 | 62 => {
            let max = usize::from(leaf.layout.string_length.ok_or_else(|| {
                TagError::new(
                    format!("{name}: maximum string length unknown"),
                    ErrorKind::BadRequest,
                )
            })?);
            let s = text(name, value)?;
            if leaf.softdatatype == 19 {
                let mut bytes = Vec::with_capacity(max + 2);
                for c in s.chars() {
                    bytes.push(
                        u8::try_from(c as u32).map_err(|_| bad("STRING holds ISO-8859-1 only"))?,
                    );
                }
                if bytes.len() > max {
                    return Err(bad(&format!("longer than STRING[{max}]")));
                }
                let mut out = vec![max as u8, bytes.len() as u8];
                out.extend(bytes);
                out.resize(max + 2, 0);
                Ok(byte_array(out))
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                if units.len() > max {
                    return Err(bad(&format!("longer than WSTRING[{max}]")));
                }
                let mut out = vec![max as u16, units.len() as u16];
                out.extend(units);
                out.resize(max + 2, 0);
                Ok(WireValue::array(
                    dt::UINT,
                    out.into_iter().map(Scalar::UInt).collect(),
                ))
            }
        }
        14 => Ok(byte_array(dt_bytes(name, value)?)),
        67 => {
            let timestamp = tree
                .types
                .get(&DTL_RID)
                .map(|t| t.timestamp)
                .ok_or_else(|| {
                    TagError::new("DTL type information missing", ErrorKind::BadRequest)
                })?;
            Ok(WireValue::scalar(Scalar::Struct(Box::new(
                Struct::Packed {
                    id: DTL_RID,
                    timestamp,
                    flags: 2,
                    element_size: None,
                    data: dtl_bytes(name, value)?,
                },
            ))))
        }
        sdt if leaf.layout.is_struct()
            || leaf.layout.is_struct_array()
            || matches!(sdt, 17 | 21 | 31) =>
        {
            Err(TagError::new(
                format!("{name} is a structure: write its members"),
                ErrorKind::BadRequest,
            ))
        }
        sdt => Ok(WireValue::scalar(encode_scalar(name, sdt, value)?)),
    }
}

/// Encodes a write value for its address (spec 17.3). Whole structs (except DTL) and whole BOOL arrays are
/// refused (`BadRequest`); a value that does not fit is `BadValue`.
pub(crate) fn encode(
    tree: &SymbolTree,
    name: &str,
    address: &Address,
    value: &Value,
) -> Result<WireValue, TagError> {
    let leaf = &address.leaf;
    if !leaf.layout.is_array() || address.element {
        if address.element && leaf.layout.is_struct_array() {
            return Err(TagError::new(
                format!("{name} is a structure: write its members"),
                ErrorKind::BadRequest,
            ));
        }
        return encode_one(tree, name, leaf, value);
    }
    if leaf.is_bool() {
        return Err(TagError::new(
            format!("{name} is a BOOL array: write the elements"),
            ErrorKind::BadRequest,
        ));
    }
    if leaf.layout.is_struct_array() || matches!(leaf.softdatatype, 14 | 19 | 62 | 67) {
        return Err(TagError::new(
            format!("{name}: write the elements"),
            ErrorKind::BadRequest,
        ));
    }
    let Value::Array(items) = value else {
        return Err(bad_value(name, value, "expected a list"));
    };
    let total = leaf.layout.total();
    if items.len() as u64 != total {
        return Err(bad_value(
            name,
            value,
            &format!("expected {total} elements"),
        ));
    }
    let scalars = items
        .iter()
        .map(|v| encode_scalar(name, leaf.softdatatype, v))
        .collect::<Result<Vec<_>, _>>()?;
    let datatype = scalars.first().map_or(dt::NULL, Scalar::datatype);
    Ok(WireValue::array(datatype, scalars))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s7plus::browse::tests::sample_tree;
    use crate::s7plus::codec::Cursor;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn wire(h: &str) -> WireValue {
        WireValue::decode(&mut Cursor::new(&hex(h))).expect("wire")
    }

    fn read(tree: &SymbolTree, name: &str, h: &str) -> (Value, String) {
        let a = tree.resolve(name).expect("resolve");
        decode(tree, &a, &wire(h))
    }

    #[test]
    fn the_read_example_values_decode() {
        let tree = sample_tree();
        assert_eq!(
            read(&tree, "Line1.Conveyor.Speed", "000e3fc00000"),
            (Value::Real(1.5), "REAL".into())
        );
        assert_eq!(
            read(&tree, "Line1.Conveyor.Running", "000101"),
            (Value::Bool(true), "BOOL".into())
        );
        assert_eq!(
            read(&tree, "Line1.Count", "0008fd54"),
            (Value::DInt(-300), "DINT".into())
        );
        assert_eq!(
            read(&tree, "Line1.Total", "0005cbad07"),
            (Value::ULInt(1_234_567), "ULINT".into())
        );
        assert_eq!(
            read(&tree, "Line1.Recipe", "10020c0a044d697831000000000000"),
            (Value::String("Mix1".into()), "STRING".into())
        );
        assert_eq!(
            read(&tree, "Line1.Label", "1003060004 0002 004f 004b 0000 0000"),
            (Value::String("OK".into()), "WSTRING".into())
        );
        assert_eq!(
            read(
                &tree,
                "Line1.Stamp",
                "00170200004310ff4ad6dfd5774c020c07ea0b120410222e05f5e100"
            ),
            (
                Value::String("2026-11-18T16:34:46.100000000".into()),
                "DTL".into()
            )
        );
        assert_eq!(
            read(&tree, "StartButton", "000100"),
            (Value::Bool(false), "BOOL".into())
        );
    }

    #[test]
    fn whole_arrays_and_bool_arrays() {
        let tree = sample_tree();
        let mut h = String::from("1003 32");
        for i in 0..50u16 {
            h.push_str(&format!("{i:04x}"));
        }
        let (v, t) = read(&tree, "Line1.Items", &h);
        assert_eq!(t, "UINT[50]");
        let Value::Array(items) = v else {
            panic!("array")
        };
        assert_eq!(items[3], Value::UInt(3));
        let mut h = String::from("100a20 10");
        h.push_str(&"00".repeat(31));
        let (v, t) = read(&tree, "Line1.Flags", &h);
        assert_eq!(t, "BOOL[256]");
        let Value::Array(bits) = v else {
            panic!("array")
        };
        assert_eq!(bits.len(), 256);
        assert_eq!(bits.iter().position(|b| *b == Value::Bool(true)), Some(4));
        let (v, t) = read(&tree, "Line1.Items[4]", "00030007");
        assert_eq!((v, t.as_str()), (Value::UInt(7), "UINT"));
    }

    #[test]
    fn unexpected_wire_types_decode_generically() {
        let tree = sample_tree();
        let (v, t) = read(&tree, "Line1.Count", "000e3fc00000");
        assert_eq!((v, t.as_str()), (Value::Real(1.5), "Real"));
        let (v, t) = read(&tree, "Line1.Count", "100302 0001 0002");
        assert_eq!(v, Value::Array(vec![Value::UInt(1), Value::UInt(2)]));
        assert_eq!(t, "UInt[]");
    }

    fn member(sdt: u8) -> Member {
        Member {
            name: "X".into(),
            lid: 1,
            crc: 0,
            softdatatype: sdt,
            flags: 0x8000,
            bit_info: 0,
            layout: crate::s7plus::browse::Layout {
                kind: 8,
                ..Default::default()
            },
        }
    }

    fn roundtrip(sdt: u8, value: Value, wire_hex: Option<&str>) {
        let tree = sample_tree();
        let leaf = member(sdt);
        let w = encode_one(&tree, "X", &leaf, &value).expect("encode");
        if let Some(h) = wire_hex {
            assert_eq!(w.to_bytes(), hex(h), "{sdt} encode");
        }
        assert_eq!(decode_one(&tree, &leaf, &w), Some(value), "{sdt} decode");
    }

    #[test]
    fn each_type_roundtrips_through_its_wire_form() {
        roundtrip(1, Value::Bool(true), Some("000101"));
        roundtrip(40, Value::Bool(false), Some("000100"));
        roundtrip(2, Value::USInt(0x10), Some("000a10"));
        roundtrip(4, Value::UInt(0xBEEF), Some("000bbeef"));
        roundtrip(5, Value::Int(-2), Some("0007fffe"));
        roundtrip(6, Value::UDInt(0xDEAD_BEEF), Some("000cdeadbeef"));
        roundtrip(7, Value::DInt(-300), Some("0008fd54"));
        roundtrip(8, Value::Real(2.25), Some("000e40100000"));
        roundtrip(11, Value::DInt(5000), Some("0008a708"));
        roundtrip(48, Value::LReal(-1.0), Some("000fbff0000000000000"));
        roundtrip(49, Value::ULInt(1_234_567), Some("0005cbad07"));
        roundtrip(50, Value::LInt(-1), Some("00097f"));
        roundtrip(51, Value::ULInt(1), Some("000d0000000000000001"));
        roundtrip(52, Value::USInt(200), Some("0002c8"));
        roundtrip(53, Value::UInt(7), Some("00030007"));
        roundtrip(54, Value::UDInt(300), Some("0004822c"));
        roundtrip(55, Value::SInt(-5), Some("0006fb"));
        roundtrip(64, Value::LInt(-5_000_000_000), None);
        roundtrip(208, Value::UInt(5), Some("00030005"));
        roundtrip(3, Value::String("A".into()), Some("000241"));
        roundtrip(61, Value::String("\u{3a9}".into()), Some("000303a9"));
        roundtrip(9, Value::String("2026-11-18".into()), None);
        roundtrip(10, Value::String("16:34:46.100".into()), None);
        roundtrip(65, Value::String("16:34:46.100000001".into()), None);
        roundtrip(
            66,
            Value::String("2026-11-18T16:34:46.100000000".into()),
            None,
        );
        roundtrip(12, Value::DInt(2500), Some("000b0250"));
        roundtrip(12, Value::DInt(9_990_000), Some("000b3999"));
    }

    #[test]
    fn strings_and_date_and_time_and_dtl() {
        let tree = sample_tree();
        let recipe = tree.resolve("Line1.Recipe").expect("recipe");
        let w = encode(
            &tree,
            "Line1.Recipe",
            &recipe,
            &Value::String("Mix2".into()),
        )
        .expect("encode");
        assert_eq!(w.to_bytes(), hex("10020c0a044d697832000000000000"));
        assert!(matches!(
            encode(&tree, "Line1.Recipe", &recipe, &Value::String("x".repeat(11))),
            Err(e) if e.kind == ErrorKind::BadValue
        ));
        let label = tree.resolve("Line1.Label").expect("label");
        let w = encode(&tree, "Line1.Label", &label, &Value::String("OK".into())).expect("encode");
        assert_eq!(w.to_bytes(), hex("1003060004 0002 004f 004b 0000 0000"));
        let stamp = tree.resolve("Line1.Stamp").expect("stamp");
        let w = encode(
            &tree,
            "Line1.Stamp",
            &stamp,
            &Value::String("2026-11-18T16:34:46.1".into()),
        )
        .expect("dtl");
        assert_eq!(
            w.to_bytes(),
            hex("00170200004310ff4ad6dfd5774c020c07ea0b120410222e05f5e100")
        );
        let dt = member(14);
        let w = encode_one(
            &tree,
            "X",
            &dt,
            &Value::String("2026-11-18T16:34:46.123".into()),
        )
        .expect("dt");
        // BCD 26 11 18 16 34 46, ms 12 / 3, Wednesday = 4
        assert_eq!(w.to_bytes(), hex("1002 08 26 11 18 16 34 46 12 34"));
        assert_eq!(
            decode_one(&tree, &dt, &w),
            Some(Value::String("2026-11-18T16:34:46.123".into()))
        );
    }

    #[test]
    fn writes_refuse_structs_bool_arrays_and_bad_values() {
        let tree = sample_tree();
        let refuse = |name: &str, value: Value, kind: ErrorKind| {
            let a = tree.resolve(name).expect(name);
            assert_eq!(
                encode(&tree, name, &a, &value).expect_err(name).kind,
                kind,
                "{name}"
            );
        };
        refuse("Line1.Conveyor", Value::Bool(true), ErrorKind::BadRequest);
        refuse("Line1.Flags", Value::Array(vec![]), ErrorKind::BadRequest);
        refuse("Line1.Parts[1]", Value::Bool(true), ErrorKind::BadRequest);
        refuse("Line1.Count", Value::LInt(1 << 40), ErrorKind::BadValue);
        refuse("Line1.Count", Value::Real(1.0), ErrorKind::BadValue);
        refuse(
            "Line1.Conveyor.Running",
            Value::DInt(2),
            ErrorKind::BadValue,
        );
        refuse(
            "Line1.Items",
            Value::Array(vec![Value::UInt(1)]),
            ErrorKind::BadValue,
        );
        refuse(
            "Line1.Stamp",
            Value::String("yesterday".into()),
            ErrorKind::BadValue,
        );
        let flag = tree.resolve("Line1.Flags[3]").expect("flag");
        let w = encode(&tree, "Line1.Flags[3]", &flag, &Value::Bool(true)).expect("element");
        assert_eq!(w.to_bytes(), hex("000101"));
        let items = tree.resolve("Line1.Items").expect("items");
        let values = Value::Array((0..50).map(Value::DInt).collect());
        let w = encode(&tree, "Line1.Items", &items, &values).expect("array");
        assert_eq!(&w.to_bytes()[..5], &hex("1003 32 0000"));
    }

    #[test]
    fn string_array_elements_are_written_with_their_declared_length() {
        let tree = sample_tree();
        let a = tree.resolve("Line1.Names[1]").expect("names");
        let w = encode(&tree, "Line1.Names[1]", &a, &Value::String("ab".into())).expect("element");
        let Payload::Array(units) = &w.payload else {
            panic!("a UInt array")
        };
        assert_eq!(units.len(), 26, "24 characters + max and length");
        assert_eq!(
            &units[..4],
            &[
                Scalar::UInt(24),
                Scalar::UInt(2),
                Scalar::UInt(u16::from(b'a')),
                Scalar::UInt(u16::from(b'b'))
            ]
        );
        let long = Value::String("x".repeat(25));
        assert_eq!(
            encode(&tree, "Line1.Names[1]", &a, &long)
                .expect_err("too long")
                .kind,
            ErrorKind::BadValue
        );
        // a string without a known maximum length is refused instead of guessed
        let mut unknown = a.clone();
        unknown.leaf.layout.string_length = None;
        assert_eq!(
            encode(&tree, "X", &unknown, &Value::String("ab".into()))
                .expect_err("unknown")
                .kind,
            ErrorKind::BadRequest
        );
    }

    #[test]
    fn packed_structs_decode_by_their_type() {
        // an IEC_TIMER-like type: ST, PT, ET TIME at 0, 4, 8; RU / IN / Q bits 0 / 1 / 2 of byte 12
        let timer = crate::s7plus::browse::tests::type_object(
            0x0200_001F,
            "",
            7,
            vec![
                crate::s7plus::browse::tests::element("ST", 1, 11, 1, 0, &[0, 0]),
                crate::s7plus::browse::tests::element("PT", 2, 11, 1, 0, &[4, 4]),
                crate::s7plus::browse::tests::element("ET", 3, 11, 1, 0, &[8, 8]),
                crate::s7plus::browse::tests::element("RU", 4, 1, 1, 0, &[12, 12]),
                crate::s7plus::browse::tests::element("IN", 5, 1, 1, 1, &[12, 12]),
                crate::s7plus::browse::tests::element("Q", 6, 1, 1, 2, &[12, 12]),
            ],
        );
        let mut tree = sample_tree();
        for t in crate::s7plus::browse::type_infos(&[timer]) {
            tree.types.insert(t.rid, t);
        }
        let data = hex("00000001 000003e8 000001f4 06");
        let v = decode_packed(&tree, 0x0200_001F, &data, false, 0).expect("timer");
        assert_eq!(v["PT"], Value::DInt(1000));
        assert_eq!(v["ET"], Value::DInt(500));
        assert_eq!(v["RU"], Value::Bool(false));
        assert_eq!(v["IN"], Value::Bool(true));
        assert_eq!(v["Q"], Value::Bool(true));
        // a struct of the sample tree read whole
        let (v, t) = read(
            &tree,
            "Line1.Conveyor",
            "0017 92010005 000000000000000b 02 06 01 00 3fc00000",
        );
        assert_eq!(t, "0x92010005");
        let Value::Struct(m) = v else {
            panic!("struct")
        };
        assert_eq!(m["Running"], Value::Bool(true));
        assert_eq!(m["Speed"], Value::Real(1.5));
        // too short: bytes, never a panic
        let (v, _) = read(
            &tree,
            "Line1.Conveyor",
            "0017 92010005 000000000000000b 02 01 01",
        );
        assert_eq!(v, Value::Bytes(vec![1]));
    }

    #[test]
    fn arrays_of_structs_decode_from_one_packed_struct() {
        let tree = sample_tree();
        // Parts: ARRAY[0..2] of {Weight REAL, Count DINT}, 8 bytes each, as a real CPU sends it
        let (v, t) = read(
            &tree,
            "Line1.Parts",
            "1017 91000001 000000000000000c 8802 08 18 3fc0000000000001 4000000000000002 4040000000000003",
        );
        assert_eq!(t, "0x91000001[3]");
        let Value::Array(parts) = v else {
            panic!("array: {v:?}")
        };
        assert_eq!(parts.len(), 3);
        let Value::Struct(last) = &parts[2] else {
            panic!("struct")
        };
        assert_eq!(last["Weight"], Value::Real(3.0));
        assert_eq!(last["Count"], Value::DInt(3));
        // one element: the same form with one element's bytes
        let (v, _) = read(
            &tree,
            "Line1.Parts[1]",
            "1017 91000001 000000000000000c 8802 08 08 4000000000000002",
        );
        let Value::Struct(part) = v else {
            panic!("struct: {v:?}")
        };
        assert_eq!(part["Count"], Value::DInt(2));
        // a size that does not divide the data: generic bytes, never a panic
        let (v, _) = read(
            &tree,
            "Line1.Parts",
            "1017 91000001 000000000000000c 8802 02 03 010203",
        );
        assert_eq!(v, Value::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn date_helpers() {
        assert_eq!(days_from_civil(1990, 1, 1), DATE_EPOCH_1990);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(weekday(days_from_civil(2026, 11, 18)), 4);
        assert_eq!(parse_date("2026-02-30"), None);
        assert_eq!(parse_time("24:00:00"), None);
        assert_eq!(parse_time("01:02:03.5"), Some(3_723_500_000_000));
        assert_eq!(s5time_ms(0x0250), 2500);
        assert_eq!(s5time_ms(0x1250), 25_000);
    }
}
