//! The simulated CPU's program: structure types (type-info objects), data blocks and areas with their values,
//! LID addressing (spec 11.6), symbol CRCs (11.7), packed structs (8.5, 11.8) and the type-info encoding (13.5).

use super::config::{MemberConfig, S7PlusConfig};
use super::wire::{self, Value, dt};
use crate::ConfigError;
use indexmap::IndexMap;
use serde_json::{Map, Value as Json, json};

pub(crate) const DTL_RID: u32 = 0x0200_0043;
pub(crate) const TIMER_RID: u32 = 0x0200_001F;
/// DTL interface timestamp, as in the spec's type-info example (13.5).
const DTL_TIMESTAMP: u64 = 1_224_779_910_406_829_900;
/// Invented.
const TIMER_TIMESTAMP: u64 = 1_224_779_910_406_829_001;
/// Base of the invented interface timestamps of user types.
const USER_TIMESTAMP: u64 = 0x1D9_A000_0000_0000;

/// Item error: LID does not exist (low 16 bits -255).
pub(crate) const ERR_NO_LID: u64 = 0x814E_8800_0962_FF01;
/// Item error: array index out of range (-61).
pub(crate) const ERR_INDEX: u64 = 0x814E_8D00_0641_FFC3;
/// Item error: symbol CRC mismatch (-17).
pub(crate) const ERR_CRC: u64 = 0x8009_8900_12C9_FFEF;
/// Item error (invented): the value does not have the type's wire form (-40).
pub(crate) const ERR_VALUE: u64 = 0x8104_8800_0000_FFD8;
/// Item error (invented): access not supported by the simulator, e.g. a whole array of structs (-41).
pub(crate) const ERR_UNSUPPORTED: u64 = 0x8104_8800_0000_FFD7;
/// Softdatatype of a plain STRUCT / UDT member.
const STRUCT_SDT: u8 = 17;

const SUB_DB: u32 = 2550;
const SUB_AREA: u32 = 3736;
pub(crate) const DB_AREA: u32 = 0x8A0E_0000;

/// An elementary S7 type (strings included).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Elem {
    Bool,
    Byte,
    Word,
    DWord,
    LWord,
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
    Char,
    WChar,
    String(u16),
    WString(u16),
    Time,
    LTime,
    S5Time,
    Date,
    Tod,
    LTod,
    Dt,
    Ldt,
    DbAny,
}

fn bracket_len(text: &str, prefix: &str) -> Option<u16> {
    let rest = text.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some(254);
    }
    rest.strip_prefix('[')?
        .strip_suffix(']')?
        .trim()
        .parse()
        .ok()
        .filter(|n| (1..=254).contains(n))
}

impl Elem {
    fn parse(upper: &str) -> Option<Elem> {
        Some(match upper {
            "BOOL" => Elem::Bool,
            "BYTE" => Elem::Byte,
            "WORD" => Elem::Word,
            "DWORD" => Elem::DWord,
            "LWORD" => Elem::LWord,
            "SINT" => Elem::SInt,
            "INT" => Elem::Int,
            "DINT" => Elem::DInt,
            "LINT" => Elem::LInt,
            "USINT" => Elem::USInt,
            "UINT" => Elem::UInt,
            "UDINT" => Elem::UDInt,
            "ULINT" => Elem::ULInt,
            "REAL" => Elem::Real,
            "LREAL" => Elem::LReal,
            "CHAR" => Elem::Char,
            "WCHAR" => Elem::WChar,
            "TIME" => Elem::Time,
            "LTIME" => Elem::LTime,
            "S5TIME" => Elem::S5Time,
            "DATE" => Elem::Date,
            "TIME_OF_DAY" | "TOD" => Elem::Tod,
            "LTIME_OF_DAY" | "LTOD" => Elem::LTod,
            "DATE_AND_TIME" | "DT" => Elem::Dt,
            "LDT" => Elem::Ldt,
            "DB_ANY" => Elem::DbAny,
            _ => {
                if let Some(n) = bracket_len(upper, "WSTRING") {
                    Elem::WString(n)
                } else {
                    Elem::String(bracket_len(upper, "STRING")?)
                }
            }
        })
    }

    /// Softdatatype (spec 11.5); a BOOL in an optimized block is BBOOL (40).
    fn sdt(self, optimized: bool) -> u8 {
        match self {
            Elem::Bool if optimized => 40,
            Elem::Bool => 1,
            Elem::Byte => 2,
            Elem::Char => 3,
            Elem::Word => 4,
            Elem::Int => 5,
            Elem::DWord => 6,
            Elem::DInt => 7,
            Elem::Real => 8,
            Elem::Date => 9,
            Elem::Tod => 10,
            Elem::Time => 11,
            Elem::S5Time => 12,
            Elem::Dt => 14,
            Elem::String(_) => 19,
            Elem::LReal => 48,
            Elem::ULInt => 49,
            Elem::LInt => 50,
            Elem::LWord => 51,
            Elem::USInt => 52,
            Elem::UInt => 53,
            Elem::UDInt => 54,
            Elem::SInt => 55,
            Elem::WChar => 61,
            Elem::WString(_) => 62,
            Elem::LTime => 64,
            Elem::LTod => 65,
            Elem::Ldt => 66,
            Elem::DbAny => 208,
        }
    }

    /// Bytes in a packed struct.
    fn size(self) -> u32 {
        match self {
            Elem::Bool | Elem::Byte | Elem::Char | Elem::USInt | Elem::SInt => 1,
            Elem::Word
            | Elem::Int
            | Elem::UInt
            | Elem::Date
            | Elem::S5Time
            | Elem::WChar
            | Elem::DbAny => 2,
            Elem::DWord | Elem::DInt | Elem::UDInt | Elem::Real | Elem::Time | Elem::Tod => 4,
            Elem::LWord
            | Elem::LInt
            | Elem::ULInt
            | Elem::LReal
            | Elem::LTime
            | Elem::LTod
            | Elem::Ldt
            | Elem::Dt => 8,
            Elem::String(n) => u32::from(n) + 2,
            Elem::WString(n) => 2 * (u32::from(n) + 2),
        }
    }

    /// A string-like type that is an array on the wire (cannot be an array element here).
    fn is_array_form(self) -> bool {
        matches!(self, Elem::String(_) | Elem::WString(_) | Elem::Dt)
    }

    fn default_value(self) -> Value {
        match self {
            Elem::Bool => Value::Bool(false),
            Elem::Byte => Value::Byte(0),
            Elem::Word | Elem::S5Time => Value::Word(0),
            Elem::DWord => Value::DWord(0),
            Elem::LWord => Value::LWord(0),
            Elem::SInt => Value::SInt(0),
            Elem::Int => Value::Int(0),
            Elem::DInt | Elem::Time => Value::DInt(0),
            Elem::LInt => Value::LInt(0),
            Elem::USInt | Elem::Char => Value::USInt(0),
            Elem::UInt | Elem::WChar | Elem::Date | Elem::DbAny => Value::UInt(0),
            Elem::UDInt | Elem::Tod => Value::UDInt(0),
            Elem::ULInt | Elem::LTod => Value::ULInt(0),
            Elem::Real => Value::Real(0.0),
            Elem::LReal => Value::LReal(0.0),
            Elem::LTime => Value::Timespan(0),
            Elem::Ldt => Value::Timestamp(0),
            Elem::String(n) => string_value(n, &[]),
            Elem::WString(n) => wstring_value(n, &[]),
            // DT#1990-01-01-00:00:00, a Monday
            Elem::Dt => Value::array(
                dt::USINT,
                [0x90, 1, 1, 0, 0, 0, 0, 2].map(Value::USInt).to_vec(),
            ),
        }
    }

    /// Whether a written value has this type's wire form.
    fn accepts(self, value: &Value) -> bool {
        let template = self.default_value();
        match (&template, value) {
            (
                Value::Array {
                    datatype: want,
                    items: like,
                    ..
                },
                Value::Array {
                    flags: 0x10,
                    datatype,
                    items,
                },
            ) => {
                if datatype != want || items.len() != like.len() {
                    return false;
                }
                match self {
                    Elem::String(n) | Elem::WString(n) => {
                        let number = |v: &Value| match v {
                            Value::USInt(x) => Some(u16::from(*x)),
                            Value::UInt(x) => Some(*x),
                            _ => None,
                        };
                        number(&items[0]) == Some(n) && number(&items[1]).is_some_and(|l| l <= n)
                    }
                    _ => true,
                }
            }
            (Value::Array { .. }, _) | (_, Value::Array { .. }) => false,
            _ => std::mem::discriminant(&template) == std::mem::discriminant(value),
        }
    }

    fn to_json(self, value: &Value) -> Json {
        match (self, value) {
            (Elem::Bool, Value::Bool(v)) => json!(v),
            (Elem::Char, Value::USInt(c)) => json!(char::from(*c).to_string()),
            (Elem::WChar, Value::UInt(c)) => json!(String::from_utf16_lossy(&[*c])),
            (Elem::String(_), Value::Array { items, .. }) => {
                let bytes: Vec<u8> = items.iter().map(raw_u16).map(|v| v as u8).collect();
                let len = usize::from(bytes.get(1).copied().unwrap_or(0));
                json!(
                    bytes
                        .iter()
                        .skip(2)
                        .take(len)
                        .map(|&b| char::from(b))
                        .collect::<String>()
                )
            }
            (Elem::WString(_), Value::Array { items, .. }) => {
                let units: Vec<u16> = items.iter().map(raw_u16).collect();
                let len = usize::from(units.get(1).copied().unwrap_or(0));
                json!(String::from_utf16_lossy(
                    &units[2.min(units.len())..(2 + len).min(units.len())]
                ))
            }
            (Elem::S5Time, Value::Word(w)) => json!(s5time_ms(*w)),
            (Elem::Date, Value::UInt(days)) => json!(format_date(i64::from(*days) + DAYS_1990)),
            (Elem::Tod, Value::UDInt(ms)) => json!(format_time(u64::from(*ms) * 1_000_000, 3)),
            (Elem::LTod, Value::ULInt(ns)) => json!(format_time(*ns, 9)),
            (Elem::Ldt, Value::Timestamp(ns)) => {
                json!(format_datetime(*ns / NS_PER_DAY, *ns % NS_PER_DAY, 9))
            }
            (Elem::Dt, Value::Array { items, .. }) => {
                let b: Vec<u8> = items.iter().map(|v| raw_u16(v) as u8).collect();
                json!(dt_to_string(&b))
            }
            (_, value) => number_json(value),
        }
    }

    fn parse_json(self, j: &Json) -> Result<Value, String> {
        let bad = || format!("{j} is not a valid {self:?}");
        Ok(match self {
            Elem::Bool => Value::Bool(match j {
                Json::Bool(b) => *b,
                _ => int::<u8>(j).filter(|v| *v <= 1).ok_or_else(bad)? == 1,
            }),
            Elem::Byte => Value::Byte(int(j).ok_or_else(bad)?),
            Elem::Word => Value::Word(int(j).ok_or_else(bad)?),
            Elem::DWord => Value::DWord(int(j).ok_or_else(bad)?),
            Elem::LWord => Value::LWord(int(j).ok_or_else(bad)?),
            Elem::SInt => Value::SInt(int(j).ok_or_else(bad)?),
            Elem::Int => Value::Int(int(j).ok_or_else(bad)?),
            Elem::DInt | Elem::Time => Value::DInt(int(j).ok_or_else(bad)?),
            Elem::LInt => Value::LInt(int(j).ok_or_else(bad)?),
            Elem::USInt => Value::USInt(int(j).ok_or_else(bad)?),
            Elem::UInt | Elem::DbAny => Value::UInt(int(j).ok_or_else(bad)?),
            Elem::UDInt => Value::UDInt(int(j).ok_or_else(bad)?),
            Elem::ULInt => Value::ULInt(int(j).ok_or_else(bad)?),
            Elem::LTime => Value::Timespan(int(j).ok_or_else(bad)?),
            Elem::Real => Value::Real(j.as_f64().ok_or_else(bad)? as f32),
            Elem::LReal => Value::LReal(j.as_f64().ok_or_else(bad)?),
            Elem::Char => {
                let c = one_char(j).ok_or_else(bad)?;
                Value::USInt(u8::try_from(u32::from(c)).map_err(|_| bad())?)
            }
            Elem::WChar => {
                let c = one_char(j).ok_or_else(bad)?;
                let mut units = [0u16; 2];
                let units = c.encode_utf16(&mut units);
                if units.len() != 1 {
                    return Err(bad());
                }
                Value::UInt(units[0])
            }
            Elem::String(n) => {
                let text = j.as_str().ok_or_else(bad)?;
                let bytes: Vec<u8> = text
                    .chars()
                    .map(|c| u8::try_from(u32::from(c)).map_err(|_| bad()))
                    .collect::<Result<_, _>>()?;
                if bytes.len() > usize::from(n) {
                    return Err(format!("{text:?} is longer than STRING[{n}]"));
                }
                string_value(n, &bytes)
            }
            Elem::WString(n) => {
                let text = j.as_str().ok_or_else(bad)?;
                let units: Vec<u16> = text.encode_utf16().collect();
                if units.len() > usize::from(n) {
                    return Err(format!("{text:?} is longer than WSTRING[{n}]"));
                }
                wstring_value(n, &units)
            }
            Elem::S5Time => Value::Word(s5time_word(int(j).ok_or_else(bad)?).ok_or_else(bad)?),
            Elem::Date => {
                let days = parse_date(j.as_str().ok_or_else(bad)?).ok_or_else(bad)? - DAYS_1990;
                Value::UInt(u16::try_from(days).map_err(|_| bad())?)
            }
            Elem::Tod => {
                let ns = parse_time(j.as_str().ok_or_else(bad)?).ok_or_else(bad)?;
                Value::UDInt((ns / 1_000_000) as u32)
            }
            Elem::LTod => Value::ULInt(parse_time(j.as_str().ok_or_else(bad)?).ok_or_else(bad)?),
            Elem::Ldt => {
                let (days, ns) = parse_datetime(j.as_str().ok_or_else(bad)?).ok_or_else(bad)?;
                let days = u64::try_from(days).map_err(|_| bad())?;
                Value::Timestamp(days * NS_PER_DAY + ns)
            }
            Elem::Dt => {
                let (days, ns) = parse_datetime(j.as_str().ok_or_else(bad)?).ok_or_else(bad)?;
                let bytes = dt_bytes(days, ns).ok_or_else(bad)?;
                Value::array(dt::USINT, bytes.map(Value::USInt).to_vec())
            }
        })
    }
}

fn one_char(j: &Json) -> Option<char> {
    let mut chars = j.as_str()?.chars();
    let c = chars.next()?;
    chars.next().is_none().then_some(c)
}

fn int<T: TryFrom<i128>>(j: &Json) -> Option<T> {
    let value = j
        .as_i64()
        .map(i128::from)
        .or_else(|| j.as_u64().map(i128::from))?;
    T::try_from(value).ok()
}

fn raw_u16(v: &Value) -> u16 {
    match v {
        Value::USInt(x) | Value::Byte(x) => u16::from(*x),
        Value::UInt(x) | Value::Word(x) => *x,
        _ => 0,
    }
}

fn number_json(value: &Value) -> Json {
    match value {
        Value::Bool(v) => json!(v),
        Value::USInt(v) | Value::Byte(v) => json!(v),
        Value::UInt(v) | Value::Word(v) => json!(v),
        Value::UDInt(v) | Value::DWord(v) | Value::Rid(v) => json!(v),
        Value::ULInt(v) | Value::LWord(v) | Value::Timestamp(v) => json!(v),
        Value::SInt(v) => json!(v),
        Value::Int(v) => json!(v),
        Value::DInt(v) => json!(v),
        Value::LInt(v) | Value::Timespan(v) => json!(v),
        Value::Real(v) => json!(v),
        Value::LReal(v) => json!(v),
        _ => Json::Null,
    }
}

fn string_value(n: u16, bytes: &[u8]) -> Value {
    let mut items = vec![Value::USInt(n as u8), Value::USInt(bytes.len() as u8)];
    items.extend(bytes.iter().map(|&b| Value::USInt(b)));
    items.resize(usize::from(n) + 2, Value::USInt(0));
    Value::array(dt::USINT, items)
}

fn wstring_value(n: u16, units: &[u16]) -> Value {
    let mut items = vec![Value::UInt(n), Value::UInt(units.len() as u16)];
    items.extend(units.iter().map(|&u| Value::UInt(u)));
    items.resize(usize::from(n) + 2, Value::UInt(0));
    Value::array(dt::UINT, items)
}

fn s5time_ms(word: u16) -> u32 {
    let bcd = u32::from(word & 0x0FFF);
    let value = (bcd >> 8) * 100 + ((bcd >> 4) & 0xF) * 10 + (bcd & 0xF);
    value * [10, 100, 1000, 10_000][usize::from((word >> 12) & 3)]
}

/// The finest time base that holds `ms` exactly.
fn s5time_word(ms: u32) -> Option<u16> {
    for (base, unit) in [10u32, 100, 1000, 10_000].into_iter().enumerate() {
        if ms % unit == 0 && ms / unit <= 999 {
            let v = ms / unit;
            let bcd = ((v / 100) << 8) | (((v / 10) % 10) << 4) | (v % 10);
            return Some(((base as u16) << 12) | bcd as u16);
        }
    }
    None
}

// ---- dates (proleptic Gregorian, days since 1970-01-01) ----

const NS_PER_DAY: u64 = 86_400_000_000_000;
const DAYS_1990: i64 = 7305;

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

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

/// S7 weekday, 1 = Sunday.
fn weekday(days: i64) -> u8 {
    ((days + 4).rem_euclid(7) + 1) as u8
}

fn parse_date(text: &str) -> Option<i64> {
    let mut parts = text.trim().split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

fn parse_time(text: &str) -> Option<u64> {
    let mut parts = text.trim().split(':');
    let h: u64 = parts.next()?.parse().ok()?;
    let m: u64 = parts.next()?.parse().ok()?;
    let seconds = parts.next()?;
    if parts.next().is_some() || h > 23 || m > 59 {
        return None;
    }
    let (s, frac) = seconds.split_once('.').unwrap_or((seconds, ""));
    let s: u64 = s.parse().ok()?;
    if s > 59 || frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ns: u64 = format!("{frac:0<9}").parse().ok()?;
    Some(((h * 60 + m) * 60 + s) * 1_000_000_000 + ns)
}

fn parse_datetime(text: &str) -> Option<(i64, u64)> {
    let (date, time) = text.trim().split_once(['T', ' '])?;
    Some((parse_date(date)?, parse_time(time)?))
}

fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn format_time(ns: u64, digits: usize) -> String {
    let s = ns / 1_000_000_000;
    let frac = format!("{:09}", ns % 1_000_000_000);
    format!(
        "{:02}:{:02}:{:02}.{}",
        s / 3600,
        (s / 60) % 60,
        s % 60,
        &frac[..digits]
    )
}

fn format_datetime(days: u64, ns: u64, digits: usize) -> String {
    format!("{}T{}", format_date(days as i64), format_time(ns, digits))
}

fn bcd(v: u64) -> u8 {
    (((v / 10) % 10) << 4 | (v % 10)) as u8
}

fn from_bcd(b: u8) -> u64 {
    u64::from(b >> 4) * 10 + u64::from(b & 0xF)
}

fn dt_bytes(days: i64, ns: u64) -> Option<[u8; 8]> {
    let (y, m, d) = civil_from_days(days);
    if !(1990..=2089).contains(&y) {
        return None;
    }
    let s = ns / 1_000_000_000;
    let ms = (ns / 1_000_000) % 1000;
    Some([
        bcd((y % 100) as u64),
        bcd(u64::from(m)),
        bcd(u64::from(d)),
        bcd(s / 3600),
        bcd((s / 60) % 60),
        bcd(s % 60),
        bcd(ms / 10),
        (((ms % 10) as u8) << 4) | weekday(days),
    ])
}

fn dt_to_string(b: &[u8]) -> String {
    if b.len() < 8 {
        return String::new();
    }
    let yy = from_bcd(b[0]) as i64;
    let y = if yy >= 90 { 1900 + yy } else { 2000 + yy };
    let days = days_from_civil(y, from_bcd(b[1]) as u32, from_bcd(b[2]) as u32);
    let ms = from_bcd(b[6]) * 10 + u64::from(b[7] >> 4);
    let ns = ((from_bcd(b[3]) * 60 + from_bcd(b[4])) * 60 + from_bcd(b[5])) * 1_000_000_000
        + ms * 1_000_000;
    format!("{}T{}", format_date(days), format_time(ns, 3))
}

// ---- shapes, members, types ----

/// What a member is.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Shape {
    Leaf(Elem),
    /// A structure: STRUCT, UDT, DTL, IEC_TIMER (type RID).
    Struct(u32),
    /// An array of a leaf (not a string) or of a structure; bounds in declared order.
    Array {
        elem: Box<Shape>,
        lower: Vec<i32>,
        counts: Vec<u32>,
    },
}

fn total(counts: &[u32]) -> u64 {
    counts.iter().map(|&c| u64::from(c)).product()
}

#[derive(Clone, Debug)]
pub(crate) struct Member {
    pub name: String,
    pub lid: u32,
    pub crc: u32,
    sdt: u8,
    pub shape: Shape,
    offset: u32,
    /// Bit number of a BOOL that is one bit of a byte (classic layout, IEC_TIMER bits).
    bit: Option<u8>,
    hmi_visible: bool,
    hmi_accessible: bool,
    hmi_read_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// Struct form (1503 = 0): members use offset-info types 1 to 6.
    Struct,
    /// DB form (1503 = 1): blocks and areas, offset-info types 8 to 13.
    Db,
}

#[derive(Clone, Debug)]
pub(crate) struct TypeDef {
    pub rid: u32,
    name: String,
    form: Form,
    /// Attribute 392.
    kind: u32,
    pub timestamp: u64,
    classic: bool,
    pub members: Vec<Member>,
    size: u32,
}

impl TypeDef {
    fn member_by_name(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name).or_else(|| {
            self.members
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(name))
        })
    }
}

/// A value tree: leaves are wire values, nodes are structure members or array elements.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Data {
    Leaf(Value),
    Node(Vec<Data>),
}

impl Data {
    fn at(&self, steps: &[usize]) -> Option<&Data> {
        let mut data = self;
        for &s in steps {
            match data {
                Data::Node(items) => data = items.get(s)?,
                Data::Leaf(_) => return None,
            }
        }
        Some(data)
    }

    fn at_mut(&mut self, steps: &[usize]) -> Option<&mut Data> {
        let mut data = self;
        for &s in steps {
            match data {
                Data::Node(items) => data = items.get_mut(s)?,
                Data::Leaf(_) => return None,
            }
        }
        Some(data)
    }
}

/// A data block or an area.
#[derive(Clone, Debug)]
pub(crate) struct Block {
    pub name: String,
    /// Object RID (DB: 0x8A0E0000 + number, area: 80 / 81 / 82); also the access area.
    pub rid: u32,
    pub type_rid: u32,
    pub data: Data,
}

/// The program.
#[derive(Clone, Debug)]
pub(crate) struct Model {
    pub types: IndexMap<u32, TypeDef>,
    pub dbs: Vec<Block>,
    pub areas: Vec<Block>,
}

/// A resolved address.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    area: bool,
    block: usize,
    steps: Vec<usize>,
    shape: Shape,
    /// The address has an index.
    element: bool,
}

/// Where a request names something: access area, sub-area, LIDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Address {
    pub crc: u32,
    pub area: u32,
    pub sub_area: u32,
    pub lids: Vec<u32>,
}

const AREAS: [(&str, &str, u32, u32); 3] = [
    ("I", "IArea", 80, 0x9001_0000),
    ("Q", "QArea", 81, 0x9002_0000),
    ("M", "MArea", 82, 0x9003_0000),
];

/// Classes of the area objects in the block list (spec 13.2).
pub(crate) const AREA_CLASSES: [u32; 3] = [2595, 2621, 2602];

struct Layout {
    pos: u32,
    bit: Option<u8>,
}

impl Layout {
    fn place(&mut self, size: u32, align: u32, bit_bool: bool) -> (u32, Option<u8>) {
        if bit_bool {
            match self.bit {
                Some(b) if b < 8 => {
                    self.bit = Some(b + 1);
                    return (self.pos - 1, Some(b));
                }
                _ => {
                    self.bit = Some(1);
                    self.pos += 1;
                    return (self.pos - 1, Some(0));
                }
            }
        }
        self.bit = None;
        self.pos = self.pos.next_multiple_of(align);
        let offset = self.pos;
        self.pos += size;
        (offset, None)
    }
}

/// CRC type code of a softdatatype (spec 11.7).
fn type_code(sdt: u8) -> u8 {
    match sdt {
        40 => 1,
        144..=156 => 4,
        208 => 53,
        other => other,
    }
}

struct Builder {
    types: IndexMap<u32, TypeDef>,
    udts: Vec<(String, u32)>,
}

impl Builder {
    fn size_align(&self, shape: &Shape, classic: bool) -> (u32, u32) {
        match shape {
            Shape::Leaf(e) => {
                let size = e.size();
                (size, if size >= 2 { 2 } else { 1 })
            }
            Shape::Struct(rid) => (self.types.get(rid).map_or(0, |t| t.size), 2),
            Shape::Array { elem, counts, .. } => {
                let n = total(counts) as u32;
                match elem.as_ref() {
                    Shape::Leaf(Elem::Bool) if classic => (n.div_ceil(8), 2),
                    other => {
                        let (size, align) = self.size_align(other, classic);
                        (n * size.next_multiple_of(align), 2)
                    }
                }
            }
        }
    }

    fn sdt(shape: &Shape, optimized: bool) -> u8 {
        match shape {
            Shape::Leaf(e) => e.sdt(optimized),
            Shape::Struct(DTL_RID) => 67,
            Shape::Struct(TIMER_RID) => 31,
            Shape::Struct(_) => 17,
            Shape::Array { elem, .. } => Self::sdt(elem, optimized),
        }
    }

    /// Parses a type string; a STRUCT is built as a new type with an RID from `ids`, in the classic layout
    /// when its block is a standard-access one.
    fn shape(
        &mut self,
        text: &str,
        members: &IndexMap<String, MemberConfig>,
        ids: &mut StructIds,
        allow_struct: bool,
        classic: bool,
    ) -> Result<Shape, ConfigError> {
        let text = text.trim();
        let upper = text.to_ascii_uppercase();
        let err = |m: &str| ConfigError::new(format!("type {text:?}: {m}"));
        if let Some(rest) = upper.strip_prefix("ARRAY[") {
            let (dims, elem) = rest.split_once("] OF ").ok_or_else(|| err("bad ARRAY"))?;
            let mut lower = Vec::new();
            let mut counts = Vec::new();
            for dim in dims.split(',') {
                let (lo, hi) = dim.split_once("..").ok_or_else(|| err("bad bounds"))?;
                let lo: i32 = lo.trim().parse().map_err(|_| err("bad bound"))?;
                let hi: i32 = hi.trim().parse().map_err(|_| err("bad bound"))?;
                if hi < lo {
                    return Err(err("empty array"));
                }
                lower.push(lo);
                counts.push(
                    u32::try_from(i64::from(hi) - i64::from(lo) + 1)
                        .map_err(|_| err("too large"))?,
                );
            }
            if counts.len() > 6 || total(&counts) > 1_000_000 {
                return Err(err("too many dimensions or elements"));
            }
            let elem_text = &text[text.len() - elem.len()..];
            let elem = self.shape(elem_text, members, ids, allow_struct, classic)?;
            match &elem {
                Shape::Leaf(e) if e.is_array_form() => {
                    return Err(err("arrays of STRING, WSTRING and DT are not simulated"));
                }
                Shape::Struct(_) if counts.len() > 1 => {
                    return Err(err(
                        "multi-dimensional arrays of structures are not simulated",
                    ));
                }
                Shape::Array { .. } => return Err(err("nested arrays")),
                _ => {}
            }
            return Ok(Shape::Array {
                elem: Box::new(elem),
                lower,
                counts,
            });
        }
        if let Some(e) = Elem::parse(&upper) {
            return Ok(Shape::Leaf(e));
        }
        if !allow_struct {
            return Err(err("only elementary types in the I, Q and M areas"));
        }
        match upper.as_str() {
            "STRUCT" => {
                let rid = ids.next()?;
                self.build(rid, "", Form::Struct, classic, members, ids)?;
                Ok(Shape::Struct(rid))
            }
            "DTL" => Ok(Shape::Struct(DTL_RID)),
            "IEC_TIMER" => Ok(Shape::Struct(TIMER_RID)),
            _ => self
                .udts
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(text))
                .map(|&(_, rid)| rid)
                .filter(|rid| self.types.contains_key(rid))
                .map(Shape::Struct)
                .ok_or_else(|| err("unknown type (a UDT can only use UDTs declared before it)")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        &mut self,
        rid: u32,
        name: &str,
        form: Form,
        classic: bool,
        members: &IndexMap<String, MemberConfig>,
        ids: &mut StructIds,
    ) -> Result<(), ConfigError> {
        let area = AREAS.iter().any(|a| a.3 == rid);
        let mut next = if form == Form::Struct { 9 } else { 0xA };
        let mut layout = Layout { pos: 0, bit: None };
        let mut built: Vec<Member> = Vec::with_capacity(members.len());
        for (member_name, config) in members {
            let detail = config.detail();
            if member_name.is_empty() || member_name.len() > 255 {
                return Err(ConfigError::new(format!("bad member name {member_name:?}")));
            }
            let shape = self.shape(&detail.data_type, &detail.members, ids, !area, classic)?;
            let lid = detail.lid.unwrap_or(next);
            if lid < 2 || built.iter().any(|m| m.lid == lid) {
                return Err(ConfigError::new(format!(
                    "member {member_name}: LID {lid} is reserved or used twice"
                )));
            }
            next = next.max(lid + 1);
            let optimized = !classic;
            let sdt = Self::sdt(&shape, optimized);
            let crc = match &shape {
                Shape::Array { lower, counts, .. } => {
                    let mut extra = vec![type_code(sdt)];
                    extra.extend_from_slice(&lower[0].to_le_bytes());
                    if counts.len() > 1 {
                        let upper = i64::from(lower[0]) + i64::from(counts[0]) - 1;
                        extra.extend_from_slice(&(upper as i32).to_le_bytes());
                        extra.extend_from_slice(&lower[1].to_le_bytes());
                    }
                    wire::member_crc(member_name, 0x10, &extra)
                }
                _ => wire::member_crc(member_name, type_code(sdt), &[]),
            };
            let (size, align) = self.size_align(&shape, classic);
            let bit_bool = classic && shape == Shape::Leaf(Elem::Bool);
            let (offset, bit) = layout.place(size, align, bit_bool);
            built.push(Member {
                name: member_name.clone(),
                lid,
                crc,
                sdt,
                shape,
                offset,
                bit,
                hmi_visible: detail.hmi_visible,
                hmi_accessible: detail.hmi_accessible,
                hmi_read_only: detail.hmi_read_only,
            });
        }
        let kind = if area { 0x8000_0001 } else { 0x8000_0002 };
        self.types.insert(
            rid,
            TypeDef {
                rid,
                name: name.to_owned(),
                form,
                kind,
                timestamp: USER_TIMESTAMP + u64::from(rid),
                classic,
                members: built,
                size: layout.pos,
            },
        );
        Ok(())
    }
}

/// RIDs for STRUCT types declared inside a block or UDT: base | ss << 16, ss = 1, 2, ...
struct StructIds {
    base: u32,
    next: u32,
}

impl StructIds {
    fn next(&mut self) -> Result<u32, ConfigError> {
        if self.next >= 0xFD {
            return Err(ConfigError::new("too many STRUCT members in one block"));
        }
        let rid = self.base | (self.next << 16);
        self.next += 1;
        Ok(rid)
    }
}

fn system_member(name: &str, lid: u32, elem: Elem, offset: u32, bit: Option<u8>) -> Member {
    let sdt = elem.sdt(false);
    Member {
        name: name.to_owned(),
        lid,
        crc: wire::member_crc(name, type_code(sdt), &[]),
        sdt,
        shape: Shape::Leaf(elem),
        offset,
        bit,
        hmi_visible: true,
        hmi_accessible: true,
        hmi_read_only: false,
    }
}

fn system_types() -> [TypeDef; 2] {
    let dtl = [
        ("YEAR", Elem::UInt, 0),
        ("MONTH", Elem::USInt, 2),
        ("DAY", Elem::USInt, 3),
        ("WEEKDAY", Elem::USInt, 4),
        ("HOUR", Elem::USInt, 5),
        ("MINUTE", Elem::USInt, 6),
        ("SECOND", Elem::USInt, 7),
        ("NANOSECOND", Elem::UDInt, 8),
    ];
    let timer = [
        ("ST", Elem::Time, 0, None),
        ("PT", Elem::Time, 4, None),
        ("ET", Elem::Time, 8, None),
        ("RU", Elem::Bool, 12, Some(0)),
        ("IN", Elem::Bool, 12, Some(1)),
        ("Q", Elem::Bool, 12, Some(2)),
    ];
    [
        TypeDef {
            rid: DTL_RID,
            name: String::new(),
            form: Form::Struct,
            kind: 0x8000_0003,
            timestamp: DTL_TIMESTAMP,
            classic: false,
            members: dtl
                .iter()
                .zip(9..)
                .map(|(&(name, elem, offset), lid)| system_member(name, lid, elem, offset, None))
                .collect(),
            size: 12,
        },
        TypeDef {
            rid: TIMER_RID,
            name: String::new(),
            form: Form::Struct,
            kind: 0x8000_0003,
            timestamp: TIMER_TIMESTAMP,
            classic: false,
            members: timer
                .iter()
                .zip(9..)
                .map(|(&(name, elem, offset, bit), lid)| {
                    system_member(name, lid, elem, offset, bit)
                })
                .collect(),
            size: 13,
        },
    ]
}

/// Raw big-endian bytes of a leaf value in a packed struct.
fn raw(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Bool(v) => out.push(u8::from(*v)),
        Value::USInt(v) | Value::Byte(v) => out.push(*v),
        Value::SInt(v) => out.push(*v as u8),
        Value::UInt(v) | Value::Word(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::Int(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::UDInt(v) | Value::DWord(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::DInt(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::Real(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::ULInt(v) | Value::LWord(v) | Value::Timestamp(v) => {
            out.extend_from_slice(&v.to_be_bytes())
        }
        Value::LInt(v) | Value::Timespan(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::LReal(v) => out.extend_from_slice(&v.to_be_bytes()),
        Value::Array { items, .. } => items.iter().for_each(|item| raw(item, out)),
        _ => {}
    }
}

/// The value of `template`'s variant read from raw bytes (as many as `raw` writes for it).
fn from_raw(template: &Value, bytes: &[u8]) -> Value {
    let mut cur = wire::Cursor::new(bytes);
    let mut get = || -> Option<Value> {
        Some(match template {
            Value::Bool(_) => Value::Bool(cur.u8().ok()? != 0),
            Value::USInt(_) => Value::USInt(cur.u8().ok()?),
            Value::Byte(_) => Value::Byte(cur.u8().ok()?),
            Value::SInt(_) => Value::SInt(cur.u8().ok()? as i8),
            Value::UInt(_) => Value::UInt(cur.u16().ok()?),
            Value::Word(_) => Value::Word(cur.u16().ok()?),
            Value::Int(_) => Value::Int(cur.u16().ok()? as i16),
            Value::UDInt(_) => Value::UDInt(cur.u32().ok()?),
            Value::DWord(_) => Value::DWord(cur.u32().ok()?),
            Value::DInt(_) => Value::DInt(cur.u32().ok()? as i32),
            Value::Real(_) => Value::Real(f32::from_bits(cur.u32().ok()?)),
            Value::ULInt(_) => Value::ULInt(cur.u64().ok()?),
            Value::LWord(_) => Value::LWord(cur.u64().ok()?),
            Value::Timestamp(_) => Value::Timestamp(cur.u64().ok()?),
            Value::LInt(_) => Value::LInt(cur.u64().ok()? as i64),
            Value::Timespan(_) => Value::Timespan(cur.u64().ok()? as i64),
            Value::LReal(_) => Value::LReal(f64::from_bits(cur.u64().ok()?)),
            Value::Array {
                flags,
                datatype,
                items,
            } => {
                let element = items.first()?;
                let width = {
                    let mut probe = Vec::new();
                    raw(element, &mut probe);
                    probe.len()
                };
                let mut out = Vec::with_capacity(items.len());
                for chunk in bytes.chunks(width.max(1)).take(items.len()) {
                    out.push(from_raw(element, chunk));
                }
                Value::Array {
                    flags: *flags,
                    datatype: *datatype,
                    items: out,
                }
            }
            other => other.clone(),
        })
    };
    get().unwrap_or_else(|| template.clone())
}

impl Model {
    pub(crate) fn new(config: &S7PlusConfig) -> Result<Model, ConfigError> {
        let mut builder = Builder {
            types: IndexMap::new(),
            udts: Vec::new(),
        };
        for (i, name) in config.types.keys().enumerate() {
            builder.udts.push((name.clone(), 0x9100_0001 + i as u32));
        }
        for (i, (_, udt)) in config.types.iter().enumerate() {
            let rid = 0x9100_0001 + i as u32;
            let mut ids = StructIds { base: rid, next: 1 };
            builder.build(rid, "", Form::Struct, false, &udt.members, &mut ids)?;
        }
        let mut dbs = Vec::new();
        for db in &config.dbs {
            let n = u32::from(db.number);
            if n == 0 || dbs.iter().any(|&(_, r)| r == 0x9200_0000 + n) {
                return Err(ConfigError::new(format!(
                    "DB number {n} is invalid or used twice"
                )));
            }
            let rid = 0x9200_0000 + n;
            let mut ids = StructIds { base: rid, next: 1 };
            builder.build(rid, "", Form::Db, !db.optimized, &db.members, &mut ids)?;
            dbs.push((db, rid));
        }
        let mut areas = Vec::new();
        for key in config.areas.keys() {
            if !AREAS.iter().any(|a| a.0.eq_ignore_ascii_case(key)) {
                return Err(ConfigError::new(format!(
                    "unknown area {key:?}, expected I, Q or M"
                )));
            }
        }
        let empty = IndexMap::new();
        for (letter, name, area, rid) in AREAS {
            let members = config
                .areas
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(letter))
                .map_or(&empty, |(_, m)| m);
            let mut ids = StructIds { base: rid, next: 1 };
            builder.build(rid, name, Form::Db, true, members, &mut ids)?;
            areas.push((name, area, rid, members));
        }
        for system in system_types() {
            builder.types.insert(system.rid, system);
        }
        let mut model = Model {
            types: builder.types,
            dbs: Vec::new(),
            areas: Vec::new(),
        };
        for (db, rid) in dbs {
            let mut data = model.default_data(&Shape::Struct(rid));
            model.apply_values(rid, &mut data, &db.members)?;
            model.dbs.push(Block {
                name: db.name.clone(),
                rid: DB_AREA + u32::from(db.number),
                type_rid: rid,
                data,
            });
        }
        for (name, area, rid, members) in areas {
            let mut data = model.default_data(&Shape::Struct(rid));
            model.apply_values(rid, &mut data, members)?;
            model.areas.push(Block {
                name: name.to_owned(),
                rid: area,
                type_rid: rid,
                data,
            });
        }
        Ok(model)
    }

    fn default_data(&self, shape: &Shape) -> Data {
        match shape {
            Shape::Leaf(e) => Data::Leaf(e.default_value()),
            Shape::Struct(rid) => Data::Node(
                self.types
                    .get(rid)
                    .map(|t| {
                        t.members
                            .iter()
                            .map(|m| self.default_data(&m.shape))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            Shape::Array { elem, counts, .. } => {
                let item = self.default_data(elem);
                Data::Node(vec![item; total(counts) as usize])
            }
        }
    }

    fn apply_values(
        &self,
        rid: u32,
        data: &mut Data,
        members: &IndexMap<String, MemberConfig>,
    ) -> Result<(), ConfigError> {
        let Some(t) = self.types.get(&rid) else {
            return Ok(());
        };
        let Data::Node(items) = data else {
            return Ok(());
        };
        for ((name, config), (member, item)) in members.iter().zip(t.members.iter().zip(items)) {
            let MemberConfig::Full(detail) = config else {
                continue;
            };
            if let Some(value) = &detail.value {
                self.set_json(&member.shape, item, value)
                    .map_err(|e| ConfigError::new(format!("{name}: {e}")))?;
            }
            if let Shape::Struct(inner) = member.shape {
                self.apply_values(inner, item, &detail.members)?;
            }
        }
        Ok(())
    }

    // ---- addressing ----

    fn block(&self, area: u32, sub_area: u32) -> Result<(bool, usize), u64> {
        if area & 0xFFFF_0000 == DB_AREA {
            let i = self
                .dbs
                .iter()
                .position(|b| b.rid == area)
                .ok_or(ERR_NO_LID)?;
            return if sub_area == SUB_DB {
                Ok((false, i))
            } else {
                Err(ERR_NO_LID)
            };
        }
        let i = self
            .areas
            .iter()
            .position(|b| b.rid == area)
            .ok_or(ERR_NO_LID)?;
        if sub_area == SUB_AREA {
            Ok((true, i))
        } else {
            Err(ERR_NO_LID)
        }
    }

    fn block_ref(&self, area: bool, i: usize) -> &Block {
        if area { &self.areas[i] } else { &self.dbs[i] }
    }

    /// Walks the LIDs of an address (spec 11.6).
    fn target(&self, address: &Address) -> Result<Target, u64> {
        let (area, block) = self.block(address.area, address.sub_area)?;
        enum Pos {
            Type(u32),
            Shape(Shape),
            Element(Shape),
        }
        let mut pos = Pos::Type(self.block_ref(area, block).type_rid);
        let mut steps = Vec::with_capacity(address.lids.len());
        let mut crcs = Vec::new();
        let mut indexed = false;
        let mut last_sdt = 0;
        for &lid in &address.lids {
            let rid = match &pos {
                Pos::Type(rid) | Pos::Shape(Shape::Struct(rid)) => *rid,
                Pos::Shape(Shape::Array { elem, counts, .. }) => {
                    if u64::from(lid) >= total(counts) {
                        return Err(ERR_INDEX);
                    }
                    steps.push(lid as usize);
                    indexed = true;
                    pos = Pos::Element(elem.as_ref().clone());
                    continue;
                }
                Pos::Element(Shape::Struct(rid)) => {
                    if lid != 1 {
                        return Err(ERR_NO_LID);
                    }
                    pos = Pos::Type(*rid);
                    continue;
                }
                _ => return Err(ERR_NO_LID),
            };
            let t = self.types.get(&rid).ok_or(ERR_NO_LID)?;
            let index = t
                .members
                .iter()
                .position(|m| m.lid == lid)
                .ok_or(ERR_NO_LID)?;
            steps.push(index);
            crcs.push(t.members[index].crc);
            last_sdt = t.members[index].sdt;
            pos = Pos::Shape(t.members[index].shape.clone());
        }
        let shape = match pos {
            Pos::Type(rid) if !steps.is_empty() => Shape::Struct(rid),
            Pos::Type(_) => return Err(ERR_UNSUPPORTED),
            Pos::Shape(shape) | Pos::Element(shape) => shape,
        };
        // a real CPU rejects any non-zero CRC on a whole STRUCT / UDT (the vartype CRC included)
        if address.crc != 0
            && !indexed
            && (wire::address_crc(&crcs) != address.crc || last_sdt == STRUCT_SDT)
        {
            return Err(ERR_CRC);
        }
        Ok(Target {
            area,
            block,
            steps,
            shape,
            element: indexed,
        })
    }

    pub(crate) fn read(&self, address: &Address) -> Result<Value, u64> {
        if address.area & 0xFFFF_0000 == DB_AREA && address.lids == [1] {
            let (area, block) = self.block(address.area, address.sub_area)?;
            return Ok(Value::Rid(self.block_ref(area, block).type_rid));
        }
        let target = self.target(address)?;
        let data = self
            .block_ref(target.area, target.block)
            .data
            .at(&target.steps)
            .ok_or(ERR_NO_LID)?;
        match (&target.shape, target.element) {
            // an element of an array of structs comes as a one-element array of structs
            (Shape::Struct(rid), true) => self.packed_array(*rid, std::slice::from_ref(data)),
            _ => self.wire_value(&target.shape, data),
        }
    }

    /// Structs of type `rid` back to back, in the form a real CPU sends an array of structs (codec.rs of the
    /// driver: array flag, one packed struct, transport flag 0x400 and the element size).
    fn packed_array(&self, rid: u32, items: &[Data]) -> Result<Value, u64> {
        let t = self.types.get(&rid).ok_or(ERR_NO_LID)?;
        let size = t.size as usize;
        let mut bytes = vec![0u8; size * items.len()];
        for (item, out) in items.iter().zip(bytes.chunks_mut(size.max(1))) {
            self.pack(t, item, out);
        }
        Ok(Value::PackedArray {
            id: rid,
            timestamp: t.timestamp,
            flags: if t.classic { 0x403 } else { 0x402 },
            size: t.size,
            data: bytes,
        })
    }

    fn wire_value(&self, shape: &Shape, data: &Data) -> Result<Value, u64> {
        match (shape, data) {
            (Shape::Leaf(_), Data::Leaf(value)) => Ok(value.clone()),
            (Shape::Struct(rid), _) => {
                let t = self.types.get(rid).ok_or(ERR_NO_LID)?;
                let mut bytes = vec![0u8; t.size as usize];
                self.pack(t, data, &mut bytes);
                Ok(Value::Packed {
                    id: *rid,
                    timestamp: t.timestamp,
                    flags: if t.classic { 3 } else { 2 },
                    data: bytes,
                })
            }
            (Shape::Array { elem, counts, .. }, Data::Node(items)) => match elem.as_ref() {
                Shape::Leaf(Elem::Bool) => {
                    // 8 elements per byte; each run of the last dimension padded to whole bytes
                    let run = counts.last().copied().unwrap_or(1).max(1) as usize;
                    let mut bytes = Vec::new();
                    for chunk in items.chunks(run) {
                        let start = bytes.len();
                        bytes.resize(start + chunk.len().div_ceil(8), 0u8);
                        for (i, item) in chunk.iter().enumerate() {
                            if matches!(item, Data::Leaf(Value::Bool(true))) {
                                bytes[start + i / 8] |= 1 << (i % 8);
                            }
                        }
                    }
                    Ok(Value::array(
                        dt::BYTE,
                        bytes.into_iter().map(Value::Byte).collect(),
                    ))
                }
                Shape::Leaf(e) => Ok(Value::array(
                    e.default_value().datatype(),
                    items
                        .iter()
                        .map(|item| match item {
                            Data::Leaf(v) => v.clone(),
                            Data::Node(_) => e.default_value(),
                        })
                        .collect(),
                )),
                Shape::Struct(rid) => self.packed_array(*rid, items),
                _ => Err(ERR_UNSUPPORTED),
            },
            _ => Err(ERR_NO_LID),
        }
    }

    pub(crate) fn write(&mut self, address: &Address, value: &Value) -> Result<(), u64> {
        if address.area & 0xFFFF_0000 == DB_AREA && address.lids == [1] {
            return Err(ERR_UNSUPPORTED);
        }
        let target = self.target(address)?;
        let packed = match (&target.shape, value) {
            (
                Shape::Struct(rid),
                Value::Packed {
                    id,
                    timestamp,
                    data,
                    ..
                },
            ) => {
                let t = self.types.get(rid).ok_or(ERR_NO_LID)?;
                if id != rid || *timestamp != t.timestamp || data.len() != t.size as usize {
                    return Err(ERR_VALUE);
                }
                let mut node = self.default_data(&target.shape);
                self.unpack(t, &mut node, data);
                Some(node)
            }
            (Shape::Struct(_), _) => return Err(ERR_VALUE),
            _ => None,
        };
        let block = if target.area {
            &mut self.areas[target.block]
        } else {
            &mut self.dbs[target.block]
        };
        let data = block.data.at_mut(&target.steps).ok_or(ERR_NO_LID)?;
        if let Some(node) = packed {
            *data = node;
            return Ok(());
        }
        match (&target.shape, data) {
            (Shape::Leaf(e), Data::Leaf(leaf)) => {
                if !e.accepts(value) {
                    return Err(ERR_VALUE);
                }
                *leaf = value.clone();
                Ok(())
            }
            (Shape::Array { elem, .. }, Data::Node(items)) => match (elem.as_ref(), value) {
                (Shape::Leaf(Elem::Bool), _) => Err(ERR_UNSUPPORTED),
                (
                    Shape::Leaf(e),
                    Value::Array {
                        flags: 0x10,
                        items: values,
                        ..
                    },
                ) => {
                    if values.len() != items.len() || !values.iter().all(|v| e.accepts(v)) {
                        return Err(ERR_VALUE);
                    }
                    for (item, v) in items.iter_mut().zip(values) {
                        *item = Data::Leaf(v.clone());
                    }
                    Ok(())
                }
                (Shape::Leaf(_), _) => Err(ERR_VALUE),
                _ => Err(ERR_UNSUPPORTED),
            },
            _ => Err(ERR_NO_LID),
        }
    }

    fn pack(&self, t: &TypeDef, data: &Data, out: &mut [u8]) {
        let Data::Node(items) = data else { return };
        for (member, item) in t.members.iter().zip(items) {
            let offset = member.offset as usize;
            match &member.shape {
                Shape::Leaf(_) => {
                    let start = offset.min(out.len());
                    self.pack_leaf(item, member.bit, &mut out[start..]);
                }
                Shape::Struct(rid) => {
                    if let Some(inner) = self.types.get(rid) {
                        let end = (offset + inner.size as usize).min(out.len());
                        self.pack(inner, item, &mut out[offset.min(end)..end]);
                    }
                }
                Shape::Array { elem, .. } => {
                    let Data::Node(elements) = item else { continue };
                    let (size, align) = self.elem_size(elem);
                    let stride = size.next_multiple_of(align) as usize;
                    for (i, element) in elements.iter().enumerate() {
                        let start = (offset + i * stride).min(out.len());
                        let end = (start + size as usize).min(out.len());
                        match elem.as_ref() {
                            Shape::Struct(rid) => {
                                if let Some(inner) = self.types.get(rid) {
                                    self.pack(inner, element, &mut out[start..end]);
                                }
                            }
                            _ => self.pack_leaf(element, None, &mut out[start..end]),
                        }
                    }
                }
            }
        }
    }

    fn pack_leaf(&self, item: &Data, bit: Option<u8>, out: &mut [u8]) {
        let Data::Leaf(value) = item else { return };
        if let (Some(bit), Value::Bool(on), Some(byte)) = (bit, value, out.first_mut()) {
            if *on {
                *byte |= 1 << bit;
            }
            return;
        }
        let mut bytes = Vec::new();
        raw(value, &mut bytes);
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
    }

    fn unpack(&self, t: &TypeDef, data: &mut Data, bytes: &[u8]) {
        let Data::Node(items) = data else { return };
        for (member, item) in t.members.iter().zip(items) {
            let offset = (member.offset as usize).min(bytes.len());
            match &member.shape {
                Shape::Leaf(_) => unpack_leaf(item, member.bit, &bytes[offset..]),
                Shape::Struct(rid) => {
                    if let Some(inner) = self.types.get(rid) {
                        self.unpack(inner, item, &bytes[offset..]);
                    }
                }
                Shape::Array { elem, .. } => {
                    let Data::Node(elements) = item else { continue };
                    let (size, align) = self.elem_size(elem);
                    let stride = size.next_multiple_of(align) as usize;
                    for (i, element) in elements.iter_mut().enumerate() {
                        let start = (offset + i * stride).min(bytes.len());
                        match elem.as_ref() {
                            Shape::Struct(rid) => {
                                if let Some(inner) = self.types.get(rid) {
                                    self.unpack(inner, element, &bytes[start..]);
                                }
                            }
                            _ => unpack_leaf(element, None, &bytes[start..]),
                        }
                    }
                }
            }
        }
    }

    fn elem_size(&self, elem: &Shape) -> (u32, u32) {
        match elem {
            Shape::Leaf(e) => (e.size(), if e.size() >= 2 { 2 } else { 1 }),
            Shape::Struct(rid) => (self.types.get(rid).map_or(0, |t| t.size), 2),
            Shape::Array { .. } => (0, 1),
        }
    }

    // ---- names (for the simulator API and faults) ----

    /// Resolves a TIA-style name (`Line1.Conveyor.Speed`, `Line1.Grid[2,5]`, `StartButton`, `IArea.StartButton`)
    /// to its address, CRC included (0 with an index).
    pub(crate) fn address(&self, name: &str) -> Result<Address, String> {
        let segments = split_name(name)?;
        let (first, first_index) = &segments[0];
        if first_index.is_some() {
            return Err(format!("{name}: a block is not an array"));
        }
        let mut rest = &segments[1..];
        let find_db = |n: &str| {
            self.dbs
                .iter()
                .find(|b| b.name == n)
                .or_else(|| self.dbs.iter().find(|b| b.name.eq_ignore_ascii_case(n)))
        };
        let (area, sub_area, rid) = if let Some(db) = find_db(first) {
            (db.rid, SUB_DB, db.type_rid)
        } else if let Some(block) = self
            .areas
            .iter()
            .find(|b| b.name.eq_ignore_ascii_case(first))
        {
            (block.rid, SUB_AREA, block.type_rid)
        } else {
            // a PLC tag by its bare name
            let block = self
                .areas
                .iter()
                .find(|b| {
                    self.types
                        .get(&b.type_rid)
                        .is_some_and(|t| t.member_by_name(first).is_some())
                })
                .ok_or_else(|| format!("{name}: no such block or PLC tag"))?;
            rest = &segments[..];
            (block.rid, SUB_AREA, block.type_rid)
        };
        if rest.is_empty() {
            return Err(format!("{name}: names a whole block"));
        }
        let mut lids = Vec::new();
        let mut crcs = Vec::new();
        let mut indexed = false;
        let mut last_sdt = 0;
        let mut current = Some(rid);
        for (segment, index) in rest {
            let t = current
                .and_then(|rid| self.types.get(&rid))
                .ok_or_else(|| format!("{name}: {segment} is not inside a structure"))?;
            let member = t
                .member_by_name(segment)
                .ok_or_else(|| format!("{name}: no member {segment}"))?;
            lids.push(member.lid);
            crcs.push(member.crc);
            last_sdt = member.sdt;
            current = match (&member.shape, index) {
                (Shape::Struct(rid), None) => Some(*rid),
                (
                    Shape::Array {
                        elem,
                        lower,
                        counts,
                    },
                    Some(index),
                ) => {
                    if index.len() != counts.len() {
                        return Err(format!("{name}: {segment} has {} dimensions", counts.len()));
                    }
                    let mut linear: u64 = 0;
                    for ((&i, &lo), &count) in index.iter().zip(lower).zip(counts) {
                        let offset = i - i64::from(lo);
                        if offset < 0 || offset >= i64::from(count) {
                            return Err(format!("{name}: index {i} out of bounds"));
                        }
                        linear = linear * u64::from(count) + offset as u64;
                    }
                    lids.push(linear as u32);
                    indexed = true;
                    match elem.as_ref() {
                        Shape::Struct(rid) => {
                            lids.push(1);
                            Some(*rid)
                        }
                        _ => None,
                    }
                }
                (_, Some(_)) => return Err(format!("{name}: {segment} is not an array")),
                _ => None,
            };
        }
        Ok(Address {
            crc: if indexed || last_sdt == STRUCT_SDT {
                0
            } else {
                wire::address_crc(&crcs)
            },
            area,
            sub_area,
            lids,
        })
    }

    fn named(&self, name: &str) -> Result<Target, String> {
        let address = self.address(name)?;
        self.target(&address)
            .map_err(|e| format!("{name}: cannot be addressed (item error {e:#018x})"))
    }

    pub(crate) fn value(&self, name: &str) -> Result<Json, String> {
        let target = self.named(name)?;
        let data = self
            .block_ref(target.area, target.block)
            .data
            .at(&target.steps)
            .ok_or_else(|| format!("{name}: no data"))?;
        Ok(self.to_json(&target.shape, data))
    }

    pub(crate) fn set_value(&mut self, name: &str, value: &Json) -> Result<(), String> {
        let target = self.named(name)?;
        let mut node = self
            .block_ref(target.area, target.block)
            .data
            .at(&target.steps)
            .cloned()
            .ok_or_else(|| format!("{name}: no data"))?;
        self.set_json(&target.shape, &mut node, value)
            .map_err(|e| format!("{name}: {e}"))?;
        let block = if target.area {
            &mut self.areas[target.block]
        } else {
            &mut self.dbs[target.block]
        };
        if let Some(data) = block.data.at_mut(&target.steps) {
            *data = node;
        }
        Ok(())
    }

    fn to_json(&self, shape: &Shape, data: &Data) -> Json {
        match (shape, data) {
            (Shape::Leaf(e), Data::Leaf(v)) => e.to_json(v),
            (Shape::Struct(DTL_RID), Data::Node(items)) => {
                let n: Vec<u64> = items
                    .iter()
                    .map(|i| match i {
                        Data::Leaf(v) => number_json(v).as_u64().unwrap_or(0),
                        Data::Node(_) => 0,
                    })
                    .collect();
                if n.len() < 8 {
                    return Json::Null;
                }
                let days = days_from_civil(n[0] as i64, n[1] as u32, n[2] as u32);
                let ns = ((n[4] * 60 + n[5]) * 60 + n[6]) * 1_000_000_000 + n[7];
                json!(format!("{}T{}", format_date(days), format_time(ns, 9)))
            }
            (Shape::Struct(rid), Data::Node(items)) => {
                let mut object = Map::new();
                if let Some(t) = self.types.get(rid) {
                    for (m, item) in t.members.iter().zip(items) {
                        object.insert(m.name.clone(), self.to_json(&m.shape, item));
                    }
                }
                Json::Object(object)
            }
            (Shape::Array { elem, .. }, Data::Node(items)) => {
                Json::Array(items.iter().map(|i| self.to_json(elem, i)).collect())
            }
            _ => Json::Null,
        }
    }

    fn set_json(&self, shape: &Shape, data: &mut Data, value: &Json) -> Result<(), String> {
        match (shape, data) {
            (Shape::Leaf(e), Data::Leaf(leaf)) => {
                *leaf = e.parse_json(value)?;
                Ok(())
            }
            (Shape::Struct(DTL_RID), Data::Node(items)) if value.is_string() => {
                let text = value.as_str().unwrap_or_default();
                let (days, ns) =
                    parse_datetime(text).ok_or(format!("{text:?} is not a date and time"))?;
                let (y, m, d) = civil_from_days(days);
                let s = ns / 1_000_000_000;
                let year = u16::try_from(y).map_err(|_| format!("{text:?}: year out of range"))?;
                let values = [
                    Value::UInt(year),
                    Value::USInt(m as u8),
                    Value::USInt(d as u8),
                    Value::USInt(weekday(days)),
                    Value::USInt((s / 3600) as u8),
                    Value::USInt(((s / 60) % 60) as u8),
                    Value::USInt((s % 60) as u8),
                    Value::UDInt((ns % 1_000_000_000) as u32),
                ];
                *items = values.into_iter().map(Data::Leaf).collect();
                Ok(())
            }
            (Shape::Struct(rid), Data::Node(items)) => {
                let object = value
                    .as_object()
                    .ok_or(format!("{value} is not an object"))?;
                let t = self.types.get(rid).ok_or("unknown type")?;
                for (key, v) in object {
                    let index = t
                        .members
                        .iter()
                        .position(|m| m.name.eq_ignore_ascii_case(key))
                        .ok_or(format!("no member {key}"))?;
                    self.set_json(&t.members[index].shape, &mut items[index], v)?;
                }
                Ok(())
            }
            (Shape::Array { elem, .. }, Data::Node(items)) => {
                let mut flat = Vec::new();
                flatten(value, &mut flat);
                if !value.is_array() || flat.len() != items.len() {
                    return Err(format!("expected a list of {} values", items.len()));
                }
                for (item, v) in items.iter_mut().zip(flat) {
                    self.set_json(elem, item, v)?;
                }
                Ok(())
            }
            _ => Err("value does not fit".to_owned()),
        }
    }

    /// Simulates a program download that renames the first member of the first DB: its member CRC changes,
    /// so addresses with the old CRC fail with -17, and the block type's interface timestamp changes.
    pub(crate) fn change_program(&mut self) {
        let Some(rid) = self.dbs.first().map(|b| b.type_rid) else {
            return;
        };
        if let Some(t) = self.types.get_mut(&rid) {
            t.timestamp = t.timestamp.wrapping_add(1);
            if let Some(member) = t.members.first_mut() {
                member.crc = member.crc.wrapping_add(0x0101_0101);
            }
        }
    }

    // ---- type information (spec 13.4, 13.5) ----

    /// The type-info object (class 511) of one type.
    pub(crate) fn type_object(&self, t: &TypeDef, attributes: &[u32], out: &mut Vec<u8>) {
        out.push(0xA1);
        out.extend_from_slice(&t.rid.to_be_bytes());
        wire::put_vlq32(out, 511);
        wire::put_vlq32(out, 0x20);
        wire::put_vlq32(out, 0);
        let user = t.kind != 0x8000_0003;
        let attrs = [
            (233, Value::WString(t.name.clone())),
            (392, Value::DWord(t.kind)),
            (404, Value::UDInt(0)),
            (529, Value::ULInt(t.timestamp)),
            (1502, Value::UDInt(t.size)),
            (1503, Value::DInt(i32::from(t.form == Form::Db))),
            (
                611,
                Value::Struct(
                    1542,
                    vec![
                        (1543, Value::UDInt(t.size)),
                        (1544, Value::UDInt(t.size)),
                        (1545, Value::UDInt(t.size)),
                    ],
                ),
            ),
            (410, Value::ULInt(if user { t.timestamp } else { 0 })),
            (412, Value::Word(1)),
            (413, Value::UDInt(0)),
            (414, Value::UDInt(4)),
        ];
        put_attributes(out, &attrs, attributes);
        if !t.members.is_empty() {
            out.push(0xAB);
            let elements: Vec<Vec<u8>> = t.members.iter().map(|m| self.vartype(t, m)).collect();
            put_blocks(out, Some(0x8000_0004), &elements);
            out.push(0xAC);
            let names: Vec<Vec<u8>> = t
                .members
                .iter()
                .map(|m| {
                    let mut entry = vec![m.name.len() as u8];
                    entry.extend_from_slice(m.name.as_bytes());
                    entry.push(0);
                    entry
                })
                .collect();
            put_blocks(out, None, &names);
        }
        out.push(0xA2);
    }

    fn vartype(&self, t: &TypeDef, m: &Member) -> Vec<u8> {
        let db = t.form == Form::Db;
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&m.lid.to_le_bytes());
        out.extend_from_slice(&m.crc.to_le_bytes());
        out.push(m.sdt);
        let mut info: Vec<u8> = Vec::new();
        let off = m.offset;
        let u16le = |info: &mut Vec<u8>, v: u32| info.extend_from_slice(&(v as u16).to_le_bytes());
        let u32le = |info: &mut Vec<u8>, v: u32| info.extend_from_slice(&v.to_le_bytes());
        let oit: u16 = match &m.shape {
            Shape::Leaf(Elem::String(n) | Elem::WString(n)) => {
                u16le(&mut info, u32::from(*n));
                u16le(&mut info, u32::from(*n) + 2);
                u32le(&mut info, off);
                u32le(&mut info, off);
                2
            }
            Shape::Leaf(_) => {
                u16le(&mut info, off);
                u16le(&mut info, off);
                1
            }
            Shape::Struct(rid) => {
                u16le(&mut info, 0);
                u16le(&mut info, 0);
                u32le(&mut info, off);
                u32le(&mut info, off);
                u32le(&mut info, *rid);
                info.extend_from_slice(&[0; 16]);
                5
            }
            Shape::Array {
                elem,
                lower,
                counts,
            } => {
                u16le(&mut info, 0);
                u16le(&mut info, 0);
                u32le(&mut info, off);
                u32le(&mut info, off);
                info.extend_from_slice(&lower[0].to_le_bytes());
                u32le(&mut info, total(counts) as u32);
                match elem.as_ref() {
                    Shape::Struct(rid) => {
                        let size = self.types.get(rid).map_or(0, |t| t.size);
                        u32le(&mut info, size);
                        u32le(&mut info, size);
                        u32le(&mut info, *rid);
                        info.extend_from_slice(&[0; 16]);
                        6
                    }
                    _ if counts.len() > 1 => {
                        // six lower bounds and six counts, innermost dimension first
                        for i in 0..6 {
                            let lo = lower.iter().rev().nth(i).copied().unwrap_or(0);
                            info.extend_from_slice(&lo.to_le_bytes());
                        }
                        for i in 0..6 {
                            u32le(&mut info, counts.iter().rev().nth(i).copied().unwrap_or(0));
                        }
                        4
                    }
                    _ => 3,
                }
            }
        };
        let oit = if db { oit + 7 } else { oit };
        let mut flags = (oit << 12) | 0x0080;
        if m.hmi_visible {
            flags |= 0x0800;
        }
        if m.hmi_read_only {
            flags |= 0x0400;
        }
        if m.hmi_accessible {
            flags |= 0x0200;
        }
        if !db {
            flags |= u16::from(m.bit.unwrap_or(0) & 7);
        }
        let bit_info = if db && t.classic {
            0x08 | (m.bit.unwrap_or(0) << 4)
        } else {
            0
        };
        out.extend_from_slice(&flags.to_be_bytes());
        out.push(bit_info);
        out.extend_from_slice(&info);
        out
    }
}

fn unpack_leaf(item: &mut Data, bit: Option<u8>, bytes: &[u8]) {
    let Data::Leaf(value) = item else { return };
    if let (Some(bit), Value::Bool(_)) = (bit, &*value) {
        *value = Value::Bool(bytes.first().is_some_and(|b| b >> bit & 1 == 1));
        return;
    }
    *value = from_raw(value, bytes);
}

fn flatten<'a>(value: &'a Json, out: &mut Vec<&'a Json>) {
    match value {
        Json::Array(items) => items.iter().for_each(|i| flatten(i, out)),
        other => out.push(other),
    }
}

/// A name segment and its indices.
type Segment = (String, Option<Vec<i64>>);

/// Splits `"Line1".Items[3].Weight` into segments with optional indices.
fn split_name(name: &str) -> Result<Vec<Segment>, String> {
    let mut segments = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut parts = Vec::new();
    for (i, c) in name.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            '.' if depth == 0 => {
                parts.push(&name[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&name[start..]);
    for part in parts {
        let part = part.trim();
        let (base, index) = match part.split_once('[') {
            Some((base, rest)) => {
                let inner = rest
                    .strip_suffix(']')
                    .ok_or_else(|| format!("{name}: bad index"))?;
                let index: Vec<i64> = inner
                    .split(',')
                    .map(|i| i.trim().parse().map_err(|_| format!("{name}: bad index")))
                    .collect::<Result<_, _>>()?;
                (base, Some(index))
            }
            None => (part, None),
        };
        let base = base
            .strip_prefix('"')
            .and_then(|b| b.strip_suffix('"'))
            .unwrap_or(base);
        if base.is_empty() {
            return Err(format!("{name}: empty name segment"));
        }
        segments.push((base.to_owned(), index));
    }
    Ok(segments)
}

/// `A3` attributes, only those asked for (all when `wanted` is empty).
pub(crate) fn put_attributes(out: &mut Vec<u8>, attrs: &[(u32, Value)], wanted: &[u32]) {
    for (id, value) in attrs {
        if wanted.is_empty() || wanted.contains(id) {
            out.push(0xA3);
            wire::put_vlq32(out, *id);
            value.encode(out);
        }
    }
}

/// Vartype / varname list blocks: 2-byte BE length, entries, `00 00` (spec 13.5).
fn put_blocks(out: &mut Vec<u8>, first_id: Option<u32>, entries: &[Vec<u8>]) {
    let mut block: Vec<u8> = Vec::new();
    if let Some(id) = first_id {
        block.extend_from_slice(&id.to_le_bytes());
    }
    for entry in entries {
        if block.len() + entry.len() > 60_000 {
            out.extend_from_slice(&(block.len() as u16).to_be_bytes());
            out.append(&mut block);
        }
        block.extend_from_slice(entry);
    }
    if !block.is_empty() {
        out.extend_from_slice(&(block.len() as u16).to_be_bytes());
        out.append(&mut block);
    }
    out.extend_from_slice(&[0, 0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dtl_type_object_is_the_spec_example_byte_for_byte() {
        let model = Model::new(&S7PlusConfig::default()).expect("model");
        let mut out = Vec::new();
        model.type_object(&model.types[&DTL_RID], &[], &mut out);
        let expected = wire::hex(
            "a102000043837f2000a38169001500a38308000c80000003a38314000400a38411000588bfe9adb6ffaaf74ca38b5e00
             040ca38b5f000800a384630017000006068c0700040c8c0800040c8c0900040c00a3831a000500a3831c000b0001a383
             1d000400a3831e000404ab0084040000800900000093973bd7351a8000000000000a000000147f4ed7341a8000020002
             000b0000006de7eef6341a8000030003000c0000004101e2c2341a8000040004000d00000084d6a870341a8000050005
             000e0000006086d75e341a8000060006000f0000006ea81211341a8000070007001000000073001b76361a8000080008
             000000ac003d045945415200054d4f4e5448000344415900075745454b4441590004484f555200064d494e5554450006
             5345434f4e44000a4e414e4f5345434f4e44000000a2",
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn dates_convert_both_ways() {
        let days = parse_date("2026-11-18").expect("date");
        assert_eq!(format_date(days), "2026-11-18");
        assert_eq!(weekday(days), 4); // Wednesday
        assert_eq!(parse_date("1990-01-01"), Some(DAYS_1990));
        let bytes = dt_bytes(days, parse_time("16:34:46.123").expect("time")).expect("dt");
        assert_eq!(bytes, [0x26, 0x11, 0x18, 0x16, 0x34, 0x46, 0x12, 0x34]);
        assert_eq!(dt_to_string(&bytes), "2026-11-18T16:34:46.123");
        assert_eq!(s5time_word(2500), Some(0x0250));
        assert_eq!(s5time_ms(0x0250), 2500);
        assert_eq!(s5time_word(25_000), Some(0x1250));
        assert_eq!(s5time_word(10_000_000), None);
    }

    #[test]
    fn names_resolve_to_lids_and_crcs() {
        let config = S7PlusConfig::from_json(
            r#"{"dbs": [{"name": "Line1", "number": 5, "members": {
                "Conveyor": {"type": "STRUCT", "lid": 10, "members": {
                    "Running": {"type": "BOOL", "lid": 9}, "Speed": {"type": "REAL", "lid": 11}}},
                "Items": "ARRAY[1..50] OF UINT",
                "Grid": "ARRAY[0..15, 0..3] OF DINT",
                "Parts": {"type": "ARRAY[1..3] OF STRUCT", "members": {"Weight": "REAL"}}}}],
            "areas": {"I": {"StartButton": {"type": "BOOL", "lid": 12}}}}"#,
        )
        .expect("config");
        let model = Model::new(&config).expect("model");
        let speed = model.address("\"Line1\".conveyor.Speed").expect("speed");
        assert_eq!(
            (speed.area, speed.lids.clone(), speed.crc),
            (0x8A0E_0005, vec![10, 11], 0x6E44_A73A)
        );
        let item = model.address("Line1.Items[4]").expect("item");
        assert_eq!((item.lids.clone(), item.crc), (vec![0xB, 3], 0));
        assert_eq!(
            model.address("Line1.Grid[2,3]").expect("grid").lids,
            vec![0xC, 11]
        );
        assert_eq!(
            model.address("Line1.Parts[1].Weight").expect("part").lids,
            vec![0xD, 0, 1, 9]
        );
        let button = model.address("StartButton").expect("button");
        assert_eq!(
            (button.area, button.lids.clone(), button.crc),
            (80, vec![12], 0xB285_B00A)
        );
        assert!(model.address("Line1.Items[51]").is_err());
        assert!(model.address("Line1.Nope").is_err());
    }

    const CONFIG: &str = r#"{"s7plus": {
        "types": {"Recipe": {"members": {"Speed": "REAL", "On": "BOOL", "Name": "STRING[4]"}}},
        "dbs": [{"name": "D", "number": 7, "members": {
            "Delay": "IEC_TIMER", "Flags": "ARRAY[0..15] OF BOOL", "Grid": "ARRAY[0..15, 0..3] OF DINT",
            "Parts": "ARRAY[1..3] OF Recipe", "Recipe": "Recipe", "Stamp": "DTL",
            "Day": "DATE", "Clock": "TOD", "Fine": "LTOD", "Dt": "DT", "Ldt": "LDT", "S5": "S5TIME",
            "Ch": "CHAR", "Wc": "WCHAR", "Lt": "LTIME", "W": "WORD", "Db": "DB_ANY"}}],
        "areas": {"Q": {"Motor": "BOOL", "Lamp": "BOOL", "Speed": "INT"}}}}"#;

    fn model() -> Model {
        Model::new(&S7PlusConfig::from_json(CONFIG).expect("config")).expect("model")
    }

    fn read(m: &Model, name: &str) -> Result<Value, u64> {
        m.read(&m.address(name).expect("name"))
    }

    #[test]
    fn whole_structures_are_packed_structs() {
        let mut m = model();
        m.set_value("D.Delay", &json!({"PT": 5000, "IN": true, "Q": true}))
            .expect("timer");
        let Ok(Value::Packed {
            id, flags, data, ..
        }) = read(&m, "D.Delay")
        else {
            panic!("not packed");
        };
        assert_eq!((id, flags, data.len()), (TIMER_RID, 2, 13));
        assert_eq!(&data[4..8], &5000u32.to_be_bytes());
        assert_eq!(data[12], 0b110);
        m.set_value("D.Stamp", &json!("2026-11-18T16:34:46.1"))
            .expect("dtl");
        assert_eq!(
            read(&m, "D.Stamp").expect("dtl"),
            Value::Packed {
                id: DTL_RID,
                timestamp: DTL_TIMESTAMP,
                flags: 2,
                data: wire::hex("07ea0b12 04 10 22 2e 05f5e100"),
            }
        );
        // a UDT: written back changed, read again
        m.set_value("D.Recipe", &json!({"Speed": 2.5, "On": true, "Name": "ab"}))
            .expect("udt");
        let Ok(Value::Packed {
            id,
            timestamp,
            flags,
            mut data,
        }) = read(&m, "D.Recipe")
        else {
            panic!("not packed");
        };
        assert_eq!(data, wire::hex("40200000 01 00 0402 6162 0000"));
        data[4] = 0;
        let address = m.address("D.Recipe").expect("name");
        let packed = Value::Packed {
            id,
            timestamp,
            flags,
            data: data.clone(),
        };
        m.write(&address, &packed).expect("write");
        assert_eq!(m.value("D.Recipe.On").expect("on"), json!(false));
        let stale = Value::Packed {
            id,
            timestamp: timestamp + 1,
            flags,
            data,
        };
        assert_eq!(m.write(&address, &stale), Err(ERR_VALUE));
    }

    #[test]
    fn arrays_read_whole_and_by_element() {
        let mut m = model();
        m.set_value("D.Flags[4]", &json!(true)).expect("flag");
        let Ok(Value::Array {
            datatype, items, ..
        }) = read(&m, "D.Flags")
        else {
            panic!("not an array");
        };
        assert_eq!(
            (datatype, items),
            (dt::BYTE, vec![Value::Byte(0x10), Value::Byte(0)])
        );
        m.set_value("D.Grid[2,3]", &json!(-5)).expect("grid");
        let Ok(Value::Array { items, .. }) = read(&m, "D.Grid") else {
            panic!("not an array");
        };
        assert_eq!((items.len(), &items[11]), (64, &Value::DInt(-5)));
        assert_eq!(read(&m, "D.Grid[2,3]"), Ok(Value::DInt(-5)));
        let grid = m.address("D.Grid").expect("grid");
        let mut beyond = grid.clone();
        beyond.lids.push(64);
        assert_eq!(m.read(&beyond), Err(ERR_INDEX));
        m.set_value("D.Parts[2].Speed", &json!(4.5)).expect("part");
        assert_eq!(read(&m, "D.Parts[2].Speed"), Ok(Value::Real(4.5)));
        // arrays of structs, whole and by element, come as one packed struct with the element size
        let Ok(Value::PackedArray {
            flags, size, data, ..
        }) = read(&m, "D.Parts")
        else {
            panic!("not a packed array");
        };
        assert_eq!((flags & 0x400, data.len()), (0x400, 3 * size as usize));
        let Ok(Value::PackedArray { size, data, .. }) = read(&m, "D.Parts[3]") else {
            panic!("not a packed array");
        };
        assert_eq!(data.len(), size as usize);
        // a whole STRUCT with its vartype CRC is a CRC error, as on a real CPU; with CRC 0 it reads
        let mut recipe = m.address("D.Recipe").expect("recipe");
        assert_eq!(recipe.crc, 0);
        assert!(m.read(&recipe).is_ok());
        recipe.crc = 0x1234_5678;
        assert_eq!(m.read(&recipe), Err(ERR_CRC));
        // a whole elementary array is writable, a whole BOOL array is not
        let values = Value::array(dt::DINT, vec![Value::DInt(1); 64]);
        assert_eq!(m.write(&grid, &values), Ok(()));
        assert_eq!(m.value("D.Grid[0,0]").expect("grid"), json!(1));
        let flags = m.address("D.Flags").expect("flags");
        let bools = Value::array(dt::BOOL, vec![Value::Bool(true); 16]);
        assert_eq!(m.write(&flags, &bools), Err(ERR_UNSUPPORTED));
    }

    #[test]
    fn writes_need_the_read_form() {
        let mut m = model();
        let address = m.address("D.Recipe.Speed").expect("name");
        assert_eq!(m.write(&address, &Value::Int(1)), Err(ERR_VALUE));
        assert_eq!(m.write(&address, &Value::Real(1.0)), Ok(()));
        let name = m.address("D.Recipe.Name").expect("name");
        let too_long = Value::array(dt::USINT, [4, 5, 0, 0, 0, 0].map(Value::USInt).to_vec());
        assert_eq!(m.write(&name, &too_long), Err(ERR_VALUE));
        let mut wrong_crc = address.clone();
        wrong_crc.crc ^= 1;
        assert_eq!(m.write(&wrong_crc, &Value::Real(1.0)), Err(ERR_CRC));
        let mut missing = address;
        missing.lids[1] = 0x7FFF;
        missing.crc = 0;
        assert_eq!(m.read(&missing), Err(ERR_NO_LID));
    }

    #[test]
    fn date_time_and_character_types_convert_from_and_to_json() {
        let mut m = model();
        for (name, value, wire) in [
            ("D.Day", json!("2026-11-18"), Value::UInt(13_470)),
            ("D.Clock", json!("16:34:46.100"), Value::UDInt(59_686_100)),
            (
                "D.Fine",
                json!("16:34:46.100000001"),
                Value::ULInt(59_686_100_000_001),
            ),
            (
                "D.Ldt",
                json!("2026-11-18T16:34:46.100000000"),
                Value::Timestamp(1_795_019_686_100_000_000),
            ),
            ("D.S5", json!(2500), Value::Word(0x0250)),
            ("D.Ch", json!("A"), Value::USInt(65)),
            ("D.Wc", json!("\u{20ac}"), Value::UInt(0x20AC)),
            ("D.Lt", json!(-5), Value::Timespan(-5)),
            ("D.W", json!(65535), Value::Word(65535)),
            ("D.Db", json!(7), Value::UInt(7)),
        ] {
            m.set_value(name, &value).expect(name);
            assert_eq!(read(&m, name), Ok(wire), "{name}");
            assert_eq!(m.value(name).expect(name), value, "{name}");
        }
        m.set_value("D.Dt", &json!("2026-11-18T16:34:46.123"))
            .expect("dt");
        assert_eq!(
            m.value("D.Dt").expect("dt"),
            json!("2026-11-18T16:34:46.123")
        );
        assert!(m.set_value("D.W", &json!(65536)).is_err());
        assert!(m.set_value("D.Day", &json!("1989-12-31")).is_err());
    }

    #[test]
    fn area_bools_are_bits_of_classic_bytes() {
        let m = model();
        let t = &m.types[&0x9002_0000];
        let lamp = m.vartype(t, &t.members[1]);
        // softdatatype BOOL (1), offset-info type 8, bit-offset info: classic, bit 1
        assert_eq!(lamp[8], 1);
        assert_eq!(lamp[9] >> 4, 8);
        assert_eq!(lamp[11], 0x18);
        assert_eq!(read(&m, "QArea.Lamp"), Ok(Value::Bool(false)));
    }
}
