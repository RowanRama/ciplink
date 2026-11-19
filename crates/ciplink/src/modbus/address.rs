//! Areas, types, word orders, the plain-address syntax, and resolving a caller's name to a [`Target`].

use std::fmt;

use super::map::{MapTag, TagMap};
use crate::{ErrorKind, TagError};

/// One of the four Modbus data tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Area {
    /// Coils (read/write bits, FC01/05/15).
    Coil,
    /// Discrete inputs (read-only bits, FC02).
    Discrete,
    /// Holding registers (read/write words, FC03/06/16/22).
    Holding,
    /// Input registers (read-only words, FC04).
    Input,
}

impl Area {
    /// The area of a map file's `area` column or a plain address's prefix (case-insensitive).
    pub fn parse(text: &str) -> Option<Area> {
        Some(match text.to_ascii_lowercase().as_str() {
            "coil" | "co" => Area::Coil,
            "discrete" | "di" => Area::Discrete,
            "holding" | "hr" => Area::Holding,
            "input" | "ir" => Area::Input,
            _ => return None,
        })
    }

    /// True for coils and discrete inputs.
    pub fn is_bits(self) -> bool {
        matches!(self, Area::Coil | Area::Discrete)
    }

    /// True for coils and holding registers.
    pub fn is_writable(self) -> bool {
        matches!(self, Area::Coil | Area::Holding)
    }

    /// The read function code.
    pub(crate) fn read_function(self) -> u8 {
        match self {
            Area::Coil => 1,
            Area::Discrete => 2,
            Area::Holding => 3,
            Area::Input => 4,
        }
    }

    /// The map file name: `coil`, `discrete`, `holding`, `input`.
    pub fn as_str(self) -> &'static str {
        match self {
            Area::Coil => "coil",
            Area::Discrete => "discrete",
            Area::Holding => "holding",
            Area::Input => "input",
        }
    }
}

impl fmt::Display for Area {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The type of a map row or plain address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataType {
    /// A coil, discrete input or bit of a register (`BOOL`).
    Bool,
    /// One register, signed (`INT`).
    Int16,
    /// One register (`UINT`).
    UInt16,
    /// Two registers, signed (`DINT`).
    Int32,
    /// Two registers (`UDINT`).
    UInt32,
    /// Four registers, signed (`LINT`).
    Int64,
    /// Four registers (`ULINT`).
    UInt64,
    /// Two registers, IEEE 754 (`REAL`).
    Float32,
    /// Four registers, IEEE 754 (`LREAL`).
    Float64,
    /// Characters packed two per register (`STRING`).
    String,
}

/// The type names of the map file, in the order error messages list them.
pub(crate) const TYPE_NAMES: &str =
    "bool, int16, uint16, int32, uint32, int64, uint64, float32, float64, string";

impl DataType {
    /// The type of a map file's `type` column or a plain address's `:type` (case-insensitive).
    pub fn parse(text: &str) -> Option<DataType> {
        Some(match text.to_ascii_lowercase().as_str() {
            "bool" => DataType::Bool,
            "int16" => DataType::Int16,
            "uint16" => DataType::UInt16,
            "int32" => DataType::Int32,
            "uint32" => DataType::UInt32,
            "int64" => DataType::Int64,
            "uint64" => DataType::UInt64,
            "float32" => DataType::Float32,
            "float64" => DataType::Float64,
            "string" => DataType::String,
            _ => return None,
        })
    }

    /// The map file name (`float32`).
    pub fn as_str(self) -> &'static str {
        match self {
            DataType::Bool => "bool",
            DataType::Int16 => "int16",
            DataType::UInt16 => "uint16",
            DataType::Int32 => "int32",
            DataType::UInt32 => "uint32",
            DataType::Int64 => "int64",
            DataType::UInt64 => "uint64",
            DataType::Float32 => "float32",
            DataType::Float64 => "float64",
            DataType::String => "string",
        }
    }

    /// The CIP type name reads report (`REAL` for float32).
    pub fn cip_name(self) -> &'static str {
        match self {
            DataType::Bool => "BOOL",
            DataType::Int16 => "INT",
            DataType::UInt16 => "UINT",
            DataType::Int32 => "DINT",
            DataType::UInt32 => "UDINT",
            DataType::Int64 => "LINT",
            DataType::UInt64 => "ULINT",
            DataType::Float32 => "REAL",
            DataType::Float64 => "LREAL",
            DataType::String => "STRING",
        }
    }

    /// Registers per element; 0 for bool and string (sized otherwise).
    pub(crate) fn registers(self) -> u16 {
        match self {
            DataType::Bool | DataType::String => 0,
            DataType::Int16 | DataType::UInt16 => 1,
            DataType::Int32 | DataType::UInt32 | DataType::Float32 => 2,
            DataType::Int64 | DataType::UInt64 | DataType::Float64 => 4,
        }
    }

    /// True for the numeric types (scale and offset apply).
    pub fn is_numeric(self) -> bool {
        !matches!(self, DataType::Bool | DataType::String)
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Byte and register order of multi-byte values. `ABCD` is the Modbus standard (big-endian, most significant
/// register first); the others swap the bytes in each register, the register order, or both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WordOrder {
    /// Big-endian, most significant register first.
    #[default]
    Abcd,
    /// Least significant register first.
    Cdab,
    /// Bytes swapped in each register.
    Badc,
    /// Both: little-endian.
    Dcba,
}

impl WordOrder {
    /// `ABCD`, `CDAB`, `BADC` or `DCBA` (case-insensitive).
    pub fn parse(text: &str) -> Option<WordOrder> {
        Some(match text.to_ascii_uppercase().as_str() {
            "ABCD" => WordOrder::Abcd,
            "CDAB" => WordOrder::Cdab,
            "BADC" => WordOrder::Badc,
            "DCBA" => WordOrder::Dcba,
            _ => return None,
        })
    }

    /// The upper-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            WordOrder::Abcd => "ABCD",
            WordOrder::Cdab => "CDAB",
            WordOrder::Badc => "BADC",
            WordOrder::Dcba => "DCBA",
        }
    }

    /// The two bytes of each register are swapped.
    pub(crate) fn swap_bytes(self) -> bool {
        matches!(self, WordOrder::Badc | WordOrder::Dcba)
    }

    /// The least significant register comes first.
    pub(crate) fn low_first(self) -> bool {
        matches!(self, WordOrder::Cdab | WordOrder::Dcba)
    }
}

impl fmt::Display for WordOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed plain address (`hr100:float32:cdab{2}@3`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The table.
    pub area: Area,
    /// 0-based protocol address of the first register or bit.
    pub offset: u16,
    /// The bit of a register (`hr10.4`).
    pub bit: Option<u8>,
    /// The type: `co`/`di` and bits are bool, `hr`/`ir` default to uint16.
    pub data_type: DataType,
    /// None: the driver's word order.
    pub order: Option<WordOrder>,
    /// Elements; a string's length in characters.
    pub count: u16,
    /// None: the path's unit.
    pub unit: Option<u8>,
}

/// Registers (or bits) that `count` elements of `data_type` take; None past u16.
pub(crate) fn size_of(area: Area, bit: Option<u8>, data_type: DataType, count: u16) -> Option<u16> {
    if area.is_bits() {
        return Some(count);
    }
    if bit.is_some() {
        return Some(1);
    }
    match data_type {
        DataType::String => Some(count.div_ceil(2)),
        DataType::Bool => Some(0),
        _ => data_type.registers().checked_mul(count),
    }
}

/// True if `name` starts like a plain address: an area prefix then a digit (`hr1...`).
pub(crate) fn looks_like_address(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 3 && Area::parse(&name[..2]).is_some() && b[2].is_ascii_digit()
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{what} '{text}' is not a number"));
    }
    text.parse()
        .map_err(|_| format!("{what} {text} is out of range"))
}

/// Splits `text` at the last `sep`, if any.
fn take_suffix(text: &str, sep: char) -> (&str, Option<&str>) {
    match text.rfind(sep) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    }
}

impl Address {
    /// Parses a plain address (case-insensitive, no spaces):
    /// `area offset ["." bit] [":" type [":" order]] ["{" count "}"] ["@" unit]`.
    pub fn parse(text: &str) -> Result<Address, String> {
        let bad = |why: String| format!("bad Modbus address '{text}': {why}");
        let lower = text.to_ascii_lowercase();
        let (rest, unit) = take_suffix(&lower, '@');
        let unit = unit
            .map(|u| number::<u8>(u, "unit"))
            .transpose()
            .map_err(bad)?;
        let (rest, count) = match rest.strip_suffix('}') {
            Some(inner) => {
                let (rest, count) = take_suffix(inner, '{');
                let count = count.ok_or_else(|| bad("'}' without '{'".into()))?;
                (rest, Some(number::<u16>(count, "count").map_err(bad)?))
            }
            None => (rest, None),
        };
        if count == Some(0) {
            return Err(bad("count must be at least 1".into()));
        }
        let mut parts = rest.split(':');
        let head = parts.next().unwrap_or_default();
        let data_type = parts
            .next()
            .map(|t| {
                DataType::parse(t)
                    .ok_or_else(|| bad(format!("type '{t}' is not one of {TYPE_NAMES}")))
            })
            .transpose()?;
        let order = parts
            .next()
            .map(|o| {
                WordOrder::parse(o).ok_or_else(|| {
                    bad(format!(
                        "word order '{o}' is not one of abcd, cdab, badc, dcba"
                    ))
                })
            })
            .transpose()?;
        if parts.next().is_some() {
            return Err(bad("too many ':' parts".into()));
        }
        if head.len() < 3 || !head.is_char_boundary(2) {
            return Err(bad("expected co, di, hr or ir and an address".into()));
        }
        let area = Area::parse(&head[..2])
            .ok_or_else(|| bad("expected co, di, hr or ir and an address".into()))?;
        let (offset, bit) = take_suffix(&head[2..], '.');
        let offset = number::<u16>(offset, "address").map_err(bad)?;
        let bit = bit
            .map(|b| number::<u8>(b, "bit"))
            .transpose()
            .map_err(bad)?;
        let data_type = if let Some(bit) = bit {
            if area.is_bits() {
                return Err(bad(format!(
                    "a bit is only valid on hr or ir, not {}",
                    &head[..2]
                )));
            }
            if bit > 15 {
                return Err(bad(format!("bit {bit} is not 0..15")));
            }
            if data_type.is_some_and(|t| t != DataType::Bool) {
                return Err(bad("a bit of a register is bool".into()));
            }
            if count.is_some_and(|c| c != 1) {
                return Err(bad("a bit of a register has no count".into()));
            }
            DataType::Bool
        } else if area.is_bits() {
            match data_type {
                None | Some(DataType::Bool) => DataType::Bool,
                Some(t) => return Err(bad(format!("{} holds bits, not {t}", area))),
            }
        } else {
            match data_type {
                None => DataType::UInt16,
                Some(DataType::Bool) => {
                    return Err(bad("a bool in a register needs a bit (hr10.4)".into()));
                }
                Some(t) => t,
            }
        };
        if data_type == DataType::String && count.is_none() {
            return Err(bad("a string needs its length in characters ({n})".into()));
        }
        let count = count.unwrap_or(1);
        let size =
            size_of(area, bit, data_type, count).ok_or_else(|| bad("too many registers".into()))?;
        if u32::from(offset) + u32::from(size.max(1)) - 1 > 65535 {
            return Err(bad("runs past address 65535".into()));
        }
        Ok(Address {
            area,
            offset,
            bit,
            data_type,
            order,
            count,
            unit,
        })
    }
}

/// A resolved name: what to read or write, with every default applied.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Target {
    pub unit: u8,
    pub area: Area,
    /// First register or bit.
    pub address: u16,
    /// The bit of a register.
    pub bit: Option<u8>,
    pub data_type: DataType,
    /// Elements; a string's length in characters.
    pub count: u16,
    pub order: WordOrder,
    pub scale: Option<f64>,
    pub offset: Option<f64>,
    pub writable: bool,
}

impl Target {
    /// Registers (or bits) the target spans.
    pub fn size(&self) -> u16 {
        // checked when the map row or address was parsed
        size_of(self.area, self.bit, self.data_type, self.count).unwrap_or(1)
    }

    /// True when both touch a register or bit of the same unit and area.
    fn overlaps(&self, other: &Target) -> bool {
        let end = |t: &Target| u32::from(t.address) + u32::from(t.size());
        self.unit == other.unit
            && self.area == other.area
            && u32::from(self.address) < end(other)
            && u32::from(other.address) < end(self)
    }

    /// True when it reads as an array.
    pub fn is_array(&self) -> bool {
        self.count > 1 && self.data_type != DataType::String
    }

    /// True when scale or offset applies.
    pub fn is_scaled(&self) -> bool {
        self.scale.is_some() || self.offset.is_some()
    }

    /// The CIP type name of its value (of an element, for arrays).
    pub fn type_name(&self) -> &'static str {
        if self.is_scaled() && self.bit.is_none() {
            "LREAL"
        } else {
            self.data_type.cip_name()
        }
    }

    fn from_row(row: &MapTag, unit: u8, order: WordOrder) -> Target {
        Target {
            unit: row.unit.unwrap_or(unit),
            area: row.area,
            address: row.address,
            bit: row.bit,
            data_type: row.data_type,
            count: row.count,
            order: row.order.unwrap_or(order),
            scale: row.scale,
            offset: row.offset,
            writable: row.writable,
        }
    }

    /// Element `index` of an array target.
    fn element(mut self, index: u16, name: &str) -> Result<Target, TagError> {
        if self.data_type == DataType::String || self.bit.is_some() {
            return Err(TagError::new(
                format!("'{name}': not an array"),
                ErrorKind::BadRequest,
            ));
        }
        if index >= self.count {
            return Err(TagError::new(
                format!(
                    "'{name}': index {index} is out of range (count {})",
                    self.count
                ),
                ErrorKind::NotFound,
            ));
        }
        let step = if self.area.is_bits() {
            1
        } else {
            self.data_type.registers()
        };
        // index < count and the row fits below 65536
        self.address += index * step;
        self.count = 1;
        Ok(self)
    }

    /// Bit `bit` of a 16-bit integer target in a register.
    fn bit_of(mut self, bit: u8, name: &str) -> Result<Target, TagError> {
        let word = matches!(self.data_type, DataType::Int16 | DataType::UInt16)
            && !self.area.is_bits()
            && self.bit.is_none()
            && self.count == 1;
        if !word {
            return Err(TagError::new(
                format!("'{name}': a bit needs a 16-bit integer register"),
                ErrorKind::BadRequest,
            ));
        }
        if bit > 15 {
            return Err(TagError::new(
                format!("'{name}': bit {bit} is not 0..15"),
                ErrorKind::BadRequest,
            ));
        }
        // bit N of the value the user sees: with the bytes swapped (BADC, DCBA) that is register bit N ^ 8
        self.bit = Some(if self.order.swap_bytes() {
            bit ^ 8
        } else {
            bit
        });
        self.data_type = DataType::Bool;
        self.scale = None;
        self.offset = None;
        Ok(self)
    }
}

/// Splits `name` into its base, an element index (`[i]`) and a bit (`.N`), where present.
fn split_suffixes(name: &str) -> Option<(&str, Option<u16>, Option<u8>)> {
    let mut base = name;
    let mut bit = None;
    if let (head, Some(b)) = take_suffix(base, '.') {
        if !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()) {
            bit = Some(b.parse().unwrap_or(u8::MAX));
            base = head;
        }
    }
    let mut index = None;
    if let Some(inner) = base.strip_suffix(']') {
        let (head, i) = take_suffix(inner, '[');
        let i = i?;
        index = Some(i.parse().ok()?);
        base = head;
    }
    (index.is_some() || bit.is_some()).then_some((base, index, bit))
}

/// Resolves a caller's name: a map row, an element of one (`Totals[2]`), a bit of a 16-bit one
/// (`Drive_Status.5`, `Words[3].15`), else a plain address.
pub(crate) fn resolve(
    name: &str,
    map: &TagMap,
    unit: u8,
    order: WordOrder,
) -> Result<Target, TagError> {
    if let Some(row) = map.get(name) {
        return Ok(Target::from_row(row, unit, order));
    }
    if let Some((base, index, bit)) = split_suffixes(name) {
        if let Some(row) = map.get(base) {
            let mut target = Target::from_row(row, unit, order);
            if let Some(index) = index {
                target = target.element(index, name)?;
            }
            if let Some(bit) = bit {
                target = target.bit_of(bit, name)?;
            }
            return Ok(target);
        }
    }
    if !looks_like_address(name) {
        return Err(TagError::new(
            format!("no tag or address '{name}'"),
            ErrorKind::NotFound,
        ));
    }
    let address = Address::parse(name).map_err(|m| TagError::new(m, ErrorKind::BadRequest))?;
    let mut target = Target {
        unit: address.unit.unwrap_or(unit),
        area: address.area,
        address: address.offset,
        bit: address.bit,
        data_type: address.data_type,
        count: address.count,
        order: address.order.unwrap_or(order),
        scale: None,
        offset: None,
        writable: address.area.is_writable(),
    };
    // a plain address must not write around a read-only map row
    if target.writable {
        target.writable = !map
            .tags()
            .filter(|row| !row.writable)
            .map(|row| Target::from_row(row, unit, order))
            .any(|row| row.overlaps(&target));
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> Address {
        Address::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    fn a(area: Area, offset: u16, data_type: DataType, count: u16) -> Address {
        Address {
            area,
            offset,
            bit: None,
            data_type,
            order: None,
            count,
            unit: None,
        }
    }

    #[test]
    fn every_example_of_the_address_table() {
        assert_eq!(addr("hr0"), a(Area::Holding, 0, DataType::UInt16, 1));
        assert_eq!(
            addr("hr100:float32"),
            a(Area::Holding, 100, DataType::Float32, 1)
        );
        assert_eq!(
            addr("hr100:float32:cdab"),
            Address {
                order: Some(WordOrder::Cdab),
                ..a(Area::Holding, 100, DataType::Float32, 1)
            }
        );
        assert_eq!(
            addr("hr200:int16{10}"),
            a(Area::Holding, 200, DataType::Int16, 10)
        );
        assert_eq!(
            addr("hr300:string{20}"),
            a(Area::Holding, 300, DataType::String, 20)
        );
        assert_eq!(
            addr("hr10.4"),
            Address {
                bit: Some(4),
                ..a(Area::Holding, 10, DataType::Bool, 1)
            }
        );
        assert_eq!(addr("ir5:int32"), a(Area::Input, 5, DataType::Int32, 1));
        assert_eq!(addr("co0{16}"), a(Area::Coil, 0, DataType::Bool, 16));
        assert_eq!(
            addr("di7@3"),
            Address {
                unit: Some(3),
                ..a(Area::Discrete, 7, DataType::Bool, 1)
            }
        );
        // case-insensitive, every part together
        assert_eq!(
            addr("HR65532:Float64:DCBA{1}@0"),
            Address {
                order: Some(WordOrder::Dcba),
                unit: Some(0),
                ..a(Area::Holding, 65532, DataType::Float64, 1)
            }
        );
        assert_eq!(addr("hr10.4:bool"), addr("hr10.4"));
        assert_eq!(addr("co3:bool"), a(Area::Coil, 3, DataType::Bool, 1));
    }

    #[test]
    fn rejects() {
        for bad in [
            "co5.1",            // bit on a coil
            "hr10.16",          // bit 16
            "hr0:string",       // string without count
            "hr10.4:int16",     // type on a bit
            "hr10.4{2}",        // count on a bit
            "hr65535:int32",    // past 65535
            "co65535{2}",       // past 65535
            "hr0@256",          // unit 256
            "hr70000",          // address past 65535
            "hr0:float",        // unknown type
            "hr0:int32:abdc",   // unknown order
            "hr0{0}",           // count 0
            "hr0:bool",         // bool in a register without a bit
            "co0:int16",        // a word type on a coil
            "hr0:int16:abcd:x", // too many parts
            "xx0",              // unknown area
            "hr",               // no address
            "hr1x",             // not a number
        ] {
            assert!(Address::parse(bad).is_err(), "{bad} parsed");
        }
        assert!(Address::parse("hr65534:int32").is_ok());
        assert!(Address::parse("co65535").is_ok());
    }

    fn map() -> TagMap {
        TagMap::from_csv(
            "name,area,address,type,count,unit,scale,writable\n\
             Totals,holding,100,uint32,4,,,\n\
             Words,holding,10,uint16,4,,,\n\
             Drive_Status,holding,300,uint16,,,,false\n\
             Level,input,5,int16,,,0.1,\n\
             Flags,coil,20,bool,8,2,,\n\
             Name,holding,200,string,6,,,\n\
             Pump1.Speed,holding,0,float32,,,,\n",
        )
        .expect("map")
    }

    fn resolved(name: &str) -> Result<Target, TagError> {
        resolve(name, &map(), 1, WordOrder::Abcd)
    }

    #[test]
    fn name_then_element_then_bit_then_address() {
        let totals = resolved("totals").expect("row, ignoring case");
        assert_eq!((totals.address, totals.count, totals.size()), (100, 4, 8));
        let third = resolved("Totals[2]").expect("element");
        assert_eq!((third.address, third.count, third.size()), (104, 1, 2));
        let flag = resolved("Flags[3]").expect("bit element");
        assert_eq!((flag.unit, flag.address, flag.count), (2, 23, 1));
        let bit = resolved("Drive_Status.5").expect("bit");
        assert_eq!(
            (bit.address, bit.bit, bit.data_type),
            (300, Some(5), DataType::Bool)
        );
        assert!(!bit.writable);
        let word_bit = resolved("Words[3].15").expect("element bit");
        assert_eq!((word_bit.address, word_bit.bit), (13, Some(15)));
        let dotted = resolved("Pump1.Speed").expect("dotted name");
        assert_eq!(dotted.data_type, DataType::Float32);
        let plain = resolved("hr20.3@4").expect("address");
        assert_eq!((plain.unit, plain.address, plain.bit), (4, 20, Some(3)));
        assert!(plain.writable);
        assert!(!resolved("ir0").expect("input").writable);
        assert_eq!(resolved("Level").expect("scaled").type_name(), "LREAL");

        let kind = |name: &str| resolved(name).expect_err(name).kind;
        assert_eq!(kind("Totals[4]"), ErrorKind::NotFound);
        assert_eq!(kind("Totals.3"), ErrorKind::BadRequest);
        assert_eq!(kind("Words.3"), ErrorKind::BadRequest); // an array, not a word
        assert_eq!(kind("Drive_Status.16"), ErrorKind::BadRequest);
        assert_eq!(kind("Name[1]"), ErrorKind::BadRequest);
        assert_eq!(kind("Nope"), ErrorKind::NotFound);
        assert_eq!(kind("Nope[1]"), ErrorKind::NotFound);
        assert_eq!(kind("hr0:nope"), ErrorKind::BadRequest);
        assert_eq!(
            resolved("Nope").expect_err("missing").message,
            "no tag or address 'Nope'"
        );
    }

    #[test]
    fn bit_of_a_byte_swapped_word_is_the_bit_of_its_value() {
        let rows = TagMap::from_csv(
            "name,area,address,type,order
             W,holding,5,uint16,BADC
             D,holding,6,int16,DCBA
             A,holding,7,uint16,CDAB
",
        )
        .expect("map");
        let bit = |name: &str| resolve(name, &rows, 1, WordOrder::Abcd).expect(name).bit;
        assert_eq!(bit("W.0"), Some(8));
        assert_eq!(bit("W.8"), Some(0));
        assert_eq!(bit("D.15"), Some(7));
        assert_eq!(bit("A.3"), Some(3), "no byte swap");
        // a byte-swapping driver default applies too; a plain address names a register bit
        let swapped = |name: &str| resolve(name, &map(), 1, WordOrder::Dcba).expect(name).bit;
        assert_eq!(swapped("Drive_Status.1"), Some(9));
        assert_eq!(swapped("hr300.1"), Some(1));
    }

    #[test]
    fn plain_address_over_a_read_only_row_is_read_only() {
        let writable = |name: &str| resolved(name).expect(name).writable;
        assert!(!writable("hr300"), "Drive_Status");
        assert!(!writable("hr300.5"));
        assert!(!writable("hr299:uint32"), "overlaps register 300");
        assert!(writable("hr299"));
        assert!(writable("hr301"));
        assert!(writable("hr300@2"), "another unit");
        assert!(writable("co20@2"));
    }
}
