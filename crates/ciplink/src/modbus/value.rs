//! Registers and bits to and from [`Value`]s: word order, scale and offset, strings, range checks. Pure.

use super::address::{DataType, Target, WordOrder};
use crate::Value;

/// The bytes of one element's registers, most significant first, undoing `order`.
fn to_bytes(regs: &[u16], order: WordOrder) -> Vec<u8> {
    let mut out = Vec::with_capacity(regs.len() * 2);
    let mut push = |r: u16| {
        out.extend_from_slice(&if order.swap_bytes() {
            r.to_le_bytes()
        } else {
            r.to_be_bytes()
        });
    };
    if order.low_first() {
        regs.iter().rev().for_each(|&r| push(r));
    } else {
        regs.iter().for_each(|&r| push(r));
    }
    out
}

/// The registers of one element from its bytes (most significant first), applying `order`.
fn from_bytes(bytes: &[u8], order: WordOrder) -> Vec<u16> {
    let mut regs: Vec<u16> = bytes
        .chunks(2)
        .map(|c| {
            let pair = [c[0], c.get(1).copied().unwrap_or(0)];
            if order.swap_bytes() {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        })
        .collect();
    if order.low_first() {
        regs.reverse();
    }
    regs
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

/// One numeric element from its registers.
fn decode_number(data_type: DataType, regs: &[u16], order: WordOrder) -> Value {
    let b = to_bytes(regs, order);
    match data_type {
        DataType::Int16 => Value::Int(i16::from_be_bytes(array(&b))),
        DataType::UInt16 => Value::UInt(u16::from_be_bytes(array(&b))),
        DataType::Int32 => Value::DInt(i32::from_be_bytes(array(&b))),
        DataType::UInt32 => Value::UDInt(u32::from_be_bytes(array(&b))),
        DataType::Int64 => Value::LInt(i64::from_be_bytes(array(&b))),
        DataType::UInt64 => Value::ULInt(u64::from_be_bytes(array(&b))),
        DataType::Float32 => Value::Real(f32::from_be_bytes(array(&b))),
        DataType::Float64 => Value::LReal(f64::from_be_bytes(array(&b))),
        DataType::Bool | DataType::String => Value::Bytes(b),
    }
}

fn scaled(target: &Target, value: Value) -> Value {
    if !target.is_scaled() {
        return value;
    }
    let raw = value.as_f64().unwrap_or_default();
    Value::LReal(raw * target.scale.unwrap_or(1.0) + target.offset.unwrap_or(0.0))
}

/// The value of a register target from its `size()` registers.
pub(crate) fn decode_registers(target: &Target, regs: &[u16]) -> Value {
    if let Some(bit) = target.bit {
        return Value::Bool(regs.first().is_some_and(|r| r >> bit & 1 == 1));
    }
    if target.data_type == DataType::String {
        let swap = target.order.swap_bytes();
        let bytes = regs.iter().flat_map(|r| {
            if swap {
                r.to_le_bytes()
            } else {
                r.to_be_bytes()
            }
        });
        return Value::String(
            bytes
                .take(usize::from(target.count))
                .take_while(|&b| b != 0)
                .map(char::from)
                .collect(),
        );
    }
    let per = usize::from(target.data_type.registers()).max(1);
    let mut items = regs
        .chunks_exact(per)
        .map(|chunk| scaled(target, decode_number(target.data_type, chunk, target.order)));
    if target.is_array() {
        Value::Array(items.collect())
    } else {
        items.next().unwrap_or(Value::Array(Vec::new()))
    }
}

/// The value of a coil or discrete input target from its bits.
pub(crate) fn decode_bits(target: &Target, bits: &[bool]) -> Value {
    if target.is_array() {
        Value::Array(bits.iter().map(|&b| Value::Bool(b)).collect())
    } else {
        Value::Bool(bits.first().copied().unwrap_or(false))
    }
}

/// A bool from `value`: `Bool` or the integers 0 and 1.
pub(crate) fn encode_bool(value: &Value) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("{} is not a bool", value.py_repr()))
}

/// The elements of a write: an array of exactly `count` for an array target, else the value alone.
fn elements<'a>(target: &Target, value: &'a Value) -> Result<Vec<&'a Value>, String> {
    if !target.is_array() {
        return Ok(vec![value]);
    }
    match value {
        Value::Array(items) if items.len() == usize::from(target.count) => {
            Ok(items.iter().collect())
        }
        Value::Array(items) => Err(format!(
            "expected {} elements, got {}",
            target.count,
            items.len()
        )),
        other => Err(format!(
            "expected a list of {} elements, got {}",
            target.count,
            other.py_repr()
        )),
    }
}

/// The bits of a coil write.
pub(crate) fn encode_bits(target: &Target, value: &Value) -> Result<Vec<bool>, String> {
    elements(target, value)?
        .into_iter()
        .map(encode_bool)
        .collect()
}

/// An integer from an integer variant or a float with no fractional part.
fn integer(value: &Value) -> Option<i128> {
    match value.as_i128() {
        Some(v) => Some(v),
        None => {
            let f = match value {
                Value::Real(f) => f64::from(*f),
                Value::LReal(f) => *f,
                _ => return None,
            };
            // in range of i128 for every value a Modbus type holds; the range check follows
            (f.is_finite() && f.fract() == 0.0 && f.abs() < 1e30).then_some(f as i128)
        }
    }
}

fn int_bytes(data_type: DataType, v: i128) -> Option<Vec<u8>> {
    Some(match data_type {
        DataType::Int16 => i16::try_from(v).ok()?.to_be_bytes().to_vec(),
        DataType::UInt16 => u16::try_from(v).ok()?.to_be_bytes().to_vec(),
        DataType::Int32 => i32::try_from(v).ok()?.to_be_bytes().to_vec(),
        DataType::UInt32 => u32::try_from(v).ok()?.to_be_bytes().to_vec(),
        DataType::Int64 => i64::try_from(v).ok()?.to_be_bytes().to_vec(),
        DataType::UInt64 => u64::try_from(v).ok()?.to_be_bytes().to_vec(),
        _ => return None,
    })
}

fn float_bytes(data_type: DataType, f: f64) -> Option<Vec<u8>> {
    match data_type {
        DataType::Float64 => Some(f.to_be_bytes().to_vec()),
        // f64 to f32 may round; a finite value past f32 is out of range
        _ if f.is_finite() && f.abs() > f64::from(f32::MAX) => None,
        _ => Some((f as f32).to_be_bytes().to_vec()),
    }
}

/// The big-endian bytes of one numeric element.
fn number_bytes(target: &Target, value: &Value) -> Result<Vec<u8>, String> {
    let data_type = target.data_type;
    let float = matches!(data_type, DataType::Float32 | DataType::Float64);
    let misfit = || format!("{} does not fit {data_type}", value.py_repr());
    if target.is_scaled() {
        let x = value.as_f64().ok_or_else(misfit)?;
        let raw = (x - target.offset.unwrap_or(0.0)) / target.scale.unwrap_or(1.0);
        return if float {
            float_bytes(data_type, raw).ok_or_else(misfit)
        } else {
            let rounded = raw.round();
            if !rounded.is_finite() || rounded.abs() >= 1e30 {
                return Err(misfit());
            }
            int_bytes(data_type, rounded as i128).ok_or_else(misfit)
        };
    }
    if float {
        let f = value.as_f64().ok_or_else(misfit)?;
        float_bytes(data_type, f).ok_or_else(misfit)
    } else {
        int_bytes(data_type, integer(value).ok_or_else(misfit)?).ok_or_else(misfit)
    }
}

/// The registers of a register write (not a bit of a register).
pub(crate) fn encode_registers(target: &Target, value: &Value) -> Result<Vec<u16>, String> {
    if target.data_type == DataType::String {
        let Value::String(text) = value else {
            return Err(format!("{} is not a string", value.py_repr()));
        };
        let mut bytes = Vec::with_capacity(usize::from(target.count) + 1);
        for c in text.chars() {
            let b = u8::try_from(u32::from(c))
                .map_err(|_| format!("'{c}' is not a Latin-1 character"))?;
            bytes.push(b);
        }
        if bytes.len() > usize::from(target.count) {
            return Err(format!(
                "{} characters do not fit a string of {}",
                bytes.len(),
                target.count
            ));
        }
        bytes.resize(usize::from(target.count.div_ceil(2)) * 2, 0);
        // the register order does not apply to strings
        let order = if target.order.swap_bytes() {
            WordOrder::Badc
        } else {
            WordOrder::Abcd
        };
        return Ok(from_bytes(&bytes, order));
    }
    let mut regs = Vec::with_capacity(usize::from(target.size()));
    for item in elements(target, value)? {
        regs.extend(from_bytes(&number_bytes(target, item)?, target.order));
    }
    Ok(regs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modbus::address::Area;

    fn target(data_type: DataType, count: u16, order: WordOrder) -> Target {
        Target {
            unit: 1,
            area: Area::Holding,
            address: 0,
            bit: None,
            data_type,
            count,
            order,
            scale: None,
            offset: None,
            writable: true,
        }
    }

    #[test]
    fn float32_in_every_word_order() {
        let table = [
            (WordOrder::Abcd, [0x42F6, 0xE979]),
            (WordOrder::Cdab, [0xE979, 0x42F6]),
            (WordOrder::Badc, [0xF642, 0x79E9]),
            (WordOrder::Dcba, [0x79E9, 0xF642]),
        ];
        for (order, regs) in table {
            let t = target(DataType::Float32, 1, order);
            assert_eq!(decode_registers(&t, &regs), Value::Real(123.456), "{order}");
            assert_eq!(
                encode_registers(&t, &Value::Real(123.456)).expect("encode"),
                regs,
                "{order}"
            );
        }
    }

    #[test]
    fn int64_and_float64_word_orders() {
        let v = 0x0102_0304_0506_0708_i64;
        let table = [
            (WordOrder::Abcd, [0x0102, 0x0304, 0x0506, 0x0708]),
            (WordOrder::Cdab, [0x0708, 0x0506, 0x0304, 0x0102]),
            (WordOrder::Badc, [0x0201, 0x0403, 0x0605, 0x0807]),
            (WordOrder::Dcba, [0x0807, 0x0605, 0x0403, 0x0201]),
        ];
        for (order, regs) in table {
            let t = target(DataType::Int64, 1, order);
            assert_eq!(decode_registers(&t, &regs), Value::LInt(v));
            assert_eq!(encode_registers(&t, &Value::LInt(v)).expect("encode"), regs);
            let u = target(DataType::UInt64, 1, order);
            assert_eq!(decode_registers(&u, &regs), Value::ULInt(v as u64));
        }
        // 1.0 is 0x3FF0_0000_0000_0000
        let t = target(DataType::Float64, 1, WordOrder::Cdab);
        assert_eq!(
            encode_registers(&t, &Value::LReal(1.0)).expect("encode"),
            [0, 0, 0, 0x3FF0]
        );
        assert_eq!(decode_registers(&t, &[0, 0, 0, 0x3FF0]), Value::LReal(1.0));
        let t = target(DataType::Int32, 1, WordOrder::Cdab);
        assert_eq!(decode_registers(&t, &[0xFFFE, 0xFFFF]), Value::DInt(-2));
        let t = target(DataType::UInt32, 1, WordOrder::Abcd);
        assert_eq!(
            decode_registers(&t, &[0x0001, 0x0002]),
            Value::UDInt(0x0001_0002)
        );
    }

    #[test]
    fn int16_byte_swap() {
        for (order, reg) in [
            (WordOrder::Abcd, 0x1234),
            (WordOrder::Cdab, 0x1234),
            (WordOrder::Badc, 0x3412),
            (WordOrder::Dcba, 0x3412),
        ] {
            let t = target(DataType::Int16, 1, order);
            assert_eq!(decode_registers(&t, &[reg]), Value::Int(0x1234));
            assert_eq!(
                encode_registers(&t, &Value::Int(0x1234)).expect("encode"),
                [reg]
            );
        }
        let t = target(DataType::Int16, 1, WordOrder::Abcd);
        assert_eq!(decode_registers(&t, &[0xFFFF]), Value::Int(-1));
        let t = target(DataType::UInt16, 3, WordOrder::Abcd);
        assert_eq!(
            decode_registers(&t, &[1, 2, 3]),
            Value::Array(vec![Value::UInt(1), Value::UInt(2), Value::UInt(3)])
        );
        assert_eq!(
            encode_registers(
                &t,
                &Value::Array(vec![Value::Int(1), Value::DInt(2), Value::LReal(3.0)])
            )
            .expect("encode"),
            [1, 2, 3]
        );
        assert!(encode_registers(&t, &Value::Array(vec![Value::Int(1)])).is_err());
        assert!(encode_registers(&t, &Value::Int(1)).is_err());
    }

    #[test]
    fn string_packing_and_byte_swap() {
        let t = target(DataType::String, 5, WordOrder::Abcd);
        let regs = encode_registers(&t, &Value::String("AB".into())).expect("encode");
        assert_eq!(regs, [0x4142, 0, 0]);
        assert_eq!(decode_registers(&t, &regs), Value::String("AB".into()));
        assert_eq!(
            decode_registers(&t, &[0x4142, 0x4344, 0x4546]),
            Value::String("ABCDE".into()),
            "cut at count"
        );
        // the register order flag does not apply to strings
        let t = target(DataType::String, 4, WordOrder::Cdab);
        assert_eq!(
            encode_registers(&t, &Value::String("ABCD".into())).expect("encode"),
            [0x4142, 0x4344]
        );
        let t = target(DataType::String, 4, WordOrder::Dcba);
        let regs = encode_registers(&t, &Value::String("ABC".into())).expect("encode");
        assert_eq!(regs, [0x4241, 0x0043]);
        assert_eq!(decode_registers(&t, &regs), Value::String("ABC".into()));
        let t = target(DataType::String, 2, WordOrder::Abcd);
        assert_eq!(decode_registers(&t, &[0xE900]), Value::String("é".into()));
        assert_eq!(
            encode_registers(&t, &Value::String("é".into())).expect("Latin-1"),
            [0xE900]
        );
    }

    #[test]
    fn scale_and_offset_round_trip() {
        let mut t = target(DataType::Int16, 1, WordOrder::Abcd);
        t.scale = Some(0.1);
        t.offset = Some(-40.0);
        assert_eq!(
            decode_registers(&t, &[650]),
            Value::LReal(650.0 * 0.1 - 40.0)
        );
        assert_eq!(
            encode_registers(&t, &Value::LReal(25.0)).expect("encode"),
            [650]
        );
        let mut only_offset = target(DataType::UInt16, 1, WordOrder::Abcd);
        only_offset.offset = Some(10.0);
        assert_eq!(decode_registers(&only_offset, &[5]), Value::LReal(15.0));
        assert_eq!(
            encode_registers(&only_offset, &Value::Int(15)).expect("encode"),
            [5]
        );
        let mut f = target(DataType::Float32, 1, WordOrder::Abcd);
        f.scale = Some(2.0);
        assert_eq!(decode_registers(&f, &[0x3F80, 0]), Value::LReal(2.0));
        assert_eq!(
            encode_registers(&f, &Value::LReal(2.0)).expect("encode"),
            [0x3F80, 0]
        );
    }

    #[test]
    fn write_range_checks() {
        let i16t = target(DataType::Int16, 1, WordOrder::Abcd);
        assert!(encode_registers(&i16t, &Value::DInt(70000)).is_err());
        assert!(encode_registers(&i16t, &Value::LReal(1.5)).is_err());
        assert!(encode_registers(&i16t, &Value::LReal(f64::NAN)).is_err());
        assert!(encode_registers(&i16t, &Value::Bool(true)).is_err());
        assert_eq!(
            encode_registers(&i16t, &Value::LReal(-2.0)).expect("whole"),
            [0xFFFE]
        );
        let u16t = target(DataType::UInt16, 1, WordOrder::Abcd);
        assert!(encode_registers(&u16t, &Value::Int(-1)).is_err());
        let u64t = target(DataType::UInt64, 1, WordOrder::Abcd);
        assert_eq!(
            encode_registers(&u64t, &Value::ULInt(u64::MAX)).expect("max"),
            [0xFFFF; 4]
        );
        let f32t = target(DataType::Float32, 1, WordOrder::Abcd);
        assert!(encode_registers(&f32t, &Value::LReal(1e39)).is_err());
        assert!(encode_registers(&f32t, &Value::Int(3)).is_ok());
        assert!(encode_registers(&f32t, &Value::LReal(f64::NAN)).is_ok());
        let s = target(DataType::String, 4, WordOrder::Abcd);
        assert!(encode_registers(&s, &Value::String("€".into())).is_err());
        assert!(encode_registers(&s, &Value::String("ABCDE".into())).is_err());
        assert!(encode_registers(&s, &Value::Int(1)).is_err());
        assert_eq!(encode_bool(&Value::Int(1)), Ok(true));
        assert!(encode_bool(&Value::Int(2)).is_err());
        let mut coils = target(DataType::Bool, 3, WordOrder::Abcd);
        coils.area = Area::Coil;
        assert_eq!(
            encode_bits(
                &coils,
                &Value::Array(vec![Value::Bool(true), Value::Int(0), Value::Bool(true)])
            ),
            Ok(vec![true, false, true])
        );
        assert!(encode_bits(&coils, &Value::Bool(true)).is_err());
    }

    #[test]
    fn scaled_write_rounds() {
        let mut t = target(DataType::Int16, 1, WordOrder::Abcd);
        t.scale = Some(0.1);
        assert_eq!(
            encode_registers(&t, &Value::LReal(12.34)).expect("encode"),
            [123]
        );
        assert_eq!(
            encode_registers(&t, &Value::LReal(12.36)).expect("encode"),
            [124]
        );
        assert!(encode_registers(&t, &Value::LReal(5000.0)).is_err());
    }

    #[test]
    fn bits_and_bit_of_a_register() {
        let mut t = target(DataType::Bool, 1, WordOrder::Abcd);
        t.bit = Some(4);
        assert_eq!(decode_registers(&t, &[0x0010]), Value::Bool(true));
        assert_eq!(decode_registers(&t, &[0xFFEF]), Value::Bool(false));
        let mut coils = target(DataType::Bool, 2, WordOrder::Abcd);
        coils.area = Area::Coil;
        assert_eq!(
            decode_bits(&coils, &[true, false]),
            Value::Array(vec![Value::Bool(true), Value::Bool(false)])
        );
        coils.count = 1;
        assert_eq!(decode_bits(&coils, &[true]), Value::Bool(true));
    }
}
