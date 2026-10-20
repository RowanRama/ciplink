use indexmap::IndexMap;
use std::fmt::Write;

/// A tag or message value.
///
/// Reads return the variant of the tag's type (`DInt` for a DINT, `Array` for arrays and BOOL words, `Struct`
/// for UDTs). Writes accept any variant of the right class: any integer variant for an integer type (range
/// checked), integers or floats for REAL/LREAL, `Bool` (or the integers 0 and 1) for BOOL.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// BOOL
    Bool(bool),
    /// SINT
    SInt(i8),
    /// INT
    Int(i16),
    /// DINT
    DInt(i32),
    /// LINT
    LInt(i64),
    /// USINT
    USInt(u8),
    /// UINT
    UInt(u16),
    /// UDINT
    UDInt(u32),
    /// ULINT
    ULInt(u64),
    /// REAL
    Real(f32),
    /// LREAL
    LReal(f64),
    /// Any string type.
    String(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
    /// Array elements, BOOL words as one `Bool` per bit.
    Array(Vec<Value>),
    /// Structure members in template order.
    Struct(IndexMap<String, Value>),
}

impl Value {
    /// The value of an integer variant, None for anything else (including `Bool`).
    pub fn as_i128(&self) -> Option<i128> {
        Some(match *self {
            Value::SInt(v) => v.into(),
            Value::Int(v) => v.into(),
            Value::DInt(v) => v.into(),
            Value::LInt(v) => v.into(),
            Value::USInt(v) => v.into(),
            Value::UInt(v) => v.into(),
            Value::UDInt(v) => v.into(),
            Value::ULInt(v) => v.into(),
            _ => return None,
        })
    }

    /// The value of a number variant as f64 (integers convert), None for anything else (including `Bool`).
    pub fn as_f64(&self) -> Option<f64> {
        match *self {
            Value::Real(v) => Some(v.into()),
            Value::LReal(v) => Some(v),
            _ => self.as_i128().map(|v| v as f64),
        }
    }

    /// A BOOL value: `Bool` or the integers 0 and 1, like the Python driver accepts.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => match self.as_i128() {
                Some(0) => Some(false),
                Some(1) => Some(true),
                _ => None,
            },
        }
    }

    /// The value as Python would print it with `repr()`, used in error messages.
    pub fn py_repr(&self) -> String {
        let mut out = String::new();
        self.write_repr(&mut out);
        out
    }

    fn write_repr(&self, out: &mut String) {
        match self {
            Value::Bool(true) => out.push_str("True"),
            Value::Bool(false) => out.push_str("False"),
            Value::Real(v) => out.push_str(&py_float_repr(f64::from(*v))),
            Value::LReal(v) => out.push_str(&py_float_repr(*v)),
            Value::String(s) => out.push_str(&py_str_repr(s)),
            Value::Bytes(b) => out.push_str(&py_bytes_repr(b)),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    item.write_repr(out);
                }
                out.push(']');
            }
            Value::Struct(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&py_str_repr(k));
                    out.push_str(": ");
                    v.write_repr(out);
                }
                out.push('}');
            }
            other => {
                let _ = write!(out, "{}", other.as_i128().unwrap_or_default());
            }
        }
    }
}

/// Python's `repr()` of a float.
pub(crate) fn py_float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    // shortest round-trip digits and decimal exponent, then Python's 'r' formatting rules
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if x < 0.0 { "-" } else { "" };
    if !(-4..16).contains(&exp) {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{first}{rest}e{esign}{:02}", exp.abs());
    }
    let point = exp + 1; // digits before the decimal point
    let body = if point <= 0 {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else if point as usize >= digits.len() {
        format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
    } else {
        let (a, b) = digits.split_at(point as usize);
        format!("{a}.{b}")
    };
    format!("{sign}{body}")
}

/// Python's `repr()` of a str.
pub(crate) fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `repr()` of bytes.
pub(crate) fn py_bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(quote as char);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            c => {
                let _ = write!(out, "\\x{c:02x}");
            }
        }
    }
    out.push(quote as char);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        let cases = [
            (1.5, "1.5"),
            (1e39, "1e+39"),
            (-1e39, "-1e+39"),
            (1.0, "1.0"),
            (0.5, "0.5"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (123456789.0, "123456789.0"),
            (3.4028234663852886e38, "3.4028234663852886e+38"),
            (0.1, "0.1"),
            (1.401298464324817e-45, "1.401298464324817e-45"),
        ];
        for (x, want) in cases {
            assert_eq!(py_float_repr(x), want);
        }
    }

    #[test]
    fn str_and_bytes_repr_match_python() {
        assert_eq!(py_str_repr("it's"), "\"it's\"");
        assert_eq!(py_str_repr("a\nb"), "'a\\nb'");
        assert_eq!(py_bytes_repr(b"\x00ab'"), "b\"\\x00ab'\"");
        assert_eq!(py_bytes_repr(b"\xff"), "b'\\xff'");
    }

    #[test]
    fn bool_class_accepts_only_bool_or_zero_and_one() {
        assert_eq!(Value::LInt(1).as_bool(), Some(true));
        assert_eq!(Value::LInt(2).as_bool(), None);
        assert_eq!(Value::Real(1.0).as_bool(), None);
        assert_eq!(Value::Bool(true).as_i128(), None);
    }
}
