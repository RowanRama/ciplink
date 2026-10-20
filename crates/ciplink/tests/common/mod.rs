//! Helpers for the fixture tests: the fixtures are written by tools/fixtures/*.py from the reference Python
//! driver, values tagged as {"int": n}, {"float": x}, {"str": s}, {"bytes": hex}, {"list": [..]},
//! {"dict": [[k, v], ..]}, {"bool": b} or null, results as {"ok": value} or {"err": class, "msg": text}.
#![allow(dead_code, clippy::unwrap_used)]

use ciplink::{Error, Value};
use serde_json::Value as Json;

pub fn load(name: &str) -> Json {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

pub fn cases<'a>(fixture: &'a Json, section: &str) -> &'a Vec<Json> {
    fixture[section]
        .as_array()
        .unwrap_or_else(|| panic!("no section {section}"))
}

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// a tagged input value, None for Python's None
pub fn input(json: &Json) -> Option<Value> {
    if json.is_null() {
        return None;
    }
    let (tag, inner) = json.as_object().unwrap().iter().next().unwrap();
    Some(match tag.as_str() {
        "bool" => Value::Bool(inner.as_bool().unwrap()),
        "int" => match inner.as_i64() {
            Some(n) => Value::LInt(n),
            None => Value::ULInt(inner.as_u64().unwrap()),
        },
        "float" => match inner.as_f64() {
            Some(x) => Value::LReal(x),
            None => Value::LReal(inner.as_str().unwrap().parse().unwrap()),
        },
        "str" => Value::String(inner.as_str().unwrap().to_owned()),
        "bytes" => Value::Bytes(hex(inner.as_str().unwrap())),
        "list" => Value::Array(
            inner
                .as_array()
                .unwrap()
                .iter()
                .map(|v| input(v).unwrap())
                .collect(),
        ),
        "dict" => Value::Struct(
            inner
                .as_array()
                .unwrap()
                .iter()
                .map(|kv| (kv[0].as_str().unwrap().to_owned(), input(&kv[1]).unwrap()))
                .collect(),
        ),
        other => panic!("unknown tag {other}"),
    })
}

pub fn input_int(json: &Json) -> i64 {
    json["int"].as_i64().unwrap()
}

/// the Python exception class an Error stands for
pub fn class(err: &Error) -> &'static str {
    match err {
        Error::Comm(_) => "CommError",
        Error::Data(_) => "DataError",
        Error::BufferEmpty => "BufferEmptyError",
        Error::Response { .. } => "ResponseError",
        Error::Request { .. } => "RequestError",
    }
}

/// asserts a Value equals a tagged expected value (any integer variant matches {"int": n})
pub fn assert_value(actual: &Value, expected: &Json, ctx: &str) {
    let (tag, inner) = expected.as_object().unwrap().iter().next().unwrap();
    match (tag.as_str(), actual) {
        ("bool", Value::Bool(b)) => assert_eq!(*b, inner.as_bool().unwrap(), "{ctx}"),
        ("int", v) => {
            let want: i128 = inner
                .as_i64()
                .map(i128::from)
                .unwrap_or_else(|| inner.as_u64().unwrap().into());
            assert_eq!(v.as_i128(), Some(want), "{ctx}: {v:?}");
        }
        ("float", Value::Real(x)) => assert_eq!(f64::from(*x), inner.as_f64().unwrap(), "{ctx}"),
        ("float", Value::LReal(x)) => assert_eq!(*x, inner.as_f64().unwrap(), "{ctx}"),
        ("float_bits", Value::Real(x)) => {
            assert_eq!(to_hex(&x.to_le_bytes()), inner.as_str().unwrap(), "{ctx}")
        }
        ("float_bits", Value::LReal(x)) => {
            assert_eq!(to_hex(&x.to_le_bytes()), inner.as_str().unwrap(), "{ctx}")
        }
        ("str", Value::String(s)) => assert_eq!(s, inner.as_str().unwrap(), "{ctx}"),
        ("bytes", Value::Bytes(b)) => assert_eq!(to_hex(b), inner.as_str().unwrap(), "{ctx}"),
        ("list", Value::Array(items)) => {
            let want = inner.as_array().unwrap();
            assert_eq!(items.len(), want.len(), "{ctx}: length");
            for (i, (a, e)) in items.iter().zip(want).enumerate() {
                assert_value(a, e, &format!("{ctx}[{i}]"));
            }
        }
        ("dict", Value::Struct(map)) => {
            let want = inner.as_array().unwrap();
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            let want_keys: Vec<&str> = want.iter().map(|kv| kv[0].as_str().unwrap()).collect();
            assert_eq!(keys, want_keys, "{ctx}: keys");
            for kv in want {
                let key = kv[0].as_str().unwrap();
                assert_value(&map[key], &kv[1], &format!("{ctx}.{key}"));
            }
        }
        (tag, v) => panic!("{ctx}: expected {tag} {inner}, got {v:?}"),
    }
}

/// checks a result against {"ok": ..} / {"err": class}; `ok` compares a success
pub fn check<T: std::fmt::Debug>(
    result: Result<T, Error>,
    expected: &Json,
    ctx: &str,
    ok: impl FnOnce(&T, &Json),
) {
    match (&result, expected.get("ok"), expected.get("err")) {
        (Ok(value), Some(want), None) => ok(value, want),
        (Err(err), None, Some(want)) => {
            let want = want.as_str().unwrap();
            // Python raises ValueError/TypeError/KeyError from a few helpers; any Rust error stands for those
            if matches!(
                want,
                "DataError" | "BufferEmptyError" | "RequestError" | "ResponseError" | "CommError"
            ) {
                assert_eq!(class(err), want, "{ctx}: {err:?}");
            }
        }
        _ => panic!("{ctx}: got {result:?}, expected {expected}"),
    }
}

/// checks a byte result
pub fn check_bytes(result: Result<Vec<u8>, Error>, expected: &Json, ctx: &str) {
    check(result, expected, ctx, |bytes, want| {
        assert_eq!(to_hex(bytes), want["bytes"].as_str().unwrap(), "{ctx}")
    });
}

/// the scripted fake transport (common/fake.rs)
pub mod fake;
