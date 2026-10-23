//! Turns driver results into JSON-ready cache entries, and JSON write values into driver values.

use ciplink::cip::TagResult;
use ciplink::{ErrorKind, Value};
use serde_json::{Map, Number, Value as Json, json};

/// Milliseconds since the epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// A cache entry, sent as `[value, quality, t, error]`.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// The value, null unless good (or bad/stale with a kept value).
    pub value: Json,
    /// `good`, `missing`, `bad` or `stale`.
    pub quality: &'static str,
    /// Milliseconds since the epoch of the read.
    pub t: i64,
    /// Null when good, else `{"kind", "message"}`.
    pub error: Json,
}

impl Entry {
    /// The entry as the protocol sends it.
    pub fn to_json(&self) -> Json {
        json!([self.value, self.quality, self.t, self.error])
    }

    /// What decides whether a client is told: value, quality and error, not the time.
    pub fn same(&self, other: &Entry) -> bool {
        self.value == other.value && self.quality == other.quality && self.error == other.error
    }
}

/// good, missing (no such tag or not accessible) or bad, from an error kind.
pub fn quality(kind: Option<ErrorKind>) -> &'static str {
    match kind {
        None => "good",
        Some(ErrorKind::NotFound | ErrorKind::Access) => "missing",
        Some(_) => "bad",
    }
}

/// Objects for structs, lists for arrays, bytes as hex, non-finite floats as strings.
pub fn jsonable(value: &Value) -> Json {
    match value {
        Value::Bool(b) => Json::Bool(*b),
        Value::SInt(v) => json!(v),
        Value::Int(v) => json!(v),
        Value::DInt(v) => json!(v),
        Value::LInt(v) => json!(v),
        Value::USInt(v) => json!(v),
        Value::UInt(v) => json!(v),
        Value::UDInt(v) => json!(v),
        Value::ULInt(v) => json!(v),
        Value::Real(v) => float(f64::from(*v)),
        Value::LReal(v) => float(*v),
        Value::String(s) => Json::String(s.clone()),
        Value::Bytes(b) => Json::String(b.iter().map(|x| format!("{x:02x}")).collect()),
        Value::Array(items) => Json::Array(items.iter().map(jsonable).collect()),
        Value::Struct(members) => Json::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), jsonable(v)))
                .collect(),
        ),
    }
}

fn float(v: f64) -> Json {
    Number::from_f64(v).map_or_else(
        || {
            Json::String(
                if v.is_nan() {
                    "NaN"
                } else if v > 0.0 {
                    "Infinity"
                } else {
                    "-Infinity"
                }
                .into(),
            )
        },
        Json::Number,
    )
}

/// A JSON write value as a driver value: integers stay integers, other numbers are LREAL; the driver checks
/// it against the tag's type. None for null.
pub fn from_json(value: &Json) -> Option<Value> {
    Some(match value {
        Json::Null => return None,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::LInt(i)
            } else if let Some(u) = n.as_u64() {
                Value::ULInt(u)
            } else {
                Value::LReal(n.as_f64()?)
            }
        }
        Json::String(s) => Value::String(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(from_json).collect::<Option<_>>()?),
        Json::Object(members) => Value::Struct(
            members
                .iter()
                .map(|(k, v)| Some((k.clone(), from_json(v)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

/// (value, quality, error) of a driver result; the value is null unless the read succeeded.
pub fn to_value(result: &TagResult) -> (Json, &'static str, Json) {
    let kind = result.error.as_ref().map(|e| e.kind);
    let q = quality(kind);
    let value = match (&result.value, q) {
        (Some(v), "good") => jsonable(v),
        _ => Json::Null,
    };
    let error = match &result.error {
        None => Json::Null,
        Some(e) => {
            let mut m = Map::new();
            m.insert("kind".into(), json!(e.kind.as_str()));
            m.insert("message".into(), json!(e.message));
            Json::Object(m)
        }
    };
    (value, q, error)
}

/// The cache entry of a read result; `bad` keeps the value of `old`, so a screen shows the last value marked bad.
pub fn merge(old: Option<&Entry>, result: &TagResult, t: i64) -> Entry {
    let (mut value, quality, error) = to_value(result);
    if quality == "bad" {
        if let Some(old) = old {
            value = old.value.clone();
        }
    }
    Entry {
        value,
        quality,
        t,
        error,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ciplink::TagError;

    fn result(value: Option<Value>, kind: Option<ErrorKind>) -> TagResult {
        TagResult {
            tag: "T".into(),
            value,
            data_type: None,
            error: kind.map(|k| TagError::new("boom", k)),
        }
    }

    #[test]
    fn json_forms() {
        assert_eq!(jsonable(&Value::Real(3.25)), json!(3.25));
        assert_eq!(jsonable(&Value::LReal(f64::NAN)), json!("NaN"));
        assert_eq!(
            jsonable(&Value::Real(f32::NEG_INFINITY)),
            json!("-Infinity")
        );
        assert_eq!(jsonable(&Value::Bytes(vec![0, 0xab])), json!("00ab"));
        assert_eq!(jsonable(&Value::ULInt(u64::MAX)), json!(u64::MAX));
    }

    #[test]
    fn write_values() {
        assert_eq!(from_json(&json!(5)), Some(Value::LInt(5)));
        assert_eq!(from_json(&json!(1.5)), Some(Value::LReal(1.5)));
        assert_eq!(
            from_json(&json!([true])),
            Some(Value::Array(vec![Value::Bool(true)]))
        );
        assert_eq!(from_json(&Json::Null), None);
    }

    #[test]
    fn quality_and_bad_keeps_the_last_value() {
        let good = merge(None, &result(Some(Value::DInt(4)), None), 1);
        assert_eq!(good.to_json(), json!([4, "good", 1, null]));
        let bad = merge(Some(&good), &result(None, Some(ErrorKind::Comm)), 2);
        assert_eq!(
            bad.to_json(),
            json!([4, "bad", 2, {"kind": "comm", "message": "boom"}])
        );
        let missing = merge(Some(&good), &result(None, Some(ErrorKind::NotFound)), 3);
        assert_eq!(missing.value, Json::Null);
        assert_eq!(missing.quality, "missing");
    }
}
