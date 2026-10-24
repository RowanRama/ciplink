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
    // ---- ports of ciplink-tagserver's tests/test_config_values.py

    fn with_error(error: Option<TagError>, value: Option<Value>) -> TagResult {
        TagResult {
            tag: "x".into(),
            value,
            data_type: Some("DINT".into()),
            error,
        }
    }

    #[test]
    fn quality_from_error_kinds() {
        for (kind, expected) in [
            (None, "good"),
            (Some(ErrorKind::NotFound), "missing"),
            (Some(ErrorKind::Access), "missing"),
            (Some(ErrorKind::BadValue), "bad"),
            (Some(ErrorKind::Refused), "bad"),
            (Some(ErrorKind::TableChanged), "bad"),
            (Some(ErrorKind::Comm), "bad"),
            (Some(ErrorKind::Other), "bad"),
        ] {
            let r = with_error(kind.map(|k| TagError::new("boom", k)), Some(Value::DInt(5)));
            assert_eq!(to_value(&r).1, expected);
        }
    }

    #[test]
    fn quality_never_reads_message_text() {
        // a plain string error is kind other
        let r = with_error(
            Some(TagError::new("Tag doesn't exist - Foo", ErrorKind::Other)),
            Some(Value::DInt(5)),
        );
        assert_eq!(to_value(&r).1, "bad");
        let r = with_error(
            Some(TagError::new("General failure", ErrorKind::Other)),
            Some(Value::DInt(5)),
        );
        assert_eq!(
            to_value(&r).2,
            json!({"kind": "other", "message": "General failure"})
        );
    }

    #[test]
    fn to_value_and_merge() {
        let missing = with_error(
            Some(TagError::new("Tag doesn't exist - x", ErrorKind::NotFound)),
            Some(Value::DInt(5)),
        );
        let bad = with_error(
            Some(TagError::new("Service not supported", ErrorKind::Device)),
            Some(Value::DInt(5)),
        );
        let device = json!({"kind": "device", "message": "Service not supported"});
        assert_eq!(
            to_value(&with_error(None, Some(Value::DInt(5)))),
            (json!(5), "good", Json::Null)
        );
        assert_eq!(to_value(&bad), (Json::Null, "bad", device.clone()));
        let seven = merge(None, &with_error(None, Some(Value::DInt(7))), 10);
        assert_eq!(seven.to_json(), json!([7, "good", 10, null]));
        assert_eq!(
            merge(Some(&seven), &bad, 11).to_json(),
            json!([7, "bad", 11, device])
        );
        let first_bad = merge(None, &bad, 11);
        assert_eq!((first_bad.value, first_bad.quality), (Json::Null, "bad"));
        assert_eq!(
            merge(Some(&seven), &missing, 12).to_json(),
            json!([null, "missing", 12, {"kind": "not_found", "message": "Tag doesn't exist - x"}])
        );
    }

    #[test]
    fn jsonable_values() {
        let value = Value::Struct(
            [
                ("A", Value::Array(vec![Value::DInt(1), Value::DInt(2)])),
                ("B", Value::Bytes(vec![0x01, 0xff])),
                (
                    "C",
                    Value::Struct(
                        [("D".to_owned(), Value::LReal(f64::NAN))]
                            .into_iter()
                            .collect(),
                    ),
                ),
                ("E", Value::LReal(f64::NEG_INFINITY)),
                ("F", Value::Bool(true)),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
        );
        assert_eq!(
            jsonable(&value),
            json!({"A": [1, 2], "B": "01ff", "C": {"D": "NaN"}, "E": "-Infinity", "F": true})
        );
    }
}
