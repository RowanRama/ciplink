//! A fake driver for `--mock`: serves the tags of the PLC's `mock_tags` JSON file with simulated values.
//!
//! The file is the old flat `{name: TYPE}` or `{"types": {UDT: {member: TYPE}}, "tags": {name: TYPE}}`, TYPE
//! being `NAME` or `NAME[n]` (1-D). Values are functions of the path and the clock, shaped by the name; written
//! values hold. BYTE, WORD, DWORD and LWORD are bit strings as in ciplink: a list of BOOLs, least significant
//! first.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use ciplink::cip::TagResult;
use ciplink::{ErrorKind, TagError, Value};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value as Json, json};

use crate::config::PlcConfig;
use crate::plc::{Catalog, Factory, Kind, Node, Plc, TypeDef, atomic_size};

const STRING_LEN: usize = 82;
const STRING_SIZE: u64 = 88;

/// What the drivers of one PLC share: written values, `fail` (open, read and write fail like a lost connection),
/// a settable clock (seconds; None = real time) and the tag table version.
#[derive(Debug)]
pub struct MockState {
    /// Written values by canonical leaf path, lowercase.
    pub written: Mutex<HashMap<String, Value>>,
    /// Open, read and write fail like a lost connection.
    pub fail: AtomicBool,
    /// The clock in seconds since the epoch; None reads the real time.
    pub clock: Mutex<Option<f64>>,
    /// The tag table version.
    pub version: AtomicU64,
}

impl Default for MockState {
    fn default() -> Self {
        MockState {
            written: Mutex::default(),
            fail: AtomicBool::new(false),
            clock: Mutex::new(None),
            version: AtomicU64::new(1),
        }
    }
}

impl MockState {
    /// Sets the clock (seconds); None goes back to real time.
    pub fn set_clock(&self, now: Option<f64>) {
        *lock(&self.clock) = now;
    }

    fn now(&self) -> f64 {
        lock(&self.clock).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64())
        })
    }

    fn get(&self, path: &str) -> Option<Value> {
        lock(&self.written).get(&path.to_lowercase()).cloned()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The [`MockState`] of each PLC by name.
pub type MockStates = Arc<Mutex<HashMap<String, Arc<MockState>>>>;

/// A factory for the server; its drivers share a MockState per PLC name, kept in the returned map for tests.
pub fn factory() -> (Factory, MockStates) {
    let states = MockStates::default();
    let shared = Arc::clone(&states);
    let factory: Factory = Arc::new(move |cfg: &PlcConfig| {
        let state = Arc::clone(lock(&shared).entry(cfg.name.clone()).or_default());
        Ok(Box::new(MockPlc::new(cfg, state)?) as Box<dyn Plc>)
    });
    (factory, states)
}

// ------------------------------------------------------------------------------------------------ definitions

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Atomic,
    Struct,
    Str,
    /// A type the file does not define: listed, but reads and writes fail.
    Unknown,
}

/// A tag or member: its type and element count (0 for a scalar).
#[derive(Clone, Debug)]
struct Def {
    type_name: String,
    ty: Ty,
    count: u64,
}

#[derive(Debug)]
struct Udt {
    members: IndexMap<String, Def>,
    size: u64,
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    // invariant: the patterns are constants that compile
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

fn type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*([0-9]+)\s*\])?\s*$",
    )
}

fn part_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"^(?:(\.?)([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+(?:,[0-9]+)*)\]|\.([0-9]+)|\{([0-9]+)\})",
    )
}

fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"[A-Za-z_][A-Za-z0-9_]*")
}

fn parse_type(text: &Json) -> Result<(String, u64), String> {
    let bad = || format!("mock_tags: bad type {text}");
    let caps = type_re()
        .captures(text.as_str().ok_or_else(bad)?)
        .ok_or_else(bad)?;
    let count = match caps.get(2) {
        Some(n) => n.as_str().parse().map_err(|_| bad())?,
        None => 0,
    };
    Ok((caps[1].to_owned(), count))
}

/// The key of `map` that is `name` ignoring case.
fn key<'a, V>(map: &'a IndexMap<String, V>, name: &str) -> Option<&'a String> {
    if let Some((k, _)) = map.get_key_value(name) {
        return Some(k);
    }
    let lower = name.to_lowercase();
    map.keys().find(|k| k.to_lowercase() == lower)
}

/// Builds the UDTs the tags use, in the layout mock.py computes.
struct Loader<'a> {
    file_types: &'a Map<String, Json>,
    udts: IndexMap<String, Udt>,
}

impl Loader<'_> {
    fn def(&mut self, text: &Json, stack: &mut Vec<String>) -> Result<Def, String> {
        let (name, count) = parse_type(text)?;
        let upper = name.to_uppercase();
        let (type_name, ty) = if atomic_size(&upper).is_some() {
            (upper, Ty::Atomic)
        } else if upper == "STRING" {
            (upper, Ty::Str)
        } else if let Some(k) = self
            .file_types
            .keys()
            .find(|k| k.to_lowercase() == name.to_lowercase())
        {
            let k = k.clone();
            self.udt(&k, stack)?;
            (k, Ty::Struct)
        } else {
            (name, Ty::Unknown)
        };
        Ok(Def {
            type_name,
            ty,
            count,
        })
    }

    fn udt(&mut self, name: &str, stack: &mut Vec<String>) -> Result<(), String> {
        if self.udts.contains_key(name) {
            return Ok(());
        }
        if stack.iter().any(|s| s == name) {
            return Err(format!("mock_tags: {name} contains itself"));
        }
        let members = self.file_types[name]
            .as_object()
            .ok_or_else(|| format!("mock_tags: type {name} is not an object"))?;
        stack.push(name.to_owned());
        let mut defs = IndexMap::new();
        let mut offset = 0;
        for (member, text) in members {
            let def = self.def(text, stack)?;
            offset += self.size(&def) * def.count.max(1);
            defs.insert(member.clone(), def);
        }
        stack.pop();
        self.udts.insert(
            name.to_owned(),
            Udt {
                members: defs,
                size: (offset.div_ceil(4) * 4).max(4),
            },
        );
        Ok(())
    }

    fn size(&self, def: &Def) -> u64 {
        match def.ty {
            Ty::Atomic => atomic_size(&def.type_name).unwrap_or(4),
            Ty::Struct => self.udts.get(&def.type_name).map_or(4, |u| u.size),
            Ty::Str => STRING_SIZE,
            Ty::Unknown => 4,
        }
    }
}

// ------------------------------------------------------------------------------------------------ types

fn int_range(type_name: &str) -> Option<(i128, i128)> {
    Some(match type_name {
        "SINT" => (i8::MIN.into(), i8::MAX.into()),
        "INT" => (i16::MIN.into(), i16::MAX.into()),
        "DINT" => (i32::MIN.into(), i32::MAX.into()),
        "LINT" => (i64::MIN.into(), i64::MAX.into()),
        "USINT" => (0, u8::MAX.into()),
        "UINT" => (0, u16::MAX.into()),
        "UDINT" => (0, u32::MAX.into()),
        "ULINT" => (0, u64::MAX.into()),
        _ => return None,
    })
}

/// Bits of a bit string type.
fn bit_count(type_name: &str) -> Option<u32> {
    Some(match type_name {
        "BYTE" => 8,
        "WORD" => 16,
        "DWORD" => 32,
        "LWORD" => 64,
        _ => return None,
    })
}

fn is_float(type_name: &str) -> bool {
    matches!(type_name, "REAL" | "LREAL")
}

/// `v` wrapped into the range of an integer or bit string type, as that type's value.
fn wrap(type_name: &str, v: i128) -> Value {
    if let Some(n) = bit_count(type_name) {
        let word = v.rem_euclid(1i128 << n) as u64;
        return Value::Array((0..n).map(|i| Value::Bool(word >> i & 1 == 1)).collect());
    }
    let Some((low, high)) = int_range(type_name) else {
        return Value::LInt(v as i64);
    };
    let w = low + (v - low).rem_euclid(high - low + 1);
    // `w` is in the type's range, so the casts keep it
    match type_name {
        "SINT" => Value::SInt(w as i8),
        "INT" => Value::Int(w as i16),
        "DINT" => Value::DInt(w as i32),
        "LINT" => Value::LInt(w as i64),
        "USINT" => Value::USInt(w as u8),
        "UINT" => Value::UInt(w as u16),
        "UDINT" => Value::UDInt(w as u32),
        _ => Value::ULInt(w as u64),
    }
}

/// The bits of an integer (two's complement) or a bit string.
fn word_of(value: &Value) -> Option<u64> {
    match value {
        Value::Array(bits) => bits.iter().enumerate().try_fold(0u64, |word, (i, b)| {
            Some(if b.as_bool()? { word | 1 << i } else { word })
        }),
        _ => value.as_i128().map(|v| v as u64),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        _ => value.as_f64().is_some_and(|v| v != 0.0),
    }
}

fn error(message: impl Into<String>, kind: ErrorKind) -> TagError {
    TagError::new(message, kind)
}

fn invalid(type_name: &str, value: &Value) -> TagError {
    error(
        format!("Invalid value for {type_name} - {}", value.py_repr()),
        ErrorKind::BadValue,
    )
}

/// `value` as stored for a leaf of `type_name`, or a `bad_value` error if it does not fit.
fn check(type_name: &str, value: &Value) -> Result<Value, TagError> {
    let checked = if type_name == "BOOL" {
        value.as_bool().map(Value::Bool)
    } else if let Some((low, high)) = int_range(type_name) {
        value
            .as_i128()
            .filter(|v| (low..=high).contains(v))
            .map(|v| wrap(type_name, v))
    } else if let Some(n) = bit_count(type_name) {
        // as ciplink: exactly one BOOL (or 0/1) per bit
        match value {
            Value::Array(bits) if bits.len() != n as usize => {
                return Err(error(
                    format!("{type_name} needs exactly {n} values, got {}", bits.len()),
                    ErrorKind::BadValue,
                ));
            }
            Value::Array(_) => word_of(value).map(|w| wrap(type_name, w.into())),
            _ => None,
        }
    } else if is_float(type_name) {
        // a REAL refuses what does not fit a float32, as ciplink's packing does
        value
            .as_f64()
            .filter(|v| type_name == "LREAL" || !v.is_finite() || (*v as f32).is_finite())
            .map(Value::LReal)
    } else if type_name == "STRING" {
        match value {
            Value::String(s) if s.chars().count() <= STRING_LEN => Some(value.clone()),
            _ => None,
        }
    } else {
        None
    };
    checked.ok_or_else(|| invalid(type_name, value))
}

// ------------------------------------------------------------------------------------------------ the driver

/// The mock driver of one PLC.
pub struct MockPlc {
    tags: IndexMap<String, Def>,
    udts: IndexMap<String, Udt>,
    state: Arc<MockState>,
}

/// A request name resolved against the tags.
struct Resolved<'a> {
    /// The canonical path.
    path: String,
    def: &'a Def,
    /// A whole array (no index).
    array: bool,
    bit: Option<u64>,
    count: Option<u64>,
    /// (array path, start) of a range.
    run: (String, u64),
}

fn simulated(type_name: &str, value: f64) -> Value {
    if is_float(type_name) {
        Value::LReal((value * 1000.0).round() / 1000.0)
    } else {
        wrap(type_name, value.round_ties_even() as i128)
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                crc >> 1 ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn last_name(path: &str) -> &str {
    name_re().find_iter(path).last().map_or("", |m| m.as_str())
}

impl MockPlc {
    /// The driver of a PLC, serving its `mock_tags` file (no tags without one).
    pub fn new(cfg: &PlcConfig, state: Arc<MockState>) -> Result<Self, String> {
        let data = match &cfg.mock_tags {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("mock_tags {}: {e}", path.display()))?;
                serde_json::from_str(&text)
                    .map_err(|e| format!("mock_tags {}: {e}", path.display()))?
            }
            None => json!({}),
        };
        let Json::Object(data) = data else {
            return Err("mock_tags: not a JSON object".into());
        };
        let empty = Map::new();
        let (file_types, tags) = match data.get("tags") {
            Some(Json::Object(tags)) => (
                data.get("types")
                    .and_then(Json::as_object)
                    .unwrap_or(&empty),
                tags,
            ),
            _ => (&empty, &data),
        };
        let mut loader = Loader {
            file_types,
            udts: IndexMap::new(),
        };
        let mut defs = IndexMap::new();
        for (name, text) in tags {
            let def = loader.def(text, &mut Vec::new())?;
            defs.insert(name.clone(), def);
        }
        Ok(MockPlc {
            tags: defs,
            udts: loader.udts,
            state,
        })
    }

    /// The state this driver shares.
    pub fn state(&self) -> &Arc<MockState> {
        &self.state
    }

    fn resolve(&self, name: &str) -> Result<Resolved<'_>, TagError> {
        let missing = || error(format!("Tag doesn't exist - {name}"), ErrorKind::NotFound);
        let bad_name = || error(format!("Invalid tag name - {name}"), ErrorKind::BadRequest);
        if let Some(k) = key(&self.tags, name) {
            let def = &self.tags[k];
            return Ok(Resolved {
                path: k.clone(),
                def,
                array: def.count > 0,
                bit: None,
                count: None,
                run: (k.clone(), 0),
            });
        }
        let (prefix, rest) = if name.len() >= 8
            && name.is_char_boundary(8)
            && name[..8].eq_ignore_ascii_case("program:")
        {
            let dot = name.find('.').ok_or_else(missing)?;
            (&name[..=dot], &name[dot + 1..])
        } else {
            ("", name)
        };
        let mut parts = Vec::new();
        let mut pos = 0;
        while pos < rest.len() {
            let caps = part_re().captures(&rest[pos..]).ok_or_else(bad_name)?;
            if caps.get(2).is_some() && caps.get(1).is_some_and(|d| !d.is_empty()) != (pos > 0) {
                return Err(bad_name());
            }
            pos += caps[0].len();
            parts.push(caps);
        }
        let first = parts.first().and_then(|c| c.get(2)).ok_or_else(missing)?;
        let k = key(&self.tags, &format!("{prefix}{}", first.as_str())).ok_or_else(missing)?;
        let mut def = &self.tags[k];
        let mut path = k.clone();
        let (mut array, mut bit, mut count) = (def.count > 0, None, None);
        let mut run = (path.clone(), 0);
        let mut indexed = false;
        let number = |s: &str| s.parse::<u64>().unwrap_or(u64::MAX);
        for caps in &parts[1..] {
            if bit.is_some() || count.is_some() {
                return Err(bad_name());
            }
            if let Some(member) = caps.get(2) {
                if array || def.ty != Ty::Struct {
                    return Err(missing());
                }
                let udt = self.udts.get(&def.type_name).ok_or_else(missing)?;
                let m = key(&udt.members, member.as_str()).ok_or_else(missing)?;
                path = format!("{path}.{m}");
                def = &udt.members[m];
                array = def.count > 0;
                indexed = false;
            } else if let Some(index) = caps.get(3) {
                let index: Vec<u64> = index.as_str().split(',').map(number).collect();
                if !array || index.len() != 1 || index[0] >= def.count {
                    return Err(missing());
                }
                run = (path.clone(), index[0]);
                path = format!("{path}[{}]", index[0]);
                array = false;
                indexed = true;
            } else if let Some(b) = caps.get(4) {
                let size = int_range(&def.type_name)
                    .and(atomic_size(&def.type_name))
                    .or_else(|| bit_count(&def.type_name).map(|n| u64::from(n) / 8));
                let Some(size) = size.filter(|_| !array && def.ty == Ty::Atomic) else {
                    return Err(error(
                        format!("No bits in {} - {name}", def.type_name),
                        ErrorKind::BadRequest,
                    ));
                };
                let b = number(b.as_str());
                if b >= size * 8 {
                    return Err(missing());
                }
                bit = Some(b);
            } else if let Some(c) = caps.get(5) {
                let c = number(c.as_str());
                if !(array || indexed) || c < 1 {
                    return Err(error(
                        format!("Invalid element count - {name}"),
                        ErrorKind::BadRequest,
                    ));
                }
                if array {
                    run = (path.clone(), 0);
                }
                if run.1.saturating_add(c) > def.count {
                    return Err(missing());
                }
                count = Some(c);
            }
        }
        Ok(Resolved {
            path,
            def,
            array,
            bit,
            count,
            run,
        })
    }

    fn read_one(&self, name: &str, now: f64) -> TagResult {
        let result = (|| {
            let r = self.resolve(name)?;
            let type_name = r.def.type_name.as_str();
            if let Some(count) = r.count {
                let (array_path, start) = &r.run;
                let values = (*start..start + count)
                    .map(|i| self.value(&format!("{array_path}[{i}]"), r.def, false, now))
                    .collect::<Result<_, _>>()?;
                return Ok((Value::Array(values), format!("{type_name}[{count}]")));
            }
            if r.array {
                // an array without an index reads its first element
                return Ok((
                    self.value(&format!("{}[0]", r.path), r.def, false, now)?,
                    type_name.to_owned(),
                ));
            }
            let value = self.value(&r.path, r.def, false, now)?;
            if let Some(bit) = r.bit {
                let word = word_of(&value).unwrap_or(0);
                return Ok((Value::Bool(word >> bit & 1 == 1), "BOOL".to_owned()));
            }
            Ok((value, type_name.to_owned()))
        })();
        match result {
            Ok((value, data_type)) => TagResult {
                tag: name.to_owned(),
                value: Some(value),
                data_type: Some(data_type),
                error: None,
            },
            Err(e) => TagResult {
                tag: name.to_owned(),
                value: None,
                data_type: None,
                error: Some(e),
            },
        }
    }

    /// The value at `path`: a list for a whole array, members for a struct, else the simulated leaf.
    fn value(&self, path: &str, def: &Def, array: bool, now: f64) -> Result<Value, TagError> {
        if array {
            return (0..def.count)
                .map(|i| self.value(&format!("{path}[{i}]"), def, false, now))
                .collect::<Result<_, _>>()
                .map(Value::Array);
        }
        if def.ty == Ty::Struct {
            if let Some(udt) = self.udts.get(&def.type_name) {
                return udt
                    .members
                    .iter()
                    .map(|(m, sub)| {
                        Ok((
                            m.clone(),
                            self.value(&format!("{path}.{m}"), sub, sub.count > 0, now)?,
                        ))
                    })
                    .collect::<Result<_, _>>()
                    .map(Value::Struct);
            }
        }
        self.leaf(path, def, now)
    }

    /// A written value, else a deterministic function of the path and time, shaped by the member name.
    fn leaf(&self, path: &str, def: &Def, now: f64) -> Result<Value, TagError> {
        if let Some(written) = self.state.get(path) {
            return Ok(written);
        }
        let type_name = def.type_name.as_str();
        if !matches!(def.ty, Ty::Atomic | Ty::Str) {
            return Err(error(
                format!("mock does not simulate {type_name}"),
                ErrorKind::Other,
            ));
        }
        let seed = crc32(path.to_lowercase().as_bytes());
        let wave = (2.0 * std::f64::consts::PI * now / f64::from(10 + seed % 20)
            + f64::from(seed % 628) / 100.0)
            .sin();
        let member = last_name(path);
        let name = member.to_lowercase();
        let parent = &path[..path.rfind('.').map_or(0, |i| i + 1)];
        if def.ty == Ty::Str {
            return Ok(Value::String(format!(
                "{member} {}",
                ((now / 5.0).floor() as i64).rem_euclid(100)
            )));
        }
        if type_name == "BOOL" {
            return Ok(Value::Bool(
                !(name.ends_with("pb") || name == "running") && wave > 0.0,
            ));
        }
        let value = if name.ends_with("sp") || name.contains("setpoint") {
            f64::from(seed % 10 * 100)
        } else if name.contains("temp") {
            55.0 + 35.0 * wave
        } else if name.contains("level") {
            50.0 + 50.0 * wave
        } else if name.contains("speed") || name.contains("rpm") {
            self.follow(parent, member, now)?
                .unwrap_or(50.0 + 50.0 * wave)
        } else if name.contains("position") {
            (now * 25.0 + f64::from(seed)).rem_euclid(1000.0)
        } else if name.contains("count") {
            ((now.trunc() as i64).rem_euclid(100_000) + i64::from(seed % 1000)) as f64
        } else if (int_range(type_name).is_some() || bit_count(type_name).is_some())
            && ["word", "status", "flags", "bits"]
                .iter()
                .any(|w| name.contains(w))
        {
            // a few toggling bits
            (0..4u32)
                .map(|i| {
                    ((now / f64::from(2 + i)).trunc() as i64 + i64::from(seed >> i)).rem_euclid(2)
                        << i
                })
                .sum::<i64>() as f64
        } else {
            50.0 + 25.0 * wave
        };
        Ok(simulated(type_name, value))
    }

    /// Its setpoint `<member>SP` while the sibling `Running` is true, 0 while it is false; None if there are no
    /// such siblings.
    fn follow(&self, parent: &str, member: &str, now: f64) -> Result<Option<f64>, TagError> {
        let (Ok(sp), Ok(running)) = (
            self.resolve(&format!("{parent}{member}SP")),
            self.resolve(&format!("{parent}Running")),
        ) else {
            return Ok(None);
        };
        let bool_def = Def {
            type_name: "BOOL".into(),
            ty: Ty::Atomic,
            count: 0,
        };
        if !truthy(&self.leaf(&running.path, &bool_def, now)?) {
            return Ok(Some(0.0));
        }
        let target = self.leaf(&sp.path, sp.def, now)?.as_f64().unwrap_or(0.0);
        // a ripple under a typical deadband
        Ok(Some(if target != 0.0 {
            target + 0.2 * now.sin()
        } else {
            target
        }))
    }

    /// [(leaf path, value)] for writing `value` at `path`. As ciplink: an array written by name takes one value
    /// (element 0), an array member of a written struct takes all its elements, and a struct takes all its
    /// members.
    fn writes(
        &self,
        path: &str,
        def: &Def,
        array: bool,
        value: &Value,
        member: bool,
    ) -> Result<Vec<(String, Value)>, TagError> {
        if array {
            let length = def.count;
            let one = std::slice::from_ref(value);
            let values = match value {
                Value::Array(items) if member => {
                    if items.len() as u64 != length {
                        return Err(error(
                            format!("Expected {length} values - {}", value.py_repr()),
                            ErrorKind::BadValue,
                        ));
                    }
                    items.as_slice()
                }
                _ if member => {
                    return Err(error(
                        format!("Expected {length} values - {}", value.py_repr()),
                        ErrorKind::BadValue,
                    ));
                }
                // a bit string's value is itself a list
                Value::Array(items) if bit_count(&def.type_name).is_none() => {
                    if items.len() != 1 {
                        return Err(error(
                            "Too many values for requested elements, expected 1",
                            ErrorKind::BadValue,
                        ));
                    }
                    items.as_slice()
                }
                _ => one,
            };
            let mut out = Vec::new();
            for (i, v) in values.iter().enumerate() {
                out.extend(self.writes(&format!("{path}[{i}]"), def, false, v, false)?);
            }
            return Ok(out);
        }
        if def.ty == Ty::Struct {
            if let Some(udt) = self.udts.get(&def.type_name) {
                let Value::Struct(members) = value else {
                    return Err(invalid(&def.type_name, value));
                };
                let mut out = Vec::new();
                for (name, v) in members {
                    // member names are case-sensitive here
                    let Some(sub) = udt.members.get(name) else {
                        return Err(error(
                            format!("No member {name} in {}", def.type_name),
                            ErrorKind::BadValue,
                        ));
                    };
                    out.extend(self.writes(
                        &format!("{path}.{name}"),
                        sub,
                        sub.count > 0,
                        v,
                        true,
                    )?);
                }
                let missing: Vec<&str> = udt
                    .members
                    .keys()
                    .filter(|m| !members.contains_key(*m))
                    .map(String::as_str)
                    .collect();
                if !missing.is_empty() {
                    return Err(error(
                        format!(
                            "Missing members {} of {}",
                            missing.join(", "),
                            def.type_name
                        ),
                        ErrorKind::BadValue,
                    ));
                }
                return Ok(out);
            }
        }
        Ok(vec![(path.to_owned(), check(&def.type_name, value)?)])
    }

    fn write_one(
        &self,
        name: &str,
        value: &Value,
        now: f64,
    ) -> Result<(Vec<(String, Value)>, String), TagError> {
        let r = self.resolve(name)?;
        if let Some(bit) = r.bit {
            let current = self.value(&r.path, r.def, false, now)?;
            let word = word_of(&current).unwrap_or(0);
            let word = match check("BOOL", value)? {
                Value::Bool(true) => word | 1 << bit,
                _ => word & !(1 << bit),
            };
            let word = if bit_count(&r.def.type_name).is_some() {
                i128::from(word)
            } else {
                i128::from(word as i64) // back to signed for a signed type
            };
            return Ok((vec![(r.path, wrap(&r.def.type_name, word))], "BOOL".into()));
        }
        let writes = if let Some(count) = r.count {
            let items = match value {
                Value::Array(items) if items.len() as u64 == count => items,
                _ => {
                    return Err(error(
                        format!("Expected {count} values - {}", value.py_repr()),
                        ErrorKind::BadValue,
                    ));
                }
            };
            let (array_path, start) = &r.run;
            let mut out = Vec::new();
            for (i, v) in (*start..).zip(items) {
                out.extend(self.writes(&format!("{array_path}[{i}]"), r.def, false, v, false)?);
            }
            out
        } else {
            self.writes(&r.path, r.def, r.array, value, false)?
        };
        Ok((writes, r.def.type_name.clone()))
    }
}

fn node(def: &Def, member: bool, instance_id: Option<u32>, udts: &IndexMap<String, Udt>) -> Node {
    let (kind, structure_size) = match def.ty {
        Ty::Struct => (Kind::Struct, udts.get(&def.type_name).map(|u| u.size)),
        Ty::Str => (Kind::String, Some(STRING_SIZE)),
        Ty::Atomic | Ty::Unknown => (Kind::Atomic, None),
    };
    Node {
        type_name: def.type_name.clone(),
        kind,
        dims: if def.count > 0 {
            vec![def.count]
        } else {
            Vec::new()
        },
        member,
        instance_id,
        structure_size,
    }
}

impl Plc for MockPlc {
    fn open(&mut self) -> Result<(), String> {
        if self.state.fail.load(Ordering::SeqCst) {
            return Err("mock: connection refused".into());
        }
        Ok(())
    }

    fn close(&mut self) {}

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String> {
        if self.state.fail.load(Ordering::SeqCst) {
            return Err("mock: connection lost".into());
        }
        let now = self.state.now();
        Ok(tags.iter().map(|name| self.read_one(name, now)).collect())
    }

    fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String> {
        if self.state.fail.load(Ordering::SeqCst) {
            return Err("mock: connection lost".into());
        }
        let now = self.state.now();
        let (writes, data_type) = match self.write_one(tag, value, now) {
            Ok(ok) => ok,
            Err(e) => {
                return Ok(TagResult {
                    tag: tag.to_owned(),
                    value: None,
                    data_type: None,
                    error: Some(e),
                });
            }
        };
        for (leaf, leaf_value) in writes {
            let member = last_name(&leaf).to_lowercase();
            let pushed = leaf_value == Value::Bool(true)
                && (member.ends_with("startpb") || member.ends_with("stoppb"));
            lock(&self.state.written).insert(leaf.to_lowercase(), leaf_value);
            if pushed {
                let sibling = format!("{}Running", &leaf[..leaf.rfind('.').map_or(0, |i| i + 1)]);
                if let Ok(running) = self.resolve(&sibling) {
                    lock(&self.state.written).insert(
                        running.path.to_lowercase(),
                        Value::Bool(member.ends_with("startpb")),
                    );
                }
            }
        }
        Ok(TagResult {
            tag: tag.to_owned(),
            value: Some(value.clone()),
            data_type: Some(data_type),
            error: None,
        })
    }

    fn catalog(&mut self) -> Catalog {
        let tags = self
            .tags
            .iter()
            .enumerate()
            .map(|(i, (name, def))| {
                let id = u32::try_from(i + 1).ok();
                (name.clone(), node(def, false, id, &self.udts))
            })
            .collect();
        let types = self
            .udts
            .iter()
            .map(|(name, udt)| {
                let members = udt
                    .members
                    .iter()
                    .map(|(m, def)| (m.clone(), node(def, true, None, &self.udts)))
                    .collect();
                let t = TypeDef {
                    members,
                    public: udt.members.keys().cloned().collect(),
                    structure_size: udt.size,
                    aoi: None,
                    whole_readable: true,
                };
                (name.clone(), t)
            })
            .collect();
        Catalog::new(self.version(), tags, types)
    }

    fn version(&mut self) -> Json {
        json!(self.state.version.load(Ordering::SeqCst))
    }

    fn connection_size(&self) -> usize {
        4000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::from_json;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    fn bench_json() -> Json {
        json!({
            "types": {"BenchData": {"Running": "BOOL", "StartPB": "BOOL", "StopPB": "BOOL", "SpeedSP": "REAL",
                                    "Speed": "REAL", "Axis": "Axis", "StatusWord": "DINT", "Count": "DINT",
                                    "Message": "STRING", "Recipe": "Recipe"},
                      "Axis": {"Position": "REAL", "Velocity": "REAL"},
                      "Recipe": {"Name": "STRING", "Setpoints": "REAL[4]"},
                      "Tank": {"Level": "REAL", "Temp": "REAL", "Valve": "BOOL"}},
            "tags": {"Tank": "Tank[4]", "Trend": "REAL[16]", "Bench": "BenchData", "Program:Bench.Mode": "DINT",
                     "Small": "SINT", "Odd": "MyAOI"},
        })
    }

    fn mock_file(data: &Json) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ciplink-mock-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&path, data.to_string()).expect("write mock file");
        path
    }

    fn cfg(name: &str, path: Option<PathBuf>) -> PlcConfig {
        PlcConfig {
            name: name.into(),
            mock_tags: path,
            ..PlcConfig::default()
        }
    }

    fn mock(data: &Json) -> MockPlc {
        let plc =
            MockPlc::new(&cfg("PLC1", Some(mock_file(data))), Arc::default()).expect("mock driver");
        plc.state.set_clock(Some(1000.0));
        plc
    }

    fn read(plc: &mut dyn Plc, name: &str) -> TagResult {
        plc.read(&[name]).expect("connected").remove(0)
    }

    fn value(plc: &mut dyn Plc, name: &str) -> Value {
        let result = read(plc, name);
        assert!(result.error.is_none(), "{result:?}");
        result.value.expect("a value")
    }

    fn kind(result: &TagResult) -> Option<ErrorKind> {
        result.error.as_ref().map(|e| e.kind)
    }

    fn write(plc: &mut dyn Plc, name: &str, value: Json) -> TagResult {
        plc.write(name, &from_json(&value).expect("a value"))
            .expect("connected")
    }

    fn num(v: &Value) -> f64 {
        v.as_f64().expect("a number")
    }

    fn member<'a>(v: &'a Value, name: &str) -> &'a Value {
        match v {
            Value::Struct(m) => &m[name],
            _ => panic!("not a struct: {v:?}"),
        }
    }

    fn items(v: &Value) -> &[Value] {
        match v {
            Value::Array(items) => items,
            _ => panic!("not an array: {v:?}"),
        }
    }

    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn flat_file() {
        let mut plc = mock(
            &json!({"Speed": "REAL", "Run": "BOOL", "Count": "DINT", "Recipe": "UDT_R",
                                   "Line1.Level": "REAL"}),
        );
        let (mut speeds, mut runs) = (HashSet::new(), HashSet::new());
        for i in 0..40 {
            plc.state.set_clock(Some(f64::from(i) * 0.7));
            speeds.insert(num(&value(&mut plc, "Speed")).to_bits());
            runs.insert(value(&mut plc, "Run") == Value::Bool(true));
            assert!(matches!(value(&mut plc, "Count"), Value::DInt(_)));
            assert!((0.0..=100.0).contains(&num(&value(&mut plc, "Line1.Level"))));
        }
        assert!(speeds.len() > 10);
        assert_eq!(runs.len(), 2);
        let missing = read(&mut plc, "Nope");
        assert_eq!(kind(&missing), Some(ErrorKind::NotFound));
        assert!(
            missing
                .error
                .expect("error")
                .message
                .starts_with("Tag doesn't exist")
        );
        assert_eq!(kind(&read(&mut plc, "Recipe")), Some(ErrorKind::Other)); // a type the file does not define
        assert!(write(&mut plc, "Count", json!(7)).error.is_none());
        assert_eq!(value(&mut plc, "Count"), Value::DInt(7));
        let catalog = plc.catalog();
        assert_eq!(catalog.tags["Speed"].type_name, "REAL");
        assert!(catalog.types.is_empty());
    }

    #[test]
    fn flat_dotted_names_follow_their_siblings() {
        let mut plc =
            mock(&json!({"Line1.Speed": "REAL", "Line1.SpeedSP": "REAL", "Line1.Running": "BOOL"}));
        assert_eq!(num(&value(&mut plc, "Line1.Speed")), 0.0);
        assert!(write(&mut plc, "line1.speedsp", json!(300)).error.is_none());
        assert!(
            write(&mut plc, "Line1.Running", json!(true))
                .error
                .is_none()
        );
        assert!((num(&value(&mut plc, "Line1.Speed")) - 300.0).abs() <= 0.2);
        let catalog = plc.catalog();
        assert_eq!(
            catalog.info("line1.speed").map(|n| n.type_name.as_str()),
            Some("REAL")
        );
    }

    #[test]
    fn catalog_is_ciplink_shaped() {
        let mut plc = mock(&bench_json());
        let c = plc.catalog();
        let tank = &c.tags["Tank"];
        assert_eq!(
            (tank.kind, tank.dims.clone(), tank.type_name.as_str()),
            (Kind::Struct, vec![4], "Tank")
        );
        assert_eq!(
            (tank.structure_size, tank.instance_id, tank.member),
            (Some(12), Some(1), false)
        );
        assert_eq!(
            c.tags["Trend"],
            Node {
                type_name: "REAL".into(),
                kind: Kind::Atomic,
                dims: vec![16],
                member: false,
                instance_id: Some(2),
                structure_size: None,
            }
        );
        assert_eq!(c.types["Tank"].public, ["Level", "Temp", "Valve"]);
        assert_eq!(c.types["Tank"].structure_size, 12);
        assert_eq!(c.types["BenchData"].structure_size, 220);
        let setpoints = &c.types["Recipe"].members["Setpoints"];
        assert_eq!((setpoints.dims.clone(), setpoints.member), (vec![4], true));
        let message = &c.types["BenchData"].members["Message"];
        assert_eq!(
            (message.kind, message.structure_size),
            (Kind::String, Some(88))
        );
        assert!(!c.types.contains_key("STRING"));
        assert_eq!(c.tags["Program:Bench.Mode"].type_name, "DINT");
        assert_eq!(plc.connection_size(), 4000);
        assert_eq!(
            c.info("Tank[2].level").map(|n| n.type_name.as_str()),
            Some("REAL")
        );
        assert_eq!(
            c.info("bench.recipe.setpoints[1]").map(|n| n.dims.clone()),
            Some(vec![4])
        );
        assert_eq!(
            c.info("Program:Bench.Mode").map(|n| n.type_name.as_str()),
            Some("DINT")
        );
        for unknown in ["Nope", "Bench.Nope", "Bench.Count.3"] {
            assert!(c.info(unknown).is_none(), "{unknown}");
        }
        assert_eq!(c.version, json!(1));
        assert_eq!(plc.descriptions(&["Trend"]), Ok(vec![None]));
    }

    #[test]
    fn reads() {
        let mut b = mock(&bench_json());
        let whole = value(&mut b, "Bench");
        let axis = member(&whole, "Axis");
        assert_eq!(
            member(axis, "Position"),
            &value(&mut b, "Bench.Axis.Position")
        );
        assert_eq!(
            member(axis, "Velocity"),
            &value(&mut b, "bench.axis.velocity")
        );
        let setpoints = member(member(&whole, "Recipe"), "Setpoints");
        assert_eq!(setpoints, &value(&mut b, "Bench.Recipe.Setpoints[0]{4}"));
        assert_eq!(
            &items(setpoints)[2],
            &value(&mut b, "Bench.Recipe.Setpoints[2]")
        );
        assert!(matches!(member(&whole, "Message"), Value::String(_)));
        assert_eq!(member(&whole, "Message"), &value(&mut b, "Bench.Message"));
        let trend: Vec<Value> = (0..16)
            .map(|i| value(&mut b, &format!("Trend[{i}]")))
            .collect();
        assert_eq!(
            value(&mut b, "Trend[3]{5}"),
            Value::Array(trend[3..8].to_vec())
        );
        assert_eq!(value(&mut b, "Trend{16}"), Value::Array(trend.clone()));
        assert_eq!(
            read(&mut b, "Trend[3]{5}").data_type.as_deref(),
            Some("REAL[5]")
        );
        assert_eq!(value(&mut b, "Trend"), trend[0]); // no index: the first element
        let tanks = value(&mut b, "Tank{4}");
        for (i, t) in items(&tanks).iter().enumerate() {
            assert_eq!(
                member(t, "Level"),
                &value(&mut b, &format!("Tank[{i}].Level"))
            );
            assert!((0.0..=100.0).contains(&num(member(t, "Level"))));
            assert!((20.0..=90.0).contains(&num(member(t, "Temp"))));
        }
        let word = num(&value(&mut b, "Bench.StatusWord")) as i64;
        for i in 0..4 {
            assert_eq!(
                value(&mut b, &format!("Bench.StatusWord.{i}")),
                Value::Bool(word >> i & 1 == 1)
            );
        }
        assert_eq!(
            read(&mut b, "Bench.StatusWord.0").data_type.as_deref(),
            Some("BOOL")
        );
        assert!(matches!(
            value(&mut b, "Program:Bench.Mode"),
            Value::DInt(_)
        ));
        assert!(matches!(value(&mut b, "Small"), Value::SInt(_)));
        for (name, k) in [
            ("Tank[4].Level", ErrorKind::NotFound),
            ("Trend[14]{3}", ErrorKind::NotFound),
            ("Bench.Nope", ErrorKind::NotFound),
            ("Bench.Speed.1", ErrorKind::BadRequest),
            ("Bench.Count.32", ErrorKind::NotFound),
            ("Bench..X", ErrorKind::BadRequest),
            ("Bench.Axis{2}", ErrorKind::BadRequest),
            ("Odd", ErrorKind::Other),
        ] {
            assert_eq!(kind(&read(&mut b, name)), Some(k), "{name}");
        }
        let results = b.read(&["Trend[1]", "Nope"]).expect("connected");
        assert_eq!(
            results.iter().map(kind).collect::<Vec<_>>(),
            [None, Some(ErrorKind::NotFound)]
        );
    }

    #[test]
    fn values_follow_the_names_and_the_clock() {
        let mut b = mock(&bench_json());
        assert_eq!(value(&mut b, "Bench.Running"), Value::Bool(false));
        assert_eq!(num(&value(&mut b, "Bench.Speed")), 0.0);
        let (count, position) = (
            num(&value(&mut b, "Bench.Count")),
            num(&value(&mut b, "Bench.Axis.Position")),
        );
        b.state.set_clock(Some(1002.0));
        assert_eq!(num(&value(&mut b, "Bench.Count")), count + 2.0);
        assert!((num(&value(&mut b, "Bench.Axis.Position")) - (position + 50.0)).abs() < 1e-6);
        assert!(
            write(&mut b, "Bench.SpeedSP", json!(1200.0))
                .error
                .is_none()
        );
        assert!(write(&mut b, "Bench.StartPB", json!(true)).error.is_none());
        assert_eq!(value(&mut b, "Bench.Running"), Value::Bool(true));
        assert!((num(&value(&mut b, "Bench.Speed")) - 1200.0).abs() <= 0.2);
        assert!(write(&mut b, "Bench.StartPB", json!(false)).error.is_none());
        assert_eq!(value(&mut b, "Bench.Running"), Value::Bool(true));
        write(&mut b, "Bench.StopPB", json!(1));
        assert_eq!(value(&mut b, "Bench.Running"), Value::Bool(false));
        assert_eq!(num(&value(&mut b, "Bench.Speed")), 0.0);
        // deterministic: another driver of the same state at the same time reads the same
        let mut other =
            MockPlc::new(&cfg("PLC1", None), Arc::clone(&b.state)).expect("mock driver");
        assert_eq!(kind(&read(&mut other, "Nope")), Some(ErrorKind::NotFound));
        let temp = value(&mut b, "Tank[1].Temp");
        assert_eq!(value(&mut b, "tank[1].temp"), temp);
        assert!(matches!(temp, Value::LReal(v) if (v * 1000.0).round() / 1000.0 == v));
    }

    #[test]
    fn writes_are_type_checked() {
        let mut b = mock(&bench_json());
        for (name, bad) in [
            ("Bench.Running", json!("x")),
            ("Bench.Running", json!(2)),
            ("Bench.Count", json!(1.5)),
            ("Bench.Count", json!(true)),
            ("Small", json!(300)),
            ("Bench.SpeedSP", json!("a")),
            ("Bench.SpeedSP", json!(true)),
            ("Bench.Message", json!("x".repeat(83))),
            ("Bench.Message", json!(5)),
            ("Trend[0]{2}", json!([1.0])),
            ("Bench.Recipe", json!({"Nope": 1})),
            (
                "Bench.Recipe",
                json!({"Name": "ok", "Setpoints": [1.0, 2.0, 3.0, "x"]}),
            ),
            ("Bench.Axis", json!(3)),
            ("Odd", json!(1)),
            ("Bench.Recipe", json!({"Name": "ok"})),
            (
                "Bench.Recipe",
                json!({"Name": "ok", "Setpoints": [1.0, 2.0]}),
            ),
            ("Trend", json!([1.0, 2.0])),
            (
                "Bench.Recipe",
                json!({"name": "ok", "setpoints": [1.0, 2.0, 3.0, 4.0]}),
            ),
            ("Trend[0]", json!(1e40)),
        ] {
            // as ciplink: every member (case-sensitive), all of a member array, one value by name, a REAL that
            // fits a float32
            let result = write(&mut b, name, bad.clone());
            assert_eq!(kind(&result), Some(ErrorKind::BadValue), "{name} {bad}");
        }
        assert!(lock(&b.state.written).is_empty()); // nothing of a rejected write is kept
        let result = write(&mut b, "Bench.Running", json!(2));
        assert_eq!(
            result.error.expect("error").message,
            "Invalid value for BOOL - 2"
        );
        assert_eq!(
            kind(&write(&mut b, "Nope", json!(1))),
            Some(ErrorKind::NotFound)
        );
        assert!(write(&mut b, "Bench.Running", json!(1)).error.is_none());
        assert_eq!(value(&mut b, "Bench.Running"), Value::Bool(true));
        assert!(
            write(&mut b, "Bench.Message", json!("x".repeat(82)))
                .error
                .is_none()
        );
        assert_eq!(
            value(&mut b, "Bench.Message"),
            Value::String("x".repeat(82))
        );
        assert!(write(&mut b, "Small", json!(-5)).error.is_none());
        assert_eq!(value(&mut b, "Small"), Value::SInt(-5));
        let recipe = json!({"Name": "Brass", "Setpoints": [1, 2.5, 3, 4]});
        assert!(write(&mut b, "Bench.Recipe", recipe).error.is_none());
        assert_eq!(
            member(&value(&mut b, "Bench.Recipe"), "Name"),
            &Value::String("Brass".into())
        );
        assert_eq!(
            value(&mut b, "Bench.Recipe.Setpoints[0]{2}"),
            Value::Array(vec![Value::LReal(1.0), Value::LReal(2.5)])
        );
        assert!(
            write(&mut b, "Trend[2]{3}", json!([7.0, 8.0, 9.0]))
                .error
                .is_none()
        );
        assert_eq!(
            items(&value(&mut b, "Trend[1]{4}"))[1..],
            [Value::LReal(7.0), Value::LReal(8.0), Value::LReal(9.0)]
        );
        let ok = write(&mut b, "Trend[2]", json!(1));
        assert_eq!(
            (ok.data_type.as_deref(), ok.value),
            (Some("REAL"), Some(Value::LInt(1)))
        );
    }

    #[test]
    fn bit_writes_read_modify_write() {
        let mut b = mock(&bench_json());
        write(&mut b, "Bench.StatusWord", json!(0b1000));
        assert!(
            write(&mut b, "Bench.StatusWord.1", json!(true))
                .error
                .is_none()
        );
        assert!(
            write(&mut b, "Bench.StatusWord.31", json!(1))
                .error
                .is_none()
        );
        assert_eq!(
            value(&mut b, "Bench.StatusWord"),
            Value::DInt(0b1010 + i32::MIN)
        );
        assert!(
            write(&mut b, "Bench.StatusWord.3", json!(false))
                .error
                .is_none()
        );
        assert_eq!(
            value(&mut b, "Bench.StatusWord"),
            Value::DInt(0b10 + i32::MIN)
        );
        assert_eq!(
            kind(&write(&mut b, "Bench.StatusWord.2", json!(5))),
            Some(ErrorKind::BadValue)
        );
    }

    fn bits(word: u64, n: u32) -> Json {
        json!((0..n).map(|i| word >> i & 1 == 1).collect::<Vec<_>>())
    }

    #[test]
    fn bit_strings_are_lists_of_bools() {
        let mut plc = mock(
            &json!({"types": {"Drive": {"Flags": "DWORD", "Mask": "WORD"}},
                                   "tags": {"StatusBits": "DWORD", "B": "BYTE", "L": "LWORD", "D": "Drive"}}),
        );
        let c = plc.catalog();
        assert_eq!(c.types["Drive"].structure_size, 8);
        let status = read(&mut plc, "StatusBits");
        assert_eq!(status.data_type.as_deref(), Some("DWORD"));
        let status = status.value.expect("a value");
        assert_eq!(items(&status).len(), 32);
        assert!(items(&status)[4..].iter().all(|b| *b == Value::Bool(false))); // a few toggling bits
        for (i, bit) in items(&status)[..4].iter().enumerate() {
            assert_eq!(&value(&mut plc, &format!("StatusBits.{i}")), bit);
        }
        assert_eq!(items(&value(&mut plc, "B")).len(), 8);
        assert_eq!(items(&value(&mut plc, "L")).len(), 64);
        assert_eq!(items(&value(&mut plc, "D.Mask")).len(), 16);

        assert!(write(&mut plc, "D.Flags", bits(0b101, 32)).error.is_none());
        assert_eq!(
            value(&mut plc, "D.Flags"),
            from_json(&bits(0b101, 32)).expect("bits")
        );
        assert!(write(&mut plc, "D.Flags.31", json!(true)).error.is_none());
        assert!(write(&mut plc, "D.Flags.0", json!(0)).error.is_none());
        assert_eq!(
            value(&mut plc, "D.Flags"),
            from_json(&bits(0b100 | 1 << 31, 32)).expect("bits")
        );
        assert_eq!(value(&mut plc, "D.Flags.2"), Value::Bool(true));
        assert!(
            write(
                &mut plc,
                "D",
                json!({"Flags": bits(1, 32), "Mask": bits(2, 16)})
            )
            .error
            .is_none()
        );
        assert!(write(&mut plc, "L.63", json!(true)).error.is_none());
        assert_eq!(items(&value(&mut plc, "L"))[63], Value::Bool(true));

        let short = write(&mut plc, "B", bits(1, 7));
        assert_eq!(kind(&short), Some(ErrorKind::BadValue));
        assert_eq!(
            short.error.expect("error").message,
            "BYTE needs exactly 8 values, got 7"
        );
        assert_eq!(
            kind(&write(&mut plc, "B", json!(3))),
            Some(ErrorKind::BadValue)
        ); // not an integer
        let mut odd = vec![json!(true); 8];
        odd[3] = json!(2);
        assert_eq!(
            kind(&write(&mut plc, "B", json!(odd))),
            Some(ErrorKind::BadValue)
        );
        assert_eq!(
            kind(&read(&mut plc, "D.Mask.16")),
            Some(ErrorKind::NotFound)
        );
        assert_eq!(kind(&read(&mut plc, "B.8")), Some(ErrorKind::NotFound));
    }

    #[test]
    fn factory_shares_state_and_simulates_disconnects() {
        let path = mock_file(&bench_json());
        let (factory, states) = factory();
        let mut one = factory(&cfg("PLC1", Some(path.clone()))).expect("driver");
        let mut two = factory(&cfg("PLC1", Some(path.clone()))).expect("driver");
        let mut other = factory(&cfg("PLC2", Some(path))).expect("driver");
        write(one.as_mut(), "Bench.Count", json!(5));
        assert_eq!(value(two.as_mut(), "Bench.Count"), Value::DInt(5));
        assert_ne!(value(other.as_mut(), "Bench.Count"), Value::DInt(5));
        let plc1 = Arc::clone(&lock(&states)["PLC1"]);
        plc1.fail.store(true, Ordering::SeqCst);
        assert!(two.open().is_err());
        assert!(two.read(&["Bench.Count"]).is_err());
        assert!(two.write("Bench.Count", &Value::LInt(1)).is_err());
        assert!(other.open().is_ok());
        assert_eq!(read(other.as_mut(), "Bench.Count").error, None);
        plc1.fail.store(false, Ordering::SeqCst);
        assert!(two.open().is_ok());
        assert_eq!(value(two.as_mut(), "Bench.Count"), Value::DInt(5));
        plc1.version.store(7, Ordering::SeqCst);
        assert_eq!(two.version(), json!(7));
    }

    #[test]
    fn bad_files_fail_to_load() {
        let recursive = json!({"types": {"U": {"Me": "U"}}, "tags": {"A": "U"}});
        for data in [json!([1]), json!({"tags": {"A": "REAL[x]"}}), recursive] {
            assert!(
                MockPlc::new(&cfg("P", Some(mock_file(&data))), Arc::default()).is_err(),
                "{data}"
            );
        }
        assert!(
            MockPlc::new(
                &cfg("P", Some(PathBuf::from("no/such/file.json"))),
                Arc::default()
            )
            .is_err()
        );
    }
}
