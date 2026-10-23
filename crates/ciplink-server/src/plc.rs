//! The PLC side of the server: the driver calls it makes ([`Plc`], a real controller or the mock) and the
//! controller structure it serves ([`Catalog`]).

use std::collections::HashMap;

use ciplink::Value;
use ciplink::cip::TagResult;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::metadata::TextEncoding;
use ciplink::logix::types::TypeRef;
use indexmap::IndexMap;
use serde_json::{Map, Value as Json, json};

use crate::config::PlcConfig;

/// The driver calls the server makes. `Err` is a lost connection (the worker reconnects); a tag that failed
/// is its result's error.
pub trait Plc: Send {
    /// Connects (and uploads the tag definitions).
    fn open(&mut self) -> Result<(), String>;
    /// Disconnects; errors are ignored.
    fn close(&mut self);
    /// Reads tags in one call, one result per tag in order.
    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String>;
    /// Writes one tag; a value that doesn't fit is the result's `bad_value` error, nothing sent.
    fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String>;
    /// The controller structure, after a connect and after the tag table version changed.
    fn catalog(&mut self) -> Catalog;
    /// The tag table version (null when unknown); it changes after an online edit or a download.
    fn version(&mut self) -> Json;
    /// Request and reply bytes per packet.
    fn connection_size(&self) -> usize;
    /// The controller descriptions of tags, None for each the controller has none of (or can't tell).
    fn descriptions(&mut self, tags: &[&str]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; tags.len()])
    }
}

/// Makes the (not yet opened) driver of a PLC.
pub type Factory = std::sync::Arc<dyn Fn(&PlcConfig) -> Result<Box<dyn Plc>, String> + Send + Sync>;

/// What kind of value a tag or member holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An atomic type (BOOL, DINT, REAL, DWORD, ...).
    Atomic,
    /// A structure: UDT, AOI or predefined type.
    Struct,
    /// A string type (a structure the driver reads as a string).
    String,
}

/// A tag or a structure member.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    /// The controller's type name: `DINT`, a UDT name, `DWORD` for a BOOL array; empty when unknown.
    pub type_name: String,
    /// Atomic, structure or string.
    pub kind: Kind,
    /// Array dims: a tag's dimensions (a BOOL array tag counts BOOLs), a member's `[array]` (a BOOL array member
    /// counts 32-bit words); empty for a scalar.
    pub dims: Vec<u64>,
    /// True for a structure member.
    pub member: bool,
    /// The symbol instance ID of a tag.
    pub instance_id: Option<u32>,
    /// Bytes of a value of a structure or string type.
    pub structure_size: Option<u64>,
}

impl Node {
    /// A BOOL array: a DWORD array.
    pub fn bool_array(&self) -> bool {
        self.type_name == "DWORD" && !self.dims.is_empty()
    }

    /// The type as clients see it: `BOOL` for a BOOL array, `STRING` for any string type.
    pub fn client_type(&self) -> &str {
        if self.kind == Kind::String {
            "STRING"
        } else if self.bool_array() {
            "BOOL"
        } else {
            &self.type_name
        }
    }

    /// The dims as clients see them: a BOOL array member's words as BOOLs.
    pub fn client_dims(&self) -> Vec<u64> {
        let mut dims = self.dims.clone();
        if self.member && self.bool_array() {
            if let Some(last) = dims.last_mut() {
                *last *= 32;
            }
        }
        dims
    }
}

/// What an AOI probe found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Aoi {
    /// A whole instance can be read.
    pub whole_read: bool,
    /// Members that can be read from outside, in template order.
    pub readable: Vec<String>,
}

/// A structure type.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TypeDef {
    /// Every member, private ones included.
    pub members: IndexMap<String, Node>,
    /// The members clients see, in template order.
    pub public: Vec<String>,
    /// Bytes of a value.
    pub structure_size: u64,
    /// For an AOI, what its probe found.
    pub aoi: Option<Aoi>,
    /// False if this type, or a structure inside it, is an AOI the controller refuses to read whole.
    pub whole_readable: bool,
}

/// The controller structure: tags and structure types (string types left out).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Catalog {
    /// The tag table version.
    pub version: Json,
    /// Tags by name, in upload order.
    pub tags: IndexMap<String, Node>,
    /// Structure types by name.
    pub types: IndexMap<String, TypeDef>,
    index: HashMap<String, String>,
}

/// Bytes of an atomic type, None when unknown.
pub fn atomic_size(type_name: &str) -> Option<u64> {
    Some(match type_name {
        "BOOL" | "SINT" | "USINT" | "BYTE" => 1,
        "INT" | "UINT" | "WORD" => 2,
        "DINT" | "UDINT" | "DWORD" | "REAL" => 4,
        "LINT" | "ULINT" | "LWORD" | "LREAL" => 8,
        _ => return None,
    })
}

impl Catalog {
    /// A catalog of these tags and types; computes the lookup index and which types read whole.
    pub fn new(
        version: Json,
        tags: IndexMap<String, Node>,
        mut types: IndexMap<String, TypeDef>,
    ) -> Self {
        let mut memo = HashMap::new();
        let names: Vec<String> = types.keys().cloned().collect();
        for name in &names {
            whole_readable(name, &types, &mut memo);
        }
        for (name, t) in &mut types {
            t.whole_readable = memo.get(name).copied().unwrap_or(true);
        }
        let index = tags.keys().map(|k| (k.to_lowercase(), k.clone())).collect();
        Catalog {
            version,
            tags,
            types,
            index,
        }
    }

    /// A tag by name, ignoring case.
    pub fn tag(&self, name: &str) -> Option<&Node> {
        self.tags
            .get(name)
            .or_else(|| self.tags.get(self.index.get(&name.to_lowercase())?))
    }

    /// A structure type by name.
    pub fn type_def(&self, name: &str) -> Option<&TypeDef> {
        self.types.get(name)
    }

    /// The definition of a tag or member path, indexes and element counts ignored (as ciplink's
    /// `get_tag_info`); None for unknown names and bits.
    pub fn info(&self, name: &str) -> Option<&Node> {
        if let Some(node) = self.tag(name) {
            return Some(node); // a flat mock file may list dotted names
        }
        let (prefix, rest) = match name.find('.') {
            Some(dot)
                if name.len() >= 8
                    && name.is_char_boundary(8)
                    && name[..8].eq_ignore_ascii_case("program:") =>
            {
                (&name[..=dot], &name[dot + 1..])
            }
            _ => ("", name),
        };
        let stripped = strip(rest);
        let mut attrs = stripped.split('.');
        let base = attrs.next()?;
        let mut node = self.tag(&format!("{prefix}{base}"))?;
        for attr in attrs {
            let t = self.types.get(&node.type_name)?;
            node = t.members.get(attr).or_else(|| {
                t.members
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(attr))
                    .map(|(_, v)| v)
            })?;
        }
        Some(node)
    }

    /// The structure size of a struct node that can be read whole, else None.
    pub fn struct_size(&self, node: &Node) -> Option<u64> {
        if node.kind != Kind::Struct {
            return None;
        }
        let t = self.types.get(&node.type_name)?;
        t.whole_readable.then_some(t.structure_size)
    }

    /// `GET /tags` `tags`: name, type, dims of arrays and, for AOIs, the readable members.
    pub fn tag_list(&self) -> Vec<Json> {
        self.tags
            .iter()
            .map(|(name, node)| {
                let mut entry = Map::new();
                entry.insert("name".into(), json!(name));
                entry.insert("type".into(), json!(node.client_type()));
                if !node.dims.is_empty() {
                    entry.insert("dims".into(), json!(node.client_dims()));
                }
                if node.kind == Kind::Struct {
                    if let Some(aoi) = self.types.get(&node.type_name).and_then(|t| t.aoi.as_ref())
                    {
                        entry.insert("aoi_readable".into(), json!(aoi.readable));
                    }
                }
                Json::Object(entry)
            })
            .collect()
    }

    /// `GET /tags` `types`: UDT and AOI name -> `{"members": {m: {type, dims?}}, "aoi"?: true}`; private members
    /// hidden.
    pub fn type_map(&self) -> Map<String, Json> {
        self.types
            .iter()
            .map(|(name, t)| {
                let names = t.aoi.as_ref().map_or(&t.public, |a| &a.readable);
                let members: Map<String, Json> = names
                    .iter()
                    .map(|m| {
                        let mut member = Map::new();
                        match t.members.get(m) {
                            Some(node) => {
                                member.insert("type".into(), json!(node.client_type()));
                                if !node.dims.is_empty() {
                                    member.insert("dims".into(), json!(node.client_dims()));
                                }
                            }
                            None => {
                                member.insert("type".into(), json!(""));
                            }
                        }
                        (m.clone(), Json::Object(member))
                    })
                    .collect();
                let mut entry = Map::new();
                entry.insert("members".into(), Json::Object(members));
                if t.aoi.is_some() {
                    entry.insert("aoi".into(), json!(true));
                }
                (name.clone(), Json::Object(entry))
            })
            .collect()
    }
}

fn whole_readable(
    name: &str,
    types: &IndexMap<String, TypeDef>,
    memo: &mut HashMap<String, bool>,
) -> bool {
    if let Some(ok) = memo.get(name) {
        return *ok;
    }
    memo.insert(name.to_owned(), true); // guards recursive definitions
    let Some(t) = types.get(name) else {
        return true;
    };
    let mut ok = !t.aoi.as_ref().is_some_and(|a| !a.whole_read);
    for member in t.members.values() {
        if ok && member.kind == Kind::Struct {
            ok = whole_readable(&member.type_name, types, memo);
        }
    }
    memo.insert(name.to_owned(), ok);
    ok
}

/// The path without `[...]` indexes and `{n}` element counts.
fn strip(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut skip = None;
    for c in path.chars() {
        match (skip, c) {
            (None, '[') => skip = Some(']'),
            (None, '{') => skip = Some('}'),
            (Some(end), c) if c == end => skip = None,
            (Some(_), _) => {}
            (None, c) => out.push(c),
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ real PLCs

/// A real controller through ciplink's [`LogixDriver`].
pub struct LogixPlc {
    driver: LogixDriver,
}

impl LogixPlc {
    /// The driver of a configured PLC, not yet opened.
    pub fn new(cfg: &PlcConfig) -> Result<Self, String> {
        let mut options = LogixOptions::default();
        if let Some(cache) = &cfg.tag_cache_file {
            if let Some(dir) = cache.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            options.tag_cache_file = Some(cache.clone());
        }
        let driver = LogixDriver::new(&cfg.path, options).map_err(|e| e.to_string())?;
        Ok(LogixPlc { driver })
    }

    /// The factory of real drivers.
    pub fn factory() -> Factory {
        std::sync::Arc::new(|cfg: &PlcConfig| Ok(Box::new(LogixPlc::new(cfg)?) as Box<dyn Plc>))
    }
}

fn node_of(data_type: &TypeRef, dims: Vec<u64>, member: bool, instance_id: Option<u32>) -> Node {
    let (kind, structure_size) = match data_type {
        TypeRef::Atomic(_) => (Kind::Atomic, None),
        TypeRef::Struct(dt) => (
            if dt.string.is_some() {
                Kind::String
            } else {
                Kind::Struct
            },
            Some(u64::from(dt.template.structure_size)),
        ),
    };
    Node {
        type_name: data_type.name().unwrap_or_default().to_owned(),
        kind,
        dims,
        member,
        instance_id,
        structure_size,
    }
}

impl Plc for LogixPlc {
    fn open(&mut self) -> Result<(), String> {
        self.driver.open().map(|_| ()).map_err(|e| e.to_string())
    }

    fn close(&mut self) {
        let _ = self.driver.close();
    }

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String> {
        self.driver.read(tags).map_err(|e| e.to_string())
    }

    fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String> {
        let mut results = self
            .driver
            .write(&[(tag, value.clone())])
            .map_err(|e| e.to_string())?;
        results.pop().ok_or_else(|| "no write result".to_owned())
    }

    fn catalog(&mut self) -> Catalog {
        let defs = self.driver.definitions();
        let probes: HashMap<String, Aoi> = defs
            .probes
            .iter()
            .filter_map(|(dt, probe)| {
                Some((
                    dt.name.clone()?,
                    Aoi {
                        whole_read: probe.whole_read,
                        readable: probe.readable.clone(),
                    },
                ))
            })
            .collect();
        let tags = defs
            .tags
            .iter()
            .map(|(name, t)| {
                let dims = t.dimensions[..usize::from(t.dim.min(3))]
                    .iter()
                    .map(|&d| u64::from(d))
                    .collect();
                (
                    name.clone(),
                    node_of(&t.data_type, dims, false, Some(t.instance_id)),
                )
            })
            .collect();
        let mut types = IndexMap::new();
        for (name, dt) in &defs.data_types {
            let Some(name) = name else { continue };
            if dt.string.is_some() {
                continue;
            }
            let members = dt
                .internal_tags
                .iter()
                .map(|(m, info)| {
                    let dims = info
                        .array
                        .filter(|&a| a > 0)
                        .map(|a| vec![u64::from(a)])
                        .unwrap_or_default();
                    (m.clone(), node_of(&info.data_type, dims, true, None))
                })
                .collect();
            types.insert(
                name.clone(),
                TypeDef {
                    members,
                    public: dt.attributes.clone(),
                    structure_size: u64::from(dt.template.structure_size),
                    aoi: probes.get(name).cloned(),
                    whole_readable: true,
                },
            );
        }
        Catalog::new(self.version(), tags, types)
    }

    fn version(&mut self) -> Json {
        self.driver
            .tag_table_version()
            .map_or(Json::Null, |v| json!([v.0, v.1, v.2, v.3, v.4]))
    }

    fn connection_size(&self) -> usize {
        usize::from(self.driver.connection_size())
    }

    fn descriptions(&mut self, tags: &[&str]) -> Result<Vec<Option<String>>, String> {
        let results = self
            .driver
            .get_tag_descriptions(tags, 0x007F, TextEncoding::Utf8)
            .map_err(|e| e.to_string())?;
        Ok(results
            .into_iter()
            .map(|r| match (r.error, r.value) {
                (None, Some(Value::String(s))) => Some(s),
                _ => None,
            })
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn atomic(t: &str, dims: Vec<u64>, member: bool) -> Node {
        Node {
            type_name: t.into(),
            kind: Kind::Atomic,
            dims,
            member,
            instance_id: None,
            structure_size: None,
        }
    }

    fn catalog() -> Catalog {
        let mut udt = TypeDef {
            public: vec!["Flags".into(), "Speed".into()],
            structure_size: 8,
            ..TypeDef::default()
        };
        udt.members
            .insert("Flags".into(), atomic("DWORD", vec![1], true));
        udt.members
            .insert("Speed".into(), atomic("REAL", vec![], true));
        let mut tags = IndexMap::new();
        tags.insert("Bits".into(), atomic("DWORD", vec![96], false));
        tags.insert("Word".into(), atomic("DWORD", vec![], false));
        tags.insert(
            "Motor".into(),
            Node {
                type_name: "MotorData".into(),
                kind: Kind::Struct,
                dims: vec![],
                member: false,
                instance_id: Some(5),
                structure_size: Some(8),
            },
        );
        let mut types = IndexMap::new();
        types.insert("MotorData".into(), udt);
        Catalog::new(Json::Null, tags, types)
    }

    #[test]
    fn bool_arrays_and_bit_strings() {
        let c = catalog();
        assert_eq!(
            c.tag_list(),
            vec![
                json!({"name": "Bits", "type": "BOOL", "dims": [96]}),
                json!({"name": "Word", "type": "DWORD"}),
                json!({"name": "Motor", "type": "MotorData"}),
            ]
        );
        assert_eq!(
            Json::Object(c.type_map()),
            json!({"MotorData": {"members": {"Flags": {"type": "BOOL", "dims": [32]}, "Speed": {"type": "REAL"}}}})
        );
    }

    #[test]
    fn info_ignores_case_and_indexes() {
        let c = catalog();
        assert_eq!(
            c.info("motor.SPEED").map(|n| n.type_name.as_str()),
            Some("REAL")
        );
        assert_eq!(
            c.info("Motor.Flags[3]").map(|n| n.type_name.as_str()),
            Some("DWORD")
        );
        assert_eq!(c.info("Bits{4}").map(|n| n.dims.clone()), Some(vec![96]));
        assert!(c.info("Motor.Nope").is_none());
        assert_eq!(c.struct_size(c.info("Motor").unwrap()), Some(8));
    }
}
