//! The Logix tag and data type model: symbol list pages, structure templates, tag definitions, and the encoding
//! and decoding of tag values, as the Python driver's `LogixDriver` does it (pure, no I/O).
//!
//! The driver uploads a scope's symbol list ([`parse_symbol_list`]), keeps its user tags ([`user_symbols`]) and
//! builds their definitions ([`create_tag`]); a structure tag's definition needs its template, read in pieces
//! ([`template_read_request`]) after its makeup ([`parse_structure_makeup`]) and parsed by [`parse_template`],
//! which asks a resolver for the templates nested in it.  Every model item renders to the dict the Python driver
//! returns (`to_py`), with the same keys in the same order.

use std::collections::BTreeSet;
use std::sync::Arc;

use indexmap::{IndexMap, IndexSet};

use crate::reader::Reader;
use crate::status;
use crate::types::{Elementary, FixedString};
use crate::value::{py_bytes_repr, py_float_repr, py_str_repr};
use crate::{Error, ErrorKind, Result, Value};

/// First major revision whose symbols carry the External Access attribute.
pub const MIN_VER_EXTERNAL_ACCESS: u32 = 18;
/// Software control bit set on a base tag, clear on an alias.
pub const BASE_TAG_BIT: u32 = 1 << 26;
const TEMPLATE_MEMBER_INFO_LEN: usize = 8;
const STRUCTURE_READ_REPLY: [u8; 2] = [0xA0, 0x02];
const SUCCESS: u8 = 0x00;
const INSUFFICIENT_PACKETS: u8 = 0x06;

/// A Python object, used to render the model as the dicts the Python driver returns.
#[derive(Clone, Debug, PartialEq)]
pub enum PyObj {
    /// `None`
    None,
    /// `bool`
    Bool(bool),
    /// `int`
    Int(i128),
    /// `str`
    Str(String),
    /// `list`
    List(Vec<PyObj>),
    /// `dict`, its items in order
    Dict(Vec<(PyObj, PyObj)>),
}

impl PyObj {
    fn str(s: &str) -> Self {
        PyObj::Str(s.to_owned())
    }

    fn opt_str(s: Option<&str>) -> Self {
        s.map_or(PyObj::None, PyObj::str)
    }

    fn int(n: impl Into<i128>) -> Self {
        PyObj::Int(n.into())
    }

    fn dict<'a>(items: impl IntoIterator<Item = (&'a str, PyObj)>) -> Self {
        PyObj::Dict(items.into_iter().map(|(k, v)| (PyObj::str(k), v)).collect())
    }

    fn str_list(items: &[String]) -> Self {
        PyObj::List(items.iter().map(|s| PyObj::str(s)).collect())
    }
}

// ------------------------------------------------------------------------------------------------ symbol lists

/// One entry of a symbol list page (Get Instance Attribute List of the Symbol Object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol instance id.
    pub instance_id: u32,
    /// Symbol name, e.g. `"Program:MainProgram"` or `"MyTag"`.
    pub tag_name: String,
    /// Symbol type word: bit 15 struct, bits 13-14 dimension count, bit 12 system, low bits the type.
    pub symbol_type: u16,
    /// Attribute 3.
    pub symbol_address: u32,
    /// Attribute 5.
    pub symbol_object_address: u32,
    /// Attribute 6, [`BASE_TAG_BIT`] is set on base tags.
    pub software_control: u32,
    /// External Access text, `"Unknown"` before v18.
    pub external_access: String,
    /// Array dimensions.
    pub dimensions: [u32; 3],
}

impl Symbol {
    /// The symbol as the Python driver's dict.
    pub fn to_py(&self) -> PyObj {
        PyObj::dict([
            ("instance_id", PyObj::int(self.instance_id)),
            ("tag_name", PyObj::str(&self.tag_name)),
            ("symbol_type", PyObj::int(self.symbol_type)),
            ("symbol_address", PyObj::int(self.symbol_address)),
            (
                "symbol_object_address",
                PyObj::int(self.symbol_object_address),
            ),
            ("software_control", PyObj::int(self.software_control)),
            ("external_access", PyObj::str(&self.external_access)),
            ("dimensions", dims_py(&self.dimensions)),
        ])
    }
}

fn dims_py(dims: &[u32; 3]) -> PyObj {
    PyObj::List(dims.iter().map(|d| PyObj::int(*d)).collect())
}

/// Parses a symbol list page onto `out` and returns the instance the next page starts at: `None` when the
/// list is complete (status 0, or an unexpected status), the last instance + 1 when more follows (status 6).
///
/// External access is read only from `revision_major` 18 on.  Entries parsed before a malformed one stay in
/// `out`; the error is `ResponseError("failed to parse instance attribute list")`.
pub fn parse_symbol_list(
    data: &[u8],
    service_status: u8,
    revision_major: u32,
    out: &mut Vec<Symbol>,
) -> Result<Option<u64>> {
    let mut r = Reader::new(data);
    let mut instance = 0u32;
    while !r.is_empty() {
        let symbol = read_symbol(&mut r, revision_major)
            .map_err(|_| Error::response("failed to parse instance attribute list"))?;
        instance = symbol.instance_id;
        out.push(symbol);
    }
    Ok(match service_status {
        INSUFFICIENT_PACKETS => Some(u64::from(instance) + 1),
        SUCCESS => None,
        _ => {
            log::warn!("unknown status during _parse_instance_attribute_list");
            None
        }
    })
}

fn read_symbol(r: &mut Reader<'_>, revision_major: u32) -> Result<Symbol> {
    let instance_id = r.u32()?;
    let tag_name = match Elementary::String.decode(r)? {
        Value::String(s) => s,
        _ => return Err(Error::data("symbol name is not a string")),
    };
    let symbol_type = r.u16()?;
    let symbol_address = r.u32()?;
    let symbol_object_address = r.u32()?;
    let software_control = r.u32()?;
    let dimensions = [r.u32()?, r.u32()?, r.u32()?];
    let access = if revision_major >= MIN_VER_EXTERNAL_ACCESS {
        Some(r.u8()?)
    } else {
        None
    };
    Ok(Symbol {
        instance_id,
        tag_name,
        symbol_type,
        symbol_address,
        symbol_object_address,
        software_control,
        external_access: status::external_access(access).to_owned(),
        dimensions,
    })
}

// ------------------------------------------------------------------------------------------------ templates

/// The structure makeup of a template (Template Object attributes 4, 5, 2 and 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TemplateMakeup {
    /// Template definition size in 32-bit words.
    pub object_definition_size: u32,
    /// Bytes of a value of the structure.
    pub structure_size: u32,
    /// Number of members.
    pub member_count: u16,
    /// Structure handle, sent with structure writes.
    pub structure_handle: u16,
}

impl TemplateMakeup {
    /// The makeup as the Python driver's dict.
    pub fn to_py(&self) -> PyObj {
        PyObj::dict([
            (
                "object_definition_size",
                PyObj::int(self.object_definition_size),
            ),
            ("structure_size", PyObj::int(self.structure_size)),
            ("member_count", PyObj::int(self.member_count)),
            ("structure_handle", PyObj::int(self.structure_handle)),
        ])
    }
}

/// Parses the reply data of a structure makeup read (Get Attribute List of attributes 4, 5, 2, 1); trailing
/// bytes are ignored, short data is `ResponseError("failed to parse structure attributes")`.
pub fn parse_structure_makeup(data: &[u8]) -> Result<TemplateMakeup> {
    let parse = || -> Result<TemplateMakeup> {
        let mut r = Reader::new(data);
        r.u16()?; // attribute count
        r.skip(4); // attribute number and status
        let object_definition_size = r.u32()?;
        r.skip(4);
        let structure_size = r.u32()?;
        r.skip(4);
        let member_count = r.u16()?;
        r.skip(4);
        let structure_handle = r.u16()?;
        Ok(TemplateMakeup {
            object_definition_size,
            structure_size,
            member_count,
            structure_handle,
        })
    };
    parse().map_err(|_| Error::response("failed to parse structure attributes"))
}

/// Request data of a template read from `offset`: the offset (DINT) and the bytes left to read (UINT),
/// `object_definition_size * 4 - 21 - offset`.  Out of range values are a `DataError` as in Python.
pub fn template_read_request(object_definition_size: u32, offset: u32) -> Result<Vec<u8>> {
    let size = i64::from(object_definition_size) * 4 - 21 - i64::from(offset);
    let mut out = Elementary::DInt.encode(&Value::LInt(offset.into()))?;
    out.extend(Elementary::UInt.encode(&Value::LInt(size))?);
    Ok(out)
}

/// The elementary type of a template member's type code: the code itself, else the code without its upper
/// 4 bits; None for a structure.
fn member_elementary(typ: u16) -> Option<Elementary> {
    let lookup = |code: u16| u8::try_from(code).ok().and_then(Elementary::from_code);
    lookup(typ).or_else(|| lookup(typ & 0x0FFF))
}

/// The instance ids of the templates of a raw template's structure members.
pub fn nested_template_ids(data: &[u8], makeup: &TemplateMakeup) -> Result<BTreeSet<u16>> {
    let mut ids = BTreeSet::new();
    for i in 0..usize::from(makeup.member_count) {
        let start = (i * TEMPLATE_MEMBER_INFO_LEN + 2).min(data.len());
        let end = (i * TEMPLATE_MEMBER_INFO_LEN + 4).min(data.len());
        let typ = read_u16(&mut Reader::new(&data[start..end]))?;
        if member_elementary(typ).is_none() {
            ids.insert(typ & 0x0FFF);
        }
    }
    Ok(ids)
}

/// Reads with the Python error message, which shows the whole buffer.
fn decode_elementary(e: Elementary, r: &mut Reader<'_>) -> Result<Value> {
    e.decode(r).map_err(|err| match err {
        Error::Data(_) => Error::Data(format!(
            "Error unpacking {} as {}",
            py_bytes_repr(r.buffer()),
            e.name()
        )),
        other => other,
    })
}

fn read_u16(r: &mut Reader<'_>) -> Result<u16> {
    match decode_elementary(Elementary::UInt, r)? {
        Value::UInt(v) => Ok(v),
        _ => Err(Error::data("expected a UINT")),
    }
}

fn read_u32(r: &mut Reader<'_>) -> Result<u32> {
    match decode_elementary(Elementary::UDInt, r)? {
        Value::UDInt(v) => Ok(v),
        _ => Err(Error::data("expected a UDINT")),
    }
}

/// Resolves a nested template: given its instance id and the member's type code, returns its data type (the
/// driver reads, parses and caches it, wrapping failures as
/// `ResponseError("Failed to get data type information for {id}")`).
pub type Resolver<'a> = dyn FnMut(u16, u16) -> Result<Arc<DataType>> + 'a;

/// The type of a tag or member: an elementary type (None for an unknown type code) or a structure.
#[derive(Clone, Debug, PartialEq)]
pub enum TypeRef {
    /// An atomic type; None when the code is not a known elementary type.
    Atomic(Option<Elementary>),
    /// A structure (UDT, AOI, string or predefined type).
    Struct(Arc<DataType>),
}

impl TypeRef {
    /// `"atomic"` or `"struct"`.
    pub fn tag_type(&self) -> &'static str {
        match self {
            TypeRef::Atomic(_) => "atomic",
            TypeRef::Struct(_) => "struct",
        }
    }

    /// The type name, e.g. `"DINT"` or a structure's name.
    pub fn name(&self) -> Option<&str> {
        match self {
            TypeRef::Atomic(e) => e.map(Elementary::name),
            TypeRef::Struct(dt) => dt.name.as_deref(),
        }
    }

    fn to_py(&self) -> PyObj {
        match self {
            TypeRef::Atomic(e) => PyObj::opt_str(e.map(Elementary::name)),
            TypeRef::Struct(dt) => dt.to_py(),
        }
    }
}

/// How a value of a tag or member is encoded and decoded.
#[derive(Clone, Debug, PartialEq)]
pub enum TypeClass {
    /// An elementary type.
    Elementary(Elementary),
    /// A Logix string structure (`LEN` and a SINT array `DATA`).
    String(FixedString),
    /// Any other structure.
    Struct(Arc<DataType>),
    /// A fixed length array.
    Array(usize, Box<TypeClass>),
    /// The element of an array tag of an unknown atomic type (Python's `Array(n, NoneType)`): it never decodes
    /// or encodes.
    Unknown,
}

/// A structure member stored in the structure's bytes (bit members are not, they alias bits of another).
#[derive(Clone, Debug, PartialEq)]
pub struct StructMember {
    /// Member name.
    pub name: String,
    /// Member type.
    pub type_class: TypeClass,
    /// Byte offset in the structure.
    pub offset: u32,
}

/// A template member's definition (an entry of `internal_tags`).
#[derive(Clone, Debug, PartialEq)]
pub struct MemberInfo {
    /// Byte offset in the structure.
    pub offset: u32,
    /// Member type.
    pub data_type: TypeRef,
    /// Bit number of a BOOL member.
    pub bit: Option<u16>,
    /// Array length of any other member, 0 if not an array.
    pub array: Option<u16>,
    /// Codec of the member's value.
    pub type_class: TypeClass,
}

impl MemberInfo {
    /// The member as the Python driver's dict (without its type class).
    pub fn to_py(&self) -> PyObj {
        let mut items = vec![
            ("offset", PyObj::int(self.offset)),
            ("tag_type", PyObj::str(self.data_type.tag_type())),
            ("data_type", self.data_type.to_py()),
            ("data_type_name", PyObj::opt_str(self.data_type.name())),
        ];
        if let Some(bit) = self.bit {
            items.push(("bit", PyObj::int(bit)));
        }
        if let Some(array) = self.array {
            items.push(("array", PyObj::int(array)));
        }
        PyObj::dict(items)
    }
}

/// A structure data type parsed from its template.
#[derive(Clone, Debug, PartialEq)]
pub struct DataType {
    /// Type name; `"STRING"` for the builtin string, None when the template has none.
    pub name: Option<String>,
    /// Every member, private ones included, by name.
    pub internal_tags: IndexMap<String, MemberInfo>,
    /// The public members, in template order.
    pub attributes: Vec<String>,
    /// The structure makeup.
    pub template: TemplateMakeup,
    /// For a string type, the length of its `DATA` array.
    pub string: Option<u16>,
    /// The members stored in the structure's bytes, in template order.
    pub members: Vec<StructMember>,
    /// The bit members: name to (byte offset, bit).
    pub bit_members: IndexMap<String, (u32, u16)>,
    /// Members left out of values and not written: host members, `__` names, CTL/Control of predefined types.
    pub private_members: IndexSet<String>,
}

impl DataType {
    /// The data type as the Python driver's dict (without its type class).
    pub fn to_py(&self) -> PyObj {
        let mut items = vec![
            ("name", PyObj::opt_str(self.name.as_deref())),
            (
                "internal_tags",
                PyObj::Dict(
                    self.internal_tags
                        .iter()
                        .map(|(k, v)| (PyObj::str(k), v.to_py()))
                        .collect(),
                ),
            ),
            ("attributes", PyObj::str_list(&self.attributes)),
            ("template", self.template.to_py()),
        ];
        if let Some(n) = self.string {
            items.push(("string", PyObj::int(n)));
        }
        PyObj::dict(items)
    }

    /// The codec of a value of this type: a string for a string type, else the structure.
    pub fn type_class(self: &Arc<Self>) -> TypeClass {
        match self.string {
            Some(len) => {
                let size = (self.template.structure_size as usize).saturating_sub(4);
                let max_len = if len == 0 { size } else { usize::from(len) };
                TypeClass::String(FixedString { size, max_len })
            }
            None => TypeClass::Struct(Arc::clone(self)),
        }
    }
}

/// An Add-On Instruction's type: the template has no marker for it, but every AOI has EnableIn and EnableOut.
pub fn is_aoi(data_type: &DataType) -> bool {
    data_type.internal_tags.contains_key("EnableIn")
        && data_type.internal_tags.contains_key("EnableOut")
}

/// Parses a raw template into its data type.  `symbol_type` decides whether it is a predefined type (template
/// instance outside 0x100-0xEFF), whose name is its first name; `resolver` gives the nested structures.
pub fn parse_template(
    data: &[u8],
    makeup: &TemplateMakeup,
    symbol_type: u16,
    resolver: &mut Resolver<'_>,
) -> Result<DataType> {
    let info_len = usize::from(makeup.member_count) * TEMPLATE_MEMBER_INFO_LEN;
    let info_data = &data[..info_len.min(data.len())];
    let mut infos = Vec::with_capacity(usize::from(makeup.member_count).min(data.len() / 8 + 1));
    for i in (0..info_len).step_by(TEMPLATE_MEMBER_INFO_LEN) {
        let start = i.min(info_data.len());
        let end = (i + TEMPLATE_MEMBER_INFO_LEN).min(info_data.len());
        infos.push(parse_member_info(&info_data[start..end], resolver)?);
    }

    let mut names = Vec::new();
    let mut template_name = None;
    for raw in data[info_len.min(data.len())..].split(|b| *b == 0) {
        let name = String::from_utf8_lossy(raw).into_owned();
        match name.split_once(';') {
            Some((head, _)) if template_name.is_none() => template_name = Some(head.to_owned()),
            _ => names.push(name),
        }
    }

    let id = symbol_type & 0x0FFF;
    let predefined = !(0x100..=0xEFF).contains(&id);
    if predefined && template_name.is_none() {
        if names.is_empty() {
            return Err(Error::data("pop from empty list"));
        }
        template_name = Some(names.remove(0));
    }
    if template_name.as_deref() == Some("ASCIISTRING82") {
        template_name = Some("STRING".to_owned());
    }

    let mut data_type = DataType {
        name: template_name,
        internal_tags: IndexMap::new(),
        attributes: Vec::new(),
        template: *makeup,
        string: None,
        members: Vec::new(),
        bit_members: IndexMap::new(),
        private_members: IndexSet::new(),
    };
    let mut unknown = 0;
    for (name, info) in names.into_iter().zip(infos) {
        let name = if name.is_empty() {
            unknown += 1;
            format!("__unknown{}", unknown - 1)
        } else {
            name
        };
        if name.starts_with("ZZZZZZZZZZ")
            || name.starts_with("__")
            || (predefined && (name == "CTL" || name == "Control"))
        {
            data_type.private_members.insert(name.clone());
        } else {
            data_type.attributes.push(name.clone());
        }
        match info.bit {
            Some(bit) => {
                data_type
                    .bit_members
                    .insert(name.clone(), (info.offset, bit));
            }
            None => data_type.members.push(StructMember {
                name: name.clone(),
                type_class: info.type_class.clone(),
                offset: info.offset,
            }),
        }
        data_type.internal_tags.insert(name, info);
    }

    if data_type.attributes == ["LEN", "DATA"] {
        if let Some(data) = data_type.internal_tags.get("DATA") {
            if data.data_type.name() == Some("SINT") && data.array.is_some_and(|n| n > 0) {
                data_type.string = data.array;
            }
        }
    }
    Ok(data_type)
}

fn parse_member_info(info: &[u8], resolver: &mut Resolver<'_>) -> Result<MemberInfo> {
    let mut r = Reader::new(info);
    let type_info = read_u16(&mut r)?;
    let typ = read_u16(&mut r)?;
    let offset = read_u32(&mut r)?;
    let (data_type, type_class) = match member_elementary(typ) {
        Some(e) => (TypeRef::Atomic(Some(e)), TypeClass::Elementary(e)),
        None => {
            let dt = resolver(typ & 0x0FFF, typ)?;
            let tc = dt.type_class();
            (TypeRef::Struct(dt), tc)
        }
    };
    let is_bool = matches!(data_type, TypeRef::Atomic(Some(Elementary::Bool)));
    let type_class = if !is_bool && type_info > 0 {
        TypeClass::Array(usize::from(type_info), Box::new(type_class))
    } else {
        type_class
    };
    Ok(MemberInfo {
        offset,
        data_type,
        bit: is_bool.then_some(type_info),
        array: (!is_bool).then_some(type_info),
        type_class,
    })
}

// ------------------------------------------------------------------------------------------------ tag lists

/// A program found in a symbol list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProgramInfo {
    /// Its symbol instance id.
    pub instance_id: u32,
    /// Its routines, from its own symbol list.
    pub routines: Vec<String>,
}

/// An I/O module found in a symbol list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleInfo {
    /// Connection types per slot, from `Module:slot:type` tags.
    pub slots: IndexMap<u64, Vec<String>>,
    /// `"types"` from `Module:type` tags and `"__UNKNOWN__"` from other forms, in the order first seen.
    pub lists: IndexMap<String, Vec<String>>,
}

/// The programs, tasks and I/O modules found while isolating user tags (the driver's `info` entries).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeInfo {
    /// Programs by name.
    pub programs: IndexMap<String, ProgramInfo>,
    /// Task instance ids by task name.
    pub tasks: IndexMap<String, u32>,
    /// I/O modules by name.
    pub modules: IndexMap<String, ModuleInfo>,
}

impl ScopeInfo {
    /// The `programs`, `tasks` and `modules` entries of the driver's `info` dict.
    pub fn to_py(&self) -> PyObj {
        let programs = self
            .programs
            .iter()
            .map(|(name, p)| {
                let value = PyObj::dict([
                    ("instance_id", PyObj::int(p.instance_id)),
                    ("routines", PyObj::str_list(&p.routines)),
                ]);
                (PyObj::str(name), value)
            })
            .collect();
        let tasks = self
            .tasks
            .iter()
            .map(|(name, id)| {
                let value = PyObj::dict([("instance_id", PyObj::int(*id))]);
                (PyObj::str(name), value)
            })
            .collect();
        let modules = self
            .modules
            .iter()
            .map(|(name, m)| {
                let slots = m
                    .slots
                    .iter()
                    .map(|(slot, types)| {
                        let value = PyObj::dict([("types", PyObj::str_list(types))]);
                        (PyObj::int(*slot), value)
                    })
                    .collect();
                let mut items = vec![(PyObj::str("slots"), PyObj::Dict(slots))];
                items.extend(
                    m.lists
                        .iter()
                        .map(|(k, v)| (PyObj::str(k), PyObj::str_list(v))),
                );
                (PyObj::str(name), PyObj::Dict(items))
            })
            .collect();
        PyObj::dict([
            ("programs", PyObj::Dict(programs)),
            ("tasks", PyObj::Dict(tasks)),
            ("modules", PyObj::Dict(modules)),
        ])
    }
}

/// The user tags of a scope's symbol list as (tag name, symbol), recording its programs, routines, tasks and
/// I/O modules in `info`.  `program` is the scope (None for the controller): its tags are named
/// `Program:{program}.{name}`.  System and module-defined tags are left out, and only names starting with
/// `namespace_filter` are kept (program, task and module discovery is not filtered).
pub fn user_symbols<'a>(
    info: &mut ScopeInfo,
    symbols: &'a [Symbol],
    program: Option<&str>,
    namespace_filter: &str,
) -> Vec<(String, &'a Symbol)> {
    let mut user_tags = Vec::new();
    for symbol in symbols {
        let name = symbol.tag_name.as_str();
        if name.starts_with("Program:") {
            let program_name = name.replace("Program:", "");
            info.programs.insert(
                program_name,
                ProgramInfo {
                    instance_id: symbol.instance_id,
                    routines: Vec::new(),
                },
            );
            continue;
        }
        if name.starts_with("Routine:") {
            match program.and_then(|p| info.programs.get_mut(p)) {
                Some(p) => p.routines.push(name.replace("Routine:", "")),
                None => log::error!("Program {program:?} not defined in tag list"),
            }
            continue;
        }
        if name.starts_with("Task:") {
            info.tasks
                .insert(name.replace("Task:", ""), symbol.instance_id);
            continue;
        }
        if name.contains("Map:") || name.contains("Cxn:") {
            continue;
        }
        let io_tag = [":I", ":O", ":C", ":S"].iter().any(|x| name.contains(x));
        if io_tag {
            add_module(info, name);
        }
        if (!io_tag && name.contains(':')) || name.starts_with("__") {
            continue;
        }
        if symbol.symbol_type & 0x1000 != 0 {
            continue;
        }
        if !name.starts_with(namespace_filter) {
            continue;
        }
        let name = match program {
            Some(p) => format!("Program:{p}.{name}"),
            None => name.to_owned(),
        };
        user_tags.push((name, symbol));
    }
    user_tags
}

fn add_module(info: &mut ScopeInfo, name: &str) {
    let parts: Vec<&str> = name.split(':').collect();
    let module = info.modules.entry(parts[0].to_owned()).or_default();
    let slot =
        (parts.len() == 3 && !parts[1].is_empty() && parts[1].bytes().all(|b| b.is_ascii_digit()))
            .then(|| parts[1].parse::<u64>().ok())
            .flatten();
    if let Some(slot) = slot {
        module
            .slots
            .entry(slot)
            .or_default()
            .push(parts[2].to_owned());
    } else if parts.len() == 2 {
        module
            .lists
            .entry("types".to_owned())
            .or_default()
            .push(parts[1].to_owned());
    } else {
        module
            .lists
            .entry("__UNKNOWN__".to_owned())
            .or_default()
            .push(parts[1..].join(":"));
    }
}

/// A tag definition, an entry of the driver's `tags` dict.
#[derive(Clone, Debug, PartialEq)]
pub struct TagDef {
    /// Tag name, `Program:X.name` for a program tag.
    pub tag_name: String,
    /// Number of array dimensions, 0 to 3.
    pub dim: u8,
    /// True for an alias tag.
    pub alias: bool,
    /// Symbol instance id.
    pub instance_id: u32,
    /// Symbol address.
    pub symbol_address: u32,
    /// Symbol object address.
    pub symbol_object_address: u32,
    /// Software control word.
    pub software_control: u32,
    /// External Access text.
    pub external_access: String,
    /// Array dimensions.
    pub dimensions: [u32; 3],
    /// Template instance id of a structure tag.
    pub template_instance_id: Option<u16>,
    /// The tag's type.
    pub data_type: TypeRef,
    /// Bit position of a BOOL tag.
    pub bit_position: Option<u8>,
    /// Codec of the whole tag (an array for array tags), None for a scalar of an unknown atomic type.
    pub type_class: Option<TypeClass>,
}

impl TagDef {
    /// The tag as the Python driver's dict (`LogixDriver.tags_json` shape: without type classes).
    pub fn to_py(&self) -> PyObj {
        let mut items = vec![
            ("tag_name", PyObj::str(&self.tag_name)),
            ("dim", PyObj::int(self.dim)),
            ("alias", PyObj::Bool(self.alias)),
            ("instance_id", PyObj::int(self.instance_id)),
            ("symbol_address", PyObj::int(self.symbol_address)),
            (
                "symbol_object_address",
                PyObj::int(self.symbol_object_address),
            ),
            ("software_control", PyObj::int(self.software_control)),
            ("external_access", PyObj::str(&self.external_access)),
            ("dimensions", dims_py(&self.dimensions)),
        ];
        if let Some(id) = self.template_instance_id {
            items.push(("template_instance_id", PyObj::int(id)));
        }
        items.push(("data_type", self.data_type.to_py()));
        items.push(("data_type_name", PyObj::opt_str(self.data_type.name())));
        if let Some(bit) = self.bit_position {
            items.push(("bit_position", PyObj::int(bit)));
        }
        items.push(("tag_type", PyObj::str(self.data_type.tag_type())));
        PyObj::dict(items)
    }
}

/// The definition of a user tag from its symbol; a structure's data type comes from `resolver` (called with
/// the template instance id and the symbol type).
pub fn create_tag(name: &str, symbol: &Symbol, resolver: &mut Resolver<'_>) -> Result<TagDef> {
    let st = symbol.symbol_type;
    let dim = ((st & 0x6000) >> 13) as u8;
    let (template_instance_id, data_type, bit_position, type_class) = if st & 0x8000 != 0 {
        let id = st & 0x0FFF;
        let dt = resolver(id, st)?;
        let tc = dt.type_class();
        (Some(id), TypeRef::Struct(dt), None, Some(tc))
    } else {
        let code = (st & 0xFF) as u8;
        let e = Elementary::from_code(code);
        let bit = (code == Elementary::Bool.code()).then_some(((st & 0x0700) >> 8) as u8);
        (None, TypeRef::Atomic(e), bit, e.map(TypeClass::Elementary))
    };
    // Python's Array() of an unknown type is an array of NoneType, a scalar of it has no type class
    let element = |t: Option<TypeClass>| t.unwrap_or(TypeClass::Unknown);
    let type_class = if dim > 0 {
        let mut total = 1usize;
        for d in &symbol.dimensions[..usize::from(dim)] {
            total = total
                .checked_mul(*d as usize)
                .ok_or_else(|| Error::response("array dimensions too large"))?;
        }
        Some(TypeClass::Array(total, Box::new(element(type_class))))
    } else {
        type_class
    };
    Ok(TagDef {
        tag_name: name.to_owned(),
        dim,
        alias: symbol.software_control & BASE_TAG_BIT == 0,
        instance_id: symbol.instance_id,
        symbol_address: symbol.symbol_address,
        symbol_object_address: symbol.symbol_object_address,
        software_control: symbol.software_control,
        external_access: symbol.external_access.clone(),
        dimensions: symbol.dimensions,
        template_instance_id,
        data_type,
        bit_position,
        type_class,
    })
}

/// The user tags of each (scope, symbol list), in order, with their definitions (`_isolate_scopes`).  A
/// failure other than a `CommError` is `ResponseError("failed isolating user tags")`.
pub fn isolate_scopes(
    info: &mut ScopeInfo,
    symbol_lists: &[(Option<String>, Vec<Symbol>)],
    namespace_filter: &str,
    resolver: &mut Resolver<'_>,
) -> Result<Vec<TagDef>> {
    let user: Vec<(String, &Symbol)> = symbol_lists
        .iter()
        .flat_map(|(scope, symbols)| {
            user_symbols(info, symbols, scope.as_deref(), namespace_filter)
        })
        .collect();
    user.iter()
        .map(|(name, symbol)| create_tag(name, symbol, resolver))
        .collect::<Result<Vec<_>>>()
        .map_err(|err| match err {
            Error::Comm(_) => err,
            _ => Error::response("failed isolating user tags"),
        })
}

/// The tags as the driver's `tags` dict, `{tag_name: tag}`.
pub fn tags_to_py(tags: &[TagDef]) -> PyObj {
    PyObj::Dict(
        tags.iter()
            .map(|t| (PyObj::str(&t.tag_name), t.to_py()))
            .collect(),
    )
}

// ------------------------------------------------------------------------------------------------ tag lookups

/// A tag's or a member's definition, what reads and writes are built from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TagInfo<'a> {
    /// A whole tag.
    Tag(&'a TagDef),
    /// A structure member.
    Member(&'a MemberInfo),
}

impl<'a> TagInfo<'a> {
    /// The type.
    pub fn data_type(&self) -> &'a TypeRef {
        match self {
            TagInfo::Tag(t) => &t.data_type,
            TagInfo::Member(m) => &m.data_type,
        }
    }

    /// The type name.
    pub fn data_type_name(&self) -> Option<&'a str> {
        self.data_type().name()
    }

    /// True for a BOOL array: Logix stores one as a DWORD array (a tag with dimensions, which count its BOOLs, or
    /// a member array, counted in DWORDs). A DWORD without dimensions is a 32-bit bit string, like a BYTE.
    pub fn is_bool_array(&self) -> bool {
        let dword = matches!(self.data_type(), TypeRef::Atomic(Some(Elementary::DWord)));
        dword
            && match self {
                TagInfo::Tag(t) => t.dim > 0,
                TagInfo::Member(m) => m.array.is_some_and(|n| n > 0),
            }
    }

    /// `"atomic"` or `"struct"`.
    pub fn tag_type(&self) -> &'static str {
        self.data_type().tag_type()
    }

    /// The codec of the value.
    pub fn type_class(&self) -> Option<&'a TypeClass> {
        match self {
            TagInfo::Tag(t) => t.type_class.as_ref(),
            TagInfo::Member(m) => Some(&m.type_class),
        }
    }
}

/// `name` without its array part: `"tag[100]"` is `"tag"`.
pub fn strip_array(tag: &str) -> &str {
    tag.find('[').map_or(tag, |i| &tag[..i])
}

/// The tag name and index of a one-dimension element request: `"tag[100]"` is `("tag", Some(100))`.  A bad
/// index is an error, as Python's `int()`.
pub fn get_array_index(tag: &str) -> Result<(String, Option<i64>)> {
    if tag.ends_with(']') {
        if let Some((name, index)) = tag.rsplit_once('[') {
            let digits = &index[..index.len() - 1];
            let idx = py_int(digits).ok_or_else(|| {
                Error::request(format!(
                    "invalid literal for int() with base 10: {}",
                    py_str_repr(digits)
                ))
            })?;
            return Ok((name.to_owned(), Some(idx)));
        }
    }
    Ok((tag.to_owned(), None))
}

/// Python's `int(text)` for base 10: whitespace, a sign, digits with single underscores between them.
fn py_int(text: &str) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let valid = !digits.is_empty()
        && digits
            .split('_')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if !valid {
        return None;
    }
    let value: i64 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -value } else { value })
}

/// The key of `name` (without its array part) in `data`: Logix names are case-insensitive, the exact key
/// first, else a case-insensitive match, else the name itself.
pub fn tag_key<V>(data: &IndexMap<String, V>, name: &str) -> String {
    let name = strip_array(name);
    if data.contains_key(name) {
        return name.to_owned();
    }
    let lower = name.to_lowercase();
    data.keys()
        .find(|k| k.to_lowercase() == lower)
        .cloned()
        .unwrap_or_else(|| name.to_owned())
}

/// Splits a tag request into (tag, base tag, member names): a `program:` prefix is normalised to `Program:`,
/// and a program tag's base keeps its tag name, `Program:X.tag`.  A program name alone is an error.
pub fn split_tag_name(tag: &str) -> Result<(String, String, Vec<String>)> {
    let tag = match tag.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("program:") => format!("Program:{}", &tag[8..]),
        _ => tag.to_owned(),
    };
    let mut parts = tag.split('.').map(str::to_owned);
    let mut base = parts.next().unwrap_or_default();
    let mut attrs: Vec<String> = parts.collect();
    if base.starts_with("Program:") {
        if attrs.is_empty() {
            return Err(Error::request("pop from empty list"));
        }
        base = format!("{base}.{}", attrs.remove(0));
    }
    Ok((tag, base, attrs))
}

/// The definition of a tag or member, e.g. `"MyUdt.Member"`, looked up case-insensitively.  A missing name
/// is `RequestError("Tag doesn't exist - {name}")` (NotFound), a member of an atomic tag a BadRequest.
pub fn get_tag_info<'a>(tags: &'a IndexMap<String, TagDef>, tag_name: &str) -> Result<TagInfo<'a>> {
    let (_, base, attrs) = split_tag_name(tag_name)?;
    tag_info(tags, &base, &attrs)
}

/// The definition of `base` or of its member `attrs`, see [`get_tag_info`].
pub fn tag_info<'a>(
    tags: &'a IndexMap<String, TagDef>,
    base: &str,
    attrs: &[String],
) -> Result<TagInfo<'a>> {
    let not_found = |key: String| {
        Error::request_kind(format!("Tag doesn't exist - {key}"), ErrorKind::NotFound)
    };
    let bad = || {
        let attrs: Vec<String> = attrs.iter().map(|a| py_str_repr(a)).collect();
        Error::request_kind(
            format!("failed to get tag data for: {base}, [{}]", attrs.join(", ")),
            ErrorKind::BadRequest,
        )
    };
    let name = tag_key(tags, base);
    let Some(tag) = tags.get(&name) else {
        return Err(not_found(name));
    };
    let mut data_type = &tag.data_type;
    let mut found = TagInfo::Tag(tag);
    for attr in attrs {
        let TypeRef::Struct(dt) = data_type else {
            return Err(bad());
        };
        let key = tag_key(&dt.internal_tags, attr);
        let Some(member) = dt.internal_tags.get(&key) else {
            return Err(not_found(key));
        };
        data_type = &member.data_type;
        found = TagInfo::Member(member);
    }
    Ok(found)
}

/// Bytes of `elements` values of a tag or member.  Unknown atomic types are an error.
pub fn tag_return_size(info: TagInfo<'_>, elements: usize) -> Result<usize> {
    let size = match info.data_type() {
        TypeRef::Atomic(Some(e)) => e.size(),
        TypeRef::Atomic(None) => return Err(Error::data("None")),
        TypeRef::Struct(dt) => dt.template.structure_size as usize,
    };
    Ok(size * elements)
}

/// Reply bytes of a read: the values plus sequence, reply header and type code (+2 structure handle).
pub fn read_reply_size(info: TagInfo<'_>, elements: usize) -> Result<usize> {
    let extra = if info.tag_type() == "struct" { 10 } else { 8 };
    Ok(tag_return_size(info, elements)? + extra)
}

// ------------------------------------------------------------------------------------------------ values

impl TypeClass {
    /// True for an array of BOOL words (DWORD), whose value is one bool per bit.
    fn is_bit_array(&self) -> bool {
        matches!(self, TypeClass::Elementary(e) if e.is_bit_array())
    }

    /// The type as Python prints the type class, used in error messages.
    pub fn py_repr(&self) -> String {
        match self {
            TypeClass::Elementary(e) => e.name().to_owned(),
            TypeClass::String(_) => "FixedSizeString".to_owned(),
            TypeClass::Struct(dt) => {
                let members: Vec<String> = dt
                    .members
                    .iter()
                    .map(|m| {
                        format!(
                            "{}(name={})",
                            m.type_class.class_name(),
                            py_str_repr(&m.name)
                        )
                    })
                    .collect();
                let bits: Vec<String> = dt
                    .bit_members
                    .iter()
                    .map(|(name, (offset, bit))| {
                        format!("{}: ({offset}, {bit})", py_str_repr(name))
                    })
                    .collect();
                format!(
                    "StructTag({}, bool_members={{{}}},  struct_size={})",
                    members.join(", "),
                    bits.join(", "),
                    dt.template.structure_size
                )
            }
            TypeClass::Array(len, elem) => format!("{}[{len}]", elem.py_repr()),
            TypeClass::Unknown => "<class 'NoneType'>".to_owned(),
        }
    }

    fn class_name(&self) -> String {
        match self {
            TypeClass::Struct(_) => "StructTag".to_owned(),
            other => other.py_repr(),
        }
    }

    /// Decodes a value; struct values leave out private members, bit members come after the others.
    pub fn decode(&self, r: &mut Reader<'_>) -> Result<Value> {
        match self {
            TypeClass::Elementary(e) => decode_elementary(*e, r),
            TypeClass::String(fs) => fs.decode(r).map_err(|err| match err {
                Error::Data(_) => Error::Data(format!(
                    "Error unpacking {} as FixedSizeString",
                    py_bytes_repr(r.buffer())
                )),
                other => other,
            }),
            TypeClass::Struct(dt) => decode_struct(dt, r).map_err(|err| match err {
                Error::BufferEmpty => Error::BufferEmpty,
                _ => Error::Data(format!(
                    "Error unpacking {} as StructTag",
                    py_bytes_repr(r.buffer())
                )),
            }),
            TypeClass::Array(len, elem) => decode_array(elem, *len, r).map(Value::Array),
            TypeClass::Unknown => Err(Error::data(
                "type object 'NoneType' has no attribute 'decode'",
            )),
        }
    }

    /// Encodes a value: a struct takes a `Value::Struct` with every public member, an array at least its length
    /// of values (or the characters of a string, the bytes of `Bytes`).
    pub fn encode(&self, value: &Value) -> Result<Vec<u8>> {
        match self {
            TypeClass::Elementary(e) => e.encode(value).map_err(|_| {
                Error::Data(format!("Error packing {} as {}", value.py_repr(), e.name()))
            }),
            TypeClass::String(fs) => fs.encode(value).map_err(|_| {
                Error::Data(format!(
                    "Error packing {} as FixedSizeString",
                    value.py_repr()
                ))
            }),
            TypeClass::Struct(dt) => encode_struct(dt, value).map_err(|_| {
                Error::Data(format!("Error packing {} as StructTag", value.py_repr()))
            }),
            TypeClass::Array(len, elem) => encode_array(elem, *len, value, None),
            TypeClass::Unknown => Err(Error::data(
                "type object 'NoneType' has no attribute 'encode'",
            )),
        }
    }
}

fn decode_struct(dt: &DataType, r: &mut Reader<'_>) -> Result<Value> {
    let size = (dt.template.structure_size as usize).min(r.remaining());
    let raw = &r.rest()[..size];
    r.skip(size);
    let mut sub = Reader::new(raw);
    let mut values = IndexMap::new();
    for member in &dt.members {
        let offset = member.offset as usize;
        if sub.position() < offset {
            sub.skip(offset - sub.position());
        }
        values.insert(member.name.clone(), member.type_class.decode(&mut sub)?);
    }
    for (name, (offset, bit)) in &dt.bit_members {
        let byte = raw
            .get(*offset as usize)
            .ok_or_else(|| Error::data("index out of range"))?;
        let set = *bit < 8 && byte & (1 << bit) != 0;
        values.insert(name.clone(), Value::Bool(set));
    }
    values.retain(|k, _| !dt.private_members.contains(k));
    Ok(Value::Struct(values))
}

fn encode_struct(dt: &DataType, value: &Value) -> Result<Vec<u8>> {
    let Value::Struct(values) = value else {
        return Err(Error::data("not a dict"));
    };
    let mut unknown: Vec<&str> = values
        .keys()
        .filter(|k| !dt.members.iter().any(|m| &m.name == *k) && !dt.bit_members.contains_key(*k))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(Error::Data(format!(
            "Unknown members: {}",
            unknown.join(", ")
        )));
    }
    let missing = |name: &str| Error::Data(format!("missing member {}", py_str_repr(name)));
    let mut out = vec![0u8; dt.template.structure_size as usize];
    for member in &dt.members {
        if dt.private_members.contains(&member.name) {
            continue;
        }
        let v = values
            .get(&member.name)
            .ok_or_else(|| missing(&member.name))?;
        let encoded = member.type_class.encode(v)?;
        // bytearray slice assignment: the slice is clamped to the buffer, a longer value grows it
        let start = (member.offset as usize).min(out.len());
        let end = (member.offset as usize)
            .saturating_add(encoded.len())
            .min(out.len());
        out.splice(start..end, encoded);
    }
    for (name, (offset, bit)) in &dt.bit_members {
        let set = values
            .get(name)
            .ok_or_else(|| missing(name))?
            .as_bool()
            .ok_or_else(|| Error::data("expected a bool"))?;
        let byte = out
            .get_mut(*offset as usize)
            .ok_or_else(|| Error::data("bytearray index out of range"))?;
        if set {
            if *bit >= 8 {
                return Err(Error::data("byte must be in range(0, 256)"));
            }
            *byte |= 1 << bit;
        } else if *bit < 8 {
            *byte &= !(1 << bit);
        }
    }
    Ok(out)
}

fn decode_array(elem: &TypeClass, length: usize, r: &mut Reader<'_>) -> Result<Vec<Value>> {
    let mut items = Vec::with_capacity(length.min(r.remaining()));
    let result = (|| {
        for _ in 0..length {
            items.push(elem.decode(r)?);
        }
        Ok(())
    })();
    match result {
        Ok(()) => {}
        Err(Error::BufferEmpty) => return Err(Error::BufferEmpty),
        Err(_) => {
            return Err(Error::Data(format!(
                "Error unpacking into {}[{length}] from {}",
                elem.py_repr(),
                py_bytes_repr(r.buffer())
            )));
        }
    }
    if elem.is_bit_array() {
        items = items
            .into_iter()
            .flat_map(|word| match word {
                Value::Array(bits) => bits,
                other => vec![other],
            })
            .collect();
    }
    Ok(items)
}

/// The items Python would index in a value used as a sequence; Err is the `len()` failure.
enum Items {
    List(Vec<Value>),
    /// A dict has a length, but indexing it by position fails.
    Dict(usize),
}

impl Items {
    fn len(&self) -> usize {
        match self {
            Items::List(items) => items.len(),
            Items::Dict(n) => *n,
        }
    }
}

fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Bool(_) => "bool",
        Value::Real(_) | Value::LReal(_) => "float",
        Value::String(_) => "str",
        Value::Bytes(_) => "bytes",
        Value::Array(_) => "list",
        Value::Struct(_) => "dict",
        _ => "int",
    }
}

fn items(value: &Value) -> Result<Items> {
    Ok(match value {
        Value::Array(items) => Items::List(items.clone()),
        Value::String(s) => Items::List(s.chars().map(|c| Value::String(c.into())).collect()),
        Value::Bytes(b) => Items::List(b.iter().map(|&b| Value::USInt(b)).collect()),
        Value::Struct(map) => Items::Dict(map.len()),
        other => {
            return Err(Error::Data(format!(
                "object of type '{}' has no len()",
                py_type_name(other)
            )));
        }
    })
}

fn encode_array(
    elem: &TypeClass,
    class_length: usize,
    value: &Value,
    length: Option<usize>,
) -> Result<Vec<u8>> {
    let length = length.filter(|&n| n > 0).unwrap_or(class_length);
    let items = items(value)?;
    if items.len() < length {
        return Err(Error::Data(format!(
            "Not enough values to encode array of {}[{length}]",
            elem.py_repr()
        )));
    }
    let fail = |shown: &Value| {
        Error::Data(format!(
            "Error packing {} into {}[{length}]",
            reprlib(shown),
            elem.py_repr()
        ))
    };
    let items = match items {
        Items::List(items) => items,
        // a dict has a length, but indexing or slicing it by position fails
        Items::Dict(n) => {
            let count = if elem.is_bit_array() { n } else { length };
            return if count == 0 {
                Ok(Vec::new())
            } else {
                Err(fail(value))
            };
        }
    };
    let mut out = Vec::new();
    if let TypeClass::Elementary(e) = elem {
        if e.is_bit_array() {
            let chunk = e.size() * 8;
            if items.len() % chunk != 0 {
                return Err(fail(value));
            }
            let chunks: Vec<Value> = items
                .chunks(chunk)
                .map(|c| Value::Array(c.to_vec()))
                .collect();
            for c in &chunks {
                out.extend(elem.encode(c).map_err(|_| fail(&py_chunks(value, chunk)))?);
            }
            return Ok(out);
        }
    }
    for item in &items[..length] {
        out.extend(elem.encode(item).map_err(|_| fail(value))?);
    }
    Ok(out)
}

/// The slices `values[i:i + size]` Python makes of a sequence: substrings of a str, bytes of bytes.
fn py_chunks(value: &Value, size: usize) -> Value {
    match value {
        Value::String(s) => {
            let chars: Vec<char> = s.chars().collect();
            Value::Array(
                chars
                    .chunks(size)
                    .map(|c| Value::String(c.iter().collect()))
                    .collect(),
            )
        }
        Value::Bytes(b) => Value::Array(b.chunks(size).map(|c| Value::Bytes(c.to_vec())).collect()),
        Value::Array(items) => Value::Array(
            items
                .chunks(size)
                .map(|c| Value::Array(c.to_vec()))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Python's `reprlib.repr()`, used in array error messages.
fn reprlib(value: &Value) -> String {
    reprlib_level(value, 6)
}

fn shorten(s: String, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s;
    }
    let i = (max - 3) / 2;
    let j = max - 3 - i;
    let head: String = chars[..i].iter().collect();
    let tail: String = chars[chars.len() - j..].iter().collect();
    format!("{head}...{tail}")
}

fn reprlib_str(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let first: String = chars.iter().take(30).collect();
    let repr = py_str_repr(&first);
    if repr.chars().count() <= 30 {
        return repr;
    }
    let mut both: String = chars[..13.min(chars.len())].iter().collect();
    both.extend(&chars[chars.len().saturating_sub(14)..]);
    let repr: Vec<char> = py_str_repr(&both).chars().collect();
    let head: String = repr[..13.min(repr.len())].iter().collect();
    let tail: String = repr[repr.len().saturating_sub(14)..].iter().collect();
    format!("{head}...{tail}")
}

fn reprlib_level(value: &Value, level: i32) -> String {
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return "[]".to_owned();
            }
            if level <= 0 {
                return "[...]".to_owned();
            }
            let mut pieces: Vec<String> = items
                .iter()
                .take(6)
                .map(|v| reprlib_level(v, level - 1))
                .collect();
            if items.len() > 6 {
                pieces.push("...".to_owned());
            }
            format!("[{}]", pieces.join(", "))
        }
        Value::Struct(map) => {
            if map.is_empty() {
                return "{}".to_owned();
            }
            if level <= 0 {
                return "{...}".to_owned();
            }
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut pieces: Vec<String> = keys
                .iter()
                .take(4)
                .map(|k| format!("{}: {}", reprlib_str(k), reprlib_level(&map[*k], level - 1)))
                .collect();
            if map.len() > 4 {
                pieces.push("...".to_owned());
            }
            format!("{{{}}}", pieces.join(", "))
        }
        Value::String(s) => reprlib_str(s),
        Value::Real(x) => shorten(py_float_repr(f64::from(*x)), 30),
        Value::LReal(x) => shorten(py_float_repr(*x), 30),
        Value::Bool(_) | Value::Bytes(_) => shorten(value.py_repr(), 30),
        other => shorten(other.py_repr(), 40),
    }
}

/// Decodes the data of a read reply (type code, or `A0 02` and a structure handle, then the values) of
/// `elements` values of a tag or member.  Returns the value and its type name: one element of an array tag is
/// its value alone, a BOOL array's words are flattened to bools (`BOOL[32 × n]`), more elements are `TYPE[n]`; a whole
/// structure's value has its public members in template order.
pub fn parse_read_reply(
    data: &[u8],
    info: TagInfo<'_>,
    elements: usize,
) -> Result<(Value, Option<String>)> {
    let type_class = info
        .type_class()
        .ok_or_else(|| Error::data("issubclass() arg 1 must be a class"))?;
    let is_struct = data.starts_with(&STRUCTURE_READ_REPLY);
    let body = data.get(if is_struct { 4 } else { 2 }..).unwrap_or(&[]);
    let mut r = Reader::new(body);
    let value = match type_class {
        TypeClass::Array(len, elem) => {
            let length = if elements > 0 { elements } else { *len };
            let items = decode_array(elem, length, &mut r)?;
            if elements == 1 && !elem.is_bit_array() {
                items
                    .into_iter()
                    .next()
                    .ok_or_else(|| Error::data("list index out of range"))?
            } else {
                Value::Array(items)
            }
        }
        other => {
            let value = other.decode(&mut r)?;
            match (is_struct, other, value) {
                (true, TypeClass::String(_), v) | (false, _, v) => v,
                (true, _, v) => filter_attributes(info, v)?,
            }
        }
    };
    let name = info.data_type_name();
    let type_name = if info.is_bool_array() {
        Some(format!("BOOL[{}]", elements * 32))
    } else if elements > 1 {
        Some(format!("{}[{elements}]", name.unwrap_or("None")))
    } else {
        name.map(str::to_owned)
    };
    Ok((value, type_name))
}

fn filter_attributes(info: TagInfo<'_>, value: Value) -> Result<Value> {
    let (TypeRef::Struct(dt), Value::Struct(mut map)) = (info.data_type(), value) else {
        return Err(Error::data("string indices must be integers"));
    };
    let mut out = IndexMap::with_capacity(dt.attributes.len());
    for attr in &dt.attributes {
        let v = map
            .swap_remove(attr)
            .or_else(|| out.get(attr).cloned())
            .ok_or_else(|| Error::Data(py_str_repr(attr)))?;
        out.insert(attr.clone(), v);
    }
    Ok(Value::Struct(out))
}

/// Encodes a write value of `elements` elements (`bool_elements` bools of a BOOL array).  Bytes are written
/// as they are.  An array tag takes a list of exactly that many values, or a single value for one element.
/// Failures are `RequestError("Unable to create a writable value - ...")` of kind BadValue.
pub fn encode_value(
    value: &Value,
    elements: usize,
    bool_elements: Option<usize>,
    type_class: Option<&TypeClass>,
) -> Result<Vec<u8>> {
    if let Value::Bytes(bytes) = value {
        return Ok(bytes.clone());
    }
    encode_value_inner(value, elements, bool_elements, type_class).map_err(|err| {
        Error::request_kind(
            format!("Unable to create a writable value - {err}"),
            ErrorKind::BadValue,
        )
    })
}

fn encode_value_inner(
    value: &Value,
    elements: usize,
    bool_elements: Option<usize>,
    type_class: Option<&TypeClass>,
) -> Result<Vec<u8>> {
    let type_class = type_class.ok_or_else(|| Error::data("issubclass() arg 1 must be a class"))?;
    let TypeClass::Array(class_length, elem) = type_class else {
        return type_class.encode(value);
    };
    let value_elements = bool_elements.filter(|&n| n > 0).unwrap_or(elements);
    let wrapped;
    let value = if value_elements > 1 {
        let len = items(value)?.len();
        if len < value_elements {
            return Err(Error::request(format!(
                "Insufficient data for requested elements, expected {value_elements} and got {len}"
            )));
        }
        if len > value_elements {
            return Err(Error::request(format!(
                "Too many values for requested elements, expected {value_elements} and got {len}"
            )));
        }
        value
    } else if let Value::Array(list) = value {
        if list.len() > 1 && !elem.is_bit_array() {
            return Err(Error::request(format!(
                "Too many values for requested elements, expected 1 and got {}",
                list.len()
            )));
        }
        value
    } else {
        wrapped = Value::Array(vec![value.clone()]);
        &wrapped
    };
    encode_array(elem, *class_length, value, Some(value_elements))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_int_follows_python_rules() {
        assert_eq!(py_int(" 5 "), Some(5));
        assert_eq!(py_int("+3"), Some(3));
        assert_eq!(py_int("-1"), Some(-1));
        assert_eq!(py_int("1_0"), Some(10));
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int("_1"), None);
        assert_eq!(py_int(""), None);
    }

    #[test]
    fn reprlib_truncates_like_python() {
        let list = Value::Array((0..8).map(Value::LInt).collect());
        assert_eq!(reprlib(&list), "[0, 1, 2, 3, 4, 5, ...]");
        assert_eq!(
            reprlib(&Value::String("x".repeat(40))),
            "'xxxxxxxxxxxx...xxxxxxxxxxxxx'"
        );
        let nested = Value::Array(vec![Value::Array(vec![Value::Array(vec![]); 1]); 1]);
        assert_eq!(reprlib(&nested), "[[[]]]");
    }

    #[test]
    fn member_type_codes_mask_the_upper_bits() {
        assert_eq!(member_elementary(0xC4), Some(Elementary::DInt));
        assert_eq!(member_elementary(0x20C4), Some(Elementary::DInt));
        assert_eq!(member_elementary(0x8000), Some(Elementary::LogixString));
        assert_eq!(member_elementary(0x8101), None);
    }
}
