//! The simulated Logix controller: its scopes and tags, the CIP services a Logix answers and the edit API.

use crate::cip::{Faults, reply};
use crate::config::{ConfigError, LogixConfig, TagConfig, TypeConfig};
use crate::identity::Identity;
use crate::metadata::{self, Selector};
use crate::model::{Atomic, BASE_TAG_BIT, StructKind, Tag, Ty, Types};
use crate::path::{Seg, attribute, class_instance, parse_path, parse_request};
use ciplink::reader::Reader;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A CIP status: general status and extended status words.
type Status = (u8, Vec<u16>);

fn status(general: u8) -> Status {
    (general, Vec::new())
}

fn ext(general: u8, extended: u16) -> Status {
    (general, vec![extended])
}

/// Permission denied, as a controller answers the read of an AOI with local tags.
fn denied() -> Status {
    ext(0x0F, 0x2100)
}

fn beyond_end() -> Status {
    ext(0xFF, 0x2105)
}

fn type_mismatch() -> Status {
    ext(0xFF, 0x2107)
}

/// A symbol of a symbol list that is not a tag: a program, routine, task or system symbol.
#[derive(Clone, Debug)]
struct Other {
    name: String,
    instance_id: u32,
    symbol_type: u16,
}

#[derive(Clone, Debug, Default)]
struct Scope {
    tags: Vec<Tag>,
    others: Vec<Other>,
    used: BTreeSet<u32>,
}

impl Scope {
    /// An instance ID: the one asked for if free, else the lowest free one (a deleted tag's ID is reused).
    fn alloc(&mut self, wanted: Option<u32>) -> Result<u32, ConfigError> {
        let id = match wanted {
            Some(0) => return Err(ConfigError::new("instance ID 0 is not a symbol")),
            Some(id) if self.used.contains(&id) => {
                return Err(ConfigError::new(format!("instance ID {id} is used twice")));
            }
            Some(id) => id,
            None => (1..).find(|id| !self.used.contains(id)).unwrap_or(u32::MAX),
        };
        self.used.insert(id);
        Ok(id)
    }

    fn tag(&self, name: &str) -> Option<usize> {
        self.tags
            .iter()
            .position(|t| t.name.eq_ignore_ascii_case(name))
    }

    fn name_taken(&self, name: &str) -> bool {
        self.tag(name).is_some()
            || self
                .others
                .iter()
                .any(|o| o.name.eq_ignore_ascii_case(name))
    }

    /// Every symbol of the scope, by instance ID.
    fn symbols(&self, types: &Types) -> Vec<Symbol<'_>> {
        let mut out: Vec<_> = self
            .tags
            .iter()
            .map(|t| {
                let mut dims = [0u32; 3];
                dims[..t.dims.len()].copy_from_slice(&t.dims);
                Symbol {
                    instance_id: t.instance_id,
                    name: &t.name,
                    symbol_type: t.symbol_type(types),
                    dims,
                    access: t.access,
                    control: if t.alias { 0 } else { BASE_TAG_BIT },
                    element_size: types.size(t.ty) as u16,
                }
            })
            .chain(self.others.iter().map(|o| Symbol {
                instance_id: o.instance_id,
                name: &o.name,
                symbol_type: o.symbol_type,
                dims: [0; 3],
                access: 0,
                control: 0,
                element_size: 0,
            }))
            .collect();
        out.sort_by_key(|s| s.instance_id);
        out
    }
}

/// A symbol object's attributes as Get_Instance_Attribute_List returns them.
struct Symbol<'a> {
    instance_id: u32,
    name: &'a str,
    symbol_type: u16,
    dims: [u32; 3],
    access: u8,
    /// Software control word (attribute 6): the base tag bit unless an alias.
    control: u32,
    /// Bytes of one element (attribute 7).
    element_size: u16,
}

#[derive(Clone, Debug)]
struct Program {
    name: String,
    scope: Scope,
    /// Instance of the program object (class 0x68), attribute 0x0D of its symbol and the instance of the
    /// Descriptions of its tags (0x6B << 16 | reference).
    reference: u16,
}

/// The tag table version attributes of class 0xAC: 1 the edit counter, 2, 3 and 4 the download timestamps
/// and 10 the project timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableVersion {
    counter: i16,
    attr2: i16,
    download: i32,
    download2: i32,
    project: i32,
}

/// A request path resolved to a region of a tag.
#[derive(Clone, Debug)]
struct Target {
    program: Option<usize>,
    tag: usize,
    offset: usize,
    ty: Ty,
    /// Elements from `offset` to the end of the array, 1 for a scalar.
    count: usize,
    /// The whole array (no index), its value is a list.
    whole_array: bool,
    bit: Option<u8>,
    /// The tag path, e.g. `Program:Main.tag[1].member`, and of its base tag.
    path: String,
    base: String,
    access: u8,
    /// A whole AOI with local tags, refused.
    refused: bool,
}

/// A simulated ControlLogix, CompactLogix or Micro800.
///
/// The edit methods change it like an online edit (the tag table edit counter is bumped) or a download.
#[derive(Clone, Debug)]
pub struct Logix {
    pub(crate) identity: Identity,
    pub(crate) modules: Vec<(u8, Identity)>,
    pub(crate) slot: u8,
    pub(crate) chassis_size: u8,
    pub(crate) ip: (Ipv4Addr, Ipv4Addr),
    pub(crate) network: Vec<(String, Identity)>,
    pub(crate) max_connection_size: u16,
    pub(crate) large_forward_open: bool,
    program_name: String,
    multi_service: bool,
    instance_ids: bool,
    tag_table_version: bool,
    aoi_locals_refused: bool,
    micro800: bool,
    metadata_auth: bool,
    /// The CIP connection (O->T ID) of the request being answered, None for an unconnected one.
    pub(crate) connection: Option<u32>,
    /// Metadata challenges awaiting completion: (connection, expected proof, grants).
    challenges: Vec<(u32, [u8; 20], Vec<u8>)>,
    /// Connections that passed the metadata authentication.
    authenticated: BTreeSet<u32>,
    types: Types,
    controller: Scope,
    programs: Vec<Program>,
    version: TableVersion,
    clock_offset_us: i128,
    /// Controller-side trends (class 0xB2) by instance.
    trends: BTreeMap<u32, Trend>,
}

/// A controller-side trend (class 0xB2, the object Studio 5000 trends use): one driver of pens, each a
/// tag path and a mask over the 32-bit word at the tag's address, sampled every `period_us * multiplier`.
#[derive(Clone, Debug)]
struct Trend {
    period_us: u32,
    driver: Option<TrendDriver>,
    started: Option<Instant>,
    /// Samples uploaded (or dropped) since the start.
    sent: u64,
}

/// The pens of a trend: each a resolved tag path and the mask over the word at its address.
#[derive(Clone, Debug)]
struct TrendDriver {
    id: u16,
    /// Samples are taken every `multiplier` periods.
    multiplier: u8,
    pens: Vec<(Target, u32)>,
}

/// The most samples a trend keeps for upload; older ones are dropped, as a controller's buffer overflows.
const TREND_BACKLOG: u64 = 20_000;
/// Trend clock ticks are 128 µs.
const TREND_TICK_US: u64 = 128;

fn now_us() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i128)
}

impl Logix {
    /// Builds a controller from its configuration.
    pub fn new(config: &LogixConfig) -> Result<Self, ConfigError> {
        // program references count up from 0x5AD0 in 16 bits
        if config.programs.len() > usize::from(u16::MAX - 0x5AD0) {
            return Err(ConfigError::new("too many programs"));
        }
        let types = Types::build(&config.types)?;
        let mut controller = Scope::default();
        // explicit instance IDs first, so the others are allocated around them
        let reserve = |scope: &mut Scope, id: Option<u32>| -> Result<(), ConfigError> {
            if let Some(id) = id {
                scope.alloc(Some(id))?;
            }
            Ok(())
        };
        for p in &config.programs {
            reserve(&mut controller, p.instance_id)?;
        }
        for t in &config.tasks {
            reserve(&mut controller, t.instance_id)?;
        }
        for s in &config.system_tags {
            reserve(&mut controller, s.instance_id)?;
        }
        for t in &config.tags {
            reserve(&mut controller, t.instance_id)?;
        }
        let id_of = |scope: &mut Scope, wanted: Option<u32>| -> Result<u32, ConfigError> {
            match wanted {
                Some(id) => Ok(id),
                None => scope.alloc(None),
            }
        };
        let mut programs = Vec::new();
        for p in &config.programs {
            if p.name.is_empty() || controller.name_taken(&format!("Program:{}", p.name)) {
                return Err(ConfigError::new(format!(
                    "program {:?} is defined twice or has no name",
                    p.name
                )));
            }
            let instance_id = id_of(&mut controller, p.instance_id)?;
            controller.others.push(Other {
                name: format!("Program:{}", p.name),
                instance_id,
                symbol_type: 0x1068,
            });
            let mut scope = Scope::default();
            for t in &p.tags {
                reserve(&mut scope, t.instance_id)?;
            }
            for routine in &p.routines {
                let instance_id = scope.alloc(None)?;
                scope.others.push(Other {
                    name: format!("Routine:{routine}"),
                    instance_id,
                    symbol_type: 0x106D,
                });
            }
            for t in &p.tags {
                if scope.name_taken(&t.name) {
                    return Err(ConfigError::new(format!(
                        "tag Program:{}.{} is defined twice",
                        p.name, t.name
                    )));
                }
                let id = id_of(&mut scope, t.instance_id)?;
                scope.tags.push(Tag::build(&types, t, id)?);
            }
            programs.push(Program {
                name: p.name.clone(),
                scope,
                // invariant: the program count was checked above, so this fits 16 bits
                reference: 0x5AD0 + programs.len() as u16,
            });
        }
        for t in &config.tasks {
            let instance_id = id_of(&mut controller, t.instance_id)?;
            controller.others.push(Other {
                name: format!("Task:{}", t.name),
                instance_id,
                symbol_type: 0x1070,
            });
        }
        for s in &config.system_tags {
            let instance_id = id_of(&mut controller, s.instance_id)?;
            controller.others.push(Other {
                name: s.name.clone(),
                instance_id,
                symbol_type: s.symbol_type.unwrap_or(0x10C4),
            });
        }
        for t in &config.tags {
            if controller.name_taken(&t.name) {
                return Err(ConfigError::new(format!("tag {} is defined twice", t.name)));
            }
            let id = id_of(&mut controller, t.instance_id)?;
            controller.tags.push(Tag::build(&types, t, id)?);
        }
        let mut modules = Vec::new();
        for m in &config.modules {
            if m.slot == config.slot {
                return Err(ConfigError::new(format!(
                    "module slot {} is the controller's",
                    m.slot
                )));
            }
            modules.push((m.slot, Identity::build(&m.identity)?));
        }
        let parse_ip = |text: &str| {
            text.parse::<Ipv4Addr>()
                .map_err(|_| ConfigError::new(format!("{text:?} is not an IPv4 address")))
        };
        let ip = (parse_ip(&config.ip)?, parse_ip(&config.netmask)?);
        let mut network = Vec::new();
        for d in &config.network {
            network.push((parse_ip(&d.ip)?.to_string(), Identity::build(&d.identity)?));
        }
        let micro800 = config.micro800;
        Ok(Logix {
            identity: Identity::build(&config.identity)?,
            modules,
            slot: config.slot,
            chassis_size: config.chassis_size,
            ip,
            network,
            max_connection_size: config.max_connection_size,
            large_forward_open: config.large_forward_open && !micro800,
            program_name: config.program_name.clone(),
            multi_service: config.multi_service && !micro800,
            instance_ids: config.instance_ids && !micro800,
            tag_table_version: config.tag_table_version && !micro800,
            aoi_locals_refused: config.aoi_locals_refused,
            micro800,
            metadata_auth: config.metadata_auth,
            connection: None,
            challenges: Vec::new(),
            authenticated: BTreeSet::new(),
            types,
            controller,
            programs,
            version: TableVersion {
                counter: 1,
                attr2: 0,
                download: 0x6500_0000,
                download2: 0x0001_0000,
                project: 0x6500_0001,
            },
            clock_offset_us: config.clock_us.map_or(0, |us| i128::from(us) - now_us()),
            trends: BTreeMap::new(),
        })
    }

    // ---- edit API ----

    fn scope_mut(&mut self, program: Option<&str>) -> Result<&mut Scope, ConfigError> {
        match program {
            None => Ok(&mut self.controller),
            Some(name) => self
                .programs
                .iter_mut()
                .find(|p| p.name.eq_ignore_ascii_case(name))
                .map(|p| &mut p.scope)
                .ok_or_else(|| ConfigError::new(format!("no program {name}"))),
        }
    }

    fn edited(&mut self) {
        self.version.counter = self.version.counter.wrapping_add(1);
    }

    /// Creates a tag (online edit) in the controller or a program scope, returns its instance ID: the one
    /// configured, else the lowest free one, so a deleted tag's ID goes to the next tag created.
    pub fn add_tag(&mut self, program: Option<&str>, tag: &TagConfig) -> Result<u32, ConfigError> {
        let types = self.types.clone();
        let scope = self.scope_mut(program)?;
        if scope.name_taken(&tag.name) {
            return Err(ConfigError::new(format!("tag {} exists", tag.name)));
        }
        let mut probe = scope.clone();
        let id = probe.alloc(tag.instance_id)?;
        let built = Tag::build(&types, tag, id)?;
        scope.used.insert(id);
        scope.tags.push(built);
        self.edited();
        Ok(id)
    }

    /// Deletes a tag (online edit), its instance ID is free again.
    pub fn remove_tag(&mut self, program: Option<&str>, name: &str) -> Result<(), ConfigError> {
        let scope = self.scope_mut(program)?;
        let index = scope
            .tag(name)
            .ok_or_else(|| ConfigError::new(format!("no tag {name}")))?;
        let tag = scope.tags.remove(index);
        scope.used.remove(&tag.instance_id);
        self.edited();
        Ok(())
    }

    /// Creates a data type (online edit).
    pub fn add_type(&mut self, data_type: &TypeConfig) -> Result<(), ConfigError> {
        if let Some(m) = data_type
            .members
            .iter()
            .find(|m| self.types.lookup(&m.data_type).is_none())
        {
            return Err(ConfigError::new(format!(
                "{}.{} has an unknown type",
                data_type.name, m.name
            )));
        }
        let mut types = self.types.clone();
        types.add(data_type)?;
        self.types = types;
        self.edited();
        Ok(())
    }

    /// Replaces the whole project as a download does: new tags and types, new download and project timestamps.
    pub fn download(&mut self, config: &LogixConfig) -> Result<(), ConfigError> {
        let mut new = Logix::new(config)?;
        new.version = TableVersion {
            counter: 1,
            attr2: self.version.attr2,
            download: self.version.download.wrapping_add(1),
            download2: self.version.download2,
            project: self.version.project.wrapping_add(1),
        };
        new.clock_offset_us = self.clock_offset_us;
        *self = new;
        Ok(())
    }

    /// Bumps the tag table edit counter without changing anything, as an edit of a routine might.
    pub fn bump_tag_table(&mut self) {
        self.edited();
    }

    /// The tag table version: the edit counter, attribute 2, the download timestamps and the project timestamp.
    pub fn tag_table_version(&self) -> (i16, i16, i32, i32, i32) {
        let v = self.version;
        (v.counter, v.attr2, v.download, v.download2, v.project)
    }

    /// The instance ID of a tag, None if there is no such tag.
    pub fn instance_id(&self, program: Option<&str>, name: &str) -> Option<u32> {
        let scope = match program {
            None => &self.controller,
            Some(p) => {
                &self
                    .programs
                    .iter()
                    .find(|x| x.name.eq_ignore_ascii_case(p))?
                    .scope
            }
        };
        scope.tag(name).map(|i| scope.tags[i].instance_id)
    }

    /// The value of a tag, member or element as JSON, e.g. `Program:Main.tag[1].member`; a whole array is a
    /// list, a structure an object of its members, a BOOL array a list of bools.
    pub fn value(&self, path: &str) -> Result<Json, ConfigError> {
        let target = self
            .resolve(&text_path(path)?, false)
            .map_err(|_| ConfigError::new(format!("no tag {path}")))?;
        let data = &self.scope(target.program).tags[target.tag].data;
        Ok(match target.bit {
            Some(bit) => Json::Bool(data[target.offset] & (1 << bit) != 0),
            None if target.whole_array => {
                let size = self.types.size(target.ty);
                self.types.decode_elements(
                    target.ty,
                    target.count,
                    &data[target.offset..target.offset + size * target.count],
                )
            }
            None => self.types.decode(
                target.ty,
                &data[target.offset..target.offset + self.types.size(target.ty)],
            ),
        })
    }

    /// Sets the value of a tag, member or element from JSON (members left out of an object are unchanged).
    pub fn set_value(&mut self, path: &str, value: &Json) -> Result<(), ConfigError> {
        let target = self
            .resolve(&text_path(path)?, false)
            .map_err(|_| ConfigError::new(format!("no tag {path}")))?;
        let size = self.types.size(target.ty);
        let types = &self.types;
        let scope = match target.program {
            None => &mut self.controller,
            Some(p) => &mut self.programs[p].scope,
        };
        let data = &mut scope.tags[target.tag].data;
        let result = match target.bit {
            Some(bit) => match value {
                Json::Bool(b) => {
                    if *b {
                        data[target.offset] |= 1 << bit;
                    } else {
                        data[target.offset] &= !(1 << bit);
                    }
                    Ok(())
                }
                other => Err(format!("expected a bool, got {other}")),
            },
            None if target.whole_array => types.encode_elements(
                target.ty,
                target.count,
                value,
                &mut data[target.offset..target.offset + size * target.count],
            ),
            None => types.encode(
                target.ty,
                value,
                &mut data[target.offset..target.offset + size],
            ),
        };
        result.map_err(|e| ConfigError::new(format!("{path}: {e}")))
    }

    /// The controller clock, microseconds since 1970 UTC.
    pub fn clock_us(&self) -> u64 {
        (now_us() + self.clock_offset_us).max(0) as u64
    }

    // ---- requests ----

    fn scope(&self, program: Option<usize>) -> &Scope {
        match program {
            None => &self.controller,
            Some(p) => &self.programs[p].scope,
        }
    }

    fn program(&self, name: &str) -> Option<usize> {
        let name = strip_program(name)?;
        self.programs
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// Resolves a tag request path; `enforce` applies the AOI and external access rules of a client request.
    fn resolve(&self, path: &[Seg], enforce: bool) -> Result<Target, Status> {
        let (program, rest) = match path {
            [Seg::Symbol(s), rest @ ..] if strip_program(s).is_some() && !rest.is_empty() => {
                (Some(self.program(s).ok_or_else(|| status(0x04))?), rest)
            }
            _ => (None, path),
        };
        let scope = self.scope(program);
        let (tag_index, rest) = match rest {
            [Seg::Symbol(name), rest @ ..] => (scope.tag(name).ok_or_else(|| status(0x04))?, rest),
            [Seg::Class(0x6B), Seg::Instance(id), rest @ ..] => {
                if !self.instance_ids {
                    return Err(status(0x05));
                }
                let index = scope
                    .tags
                    .iter()
                    .position(|t| t.instance_id == *id)
                    .ok_or_else(|| status(0x05))?;
                (index, rest)
            }
            _ => return Err(status(0x04)),
        };
        let tag = &scope.tags[tag_index];
        let base = match program {
            Some(p) => format!("Program:{}.{}", self.programs[p].name, tag.name),
            None => tag.name.clone(),
        };
        let mut target = Target {
            program,
            tag: tag_index,
            offset: 0,
            ty: tag.ty,
            count: tag.elements,
            whole_array: !tag.dims.is_empty(),
            bit: None,
            path: base.clone(),
            base,
            access: tag.access,
            refused: false,
        };
        // the dimensions of the array being indexed, None once indexed or for a scalar
        let mut dims: Option<Vec<u32>> = match (tag.ty, tag.dims.len()) {
            (_, 0) => None,
            (Ty::Atomic(Atomic::DWord), _) => Some(vec![tag.elements as u32]),
            _ => Some(tag.dims.clone()),
        };
        let mut i = 0;
        while i < rest.len() {
            match &rest[i] {
                Seg::Element(_) => {
                    let mut index = Vec::new();
                    while let Some(Seg::Element(e)) = rest.get(i) {
                        index.push(*e);
                        i += 1;
                    }
                    let shape = dims.take().ok_or_else(|| status(0x04))?;
                    if index.len() != shape.len() {
                        return Err(status(0x04));
                    }
                    let mut linear = 0usize;
                    for (&e, &d) in index.iter().zip(&shape) {
                        if e >= d {
                            return Err(status(0x05));
                        }
                        linear = linear * d as usize + e as usize;
                    }
                    target.offset += linear * self.types.size(target.ty);
                    target.count -= linear;
                    target.whole_array = false;
                    let text: Vec<String> = index.iter().map(u32::to_string).collect();
                    target.path.push_str(&format!("[{}]", text.join(",")));
                    continue;
                }
                Seg::Symbol(name) => {
                    if dims.is_some() || target.bit.is_some() {
                        return Err(status(0x04));
                    }
                    let Ty::Struct(s) = target.ty else {
                        return Err(status(0x04));
                    };
                    let def = self.types.def(s);
                    let member = def.member(name).ok_or_else(|| status(0x04))?;
                    if enforce && member.local && self.aoi_locals_refused {
                        return Err(status(0x04));
                    }
                    target.access = target.access.max(member.access);
                    target.offset += member.offset as usize;
                    target.path.push('.');
                    target.path.push_str(&member.name);
                    if member.bit.is_some() {
                        target.bit = member.bit;
                        target.ty = Ty::Atomic(Atomic::Bool);
                        target.count = 1;
                        target.whole_array = false;
                    } else {
                        target.ty = member.ty;
                        target.count = member.array.max(1) as usize;
                        target.whole_array = member.array > 0;
                        dims = (member.array > 0).then(|| vec![member.array]);
                    }
                }
                _ => return Err(status(0x04)),
            }
            i += 1;
        }
        if let Ty::Struct(s) = target.ty {
            let def = self.types.def(s);
            target.refused =
                def.kind == StructKind::Aoi && def.has_locals() && self.aoi_locals_refused;
        }
        Ok(target)
    }

    /// Answers a CIP message with a reply of at most `limit` bytes.
    pub(crate) fn message(&mut self, message: &[u8], limit: usize, faults: &Faults) -> Vec<u8> {
        let service = message.first().copied().unwrap_or(0);
        let Some(request) = parse_request(message) else {
            return reply(service, 0x04, &[], &[]);
        };
        let class =
            class_instance(&request.path)
                .map(|(c, _)| c)
                .or(match request.path.as_slice() {
                    [Seg::Symbol(_), Seg::Class(c), ..] => Some(*c),
                    _ => None,
                });
        if let Some((general, extended)) = faults.service_status(service, class) {
            return reply(service, general, &extended, &[]);
        }
        let result = match (class_instance(&request.path), service) {
            (Some((0x02, 1)), 0x0A) => return self.multi_service(request.data, limit, faults),
            (Some((0x349, 0)), 0x53) if !self.micro800 => {
                return self.descriptions(request.data, limit);
            }
            (Some((0x64, 1)), 0x4B) if !self.micro800 => self.metadata_challenge(request.data),
            (Some((0x64, 1)), 0x4C) if !self.micro800 => self.metadata_completion(request.data),
            (Some((0x6B, id)), 0x03) if !self.micro800 => self.symbol_attributes(id, request.data),
            (Some((0x01, 1)), 0x01) => Ok(self.identity.attributes_all()),
            (Some((0x01, 1)), 0x0E) => attribute(&request.path)
                .and_then(|a| self.identity.attribute(a))
                .ok_or_else(|| status(0x14)),
            (Some((0x01, _)), _)
            | (Some((0x64, _)), _)
            | (Some((0x8B, _)), _)
            | (Some((0xAC, _)), _)
                if !matches!(class_instance(&request.path), Some((_, 1))) =>
            {
                Err(status(0x05))
            }
            (Some((0x64, 1)), 0x01) => {
                let mut out = (self.program_name.len() as u16).to_le_bytes().to_vec();
                out.extend(self.program_name.as_bytes());
                Ok(out)
            }
            (Some((0x6C, id)), 0x03) => self.makeup(id, request.data),
            (Some((0x6C, id)), 0x4C) => return self.read_template(id, request.data, limit),
            (Some((0xAC, 1)), 0x03) if self.tag_table_version => {
                self.version_attributes(request.data)
            }
            (Some((0xAC, 1)), _) => Err(status(if self.tag_table_version { 0x08 } else { 0x05 })),
            (Some((0x8B, 1)), 0x03) => self.clock_get(request.data),
            (Some((0x8B, 1)), 0x0E) => match attribute(&request.path) {
                Some(6) => Ok(self.clock_us().to_le_bytes().to_vec()),
                _ => Err(status(0x14)),
            },
            (Some((0x8B, 1)), 0x04) => self.clock_set(request.data),
            (Some((0xB2, 0)), 0x08) if !self.micro800 => Ok(self.trend_create()),
            (Some((0xB2, 0)), 0x03) if !self.micro800 => {
                let last = self.trends.keys().next_back().copied().unwrap_or(0);
                let count = self.trends.len();
                get_attribute_list(request.data, |a| match a {
                    1 => Some(3u16.to_le_bytes().to_vec()),
                    2 => Some((last as u16).to_le_bytes().to_vec()),
                    3 => Some((count as u16).to_le_bytes().to_vec()),
                    _ => None,
                })
            }
            (Some((0xB2, id)), _) if !self.micro800 && id != 0 => {
                return self.trend_service(service, id, request.data, limit);
            }
            (_, 0x55) => return self.symbol_list(&request.path, request.data, limit),
            (_, 0x4C | 0x52 | 0x4D | 0x53 | 0x4E) if is_tag_path(&request.path) => {
                return self.tag_service(service, &request.path, request.data, limit, faults);
            }
            (Some((0x01 | 0x02 | 0x64 | 0x6C | 0x8B, _)), _) => Err(status(0x08)),
            _ => Err(status(0x05)),
        };
        let out = match result {
            Ok(data) => reply(service, 0, &[], &data),
            Err((general, extended)) => reply(service, general, &extended, &[]),
        };
        if out.len() > limit {
            return reply(service, 0x11, &[], &[]);
        }
        out
    }

    fn multi_service(&mut self, data: &[u8], limit: usize, faults: &Faults) -> Vec<u8> {
        if !self.multi_service {
            return reply(0x0A, 0x08, &[], &[]);
        }
        let Some(messages) = split_multi(data) else {
            return reply(0x0A, 0x13, &[], &[]);
        };
        let count = messages.len();
        let mut used = 4 + 2 + 2 * count;
        let mut replies = Vec::with_capacity(count);
        for (i, message) in messages.iter().enumerate() {
            // room for at least the reply header of each service after this one
            let sub_limit = limit.saturating_sub(used + 4 * (count - i - 1));
            let sub = match message.first() {
                Some(0x0A) => reply(0x0A, 0x08, &[], &[]), // not nested, nor recursed into
                _ => self.message(message, sub_limit, faults),
            };
            used += sub.len();
            replies.push(sub);
        }
        let general = if replies.iter().any(|r| r.get(2) != Some(&0)) {
            0x1E
        } else {
            0
        };
        // the per-service budgets cannot hold when the services' error replies alone outgrow the connection
        // (many tiny requests), and offsets past 64 KB would wrap: such a reply is refused whole
        if 4 + 2 + 2 * count + replies.iter().map(Vec::len).sum::<usize>() > limit {
            return reply(0x0A, 0x11, &[], &[]);
        }
        let mut body = (count as u16).to_le_bytes().to_vec();
        let mut offset = 2 + 2 * count;
        for r in &replies {
            body.extend((offset as u16).to_le_bytes());
            offset += r.len();
        }
        for r in &replies {
            body.extend(r);
        }
        reply(0x0A, general, &[], &body)
    }

    fn makeup(&self, id: u32, data: &[u8]) -> Result<Vec<u8>, Status> {
        let def = self.types.by_template(id).ok_or_else(|| status(0x05))?;
        get_attribute_list(data, |attribute| match attribute {
            1 => Some(def.handle.to_le_bytes().to_vec()),
            2 => Some((def.members.len() as u16).to_le_bytes().to_vec()),
            4 => Some(def.object_definition_size().to_le_bytes().to_vec()),
            5 => Some(def.size.to_le_bytes().to_vec()),
            _ => None,
        })
    }

    fn read_template(&self, id: u32, data: &[u8], limit: usize) -> Vec<u8> {
        let Some(def) = self.types.by_template(id) else {
            return reply(0x4C, 0x05, &[], &[]);
        };
        if data.len() < 6 {
            return reply(0x4C, 0x13, &[], &[]);
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let wanted = usize::from(u16::from_le_bytes([data[4], data[5]]));
        if offset > def.template.len() {
            return reply(0x4C, 0xFF, &[0x2105], &[]);
        }
        let available = wanted.min(def.template.len() - offset);
        let room = limit.saturating_sub(4);
        if available > 0 && room == 0 {
            // an empty 0x06 page would have the client ask for the same offset forever
            return reply(0x4C, 0x11, &[], &[]);
        }
        let (size, general) = if available > room {
            (room, 0x06)
        } else {
            (available, 0)
        };
        reply(0x4C, general, &[], &def.template[offset..offset + size])
    }

    fn version_attributes(&self, data: &[u8]) -> Result<Vec<u8>, Status> {
        let v = self.version;
        get_attribute_list(data, |attribute| match attribute {
            1 => Some(v.counter.to_le_bytes().to_vec()),
            2 => Some(v.attr2.to_le_bytes().to_vec()),
            3 => Some(v.download.to_le_bytes().to_vec()),
            4 => Some(v.download2.to_le_bytes().to_vec()),
            10 => Some(v.project.to_le_bytes().to_vec()),
            _ => None,
        })
    }

    // ---- trends (class 0xB2) ----

    /// Create (0x08): a new trend instance, its id twice (the attributes of the request are not checked).
    fn trend_create(&mut self) -> Vec<u8> {
        let id = (1..)
            .find(|id| !self.trends.contains_key(id))
            .unwrap_or(u32::MAX);
        self.trends.insert(
            id,
            Trend {
                period_us: 10_000,
                driver: None,
                started: None,
                sent: 0,
            },
        );
        [id.to_le_bytes(), id.to_le_bytes()].concat()
    }

    /// The services of a trend instance; answers the whole reply.
    fn trend_service(&mut self, service: u8, id: u32, data: &[u8], limit: usize) -> Vec<u8> {
        let fail = |(general, extended): Status| reply(service, general, &extended, &[]);
        if !self.trends.contains_key(&id) {
            return fail(status(0x05));
        }
        let result = match service {
            0x04 => self.trend_set(id, data),
            0x4E => self.trend_add_driver(id, data),
            0x06 => {
                let now = self.clock_us();
                self.trend_mut(id).map(|t| {
                    t.started = Some(Instant::now());
                    t.sent = 0;
                    now.to_le_bytes().to_vec()
                })
            }
            0x4C => return self.trend_upload(id, limit),
            0x07 => self.trend_mut(id).map(|t| {
                t.started = None;
                Vec::new()
            }),
            0x4F => self.trend_mut(id).map(|t| {
                t.driver = None;
                Vec::new()
            }),
            0x09 => {
                self.trends.remove(&id);
                Ok(Vec::new())
            }
            _ => Err(status(0x08)),
        };
        match result {
            Ok(data) => reply(service, 0, &[], &data),
            Err(s) => fail(s),
        }
    }

    fn trend_mut(&mut self, id: u32) -> Result<&mut Trend, Status> {
        self.trends.get_mut(&id).ok_or_else(|| status(0x05))
    }

    /// Set_Attribute_List: attribute 1 the sample period in µs (1 ms or more), attribute 5 a USINT.
    fn trend_set(&mut self, id: u32, data: &[u8]) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(data);
        let count = r.u16().map_err(|_| status(0x13))?;
        let mut out = count.to_le_bytes().to_vec();
        let mut failed = false;
        for _ in 0..count {
            let attribute = r.u16().map_err(|_| status(0x13))?;
            out.extend(attribute.to_le_bytes());
            let code: u16 = match attribute {
                1 => {
                    let period = r.u32().map_err(|_| status(0x13))?;
                    if period < 1000 {
                        0x09
                    } else {
                        self.trend_mut(id)?.period_us = period;
                        0
                    }
                }
                5 => {
                    r.u8().map_err(|_| status(0x13))?;
                    0
                }
                _ => {
                    out.extend(0x14u16.to_le_bytes());
                    return Err(status(0x0A));
                }
            };
            failed |= code != 0;
            out.extend(code.to_le_bytes());
        }
        if failed {
            return Err(status(0x0A));
        }
        Ok(out)
    }

    /// Add Driver (0x4E): driver id, sample multiplier, pen count, then each pen's padded path and mask.
    fn trend_add_driver(&mut self, id: u32, data: &[u8]) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(data);
        let short = |_| status(0x13);
        let driver = r.u16().map_err(short)?;
        let multiplier = r.u8().map_err(short)?.max(1);
        let count = r.u8().map_err(short)?;
        let mut pens = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let words = usize::from(r.u8().map_err(short)?);
            let path = parse_path(r.take(words * 2).map_err(short)?).ok_or_else(|| status(0x04))?;
            let mask = r.u32().map_err(short)?;
            pens.push((self.resolve(&path, true)?, mask));
        }
        self.trend_mut(id)?.driver = Some(TrendDriver {
            id: driver,
            multiplier,
            pens,
        });
        Ok(driver.to_le_bytes().to_vec())
    }

    /// Upload (0x4C): the samples due since the last upload, each the driver id, the elapsed 128 µs ticks
    /// and a masked word per pen; status 0x06 when more are due than fit in the reply.
    fn trend_upload(&mut self, id: u32, limit: usize) -> Vec<u8> {
        let Some(trend) = self.trends.get(&id) else {
            return reply(0x4C, 0x05, &[], &[]);
        };
        let (
            Some(started),
            Some(TrendDriver {
                id: driver,
                multiplier,
                pens,
            }),
        ) = (trend.started, &trend.driver)
        else {
            return reply(0x4C, 0x0C, &[], &[]);
        };
        let every = u64::from(trend.period_us) * u64::from(*multiplier);
        let due = started.elapsed().as_micros() as u64 / every;
        let first = trend.sent.max(due.saturating_sub(TREND_BACKLOG));
        let size = 6 + 4 * pens.len();
        let fit = (limit.saturating_sub(4) / size) as u64;
        let last = due.min(first + fit);
        let words: Vec<u32> = pens
            .iter()
            .map(|(target, mask)| {
                let data = &self.scope(target.program).tags[target.tag].data;
                let mut word = [0u8; 4];
                for (i, b) in word.iter_mut().enumerate() {
                    *b = data.get(target.offset + i).copied().unwrap_or(0);
                }
                u32::from_le_bytes(word) & mask
            })
            .collect();
        let mut out = Vec::with_capacity(size * (last - first) as usize);
        for sample in first + 1..=last {
            out.extend(driver.to_le_bytes());
            out.extend((((sample * every) / TREND_TICK_US) as u32).to_le_bytes());
            for word in &words {
                out.extend(word.to_le_bytes());
            }
        }
        let general = if last < due { 0x06 } else { 0 };
        if let Some(t) = self.trends.get_mut(&id) {
            t.sent = last;
        }
        reply(0x4C, general, &[], &out)
    }

    fn clock_get(&self, data: &[u8]) -> Result<Vec<u8>, Status> {
        let now = self.clock_us();
        get_attribute_list(data, |attribute| {
            (attribute == 6).then(|| now.to_le_bytes().to_vec())
        })
    }

    fn clock_set(&mut self, data: &[u8]) -> Result<Vec<u8>, Status> {
        let count = read_u16(data, 0).ok_or_else(|| status(0x13))?;
        let mut out = count.to_le_bytes().to_vec();
        let mut pos = 2;
        for _ in 0..count {
            let attribute = read_u16(data, pos).ok_or_else(|| status(0x13))?;
            out.extend(attribute.to_le_bytes());
            if attribute != 6 {
                out.extend(0x14u16.to_le_bytes());
                return Ok(out); // the value size of an unknown attribute is unknown, the rest is not read
            }
            let value = data.get(pos + 2..pos + 10).ok_or_else(|| status(0x13))?;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(value);
            self.clock_offset_us = i128::from(u64::from_le_bytes(bytes)) - now_us();
            out.extend(0u16.to_le_bytes());
            pos += 10;
        }
        Ok(out)
    }

    /// Get_Attribute_List of a controller-scope symbol: attribute 0x0D of a program is its program object
    /// reference (a padded path to class 0x68), any other attribute is not supported (0x14).
    fn symbol_attributes(&self, id: u32, data: &[u8]) -> Result<Vec<u8>, Status> {
        let program = self.controller.others.iter().find(|o| o.instance_id == id);
        if program.is_none() && !self.controller.tags.iter().any(|t| t.instance_id == id) {
            return Err(status(0x05));
        }
        let reference = program
            .and_then(|o| self.program(&o.name))
            .map(|index| self.programs[index].reference);
        get_attribute_list(data, |attribute| {
            let reference = reference.filter(|_| attribute == 0x0D)?;
            let mut path = vec![3, 0x20, 0x68, 0x25, 0];
            path.extend(reference.to_le_bytes());
            Some(path)
        })
    }

    /// A Description read (service 0x53 of class 0x349): a page of the records it selects.
    fn descriptions(&self, data: &[u8], limit: usize) -> Vec<u8> {
        let fail = |general| reply(0x53, general, &[], &[]);
        if self.metadata_auth
            && !self
                .connection
                .is_some_and(|c| self.authenticated.contains(&c))
        {
            return fail(0x0F);
        }
        let Some(request) = metadata::parse_request(data) else {
            return fail(0x13);
        };
        let payload = match request.selector {
            Selector::Index { language } => self.description_index(language),
            Selector::One {
                class,
                instance,
                owner,
                path,
                language,
            } => match self.description(class, instance, owner, &path, language) {
                Ok(payload) => payload,
                Err(general) => return fail(general),
            },
        };
        let Ok(offset) = usize::try_from(request.offset) else {
            return fail(0x13);
        };
        if offset > payload.len() {
            let (general, extended) = beyond_end();
            return reply(0x53, general, &extended, &[]);
        }
        match metadata::page(&payload, offset, limit.saturating_sub(4)) {
            Some(page) => reply(0x53, 0, &[], &page),
            None => fail(0x11),
        }
    }

    /// The members' default Descriptions: records of class 0x6C, the template in the instance's low word and
    /// the member ID as owner.
    fn description_index(&self, language: u16) -> Vec<u8> {
        let mut out = Vec::new();
        if language != metadata::LANGUAGE {
            return out;
        }
        for def in &self.types.defs {
            for (index, text) in &def.descriptions {
                out.extend(metadata::record(
                    0x6C,
                    0x84FE_0000 | u32::from(def.template_id),
                    (u32::from(def.member_id(*index)), 0),
                    "",
                    language,
                    text,
                ));
            }
        }
        out
    }

    /// The Description record of a tag (class 0x6B: a controller tag by instance; class 0x68: a program tag,
    /// the program in the instance and the tag in the owner), none if it has no Description at `path`; status
    /// 0x05 for no such tag.
    fn description(
        &self,
        class: u16,
        instance: u32,
        owner: (u32, u16),
        path: &str,
        language: u16,
    ) -> Result<Vec<u8>, u8> {
        let tag = match (class, owner) {
            (0x6B, (0, 0)) => self
                .controller
                .tags
                .iter()
                .find(|t| t.instance_id == instance),
            (0x68, (id, 0)) if instance >> 16 == 0x6B => self
                .programs
                .iter()
                .find(|p| u32::from(p.reference) == instance & 0xFFFF)
                .and_then(|p| p.scope.tags.iter().find(|t| t.instance_id == id)),
            _ => None,
        }
        .ok_or(0x05)?;
        let Some(key) = self.description_key(tag.ty, path) else {
            return Ok(Vec::new());
        };
        Ok(tag
            .descriptions
            .iter()
            .find(|(p, _)| p.eq_ignore_ascii_case(&key))
            .filter(|_| language == metadata::LANGUAGE)
            .map(|(_, text)| metadata::record(class, instance, owner, path, language, text))
            .unwrap_or_default())
    }

    /// A Description path with its member IDs (`.!TTTTMMMM`, template and member ID) replaced by the member
    /// names, as the configuration keys them; None if a member ID is not one of the type at that point.
    fn description_key(&self, mut ty: Ty, path: &str) -> Option<String> {
        let mut key = String::with_capacity(path.len());
        let mut rest = path;
        while let Some(at) = rest.find(".!") {
            key.push_str(&rest[..at]);
            let id = rest.get(at + 2..at + 10)?;
            let template = u16::from_str_radix(id.get(..4)?, 16).ok()?;
            let member = u16::from_str_radix(id.get(4..)?, 16).ok()?;
            let Ty::Struct(s) = ty else { return None };
            let def = self.types.def(s);
            if def.template_id != template {
                return None;
            }
            let index = (0..def.members.len()).find(|&i| def.member_id(i) == member)?;
            key.push('.');
            key.push_str(&def.members[index].name);
            ty = def.members[index].ty;
            rest = &rest[at + 10..];
        }
        key.push_str(rest);
        Some(key)
    }

    /// The metadata challenge (service 0x4B): the certificate in the request, an RSA challenge in the reply.
    fn metadata_challenge(&mut self, certificate: &[u8]) -> Result<Vec<u8>, Status> {
        let connection = self.connection.ok_or_else(|| status(0x08))?;
        let (challenge, proof, grants) =
            metadata::challenge(certificate).ok_or_else(|| status(0x0F))?;
        self.challenges.retain(|(c, _, _)| *c != connection);
        self.challenges.push((connection, proof, grants));
        Ok(challenge)
    }

    /// The metadata challenge completion (service 0x4C): the 20-byte proof, the granted claims in the reply.
    fn metadata_completion(&mut self, data: &[u8]) -> Result<Vec<u8>, Status> {
        let connection = self.connection.ok_or_else(|| status(0x08))?;
        let index = self
            .challenges
            .iter()
            .position(|(c, _, _)| *c == connection)
            .ok_or_else(|| status(0x0C))?;
        let (_, proof, grants) = self.challenges.remove(index);
        if data.len() != 22 || data[..2] != [0x14, 0] || data[2..] != proof {
            return Err(status(0x0F));
        }
        self.authenticated.insert(connection);
        Ok(grants)
    }

    /// Get_Instance_Attribute_List of the symbol class: the symbols from the requested instance on, as many as
    /// fit (status 0x06 if more follow).
    fn symbol_list(&self, path: &[Seg], data: &[u8], limit: usize) -> Vec<u8> {
        let fail = |general| reply(0x55, general, &[], &[]);
        let (program, start) = match path {
            [Seg::Class(0x6B), Seg::Instance(start)] => (None, *start),
            [Seg::Symbol(p), Seg::Class(0x6B), Seg::Instance(start)]
                if strip_program(p).is_some() =>
            {
                match self.program(p) {
                    Some(index) => (Some(index), *start),
                    None => return fail(0x05),
                }
            }
            _ => return fail(0x05),
        };
        let Some(count) = read_u16(data, 0) else {
            return fail(0x13);
        };
        let attributes: Option<Vec<u16>> = (0..usize::from(count))
            .map(|i| read_u16(data, 2 + 2 * i))
            .collect();
        let Some(attributes) = attributes else {
            return fail(0x13);
        };
        if attributes
            .iter()
            .any(|a| ![1, 2, 3, 5, 6, 7, 8, 10].contains(a))
        {
            return fail(0x14);
        }
        let room = limit.saturating_sub(4);
        let mut out = Vec::new();
        let mut general = 0;
        for symbol in self
            .scope(program)
            .symbols(&self.types)
            .into_iter()
            .filter(|s| s.instance_id >= start)
        {
            let instance = symbol.instance_id;
            let mut entry = instance.to_le_bytes().to_vec();
            for attribute in &attributes {
                match attribute {
                    1 => {
                        entry.extend((symbol.name.len() as u16).to_le_bytes());
                        entry.extend(symbol.name.as_bytes());
                    }
                    2 => entry.extend(symbol.symbol_type.to_le_bytes()),
                    3 => entry.extend(
                        instance
                            .wrapping_mul(0x100)
                            .wrapping_add(0x0010_0000)
                            .to_le_bytes(),
                    ),
                    5 => entry.extend(
                        instance
                            .wrapping_mul(0x40)
                            .wrapping_add(0x2000)
                            .to_le_bytes(),
                    ),
                    6 => entry.extend(symbol.control.to_le_bytes()),
                    7 => entry.extend(symbol.element_size.to_le_bytes()),
                    8 => symbol
                        .dims
                        .iter()
                        .for_each(|d| entry.extend(d.to_le_bytes())),
                    _ => entry.push(symbol.access),
                }
            }
            if out.len() + entry.len() > room {
                if out.is_empty() {
                    // not even one symbol fits: an empty 0x06 page would be asked for again forever
                    return fail(0x11);
                }
                general = 0x06;
                break;
            }
            out.extend(entry);
        }
        reply(0x55, general, &[], &out)
    }

    fn tag_service(
        &mut self,
        service: u8,
        path: &[Seg],
        data: &[u8],
        limit: usize,
        faults: &Faults,
    ) -> Vec<u8> {
        let target = match self.resolve(path, true) {
            Ok(target) => target,
            Err((general, extended)) => return reply(service, general, &extended, &[]),
        };
        if let Some((general, extended)) = faults.tag_status(&target.path, &target.base) {
            return reply(service, general, &extended, &[]);
        }
        let writes = matches!(service, 0x4D | 0x53 | 0x4E);
        if target.refused || target.access == 3 || (writes && target.access == 2) {
            let (general, extended) = denied();
            return reply(service, general, &extended, &[]);
        }
        let result = match service {
            0x4C | 0x52 => return self.read(service, &target, data, limit),
            0x4D | 0x53 => self.write(service, &target, data),
            _ => self.read_modify_write(&target, data),
        };
        match result {
            Ok(()) => reply(service, 0, &[], &[]),
            Err((general, extended)) => reply(service, general, &extended, &[]),
        }
    }

    fn data_mut(&mut self, target: &Target) -> &mut Vec<u8> {
        let scope = match target.program {
            None => &mut self.controller,
            Some(p) => &mut self.programs[p].scope,
        };
        &mut scope.tags[target.tag].data
    }

    fn read(&self, service: u8, target: &Target, data: &[u8], limit: usize) -> Vec<u8> {
        let fail = |(general, extended): Status| reply(service, general, &extended, &[]);
        let fragmented = service == 0x52;
        let Some(elements) = read_u16(data, 0).map(usize::from) else {
            return fail(status(0x13));
        };
        let offset = if fragmented {
            match data.get(2..6) {
                Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize,
                None => return fail(status(0x13)),
            }
        } else {
            0
        };
        let tag_data = &self.scope(target.program).tags[target.tag].data;
        let (header, value) = match target.bit {
            Some(bit) => {
                if elements != 1 {
                    return fail(beyond_end());
                }
                (
                    vec![0xC1, 0],
                    vec![u8::from(tag_data[target.offset] & (1 << bit) != 0)],
                )
            }
            None => {
                if elements == 0 {
                    return fail(status(0x03));
                }
                if elements > target.count {
                    return fail(beyond_end());
                }
                let size = self.types.size(target.ty) * elements;
                (
                    self.types.type_header(target.ty),
                    tag_data[target.offset..target.offset + size].to_vec(),
                )
            }
        };
        if offset > value.len() || (offset == value.len() && offset > 0) {
            return fail(beyond_end());
        }
        let chunk = &value[offset..];
        let room = limit.saturating_sub(4 + header.len());
        let (size, general) = if chunk.len() > room {
            // with no room (a read late in a multi-service packet) the empty 0x06 page is how a controller
            // says "send me alone": the driver reads it again by itself and stops a fragmented read whose
            // page makes no progress
            (if room >= 4 { room - room % 4 } else { room }, 0x06)
        } else {
            (chunk.len(), 0)
        };
        let mut body = header;
        body.extend(&chunk[..size]);
        reply(service, general, &[], &body)
    }

    fn write(&mut self, service: u8, target: &Target, data: &[u8]) -> Result<(), Status> {
        let code = read_u16(data, 0).ok_or_else(|| status(0x13))?;
        let (handle, rest) = if code == 0x02A0 {
            (
                Some(read_u16(data, 2).ok_or_else(|| status(0x13))?),
                &data[4..],
            )
        } else {
            (None, &data[2..])
        };
        let elements = usize::from(read_u16(rest, 0).ok_or_else(|| status(0x13))?);
        let (offset, value) = if service == 0x53 {
            let b = rest.get(2..6).ok_or_else(|| status(0x13))?;
            (
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize,
                &rest[6..],
            )
        } else {
            (0, &rest[2..])
        };
        if let Some(bit) = target.bit {
            if code != 0x00C1 {
                return Err(type_mismatch());
            }
            if elements != 1 {
                return Err(beyond_end());
            }
            let byte = *value.first().ok_or_else(|| status(0x13))?;
            if value.len() > 1 {
                return Err(status(0x15));
            }
            let at = target.offset;
            let tag_data = self.data_mut(target);
            if byte != 0 {
                tag_data[at] |= 1 << bit;
            } else {
                tag_data[at] &= !(1 << bit);
            }
            return Ok(());
        }
        let matches = match target.ty {
            Ty::Atomic(a) => handle.is_none() && code == u16::from(a.code()),
            Ty::Struct(s) => handle == Some(self.types.def(s).handle),
        };
        if !matches {
            return Err(type_mismatch());
        }
        if elements == 0 {
            return Err(status(0x03));
        }
        if elements > target.count {
            return Err(beyond_end());
        }
        let total = self.types.size(target.ty) * elements;
        if service == 0x4D {
            if value.len() < total {
                return Err(status(0x13));
            }
            if value.len() > total {
                return Err(status(0x15));
            }
        } else if offset >= total || offset + value.len() > total {
            return Err(if offset >= total {
                beyond_end()
            } else {
                status(0x15)
            });
        }
        let at = target.offset + offset;
        self.data_mut(target)[at..at + value.len()].copy_from_slice(value);
        Ok(())
    }

    fn read_modify_write(&mut self, target: &Target, data: &[u8]) -> Result<(), Status> {
        let size = usize::from(read_u16(data, 0).ok_or_else(|| status(0x13))?);
        if data.len() < 2 + 2 * size {
            return Err(status(0x13));
        }
        if data.len() > 2 + 2 * size {
            return Err(status(0x15));
        }
        let Ty::Atomic(a) = target.ty else {
            return Err(type_mismatch());
        };
        if target.bit.is_some() || !a.has_bits() || a.size() != size {
            return Err(type_mismatch());
        }
        let (or_mask, and_mask) = (&data[2..2 + size], &data[2 + size..]);
        let at = target.offset;
        let tag_data = self.data_mut(target);
        for i in 0..size {
            tag_data[at + i] = (tag_data[at + i] | or_mask[i]) & and_mask[i];
        }
        Ok(())
    }
}

fn is_tag_path(path: &[Seg]) -> bool {
    match path {
        [Seg::Symbol(s), rest @ ..] if strip_program(s).is_some() && !rest.is_empty() => {
            is_tag_path(rest)
        }
        [Seg::Symbol(_), ..] | [Seg::Class(0x6B), Seg::Instance(_), ..] => true,
        _ => false,
    }
}

/// The program name of `Program:Name` (any case), None for another name.
fn strip_program(name: &str) -> Option<&str> {
    // `get` rather than indexing: a symbol from the wire can hold any byte, so byte 8 may split a char
    let rest = name.get(8..).filter(|rest| !rest.is_empty())?;
    name[..8].eq_ignore_ascii_case("program:").then_some(rest)
}

/// Parses a tag path written as text, `Program:Main.tag[1,2].member[3]`, into path segments.
fn text_path(path: &str) -> Result<Vec<Seg>, ConfigError> {
    let fail = || ConfigError::new(format!("invalid tag path {path:?}"));
    let mut segments = Vec::new();
    let mut rest = path;
    if strip_program(path).is_some() {
        let (scope, tail) = path.split_once('.').ok_or_else(fail)?;
        segments.push(Seg::Symbol(scope.to_owned()));
        rest = tail;
    }
    for part in rest.split('.') {
        let (name, index) = match part.split_once('[') {
            Some((name, index)) => (name, index.strip_suffix(']').ok_or_else(fail)?),
            None => (part, ""),
        };
        if name.is_empty() {
            return Err(fail());
        }
        segments.push(Seg::Symbol(name.to_owned()));
        if !index.is_empty() {
            for i in index.split(',') {
                segments.push(Seg::Element(i.trim().parse().map_err(|_| fail())?));
            }
        }
    }
    Ok(segments)
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// The services of a Multiple Service Packet: a count, offsets from the count and the messages.
fn split_multi(data: &[u8]) -> Option<Vec<&[u8]>> {
    let count = usize::from(read_u16(data, 0)?);
    let mut bounds = (0..count)
        .map(|i| read_u16(data, 2 + 2 * i).map(usize::from))
        .collect::<Option<Vec<_>>>()?;
    bounds.push(data.len());
    if bounds.first().is_some_and(|&b| b < 2 + 2 * count) || bounds.windows(2).any(|w| w[0] > w[1])
    {
        return None;
    }
    Some(bounds.windows(2).map(|w| &data[w[0]..w[1]]).collect())
}

/// Get_Attribute_List: the attribute count and ids, answered as count then (id, status, value) each; an
/// unknown attribute gets status 0x14 and no value.
fn get_attribute_list(
    data: &[u8],
    value: impl Fn(u16) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, Status> {
    let count = read_u16(data, 0).ok_or_else(|| status(0x13))?;
    let mut out = count.to_le_bytes().to_vec();
    for i in 0..usize::from(count) {
        let attribute = read_u16(data, 2 + 2 * i).ok_or_else(|| status(0x13))?;
        out.extend(attribute.to_le_bytes());
        match value(attribute) {
            Some(v) => {
                out.extend(0u16.to_le_bytes());
                out.extend(v);
            }
            None => out.extend(0x14u16.to_le_bytes()),
        }
    }
    Ok(out)
}
