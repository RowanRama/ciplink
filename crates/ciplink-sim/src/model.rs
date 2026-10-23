//! The Logix data model: atomic types, structure layouts and their templates, tags, and the JSON value codec.

use crate::config::{ConfigError, MemberConfig, TagConfig, TypeConfig};
use serde_json::{Number, Value as Json};

/// The atomic types a Logix tag or member can have. BYTE, WORD, DWORD and LWORD are bit strings; a DWORD
/// array holds a BOOL array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Atomic {
    Bool,
    SInt,
    Int,
    DInt,
    LInt,
    USInt,
    UInt,
    UDInt,
    ULInt,
    Real,
    LReal,
    Byte,
    Word,
    DWord,
    LWord,
}

impl Atomic {
    const ALL: [Atomic; 15] = [
        Atomic::Bool,
        Atomic::SInt,
        Atomic::Int,
        Atomic::DInt,
        Atomic::LInt,
        Atomic::USInt,
        Atomic::UInt,
        Atomic::UDInt,
        Atomic::ULInt,
        Atomic::Real,
        Atomic::LReal,
        Atomic::Byte,
        Atomic::Word,
        Atomic::DWord,
        Atomic::LWord,
    ];

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.name().eq_ignore_ascii_case(name))
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Atomic::Bool => "BOOL",
            Atomic::SInt => "SINT",
            Atomic::Int => "INT",
            Atomic::DInt => "DINT",
            Atomic::LInt => "LINT",
            Atomic::USInt => "USINT",
            Atomic::UInt => "UINT",
            Atomic::UDInt => "UDINT",
            Atomic::ULInt => "ULINT",
            Atomic::Real => "REAL",
            Atomic::LReal => "LREAL",
            Atomic::Byte => "BYTE",
            Atomic::Word => "WORD",
            Atomic::DWord => "DWORD",
            Atomic::LWord => "LWORD",
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Atomic::Bool => 0xC1,
            Atomic::SInt => 0xC2,
            Atomic::Int => 0xC3,
            Atomic::DInt => 0xC4,
            Atomic::LInt => 0xC5,
            Atomic::USInt => 0xC6,
            Atomic::UInt => 0xC7,
            Atomic::UDInt => 0xC8,
            Atomic::ULInt => 0xC9,
            Atomic::Real => 0xCA,
            Atomic::LReal => 0xCB,
            Atomic::Byte => 0xD1,
            Atomic::Word => 0xD2,
            Atomic::DWord => 0xD3,
            Atomic::LWord => 0xD4,
        }
    }

    pub(crate) fn size(self) -> usize {
        match self {
            Atomic::Bool | Atomic::SInt | Atomic::USInt | Atomic::Byte => 1,
            Atomic::Int | Atomic::UInt | Atomic::Word => 2,
            Atomic::DInt | Atomic::UDInt | Atomic::Real | Atomic::DWord => 4,
            Atomic::LInt | Atomic::ULInt | Atomic::LReal | Atomic::LWord => 8,
        }
    }

    /// Integer and bit string types, whose bits a Read-Modify-Write can change.
    pub(crate) fn has_bits(self) -> bool {
        !matches!(self, Atomic::Bool | Atomic::Real | Atomic::LReal)
    }

    /// The bit strings, whose value is one bool per bit.
    pub(crate) fn is_bit_string(self) -> bool {
        matches!(
            self,
            Atomic::Byte | Atomic::Word | Atomic::DWord | Atomic::LWord
        )
    }
}

/// A data type: atomic or a structure (index into [`Types`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ty {
    Atomic(Atomic),
    Struct(usize),
}

impl Ty {
    fn is_bit_string(self) -> bool {
        matches!(self, Ty::Atomic(a) if a.is_bit_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StructKind {
    Udt,
    /// TIMER, COUNTER, CONTROL: template IDs above 0xEFF, the hidden member CTL holds the status bits.
    Predefined,
    /// STRING (predefined) or a custom string type: LEN and DATA.
    Str,
    Aoi,
}

#[derive(Clone, Debug)]
pub(crate) struct Member {
    pub name: String,
    pub ty: Ty,
    /// Array length, 0 for a scalar.
    pub array: u32,
    pub offset: u32,
    /// For a BOOL member: its bit in the byte at `offset`.
    pub bit: Option<u8>,
    /// Hidden from the outside (bit hosts, CTL): not addressable by name, not in values.
    pub hidden: bool,
    /// An AOI local tag.
    pub local: bool,
    /// External access code (0 Read/Write, 2 Read Only, 3 None).
    pub access: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct StructDef {
    pub name: String,
    pub template_id: u16,
    pub handle: u16,
    pub size: u32,
    pub members: Vec<Member>,
    pub kind: StructKind,
    /// The template object's data: member info then names (and the member IDs of a user type).
    pub template: Vec<u8>,
    /// The members' default Descriptions: (member index, text).
    pub descriptions: Vec<(usize, String)>,
}

impl StructDef {
    /// Template object definition size in 32-bit words: (size * 4) - 23 is the template's byte count.
    pub(crate) fn object_definition_size(&self) -> u32 {
        // invariant: templates are a few KB at most
        (self.template.len() as u32 + 23).div_ceil(4)
    }

    /// The member ID of member `index`, as Description paths name members (`.!TTTTMMMM`): a user type's
    /// template lists them after the names, a predefined type's are 1, 2, ...
    pub(crate) fn member_id(&self, index: usize) -> u16 {
        // invariant: a type has far fewer than 4096 members
        if (FIRST_UDT_ID..=LAST_UDT_ID).contains(&self.template_id) {
            0xE000 + index as u16
        } else {
            index as u16 + 1
        }
    }

    pub(crate) fn has_locals(&self) -> bool {
        self.members.iter().any(|m| m.local)
    }

    pub(crate) fn member(&self, name: &str) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| !m.hidden && m.name.eq_ignore_ascii_case(name))
    }

    /// The string length of a string type.
    pub(crate) fn string_length(&self) -> usize {
        self.members.get(1).map_or(0, |m| m.array as usize)
    }
}

/// The data types of a controller.
#[derive(Clone, Debug, Default)]
pub(crate) struct Types {
    pub defs: Vec<StructDef>,
}

const TIMER_ID: u16 = 0x0F83;
const COUNTER_ID: u16 = 0x0F82;
const CONTROL_ID: u16 = 0x0F81;
const STRING_ID: u16 = 0x0FCE;
const FIRST_UDT_ID: u16 = 0x100;
const LAST_UDT_ID: u16 = 0xEFF;
/// The most bytes of one tag or structure, above any controller's memory, so a configured size cannot overflow
/// or exhaust memory.
pub(crate) const MAX_DATA_BYTES: usize = 1 << 26;
/// The software control bit set on base tags (not aliases).
pub(crate) const BASE_TAG_BIT: u32 = 1 << 26;

impl Types {
    /// The predefined types, then the configured ones (in any order, each member type defined somewhere).
    pub(crate) fn build(configs: &[TypeConfig]) -> Result<Self, ConfigError> {
        let mut types = Types::default();
        types.add_predefined();
        let mut pending: Vec<&TypeConfig> = configs.iter().collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut rest = Vec::new();
            for config in pending {
                if config
                    .members
                    .iter()
                    .all(|m| types.lookup(&m.data_type).is_some())
                {
                    types.add(config)?;
                } else {
                    rest.push(config);
                }
            }
            if rest.len() == before {
                let names: Vec<_> = rest.iter().map(|c| c.name.as_str()).collect();
                return Err(ConfigError::new(format!(
                    "data types with unknown or circular member types: {}",
                    names.join(", ")
                )));
            }
            pending = rest;
        }
        Ok(types)
    }

    pub(crate) fn lookup(&self, name: &str) -> Option<Ty> {
        if let Some(atomic) = Atomic::from_name(name) {
            return Some(Ty::Atomic(atomic));
        }
        self.defs
            .iter()
            .position(|d| d.name.eq_ignore_ascii_case(name))
            .map(Ty::Struct)
    }

    pub(crate) fn def(&self, index: usize) -> &StructDef {
        &self.defs[index]
    }

    pub(crate) fn by_template(&self, template_id: u32) -> Option<&StructDef> {
        self.defs
            .iter()
            .find(|d| u32::from(d.template_id) == template_id)
    }

    pub(crate) fn size(&self, ty: Ty) -> usize {
        match ty {
            Ty::Atomic(a) => a.size(),
            Ty::Struct(i) => self.defs[i].size as usize,
        }
    }

    /// Logix memory is in 32-bit words: a member is aligned to its size up to 4 (a LINT or LREAL to 4 too),
    /// a structure to 4, as the memory images of controller exports show (a UDT with a LINT is 20 bytes).
    fn align(&self, ty: Ty) -> u32 {
        match ty {
            Ty::Atomic(a) => (a.size() as u32).min(4),
            Ty::Struct(_) => 4,
        }
    }

    /// The type code of a read reply or write request: the atomic code, or 0x02A0 and the structure handle.
    pub(crate) fn type_header(&self, ty: Ty) -> Vec<u8> {
        match ty {
            Ty::Atomic(a) => vec![a.code(), 0],
            Ty::Struct(i) => {
                let mut out = vec![0xA0, 0x02];
                out.extend(self.defs[i].handle.to_le_bytes());
                out
            }
        }
    }

    fn next_template_id(&self) -> Result<u16, ConfigError> {
        (FIRST_UDT_ID..=LAST_UDT_ID)
            .find(|id| self.by_template(u32::from(*id)).is_none())
            .ok_or_else(|| ConfigError::new("too many data types"))
    }

    fn add_predefined(&mut self) {
        let dint = Ty::Atomic(Atomic::DInt);
        let plain = |name: &str, ty, offset| Member {
            name: name.into(),
            ty,
            array: 0,
            offset,
            bit: None,
            hidden: false,
            local: false,
            access: 0,
        };
        // the status bits of CTL count down from bit 31 (offset 3, bit 7)
        let ctl_bits = |names: &[&str]| -> Vec<Member> {
            names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let bit = 31 - i as u32;
                    Member {
                        name: (*name).into(),
                        ty: Ty::Atomic(Atomic::Bool),
                        array: 0,
                        offset: bit / 8,
                        bit: Some((bit % 8) as u8),
                        hidden: false,
                        local: false,
                        access: 0,
                    }
                })
                .collect()
        };
        let control = |name: &str, id, words: [&str; 2], bits: &[&str]| {
            let mut members = vec![
                Member {
                    hidden: true,
                    ..plain("CTL", dint, 0)
                },
                plain(words[0], dint, 4),
                plain(words[1], dint, 8),
            ];
            members.extend(ctl_bits(bits));
            (name.to_owned(), id, members)
        };
        let predefined = [
            control("TIMER", TIMER_ID, ["PRE", "ACC"], &["EN", "TT", "DN"]),
            control(
                "COUNTER",
                COUNTER_ID,
                ["PRE", "ACC"],
                &["CU", "CD", "DN", "OV", "UN"],
            ),
            control(
                "CONTROL",
                CONTROL_ID,
                ["LEN", "POS"],
                &["EN", "EU", "DN", "EM", "ER", "UL", "IN", "FD"],
            ),
        ];
        for (name, id, members) in predefined {
            self.push(name, id, members, 12, StructKind::Predefined);
        }
        let (members, size) = string_members(82);
        self.push("STRING".into(), STRING_ID, members, size, StructKind::Str);
    }

    pub(crate) fn add(&mut self, config: &TypeConfig) -> Result<(), ConfigError> {
        if config.name.is_empty() || self.lookup(&config.name).is_some() {
            return Err(ConfigError::new(format!(
                "data type {:?} is defined twice or has no name",
                config.name
            )));
        }
        let template_id = match config.template_id {
            Some(id) if !(FIRST_UDT_ID..=LAST_UDT_ID).contains(&id) => {
                return Err(ConfigError::new(format!(
                    "template_id of {} must be in 0x100..=0xEFF",
                    config.name
                )));
            }
            Some(id) if self.by_template(u32::from(id)).is_some() => {
                return Err(ConfigError::new(format!(
                    "template_id {id:#x} is used twice"
                )));
            }
            Some(id) => id,
            None => self.next_template_id()?,
        };
        if let Some(length) = config.string {
            if length == 0
                || length as usize > MAX_DATA_BYTES - 4
                || !config.members.is_empty()
                || config.aoi
            {
                return Err(ConfigError::new(format!(
                    "string type {} needs a length and no members",
                    config.name
                )));
            }
            let (members, size) = string_members(length);
            self.push(
                config.name.clone(),
                template_id,
                members,
                size,
                StructKind::Str,
            );
            return Ok(());
        }
        let mut names: Vec<String> = Vec::new();
        for m in &config.members {
            if m.name.is_empty() || names.iter().any(|n| n.eq_ignore_ascii_case(&m.name)) {
                return Err(ConfigError::new(format!(
                    "member {:?} of {} is empty or defined twice",
                    m.name, config.name
                )));
            }
            if m.local && !config.aoi {
                return Err(ConfigError::new(format!(
                    "{}.{} is local but {} is not an AOI",
                    config.name, m.name, config.name
                )));
            }
            names.push(m.name.clone());
        }
        let (members, size) = if config.aoi {
            self.layout_aoi(&config.members)?
        } else {
            self.layout_udt(&config.name, &config.members)?
        };
        let kind = if config.aoi {
            StructKind::Aoi
        } else {
            StructKind::Udt
        };
        self.push(config.name.clone(), template_id, members, size, kind);
        if let Some(def) = self.defs.last_mut() {
            for m in &config.members {
                let index = def.members.iter().position(|x| x.name == m.name);
                if let (Some(text), Some(index)) = (&m.description, index) {
                    def.descriptions.push((index, text.clone()));
                }
            }
        }
        Ok(())
    }

    fn push(
        &mut self,
        name: String,
        template_id: u16,
        members: Vec<Member>,
        size: u32,
        kind: StructKind,
    ) {
        let mut def = StructDef {
            name,
            template_id,
            handle: 0,
            size,
            members,
            kind,
            template: Vec::new(),
            descriptions: Vec::new(),
        };
        def.template = self.template(&def);
        def.handle = structure_handle(&def.template);
        self.defs.push(def);
    }

    /// A member's type and array length: a BOOL array becomes a DWORD array of whole DWORDs.
    fn member_type(&self, config: &MemberConfig) -> Result<(Ty, u32), ConfigError> {
        let ty = self
            .lookup(&config.data_type)
            .ok_or_else(|| ConfigError::new(format!("unknown type {}", config.data_type)))?;
        Ok(match ty {
            Ty::Atomic(Atomic::Bool) if config.dim > 0 => {
                (Ty::Atomic(Atomic::DWord), config.dim.div_ceil(32))
            }
            _ => (ty, config.dim),
        })
    }

    /// Logix UDT layout: members aligned (see `align`), consecutive BOOLs share a hidden SINT host, the size
    /// rounded up to 4.
    fn layout_udt(
        &self,
        name: &str,
        configs: &[MemberConfig],
    ) -> Result<(Vec<Member>, u32), ConfigError> {
        let mut members = Vec::new();
        let mut offset = 0u32;
        let mut host: Option<(u32, u8)> = None;
        for config in configs {
            let (ty, array) = self.member_type(config)?;
            if ty == Ty::Atomic(Atomic::Bool) {
                let (host_offset, bit) = match host {
                    Some((host_offset, bit)) if bit < 8 => (host_offset, bit),
                    _ => {
                        // named after the type and the host's member index, as Studio 5000 names them
                        let prefix: String = name.chars().take(10).collect();
                        members.push(Member {
                            name: format!("ZZZZZZZZZZ{prefix}{}", members.len()),
                            ty: Ty::Atomic(Atomic::SInt),
                            array: 0,
                            offset,
                            bit: None,
                            hidden: true,
                            local: false,
                            access: 0,
                        });
                        offset += 1;
                        (offset - 1, 0)
                    }
                };
                members.push(Member {
                    name: config.name.clone(),
                    ty,
                    array: 0,
                    offset: host_offset,
                    bit: Some(bit),
                    hidden: false,
                    local: config.local,
                    access: external_access_code(&config.external_access)?,
                });
                host = Some((host_offset, bit + 1));
                continue;
            }
            host = None;
            let member_align = self.align(ty);
            offset = offset.next_multiple_of(member_align); // below MAX_DATA_BYTES, no overflow
            members.push(Member {
                name: config.name.clone(),
                ty,
                array,
                offset,
                bit: None,
                hidden: false,
                local: config.local,
                access: external_access_code(&config.external_access)?,
            });
            offset = member_end(offset, self.size(ty), array)?;
        }
        Ok((members, offset.next_multiple_of(4)))
    }

    /// AOI layout: EnableIn, EnableOut and every BOOL member are bits of hidden DINT hosts at the start, the
    /// other members follow as in a UDT.
    fn layout_aoi(&self, configs: &[MemberConfig]) -> Result<(Vec<Member>, u32), ConfigError> {
        let enable = [
            MemberConfig::new("EnableIn", "BOOL").access("Read Only"),
            MemberConfig::new("EnableOut", "BOOL").access("Read Only"),
        ];
        let all: Vec<&MemberConfig> = enable.iter().chain(configs).collect();
        let mut typed = Vec::with_capacity(all.len());
        for config in &all {
            typed.push((*config, self.member_type(config)?));
        }
        let bools = typed
            .iter()
            .filter(|(_, (ty, _))| *ty == Ty::Atomic(Atomic::Bool))
            .count();
        let hosts = bools.div_ceil(32) as u32;
        let mut members: Vec<Member> = (0..hosts)
            .map(|i| Member {
                name: format!("__BitHost{i:02}"),
                ty: Ty::Atomic(Atomic::DInt),
                array: 0,
                offset: i * 4,
                bit: None,
                hidden: true,
                local: false,
                access: 0,
            })
            .collect();
        let mut offset = hosts * 4;
        let mut bit_index = 0u32;
        for (config, (ty, array)) in typed {
            if ty == Ty::Atomic(Atomic::Bool) {
                members.push(Member {
                    name: config.name.clone(),
                    ty,
                    array: 0,
                    offset: (bit_index / 32) * 4 + (bit_index % 32) / 8,
                    bit: Some((bit_index % 8) as u8),
                    hidden: false,
                    local: config.local,
                    access: external_access_code(&config.external_access)?,
                });
                bit_index += 1;
                continue;
            }
            let member_align = self.align(ty);
            offset = offset.next_multiple_of(member_align); // below MAX_DATA_BYTES, no overflow
            members.push(Member {
                name: config.name.clone(),
                ty,
                array,
                offset,
                bit: None,
                hidden: false,
                local: config.local,
                access: external_access_code(&config.external_access)?,
            });
            offset = member_end(offset, self.size(ty), array)?;
        }
        Ok((members, offset.next_multiple_of(4)))
    }

    /// The template object's data: 8 bytes of info per member (bit or array length, type, offset), the type
    /// name (`Name;n` for user types, the bare name for predefined ones) and the member names, NUL terminated.
    fn template(&self, def: &StructDef) -> Vec<u8> {
        let mut out = Vec::new();
        for m in &def.members {
            let info = match m.bit {
                Some(bit) => u16::from(bit),
                None => m.array as u16,
            };
            let typ = match m.ty {
                Ty::Atomic(a) => u16::from(a.code()),
                Ty::Struct(i) => 0x8000 | self.defs[i].template_id,
            };
            out.extend(info.to_le_bytes());
            out.extend(typ.to_le_bytes());
            out.extend(m.offset.to_le_bytes());
        }
        let name = match (def.kind, def.template_id) {
            (StructKind::Str, STRING_ID) => "ASCIISTRING82".to_owned(),
            (StructKind::Predefined, _) => def.name.clone(),
            _ => format!("{};n", def.name),
        };
        out.extend(name.as_bytes());
        out.push(0);
        for m in &def.members {
            out.extend(m.name.as_bytes());
            out.push(0);
        }
        if (FIRST_UDT_ID..=LAST_UDT_ID).contains(&def.template_id) {
            out.resize(out.len().next_multiple_of(4), 0);
            for i in 0..def.members.len() {
                out.extend(def.member_id(i).to_le_bytes());
            }
        }
        out
    }

    // ---- values ----

    /// Encodes one element of `ty` from JSON into `out` (its size); null leaves it unchanged.
    pub(crate) fn encode(&self, ty: Ty, value: &Json, out: &mut [u8]) -> Result<(), String> {
        if value.is_null() {
            return Ok(());
        }
        match ty {
            Ty::Atomic(a) => encode_atomic(a, value, out),
            Ty::Struct(i) => {
                let def = &self.defs[i];
                if def.kind == StructKind::Str {
                    let text = value.as_str().ok_or_else(|| {
                        format!("expected a string for {}, got {value}", def.name)
                    })?;
                    let bytes: Vec<u8> = text
                        .chars()
                        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
                        .collect();
                    let length = def.string_length();
                    if bytes.len() > length {
                        return Err(format!("string longer than {length} characters"));
                    }
                    out[..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
                    out[4..4 + length].fill(0);
                    out[4..4 + bytes.len()].copy_from_slice(&bytes);
                    return Ok(());
                }
                let object = value
                    .as_object()
                    .ok_or_else(|| format!("expected an object for {}, got {value}", def.name))?;
                for (key, member_value) in object {
                    let m = def
                        .member(key)
                        .ok_or_else(|| format!("{} has no member {key}", def.name))?;
                    self.encode_member(m, member_value, out)?;
                }
                Ok(())
            }
        }
    }

    fn encode_member(&self, m: &Member, value: &Json, out: &mut [u8]) -> Result<(), String> {
        let offset = m.offset as usize;
        if let Some(bit) = m.bit {
            set_bit(&mut out[offset], bit, json_truthy(value)?);
            return Ok(());
        }
        let count = m.array.max(1) as usize;
        let size = self.size(m.ty);
        let region = &mut out[offset..offset + size * count];
        if m.array == 0 {
            self.encode(m.ty, value, region)
        } else {
            self.encode_elements(m.ty, count, value, region)
        }
    }

    /// Encodes `count` elements from a list (nested lists are flattened; a bit string array, such as the DWORDs
    /// of a BOOL array, takes a list of bools).
    pub(crate) fn encode_elements(
        &self,
        ty: Ty,
        count: usize,
        value: &Json,
        out: &mut [u8],
    ) -> Result<(), String> {
        if value.is_null() {
            return Ok(());
        }
        let mut items = Vec::new();
        flatten(value, &mut items);
        if ty.is_bit_string() && items.iter().all(|v| v.is_boolean()) {
            let bits = count * self.size(ty) * 8;
            if items.len() > bits {
                return Err(format!("{} values for {bits} BOOLs", items.len()));
            }
            for (i, item) in items.iter().enumerate() {
                set_bit(&mut out[i / 8], (i % 8) as u8, json_truthy(item)?);
            }
            return Ok(());
        }
        if items.len() > count {
            return Err(format!("{} values for {count} elements", items.len()));
        }
        let size = self.size(ty);
        for (i, item) in items.iter().enumerate() {
            self.encode(ty, item, &mut out[i * size..(i + 1) * size])?;
        }
        Ok(())
    }

    /// Decodes one element of `ty`.
    pub(crate) fn decode(&self, ty: Ty, data: &[u8]) -> Json {
        match ty {
            Ty::Atomic(a) => decode_atomic(a, data),
            Ty::Struct(i) => {
                let def = &self.defs[i];
                if def.kind == StructKind::Str {
                    let length = (u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                        as usize)
                        .min(def.string_length());
                    return Json::String(
                        data[4..4 + length].iter().map(|&b| char::from(b)).collect(),
                    );
                }
                let mut object = serde_json::Map::new();
                for m in def.members.iter().filter(|m| !m.hidden) {
                    let offset = m.offset as usize;
                    let value = if let Some(bit) = m.bit {
                        Json::Bool(data[offset] & (1 << bit) != 0)
                    } else if m.array == 0 {
                        self.decode(m.ty, &data[offset..offset + self.size(m.ty)])
                    } else {
                        let count = m.array as usize;
                        self.decode_elements(
                            m.ty,
                            count,
                            &data[offset..offset + self.size(m.ty) * count],
                        )
                    };
                    object.insert(m.name.clone(), value);
                }
                Json::Object(object)
            }
        }
    }

    /// Decodes `count` elements as a list (a bit string array, such as a BOOL array, as a list of bools).
    pub(crate) fn decode_elements(&self, ty: Ty, count: usize, data: &[u8]) -> Json {
        if ty.is_bit_string() {
            return Json::Array(
                (0..count * self.size(ty) * 8)
                    .map(|i| Json::Bool(data[i / 8] & (1 << (i % 8)) != 0))
                    .collect(),
            );
        }
        let size = self.size(ty);
        Json::Array(
            (0..count)
                .map(|i| self.decode(ty, &data[i * size..(i + 1) * size]))
                .collect(),
        )
    }
}

/// The end of a member of `array` elements (0 for a scalar) of `size` bytes at `offset`, an error past
/// [`MAX_DATA_BYTES`].
fn member_end(offset: u32, size: usize, array: u32) -> Result<u32, ConfigError> {
    usize::try_from(array.max(1))
        .ok()
        .and_then(|n| size.checked_mul(n))
        .and_then(|bytes| bytes.checked_add(offset as usize))
        .filter(|&end| end <= MAX_DATA_BYTES)
        .and_then(|end| u32::try_from(end).ok())
        .ok_or_else(|| ConfigError::new(format!("a structure is over {MAX_DATA_BYTES} bytes")))
}

fn string_members(length: u32) -> (Vec<Member>, u32) {
    let members = vec![
        Member {
            name: "LEN".into(),
            ty: Ty::Atomic(Atomic::DInt),
            array: 0,
            offset: 0,
            bit: None,
            hidden: false,
            local: false,
            access: 0,
        },
        Member {
            name: "DATA".into(),
            ty: Ty::Atomic(Atomic::SInt),
            array: length,
            offset: 4,
            bit: None,
            hidden: false,
            local: false,
            access: 0,
        },
    ];
    (members, (4 + length).next_multiple_of(4))
}

/// A 16-bit checksum of the template, standing in for the controller's structure handle (a CRC of the layout).
fn structure_handle(template: &[u8]) -> u16 {
    let hash = template.iter().fold(0x1D0Fu16, |h, &b| {
        (h.rotate_left(5) ^ u16::from(b)).wrapping_mul(0x9E37)
    });
    if hash == 0 { 1 } else { hash }
}

fn set_bit(byte: &mut u8, bit: u8, value: bool) {
    if value {
        *byte |= 1 << bit;
    } else {
        *byte &= !(1 << bit);
    }
}

fn flatten<'a>(value: &'a Json, out: &mut Vec<&'a Json>) {
    match value {
        Json::Array(items) => items.iter().for_each(|v| flatten(v, out)),
        _ => out.push(value),
    }
}

fn json_truthy(value: &Json) -> Result<bool, String> {
    match value {
        Json::Bool(b) => Ok(*b),
        Json::Number(n) => Ok(n.as_f64() != Some(0.0)),
        _ => Err(format!("expected a bool, got {value}")),
    }
}

fn json_int(value: &Json) -> Result<i128, String> {
    match value {
        Json::Bool(b) => Ok(i128::from(*b)),
        Json::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .ok_or_else(|| format!("expected an integer, got {value}")),
        _ => Err(format!("expected an integer, got {value}")),
    }
}

fn encode_atomic(a: Atomic, value: &Json, out: &mut [u8]) -> Result<(), String> {
    let int = |min: i128, max: i128| -> Result<i128, String> {
        let n = json_int(value)?;
        if n < min || n > max {
            return Err(format!("{n} is out of range for {}", a.name()));
        }
        Ok(n)
    };
    let float = || {
        value
            .as_f64()
            .ok_or_else(|| format!("expected a number, got {value}"))
    };
    match a {
        Atomic::Bool => out[0] = u8::from(json_truthy(value)?),
        Atomic::SInt => out[0] = int(-128, 127)? as i8 as u8,
        Atomic::USInt => out[0] = int(0, 255)? as u8,
        Atomic::Int => out.copy_from_slice(&(int(-32768, 32767)? as i16).to_le_bytes()),
        Atomic::UInt => out.copy_from_slice(&(int(0, 65535)? as u16).to_le_bytes()),
        Atomic::DInt => {
            out.copy_from_slice(&(int(i32::MIN.into(), i32::MAX.into())? as i32).to_le_bytes())
        }
        Atomic::UDInt => out.copy_from_slice(&(int(0, u32::MAX.into())? as u32).to_le_bytes()),
        // a bit string takes a list of bools, least significant first, or an integer
        Atomic::Byte | Atomic::Word | Atomic::DWord | Atomic::LWord => {
            let bits = a.size() * 8;
            let word = match value {
                Json::Array(_) => {
                    let mut items = Vec::new();
                    flatten(value, &mut items);
                    if items.len() > bits {
                        return Err(format!("more than {bits} bools for a {}", a.name()));
                    }
                    let mut word = 0u64;
                    for (i, item) in items.iter().enumerate() {
                        if json_truthy(item)? {
                            word |= 1 << i;
                        }
                    }
                    word
                }
                // signed or unsigned values of the size, as two's complement bits
                _ => int(-(1i128 << (bits - 1)), (1i128 << bits) - 1)? as u64,
            };
            out.copy_from_slice(&word.to_le_bytes()[..a.size()]);
        }
        Atomic::LInt => {
            out.copy_from_slice(&(int(i64::MIN.into(), i64::MAX.into())? as i64).to_le_bytes())
        }
        Atomic::ULInt => out.copy_from_slice(&(int(0, u64::MAX.into())? as u64).to_le_bytes()),
        Atomic::Real => out.copy_from_slice(&(float()? as f32).to_le_bytes()),
        Atomic::LReal => out.copy_from_slice(&float()?.to_le_bytes()),
    }
    Ok(())
}

fn decode_atomic(a: Atomic, data: &[u8]) -> Json {
    let array = |n: usize| -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..n].copy_from_slice(&data[..n]);
        out
    };
    let b = array(a.size());
    match a {
        Atomic::Bool => Json::Bool(b[0] != 0),
        Atomic::SInt => Json::from(b[0] as i8),
        Atomic::USInt => Json::from(b[0]),
        Atomic::Int => Json::from(i16::from_le_bytes([b[0], b[1]])),
        Atomic::UInt => Json::from(u16::from_le_bytes([b[0], b[1]])),
        Atomic::DInt => Json::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        Atomic::UDInt => Json::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        Atomic::Byte | Atomic::Word | Atomic::DWord | Atomic::LWord => Json::Array(
            (0..a.size() * 8)
                .map(|i| Json::Bool(b[i / 8] & (1 << (i % 8)) != 0))
                .collect(),
        ),
        Atomic::LInt => Json::from(i64::from_le_bytes(b)),
        Atomic::ULInt => Json::from(u64::from_le_bytes(b)),
        Atomic::Real => float_json(f64::from(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
        Atomic::LReal => float_json(f64::from_le_bytes(b)),
    }
}

fn float_json(x: f64) -> Json {
    Number::from_f64(x).map_or(Json::Null, Json::Number)
}

/// Bytes from hex digits, whitespace ignored.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 == 1 {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// External access codes of the symbol object (attribute 10).
pub(crate) fn external_access_code(text: &str) -> Result<u8, ConfigError> {
    match text {
        "Read/Write" => Ok(0),
        "Read Only" => Ok(2),
        "None" => Ok(3),
        other => Err(ConfigError::new(format!(
            "external_access {other:?} is not \"Read/Write\", \"Read Only\" or \"None\""
        ))),
    }
}

/// A tag: its type, dimensions and value.
#[derive(Clone, Debug)]
pub(crate) struct Tag {
    pub name: String,
    pub instance_id: u32,
    pub ty: Ty,
    /// Dimensions as the symbol object reports them (a BOOL array: its BOOLs).
    pub dims: Vec<u32>,
    /// Elements in storage (a BOOL array: its DWORDs), 1 for a scalar.
    pub elements: usize,
    pub access: u8,
    pub alias: bool,
    pub data: Vec<u8>,
    /// Descriptions by path below the tag (see `TagConfig::descriptions`).
    pub descriptions: Vec<(String, String)>,
}

impl Tag {
    pub(crate) fn build(
        types: &Types,
        config: &TagConfig,
        instance_id: u32,
    ) -> Result<Self, ConfigError> {
        let fail = |message: String| ConfigError::new(format!("tag {}: {message}", config.name));
        if config.name.is_empty() {
            return Err(ConfigError::new("a tag has no name"));
        }
        let mut ty = types
            .lookup(&config.data_type)
            .ok_or_else(|| fail(format!("unknown type {}", config.data_type)))?;
        if config.dims.len() > 3 || config.dims.contains(&0) {
            return Err(fail("dims must be 1 to 3 non-zero lengths".into()));
        }
        let mut dims = config.dims.clone();
        let elements = if ty == Ty::Atomic(Atomic::Bool) && !dims.is_empty() {
            if dims.len() > 1 {
                return Err(fail("a BOOL array has one dimension".into()));
            }
            ty = Ty::Atomic(Atomic::DWord);
            dims[0] = dims[0]
                .checked_next_multiple_of(32)
                .ok_or_else(|| fail("too many BOOLs".into()))?;
            dims[0] as usize / 32
        } else {
            dims.iter()
                .try_fold(1usize, |n, &d| n.checked_mul(d as usize))
                .ok_or_else(|| fail("too many elements".into()))?
        };
        if types
            .size(ty)
            .checked_mul(elements)
            .is_none_or(|bytes| bytes > MAX_DATA_BYTES)
        {
            return Err(fail(format!("over {MAX_DATA_BYTES} bytes")));
        }
        let mut tag = Tag {
            name: config.name.clone(),
            instance_id,
            ty,
            dims,
            elements,
            access: external_access_code(&config.external_access)?,
            alias: config.alias,
            data: vec![0; types.size(ty) * elements],
            descriptions: config
                .descriptions
                .iter()
                .map(|(path, text)| (path.clone(), text.clone()))
                .collect(),
        };
        if let Some(raw) = &config.raw {
            let bytes = parse_hex(raw).ok_or_else(|| fail("raw is not hex".into()))?;
            if bytes.len() != tag.data.len() {
                return Err(fail(format!(
                    "raw has {} bytes, the tag {}",
                    bytes.len(),
                    tag.data.len()
                )));
            }
            tag.data = bytes;
        }
        tag.set_value(types, &config.value).map_err(fail)?;
        Ok(tag)
    }

    /// Sets the whole value from JSON (a list for an array).
    pub(crate) fn set_value(&mut self, types: &Types, value: &Json) -> Result<(), String> {
        if self.dims.is_empty() {
            types.encode(self.ty, value, &mut self.data)
        } else {
            types.encode_elements(self.ty, self.elements, value, &mut self.data)
        }
    }

    /// The symbol type word: bit 15 structure (else the atomic code), bits 13-14 the dimensions.
    pub(crate) fn symbol_type(&self, types: &Types) -> u16 {
        let base = match self.ty {
            Ty::Atomic(a) => u16::from(a.code()),
            Ty::Struct(i) => 0x8000 | types.def(i).template_id,
        };
        base | ((self.dims.len() as u16) << 13)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn types(configs: &[TypeConfig]) -> Types {
        Types::build(configs).expect("types")
    }

    #[test]
    fn udt_layout_packs_bools_into_hosts_and_aligns_members() {
        let t = types(&[TypeConfig::udt(
            "Padded",
            [
                MemberConfig::new("bool1", "BOOL"),
                MemberConfig::new("sint", "SINT"),
                MemberConfig::new("dint1", "DINT"),
                MemberConfig::new("bool2", "BOOL"),
                MemberConfig::new("lint", "LINT"),
                MemberConfig::array("bools", "BOOL", 40),
            ],
        )]);
        let Some(Ty::Struct(i)) = t.lookup("padded") else {
            panic!("not found")
        };
        let def = t.def(i);
        let layout: Vec<_> = def
            .members
            .iter()
            .map(|m| (m.name.as_str(), m.offset, m.bit, m.array))
            .collect();
        assert_eq!(
            layout,
            vec![
                ("ZZZZZZZZZZPadded0", 0, None, 0),
                ("bool1", 0, Some(0), 0),
                ("sint", 1, None, 0),
                ("dint1", 4, None, 0),
                ("ZZZZZZZZZZPadded4", 8, None, 0),
                ("bool2", 8, Some(0), 0),
                ("lint", 12, None, 0), // 4-byte aligned, as in Logix
                ("bools", 20, None, 2),
            ]
        );
        assert_eq!(def.size, 28);
        assert_eq!(&def.template[8 * 8..8 * 8 + 9], b"Padded;n\0");
    }

    #[test]
    fn aoi_bools_are_bits_of_hidden_dint_hosts() {
        let members = (0..40).map(|i| MemberConfig::new(&format!("b{i}"), "BOOL"));
        let t = types(&[TypeConfig::aoi(
            "Big",
            members.chain([MemberConfig::new("x", "DINT").local()]),
        )]);
        let def = t.def(t.defs.len() - 1);
        assert_eq!(def.kind, StructKind::Aoi);
        let b39 = def.member("b39").expect("b39"); // the 42nd bool: host 1, bit 9
        assert_eq!((b39.offset, b39.bit), (5, Some(1)));
        assert_eq!(
            def.member("x").map(|m| (m.offset, m.local)),
            Some((8, true))
        );
        assert_eq!(def.size, 12);
        assert!(def.has_locals());
    }

    #[test]
    fn predefined_timer_and_string_templates() {
        let t = types(&[]);
        let Some(Ty::Struct(timer)) = t.lookup("TIMER") else {
            panic!()
        };
        let def = t.def(timer);
        assert_eq!(def.template_id, 0x0F83);
        assert_eq!(
            def.member("DN").map(|m| (m.offset, m.bit)),
            Some((3, Some(5)))
        );
        assert!(def.member("CTL").is_none());
        let Some(Ty::Struct(string)) = t.lookup("STRING") else {
            panic!()
        };
        assert_eq!(t.def(string).size, 88);
        assert!(
            t.def(string)
                .template
                .windows(14)
                .any(|w| w == b"ASCIISTRING82\0")
        );
    }

    #[test]
    fn values_roundtrip_through_json() {
        let t = types(&[
            TypeConfig::string("STRING20", 20),
            TypeConfig::udt(
                "Inner",
                [
                    MemberConfig::new("on", "BOOL"),
                    MemberConfig::array("r", "REAL", 2),
                    MemberConfig::new("s", "STRING20"),
                ],
            ),
        ]);
        let tag = Tag::build(
            &t,
            &TagConfig::new("x", "Inner")
                .dims(&[2])
                .value(json!([{"on": true, "r": [1.5, -2.0], "s": "hi"}, {"on": false}])),
            1,
        )
        .expect("tag");
        assert_eq!(
            t.decode_elements(tag.ty, 2, &tag.data),
            json!([{"on": true, "r": [1.5, -2.0], "s": "hi"}, {"on": false, "r": [0.0, 0.0], "s": ""}])
        );
        let bools = Tag::build(
            &t,
            &TagConfig::new("b", "BOOL")
                .dims(&[40])
                .value(json!([true, false, true])),
            2,
        )
        .expect("b");
        assert_eq!(
            (bools.dims.clone(), bools.elements, bools.symbol_type(&t)),
            (vec![64], 2, 0x20D3)
        );
        assert_eq!(bools.data[0], 0b101);
    }

    #[test]
    fn bad_configs_are_errors() {
        assert!(
            Types::build(&[
                TypeConfig::udt("A", [MemberConfig::new("b", "B")]),
                TypeConfig::udt("B", [MemberConfig::new("a", "A")])
            ])
            .is_err()
        );
        assert!(Types::build(&[TypeConfig::udt("A", [MemberConfig::new("x", "NOPE")])]).is_err());
        let t = types(&[]);
        assert!(Tag::build(&t, &TagConfig::new("x", "SINT").value(json!(300)), 1).is_err());
        assert!(
            Tag::build(
                &t,
                &TagConfig::new("x", "DINT").value(json!([1, 2])).dims(&[1]),
                1
            )
            .is_err()
        );
        assert!(Tag::build(&t, &TagConfig::new("x", "DINT").access("Write Only"), 1).is_err());
    }
}
