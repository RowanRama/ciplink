//! The symbol tree (spec 13): type-info objects to types, the DB list and the I/Q/M areas to top-level tags,
//! names to item addresses (spec 11.2, 11.6, 11.7), and the flat symbol list.

use std::collections::HashMap;

use indexmap::IndexMap;

use super::codec::{Cursor, Scalar, WireValue, address_crc};
use super::pdu::{ItemAddress, Object, VarType, ids};
use super::types::{S7Kind, S7Symbol, S7Tag, S7Type, softdatatype_name, system_type_name};
use crate::{ErrorKind, TagError};

/// The fixed type RIDs of the I, Q and M areas (spec 13.3), with their access areas.
pub(crate) const AREAS: [(u32, u32); 3] = [
    (ids::AREA_I, 0x9001_0000),
    (ids::AREA_Q, 0x9002_0000),
    (ids::AREA_M, 0x9003_0000),
];

/// Softdatatype of a plain STRUCT, UDT or system struct member.
const STRUCT_SDT: u8 = 17;

/// Where a member's value sits and what shape it has, from its offset info (spec 13.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Offset-info type (flags >> 12).
    pub kind: u8,
    /// Offset in the optimized layout.
    pub optimized: u32,
    /// Offset in the classic layout.
    pub classic: u32,
    /// Maximum length of a STRING / WSTRING (or of the elements of a STRING / WSTRING array).
    pub string_length: Option<u16>,
    /// Lower bounds in declared order (arrays).
    pub lower: Vec<i32>,
    /// Element counts in declared order (arrays).
    pub counts: Vec<u32>,
    /// Type RID of a structure member's type (or its elements' type).
    pub relation: Option<u32>,
    /// Element size of an array of structures: (classic, optimized).
    pub struct_size: Option<(u32, u32)>,
}

impl Layout {
    /// Struct, UDT, system type or FB instance (not an array).
    pub fn is_struct(&self) -> bool {
        matches!(self.kind, 5 | 12 | 15)
    }

    /// An array of structures or FB instances.
    pub fn is_struct_array(&self) -> bool {
        matches!(self.kind, 0 | 6 | 7 | 13 | 14)
    }

    /// Any array.
    pub fn is_array(&self) -> bool {
        !self.counts.is_empty()
    }

    /// Elements of the whole array (saturating: the counts come from the PLC).
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(1u64, |n, &c| n.saturating_mul(u64::from(c)))
    }

    fn parse(kind: u8, info: &[u8]) -> Self {
        let mut c = Cursor::new(info);
        let mut l = Layout {
            kind,
            ..Layout::default()
        };
        // the offset info has the size of its kind (checked by the vartype decoder), so reads cannot fail;
        // a short one leaves the defaults
        let _ = l.fill(&mut c);
        l
    }

    fn fill(&mut self, c: &mut Cursor<'_>) -> crate::Result<()> {
        let u32le = |c: &mut Cursor<'_>| c.u32_le();
        let i32le = |c: &mut Cursor<'_>| c.u32_le().map(|v| v as i32);
        match self.kind {
            1 => {
                self.classic = c.u16_le()?.into();
                self.optimized = c.u16_le()?.into();
            }
            8 => {
                self.optimized = c.u16_le()?.into();
                self.classic = c.u16_le()?.into();
            }
            _ => {
                let a = c.u16_le()?;
                let b = c.u16_le()?;
                // strings, and arrays (of strings: kept by Member::new only for those); for a WSTRING array b is
                // in bytes, so the smaller is still the length in characters
                if matches!(self.kind, 2 | 9 | 3 | 10 | 4 | 11) {
                    self.string_length = Some(a.min(b));
                }
                self.optimized = u32le(c)?;
                self.classic = u32le(c)?;
            }
        }
        let dims = |c: &mut Cursor<'_>, l: &mut Layout| -> crate::Result<()> {
            let mut lower = [0i32; 6];
            for v in &mut lower {
                *v = i32le(c)?;
            }
            for low in lower {
                let n = u32le(c)?;
                if n != 0 {
                    l.lower.push(low);
                    l.counts.push(n);
                }
            }
            // stored innermost (last declared) dimension first (spec 13.5, open questions)
            l.lower.reverse();
            l.counts.reverse();
            Ok(())
        };
        match self.kind {
            3 | 10 | 6 | 13 => {
                self.lower = vec![i32le(c)?];
                self.counts = vec![u32le(c)?];
                if matches!(self.kind, 6 | 13) {
                    let classic = u32le(c)?;
                    let optimized = u32le(c)?;
                    self.struct_size = Some((classic, optimized));
                    self.relation = Some(u32le(c)?);
                }
            }
            4 | 11 | 7 | 14 => {
                i32le(c)?;
                u32le(c)?; // total count
                dims(c, self)?;
                if matches!(self.kind, 7 | 14) {
                    let classic = u32le(c)?;
                    let optimized = u32le(c)?;
                    self.struct_size = Some((classic, optimized));
                    self.relation = Some(u32le(c)?);
                }
            }
            5 | 12 | 15 => self.relation = Some(u32le(c)?),
            0 => {
                self.relation = Some(u32le(c)?);
                c.take(4 * 6)?; // 4 u32, retain and volatile offsets
                u32le(c)?; // element count
                c.take(12)?; // section sizes
                dims(c, self)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// A member of a type (one vartype element and its name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Member {
    pub name: String,
    pub lid: u32,
    pub crc: u32,
    pub softdatatype: u8,
    pub flags: u16,
    pub bit_info: u8,
    pub layout: Layout,
}

impl Member {
    fn new(name: String, v: &VarType) -> Self {
        let kind = (v.flags >> 12) as u8;
        let mut layout = Layout::parse(kind, &v.offset_info);
        if !matches!(v.softdatatype, 19 | 62) {
            layout.string_length = None;
        }
        Member {
            name,
            lid: v.lid,
            crc: v.crc,
            softdatatype: v.softdatatype,
            flags: v.flags,
            bit_info: v.bit_info,
            layout,
        }
    }

    pub fn hmi_visible(&self) -> bool {
        self.flags & 0x0800 != 0
    }

    pub fn hmi_read_only(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    pub fn hmi_accessible(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// The bit number of a BOOL in a struct-form element (spec 11.8).
    pub fn bit(&self) -> u8 {
        (self.flags & 7) as u8
    }

    pub fn is_string(&self) -> bool {
        matches!(self.layout.kind, 2 | 9)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self.softdatatype, 1 | 40)
    }
}

/// A type-info object (spec 13.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TypeInfo {
    pub rid: u32,
    /// Attribute 233, often empty.
    pub name: String,
    /// Attribute 529.
    pub timestamp: u64,
    pub members: Vec<Member>,
}

impl TypeInfo {
    /// A class-511 object as a type; None for other objects.
    pub fn from_object(o: &Object) -> Option<TypeInfo> {
        if o.class != ids::CLASS_TYPE_INFO {
            return None;
        }
        let name = match o.attr(ids::ATTR_NAME).and_then(WireValue::as_scalar) {
            Some(Scalar::WString(s)) => s.clone(),
            _ => String::new(),
        };
        let timestamp = o
            .attr(529)
            .and_then(WireValue::as_scalar)
            .and_then(Scalar::as_i128)
            .map_or(0, |v| v as u64);
        let elements = o
            .vartypes
            .as_ref()
            .map(|l| l.elements.as_slice())
            .unwrap_or(&[]);
        let names = o.varnames.as_deref().unwrap_or(&[]);
        if elements.len() != names.len() {
            log::warn!(
                "S7comm-plus type 0x{:08X}: {} vartypes but {} names",
                o.rid,
                elements.len(),
                names.len()
            );
        }
        let members = elements
            .iter()
            .zip(names)
            .map(|(v, n)| Member::new(n.clone(), v))
            .collect();
        Some(TypeInfo {
            rid: o.rid,
            name,
            timestamp,
            members,
        })
    }

    fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name).or_else(|| {
            self.members
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(name))
        })
    }
}

/// A data block of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Db {
    pub name: String,
    pub number: u32,
    pub type_rid: u32,
}

/// Where a resolved name points.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Address {
    /// What goes on the wire.
    pub item: ItemAddress,
    /// The member at the end of the path.
    pub leaf: Member,
    /// True when the path ends with an index into an array (the leaf is one element).
    pub element: bool,
    pub hmi_visible: bool,
    pub hmi_accessible: bool,
    pub hmi_read_only: bool,
}

/// What identifies a tree's content: type RIDs with interface timestamps, and (name, number, type) per DB.
pub(crate) type Signature = (Vec<(u32, u64)>, Vec<(String, u32, u32)>);

/// The browsed symbol table.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SymbolTree {
    pub dbs: Vec<Db>,
    pub types: HashMap<u32, TypeInfo>,
}

/// The data blocks (class 2574) among explored objects, recursively, each once: (name, number).
pub(crate) fn data_blocks(objects: &[Object]) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = Vec::new();
    for o in objects {
        o.walk(&mut |x| {
            if x.class == ids::CLASS_DB
                && x.rid & 0xFFFF_0000 == ids::DB_AREA_BASE
                && !out.iter().any(|(_, n)| *n == x.rid & 0xFFFF)
            {
                let name = match x.attr(ids::ATTR_NAME).and_then(WireValue::as_scalar) {
                    Some(Scalar::WString(s)) => s.clone(),
                    _ => format!("DB{}", x.rid & 0xFFFF),
                };
                out.push((name, x.rid & 0xFFFF));
            }
        });
    }
    out
}

/// Every type-info object among explored objects, recursively.
pub(crate) fn type_infos(objects: &[Object]) -> Vec<TypeInfo> {
    let mut out = Vec::new();
    for o in objects {
        o.walk(&mut |x| out.extend(TypeInfo::from_object(x)));
    }
    out
}

fn not_found(name: &str) -> TagError {
    TagError::new(format!("Tag {name} not found"), ErrorKind::NotFound)
}

fn bad_name(name: &str, why: &str) -> TagError {
    TagError::new(
        format!("Invalid tag name {name}: {why}"),
        ErrorKind::BadRequest,
    )
}

/// One path segment: a member name and its indices.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    name: String,
    index: Option<Vec<i64>>,
}

/// Splits `"Line1".Items[3].Weight` into segments: on `.` outside brackets and quotes, one pair of quotes
/// stripped per segment.
fn parse_name(name: &str) -> Result<Vec<Segment>, TagError> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let (mut depth, mut quoted) = (0i32, false);
    for ch in name.chars() {
        match ch {
            '"' => quoted = !quoted,
            '[' if !quoted => depth += 1,
            ']' if !quoted => depth -= 1,
            '.' if !quoted && depth == 0 => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    parts.push(current);
    if depth != 0 || quoted {
        return Err(bad_name(name, "unbalanced brackets or quotes"));
    }
    parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let part = part.trim();
            let (head, index) = match part.rfind('[') {
                Some(open) if part.ends_with(']') && !part[open..].contains('"') => {
                    let inner = &part[open + 1..part.len() - 1];
                    let index = inner
                        .split(',')
                        .map(|s| s.trim().parse::<i64>())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| bad_name(name, "index is not a number"))?;
                    (&part[..open], Some(index))
                }
                _ => (part, None),
            };
            let head = head.trim();
            let head = head
                .strip_prefix('"')
                .and_then(|h| h.strip_suffix('"'))
                .unwrap_or(head);
            // the PLC's type information can hold members without a name (seen on a real CPU), so only the
            // first segment must have one
            if (i == 0 && head.is_empty()) || head.contains(['"', '[', ']']) {
                return Err(bad_name(name, "empty or malformed segment"));
            }
            Ok(Segment {
                name: head.to_string(),
                index,
            })
        })
        .collect()
}

/// The first name of `segments` that `exists`: one segment, or several joined by `.` (TIA names may contain
/// dots, such as clock memory bits; quoting them is not required). Returns the name, the
/// index of its last segment and how many segments it took.
fn take(
    segments: &[Segment],
    exists: impl Fn(&str) -> bool,
) -> Option<(String, Option<&Vec<i64>>, usize)> {
    let mut joined = String::new();
    for (k, seg) in segments.iter().enumerate() {
        if k > 0 {
            joined.push('.');
        }
        joined.push_str(&seg.name);
        if exists(&joined) {
            return Some((joined, seg.index.as_ref(), k + 1));
        }
        if seg.index.is_some() {
            return None;
        }
    }
    None
}

/// The zero-based linear index of `index` into an array with `lower` / `counts`, last dimension fastest.
fn linear_index(layout: &Layout, index: &[i64]) -> Option<u32> {
    if index.len() != layout.counts.len() {
        return None;
    }
    let mut linear: u64 = 0;
    for ((&i, &low), &count) in index.iter().zip(&layout.lower).zip(&layout.counts) {
        let offset = i.checked_sub(i64::from(low))?;
        if offset < 0 || offset >= i64::from(count) {
            return None;
        }
        linear = linear
            .checked_mul(u64::from(count))?
            .checked_add(offset as u64)?;
    }
    u32::try_from(linear).ok()
}

/// A path being walked: the address so far.
struct Walk {
    lids: Vec<u32>,
    crcs: Vec<u32>,
    indexed: bool,
    visible: bool,
    accessible: bool,
    read_only: bool,
}

impl Walk {
    fn new() -> Self {
        Walk {
            lids: Vec::new(),
            crcs: Vec::new(),
            indexed: false,
            visible: true,
            accessible: true,
            read_only: false,
        }
    }

    fn enter(&mut self, m: &Member) {
        self.lids.push(m.lid);
        self.crcs.push(m.crc);
        self.visible &= m.hmi_visible();
        self.accessible &= m.hmi_accessible();
        self.read_only |= m.hmi_read_only();
    }

    /// The address CRC of the path walked so far, ending at `leaf`. 0 with an index (no CRC is defined for one)
    /// and for a whole STRUCT / UDT (softdatatype 17): a real CPU rejects the vartype CRC there (item error -17)
    /// although the same CRCs work as a prefix of a member's path, and DTL, IEC_TIMER and other system types
    /// with their own softdatatype accept it.
    fn crc(&self, leaf: &Member) -> u32 {
        if self.indexed || leaf.softdatatype == STRUCT_SDT {
            0
        } else {
            address_crc(&self.crcs)
        }
    }
}

impl SymbolTree {
    /// Builds the tree from the DB list (name, number), each DB's type RID and the type information. A DB
    /// without a type RID (an item error on LID 1) is left out.
    pub fn new(
        dbs: Vec<(String, u32)>,
        db_types: &HashMap<u32, u32>,
        types: Vec<TypeInfo>,
    ) -> Self {
        let dbs = dbs
            .into_iter()
            .filter_map(|(name, number)| {
                db_types.get(&number).map(|&type_rid| Db {
                    name,
                    number,
                    type_rid,
                })
            })
            .collect();
        let types = types.into_iter().map(|t| (t.rid, t)).collect();
        SymbolTree { dbs, types }
    }

    /// The tree's identity for change detection: type RIDs and interface timestamps, and the DB list.
    pub fn signature(&self) -> Signature {
        let mut types: Vec<(u32, u64)> =
            self.types.values().map(|t| (t.rid, t.timestamp)).collect();
        types.sort_unstable();
        let dbs = self
            .dbs
            .iter()
            .map(|d| (d.name.clone(), d.number, d.type_rid))
            .collect();
        (types, dbs)
    }

    fn db(&self, name: &str) -> Option<&Db> {
        self.dbs
            .iter()
            .find(|d| d.name == name)
            .or_else(|| self.dbs.iter().find(|d| d.name.eq_ignore_ascii_case(name)))
    }

    /// The PLC tag `name` of the I, Q or M area: (access area, member).
    fn area_tag(&self, name: &str) -> Option<(u32, &Member)> {
        let find = |exact: bool| {
            AREAS.iter().find_map(|&(area, rid)| {
                let t = self.types.get(&rid)?;
                let m = t.members.iter().find(|m| {
                    if exact {
                        m.name == name
                    } else {
                        m.name.eq_ignore_ascii_case(name)
                    }
                })?;
                Some((area, m))
            })
        };
        find(true).or_else(|| find(false))
    }

    /// Resolves a tag name to its address (spec 11.2, 11.6, 11.7).
    pub fn resolve(&self, name: &str) -> Result<Address, TagError> {
        let segments = parse_name(name)?;
        let mut walk = Walk::new();
        let (area, sub_area, mut current, steps): (u32, u32, Option<u32>, &[Segment]);
        if let Some((db_name, index, k)) = take(&segments, |n| self.db(n).is_some()) {
            let db = self.db(&db_name).ok_or_else(|| not_found(name))?;
            if index.is_some() {
                return Err(bad_name(name, "a data block has no index"));
            }
            if k == segments.len() {
                return Err(TagError::new(
                    format!("{name} is a data block: read its members"),
                    ErrorKind::BadRequest,
                ));
            }
            area = ids::DB_AREA_BASE + db.number;
            sub_area = ids::DB_VALUE_ACTUAL;
            current = Some(db.type_rid);
            steps = &segments[k..];
        } else if let Some((tag, _, _)) = take(&segments, |n| self.area_tag(n).is_some()) {
            let (a, _) = self.area_tag(&tag).ok_or_else(|| not_found(name))?;
            area = a;
            sub_area = ids::CONTROLLER_AREA_VALUE_ACTUAL;
            current = AREAS.iter().find(|(x, _)| *x == a).map(|(_, rid)| *rid);
            steps = &segments;
        } else {
            return Err(not_found(name));
        }
        let mut leaf: Option<(Member, bool)> = None;
        let mut i = 0;
        while i < steps.len() {
            let t = current
                .and_then(|rid| self.types.get(&rid))
                .ok_or_else(|| not_found(name))?;
            let (member, index, k) =
                take(&steps[i..], |n| t.member(n).is_some()).ok_or_else(|| not_found(name))?;
            i += k;
            let m = t.member(&member).ok_or_else(|| not_found(name))?;
            walk.enter(m);
            current = None;
            let mut element = false;
            if let Some(index) = index {
                if !m.layout.is_array() {
                    return Err(bad_name(name, "index on a member that is not an array"));
                }
                // The flat order of a multi-dimensional array (which dimension varies fastest, and the
                // padding of BOOL runs) is not verified on a CPU (spec 11.6), and an element address carries
                // CRC 0, so a wrong guess would read or write another element without an error. Refused until
                // a bench read settles it; the whole array reads and writes.
                if m.layout.counts.len() > 1 {
                    return Err(bad_name(
                        name,
                        "elements of multi-dimensional arrays are not supported: read or write the whole array",
                    ));
                }
                let linear = linear_index(&m.layout, index).ok_or_else(|| not_found(name))?;
                walk.lids.push(linear);
                walk.indexed = true;
                element = true;
                if m.layout.is_struct_array() {
                    // members of an element follow the literal LID 1 (spec 11.6); a whole element of a system
                    // type (DTL, IEC_TIMER) is addressed without it, as tag_list lists it (unverified)
                    if !is_system(m.layout.relation) || i < steps.len() {
                        walk.lids.push(1);
                    }
                    current = m.layout.relation;
                }
            } else if m.layout.is_struct() {
                current = m.layout.relation;
            }
            leaf = Some((m.clone(), element));
        }
        let (leaf, element) = leaf.ok_or_else(|| not_found(name))?;
        Ok(Address {
            item: ItemAddress {
                crc: walk.crc(&leaf),
                area,
                sub_area,
                lids: walk.lids.clone(),
            },
            leaf,
            element,
            hmi_visible: walk.visible,
            hmi_accessible: walk.accessible,
            hmi_read_only: walk.read_only,
        })
    }

    /// The name of a structure type.
    pub fn type_name_of(&self, rid: u32) -> String {
        if let Some(t) = self.types.get(&rid)
            && !t.name.is_empty()
        {
            return t.name.clone();
        }
        system_type_name(rid).map_or_else(|| format!("0x{rid:08X}"), str::to_string)
    }

    /// The S7 type name of a member's element (no dims).
    pub fn member_type_name(&self, m: &Member) -> String {
        match m.layout.relation {
            Some(rid) if m.layout.is_struct() || m.layout.is_struct_array() => {
                match self.types.get(&rid) {
                    Some(t) if !t.name.is_empty() => t.name.clone(),
                    _ if !matches!(m.softdatatype, 17 | 21 | 0) => {
                        softdatatype_name(m.softdatatype)
                    }
                    _ => self.type_name_of(rid),
                }
            }
            _ => softdatatype_name(m.softdatatype),
        }
    }

    /// The value's type name of an address: the element type, `[n]` / `[n,m]` for a whole array.
    pub fn data_type(&self, a: &Address) -> String {
        let base = self.member_type_name(&a.leaf);
        if a.leaf.layout.is_array() && !a.element {
            let dims: Vec<String> = a.leaf.layout.counts.iter().map(u32::to_string).collect();
            format!("{base}[{}]", dims.join(","))
        } else {
            base
        }
    }

    fn tag(&self, m: &Member) -> S7Tag {
        let kind = if m.layout.is_struct() || m.layout.is_struct_array() {
            S7Kind::Struct
        } else if m.is_string() {
            S7Kind::String
        } else {
            S7Kind::Elementary
        };
        S7Tag {
            name: m.name.clone(),
            type_name: self.member_type_name(m),
            kind,
            softdatatype: m.softdatatype,
            dims: m.layout.counts.clone(),
            lower_bounds: m.layout.lower.clone(),
            string_length: m.layout.string_length,
            lid: m.lid,
            member_crc: m.crc,
            hmi_visible: m.hmi_visible(),
            hmi_accessible: m.hmi_accessible(),
            hmi_read_only: m.hmi_read_only(),
        }
    }

    /// Top-level tags: each data block, then each PLC tag of the I, Q and M areas.
    pub fn tags(&self) -> IndexMap<String, S7Tag> {
        let mut out = IndexMap::new();
        for db in &self.dbs {
            out.insert(
                db.name.clone(),
                S7Tag {
                    name: db.name.clone(),
                    type_name: self.type_name_of(db.type_rid),
                    kind: S7Kind::DataBlock,
                    softdatatype: 0,
                    dims: Vec::new(),
                    lower_bounds: Vec::new(),
                    string_length: None,
                    lid: db.number,
                    member_crc: 0,
                    hmi_visible: true,
                    hmi_accessible: true,
                    hmi_read_only: false,
                },
            );
        }
        for (_, rid) in AREAS {
            for m in self.types.get(&rid).map_or(&[][..], |t| &t.members) {
                out.entry(m.name.clone()).or_insert_with(|| self.tag(m));
            }
        }
        out
    }

    /// The structure types reachable from the data blocks and areas, by type name.
    pub fn data_types(&self) -> IndexMap<String, S7Type> {
        let mut seen = std::collections::HashSet::new();
        let mut order = Vec::new();
        let mut stack: Vec<u32> = self.dbs.iter().map(|d| d.type_rid).collect();
        stack.extend(AREAS.iter().map(|(_, rid)| *rid));
        stack.reverse();
        while let Some(rid) = stack.pop() {
            if !seen.insert(rid) {
                continue;
            }
            let Some(t) = self.types.get(&rid) else {
                continue;
            };
            order.push(rid);
            for m in t.members.iter().rev() {
                if let Some(r) = m.layout.relation {
                    stack.push(r);
                }
            }
        }
        let mut out = IndexMap::new();
        for rid in order {
            let t = &self.types[&rid];
            let members = t
                .members
                .iter()
                .map(|m| (m.name.clone(), self.tag(m)))
                .collect();
            out.insert(
                self.type_name_of(rid),
                S7Type {
                    name: self.type_name_of(rid),
                    rid,
                    interface_timestamp: t.timestamp,
                    members,
                },
            );
        }
        out
    }

    /// The symbol of a resolved name.
    pub fn symbol(&self, name: &str, a: &Address) -> S7Symbol {
        S7Symbol {
            name: name.to_string(),
            type_name: self.member_type_name(&a.leaf),
            dims: if a.element {
                Vec::new()
            } else {
                a.leaf.layout.counts.clone()
            },
            access: a.item.access(),
            crc: a.item.crc,
            hmi_visible: a.hmi_visible,
            hmi_accessible: a.hmi_accessible,
            hmi_read_only: a.hmi_read_only,
        }
    }

    /// Every symbol as a flat list (spec 13.6): structures, FB instances and arrays of structures expanded,
    /// elementary arrays and system types (DTL, IEC timers, ...) listed once.
    pub fn symbols(&self) -> Vec<S7Symbol> {
        let mut out = Vec::new();
        for db in &self.dbs {
            let area = ids::DB_AREA_BASE + db.number;
            self.expand(db.type_rid, &db.name, area, &mut Walk::new(), &mut out, 0);
        }
        for (area, rid) in AREAS {
            if let Some(t) = self.types.get(&rid) {
                for m in &t.members {
                    self.expand_member(m, "", area, &mut Walk::new(), &mut out, 0);
                }
            }
        }
        out
    }

    fn expand(
        &self,
        rid: u32,
        prefix: &str,
        area: u32,
        walk: &mut Walk,
        out: &mut Vec<S7Symbol>,
        depth: usize,
    ) {
        let Some(t) = self.types.get(&rid) else {
            log::debug!("S7comm-plus type 0x{rid:08X} has no type information");
            return;
        };
        if depth > 32 {
            return;
        }
        for m in &t.members {
            self.expand_member(m, prefix, area, walk, out, depth);
        }
    }

    fn expand_member(
        &self,
        m: &Member,
        prefix: &str,
        area: u32,
        walk: &mut Walk,
        out: &mut Vec<S7Symbol>,
        depth: usize,
    ) {
        let saved = (walk.lids.len(), walk.crcs.len(), walk.indexed);
        let flags = (walk.visible, walk.accessible, walk.read_only);
        let name = if prefix.is_empty() {
            m.name.clone()
        } else {
            format!("{prefix}.{}", m.name)
        };
        walk.enter(m);
        if m.layout.is_struct() && !is_system(m.layout.relation) && m.layout.relation.is_some() {
            if let Some(rid) = m.layout.relation {
                self.expand(rid, &name, area, walk, out, depth + 1);
            }
        } else if m.layout.is_struct_array()
            && m.layout.relation.is_some()
            && m.layout.counts.len() == 1
        {
            // multi-dimensional arrays of structures are listed once: their elements are not addressable yet
            let total = m.layout.total().min(u64::from(u32::MAX)) as u32;
            for i in 0..total {
                let label = index_label(&m.layout, i);
                let element = format!("{name}[{label}]");
                let before = (walk.lids.len(), walk.indexed);
                walk.lids.push(i);
                walk.indexed = true;
                if is_system(m.layout.relation) {
                    out.push(self.listed(&element, m, area, walk, true));
                } else {
                    walk.lids.push(1);
                    if let Some(rid) = m.layout.relation {
                        self.expand(rid, &element, area, walk, out, depth + 1);
                    }
                }
                walk.lids.truncate(before.0);
                walk.indexed = before.1;
            }
        } else {
            out.push(self.listed(&name, m, area, walk, false));
        }
        walk.lids.truncate(saved.0);
        walk.crcs.truncate(saved.1);
        walk.indexed = saved.2;
        (walk.visible, walk.accessible, walk.read_only) = flags;
    }

    fn listed(&self, name: &str, m: &Member, area: u32, walk: &Walk, element: bool) -> S7Symbol {
        let item = ItemAddress {
            crc: walk.crc(m),
            area,
            sub_area: 0,
            lids: walk.lids.clone(),
        };
        S7Symbol {
            name: name.to_string(),
            type_name: self.member_type_name(m),
            dims: if element {
                Vec::new()
            } else {
                m.layout.counts.clone()
            },
            access: item.access(),
            crc: item.crc,
            hmi_visible: walk.visible,
            hmi_accessible: walk.accessible,
            hmi_read_only: walk.read_only,
        }
    }
}

/// System types (0x0200nnnn: DTL, IEC timers and counters, ...) are values of their own; system FB instances
/// (0x0205nnnn) and system structs (0x0208nnnn) are expanded like user types.
fn is_system(relation: Option<u32>) -> bool {
    relation.is_some_and(|r| r >> 16 == 0x0200)
}

/// `3` or `2,5`: the declared indices of linear element `i`, last dimension fastest.
fn index_label(layout: &Layout, i: u32) -> String {
    let mut rest = u64::from(i);
    let mut parts = vec![0i64; layout.counts.len()];
    for (k, &count) in layout.counts.iter().enumerate().rev() {
        let count = u64::from(count.max(1));
        parts[k] = (rest % count) as i64 + i64::from(layout.lower[k]);
        rest /= count;
    }
    parts
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::s7plus::codec::member_crc;
    use crate::s7plus::pdu::VartypeList;

    /// A vartype element built from its parts (struct-form offset types use their own field order).
    pub(crate) fn element(
        name: &str,
        lid: u32,
        sdt: u8,
        kind: u8,
        hmi: u16,
        info: &[u32],
    ) -> (String, VarType) {
        let code = match sdt {
            40 => 1,
            s => s,
        };
        let crc = if matches!(kind, 3 | 10) {
            // one-dimensional arrays: name, 16, element code, lower bound (spec 11.7)
            let mut data = name.as_bytes().to_vec();
            data.extend_from_slice(&[0x10, code]);
            data.extend_from_slice(&info.get(3).copied().unwrap_or(0).to_le_bytes());
            crate::s7plus::codec::crc32(&data)
        } else {
            member_crc(name, code)
        };
        let size = crate::s7plus::pdu::offset_info_size(kind);
        let mut oi = Vec::with_capacity(size);
        match kind {
            1 | 8 => {
                oi.extend_from_slice(&(info.first().copied().unwrap_or(0) as u16).to_le_bytes());
                oi.extend_from_slice(&(info.get(1).copied().unwrap_or(0) as u16).to_le_bytes());
            }
            _ => {
                for v in info {
                    oi.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
        oi.resize(size, 0);
        (
            name.to_string(),
            VarType {
                lid,
                crc,
                softdatatype: sdt,
                flags: (u16::from(kind) << 12) | hmi | 0x0080,
                bit_info: 0,
                offset_info: oi,
            },
        )
    }

    pub(crate) fn type_object(
        rid: u32,
        name: &str,
        timestamp: u64,
        members: Vec<(String, VarType)>,
    ) -> Object {
        let (names, elements): (Vec<String>, Vec<VarType>) = members.into_iter().unzip();
        Object {
            rid,
            class: ids::CLASS_TYPE_INFO,
            flags: 0x20,
            attrs: vec![
                (233, WireValue::scalar(Scalar::WString(name.into()))),
                (529, WireValue::scalar(Scalar::ULInt(timestamp))),
            ],
            vartypes: Some(VartypeList {
                first_id: 0x8000_0004,
                elements,
            }),
            varnames: Some(names),
            ..Object::default()
        }
    }

    const HMI: u16 = 0x0A00;

    /// Two-dim array offset info (type 11): u16 pair, opt, classic, lower, total, 6 lowers, 6 counts; the
    /// bounds in declared order, stored innermost dimension first.
    fn two_dim(lower: [i32; 2], counts: [u32; 2]) -> Vec<u32> {
        let mut v = vec![0, 0, 0, 0, counts[0] * counts[1]];
        v.extend([lower[1] as u32, lower[0] as u32, 0, 0, 0, 0]);
        v.extend([counts[1], counts[0], 0, 0, 0, 0]);
        v
    }

    /// The invented `Line1` of the spec examples, plus arrays and an I-area tag.
    pub(crate) fn sample_tree() -> SymbolTree {
        let conveyor = type_object(
            0x9201_0005,
            "",
            11,
            vec![
                element("Running", 9, 1, 1, HMI, &[0, 0]),
                element("Speed", 0xB, 8, 1, HMI, &[2, 2]),
            ],
        );
        let item = type_object(
            0x9100_0001,
            "",
            12,
            vec![
                element("Weight", 0xB, 8, 1, HMI, &[0, 0]),
                element("Count", 0xC, 7, 1, HMI, &[4, 4]),
            ],
        );
        let dtl = type_object(
            0x0200_0043,
            "",
            1_224_779_910_406_829_900,
            vec![
                element("YEAR", 9, 53, 1, HMI, &[0, 0]),
                element("MONTH", 0xA, 52, 1, HMI, &[2, 2]),
                element("DAY", 0xB, 52, 1, HMI, &[3, 3]),
                element("WEEKDAY", 0xC, 52, 1, HMI, &[4, 4]),
                element("HOUR", 0xD, 52, 1, HMI, &[5, 5]),
                element("MINUTE", 0xE, 52, 1, HMI, &[6, 6]),
                element("SECOND", 0xF, 52, 1, HMI, &[7, 7]),
                element("NANOSECOND", 0x10, 54, 1, HMI, &[8, 8]),
            ],
        );
        let db = type_object(
            0x9200_0005,
            "",
            13,
            vec![
                element("Conveyor", 0xA, 17, 12, HMI, &[0, 0, 0, 0x9201_0005]),
                element("Count", 0xC, 7, 8, HMI, &[4, 4]),
                element("Total", 0xD, 49, 8, HMI, &[8, 8]),
                element("Recipe", 0xE, 19, 9, HMI, &[0x000A_000C, 16, 16]),
                element("Label", 0xF, 62, 9, HMI, &[0x0004_0006, 28, 28]),
                element("Stamp", 0x10, 67, 12, HMI, &[0, 40, 40, 0x0200_0043]),
                element("Items", 0x11, 53, 10, HMI, &[0, 52, 52, 1, 50]),
                element("Grid", 0x12, 7, 11, HMI, &two_dim([0, 0], [16, 4])),
                element(
                    "Parts",
                    0x13,
                    17,
                    13,
                    HMI,
                    &[0, 400, 400, 0, 3, 8, 8, 0x9100_0001],
                ),
                element("Flags", 0x14, 40, 10, HMI, &[0, 500, 500, 0, 256]),
                element("Hidden", 0x15, 5, 8, 0, &[540, 540]),
                element(
                    "Stamps",
                    0x16,
                    67,
                    13,
                    HMI,
                    &[0, 700, 700, 0, 3, 12, 12, 0x0200_0043],
                ),
                // ARRAY[0..2] OF WSTRING[24]: 24 characters, 52 bytes (as captured)
                element("Names", 0x17, 62, 10, HMI, &[0x0034_0018, 800, 800, 0, 3]),
                element("Bits", 0x18, 1, 11, HMI, &two_dim([0, 0], [3, 5])),
                element("Cells", 0x19, 17, 14, HMI, &{
                    let mut v = two_dim([0, 0], [2, 2]);
                    v.extend([8, 8, 0x9100_0001]);
                    v
                }),
            ],
        );
        let i_area = type_object(
            0x9001_0000,
            "IArea",
            0,
            vec![element("StartButton", 0xC, 1, 8, HMI, &[0, 0])],
        );
        let types = type_infos(&[conveyor, item, dtl, db, i_area]);
        let mut db_types = HashMap::new();
        db_types.insert(5, 0x9200_0005);
        SymbolTree::new(
            vec![("Line1".into(), 5), ("Gone".into(), 9)],
            &db_types,
            types,
        )
    }

    #[test]
    fn the_spec_paths_resolve_to_their_access_and_crc() {
        let tree = sample_tree();
        let cases = [
            ("Line1.Conveyor.Speed", "8A0E0005.A.B", 0x6E44_A73A),
            ("Line1.Conveyor.Running", "8A0E0005.A.9", 0x2556_A63B),
            ("Line1.Count", "8A0E0005.C", 0xDA02_6CFF),
            ("Line1.Total", "8A0E0005.D", 0x646C_6642),
            ("Line1.Recipe", "8A0E0005.E", 0x8C4E_AA1D),
            ("Line1.Label", "8A0E0005.F", 0xA8FA_43BE),
            ("Line1.Stamp", "8A0E0005.10", 0xFCA8_4867),
            ("StartButton", "50.C", 0xB285_B00A),
        ];
        for (name, access, crc) in cases {
            let a = tree.resolve(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(a.item.access(), access, "{name}");
            assert_eq!(a.item.crc, crc, "{name}");
        }
        let a = tree.resolve("Line1.Count").expect("count");
        assert_eq!(a.item.sub_area, ids::DB_VALUE_ACTUAL);
        let a = tree.resolve("StartButton").expect("area");
        assert_eq!(a.item.sub_area, ids::CONTROLLER_AREA_VALUE_ACTUAL);
    }

    #[test]
    fn a_whole_struct_is_read_with_crc_0_and_its_members_with_their_crc() {
        let tree = sample_tree();
        let whole = tree.resolve("Line1.Conveyor").expect("conveyor");
        assert_eq!(whole.item.access(), "8A0E0005.A");
        assert_eq!(whole.item.crc, 0);
        let listed = tree.symbols();
        assert!(
            listed
                .iter()
                .all(|s| s.name != "Line1.Conveyor" || s.crc == 0)
        );
        // a member below it and a system type (DTL) keep their CRC
        assert_eq!(
            tree.resolve("Line1.Conveyor.Speed")
                .expect("speed")
                .item
                .crc,
            0x6E44_A73A
        );
        assert_ne!(tree.resolve("Line1.Stamp").expect("stamp").item.crc, 0);
    }

    #[test]
    fn indices_use_lower_bounds_and_linear_order_and_drop_the_crc() {
        let tree = sample_tree();
        let a = tree.resolve("Line1.Items[4]").expect("items");
        assert_eq!(a.item.access(), "8A0E0005.11.3");
        assert_eq!(a.item.crc, 0);
        assert!(a.element);
        assert!(matches!(tree.resolve("Line1.Items[0]"), Err(e) if e.kind == ErrorKind::NotFound));
        assert!(matches!(tree.resolve("Line1.Items[51]"), Err(e) if e.kind == ErrorKind::NotFound));
        assert!(tree.resolve("Line1.Grid[2,3]").is_err());
        assert!(tree.resolve("Line1.Grid[16,0]").is_err());
        assert!(tree.resolve("Line1.Grid[1]").is_err(), "too few indices");
        let a = tree.resolve("Line1.Parts[2].Count").expect("struct array");
        assert_eq!(a.item.access(), "8A0E0005.13.2.1.C");
        assert_eq!(a.item.crc, 0);
        let whole = tree.resolve("Line1.Grid").expect("whole");
        assert_eq!(tree.data_type(&whole), "DINT[16,4]");
        assert_ne!(whole.item.crc, 0);
    }

    #[test]
    fn elements_of_multi_dimensional_arrays_are_refused_until_their_order_is_verified() {
        let tree = sample_tree();
        for name in [
            "Line1.Grid[1,2]",
            "Line1.Grid[5,0]",
            "Line1.Bits[1,0]",
            "Line1.Cells[1,1].Weight",
        ] {
            assert_eq!(
                tree.resolve(name).expect_err(name).kind,
                ErrorKind::BadRequest,
                "{name}"
            );
        }
        let whole = tree.resolve("Line1.Bits").expect("whole BOOL array");
        assert_eq!(whole.leaf.layout.counts, vec![3, 5]);
        let symbols = tree.symbols();
        assert!(
            symbols.iter().any(|s| s.name == "Line1.Cells"),
            "listed once"
        );
        assert!(!symbols.iter().any(|s| s.name.starts_with("Line1.Cells[")));
    }

    #[test]
    fn string_arrays_carry_their_maximum_length() {
        let tree = sample_tree();
        let names = tree.resolve("Line1.Names[1]").expect("names");
        assert_eq!(names.leaf.layout.string_length, Some(24));
        assert_eq!(tree.tags().len(), 2);
        let db = &tree.data_types()["0x92000005"];
        assert_eq!(db.members["Names"].string_length, Some(24));
        assert_eq!(db.members["Items"].string_length, None, "not a string");
        assert_eq!(db.members["Grid"].string_length, None);
    }

    #[test]
    fn elements_of_system_type_arrays_resolve_as_tag_list_lists_them() {
        let tree = sample_tree();
        let listed = tree
            .symbols()
            .into_iter()
            .find(|s| s.name == "Line1.Stamps[1]")
            .expect("listed");
        assert_eq!(listed.access, "8A0E0005.16.1");
        let a = tree.resolve("Line1.Stamps[1]").expect("element");
        assert_eq!(a.item.access(), listed.access);
        let month = tree.resolve("Line1.Stamps[1].MONTH").expect("member");
        assert_eq!(month.item.access(), "8A0E0005.16.1.1.A");
        let part = tree.resolve("Line1.Parts[2]").expect("user struct element");
        assert_eq!(part.item.access(), "8A0E0005.13.2.1");
    }

    #[test]
    fn names_are_quoted_case_insensitive_and_checked() {
        let tree = sample_tree();
        let a = tree
            .resolve("\"Line1\".\"Conveyor\".Speed")
            .expect("quoted");
        assert_eq!(a.item.crc, 0x6E44_A73A);
        let a = tree.resolve("line1.conveyor.SPEED").expect("case");
        assert_eq!(a.item.crc, 0x6E44_A73A);
        let a = tree.resolve("startbutton").expect("area case");
        assert_eq!(a.item.area, ids::AREA_I);
        for (name, kind) in [
            ("Nope.Speed", ErrorKind::NotFound),
            ("Line1.Nope", ErrorKind::NotFound),
            ("Line1.Count.Deeper", ErrorKind::NotFound),
            ("Gone.X", ErrorKind::NotFound),
            ("Line1", ErrorKind::BadRequest),
            ("Line1.Items[x]", ErrorKind::BadRequest),
            ("Line1.Items[1", ErrorKind::BadRequest),
            ("Line1..Count", ErrorKind::NotFound),
            (".Count", ErrorKind::BadRequest),
            ("Line1.Count[1]", ErrorKind::BadRequest),
        ] {
            assert_eq!(tree.resolve(name).expect_err(name).kind, kind, "{name}");
        }
    }

    #[test]
    fn names_with_dots_resolve_quoted_or_not() {
        let mut tree = sample_tree();
        let m_area = type_object(
            0x9003_0000,
            "MArea",
            0,
            vec![element("Blink_2.5s", 0x16, 1, 8, HMI, &[0, 0])],
        );
        for t in type_infos(&[m_area]) {
            tree.types.insert(t.rid, t);
        }
        let quoted = tree.resolve("\"Blink_2.5s\"").expect("quoted");
        let plain = tree.resolve("Blink_2.5s").expect("plain");
        assert_eq!(quoted, plain);
        assert_eq!(plain.item.access(), "52.16");
        assert!(tree.symbols().iter().any(|s| s.name == "Blink_2.5s"));
    }

    #[test]
    fn dtl_members_are_addressable_with_a_full_crc() {
        let tree = sample_tree();
        let a = tree.resolve("Line1.Stamp.MONTH").expect("month");
        assert_eq!(a.item.access(), "8A0E0005.10.A");
        let stamp = member_crc("Stamp", 67);
        assert_eq!(a.item.crc, address_crc(&[stamp, member_crc("MONTH", 52)]));
        assert_eq!(tree.data_type(&a), "USINT");
    }

    #[test]
    fn hmi_flags_are_anded_down_the_path() {
        let tree = sample_tree();
        let a = tree.resolve("Line1.Hidden").expect("hidden");
        assert!(!a.hmi_accessible && !a.hmi_visible);
        let a = tree.resolve("Line1.Conveyor.Speed").expect("speed");
        assert!(a.hmi_accessible && a.hmi_visible && !a.hmi_read_only);
    }

    #[test]
    fn the_dtl_type_info_example_has_eight_members() {
        let hexs = "a102000043837f2000a38169001500a38308000c80000003a38314000400a38411000588bfe9adb6ffaaf74ca38b5e00\
             040ca38b5f000800a384630017000006068c0700040c8c0800040c8c0900040c00a3831a000500a3831c000b0001a383\
             1d000400a3831e000404ab0084040000800900000093973bd7351a8000000000000a000000147f4ed7341a8000020002\
             000b0000006de7eef6341a8000030003000c0000004101e2c2341a8000040004000d00000084d6a870341a8000050005\
             000e0000006086d75e341a8000060006000f0000006ea81211341a8000070007001000000073001b76361a8000080008\
             000000ac003d045945415200054d4f4e5448000344415900075745454b4441590004484f555200064d494e5554450006\
             5345434f4e44000a4e414e4f5345434f4e44000000a2";
        let bytes: Vec<u8> = (0..hexs.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).expect("hex"))
            .collect();
        let objects = Object::decode_list(&mut Cursor::new(&bytes)).expect("decode");
        let t = TypeInfo::from_object(&objects[0]).expect("type");
        assert_eq!(t.members.len(), 8);
        assert_eq!(t.timestamp, 1_224_779_910_406_829_900);
        let lids: Vec<u32> = t.members.iter().map(|m| m.lid).collect();
        assert_eq!(lids, (9..=0x10).collect::<Vec<_>>());
        assert_eq!(t.members[0].crc, 0xD73B_9793);
        assert_eq!(t.members[0].crc, member_crc("YEAR", 53));
        assert_eq!(t.members[7].layout.optimized, 8);
        assert_eq!(t.members[7].layout.classic, 8);
        assert_eq!(t.members[1].name, "MONTH");
        assert_eq!(t.members[1].layout.optimized, 2);
        assert!(t.members[0].hmi_visible() && t.members[0].hmi_accessible());
    }

    #[test]
    fn symbols_expand_structs_and_struct_arrays_and_list_arrays_once() {
        let tree = sample_tree();
        let symbols = tree.symbols();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Line1.Conveyor.Speed"));
        assert!(names.contains(&"Line1.Stamp"), "DTL listed once");
        assert!(!names.contains(&"Line1.Stamp.MONTH"));
        assert!(names.contains(&"Line1.Items"));
        assert!(!names.iter().any(|n| n.starts_with("Line1.Items[")));
        assert!(names.contains(&"Line1.Parts[0].Weight"));
        assert!(names.contains(&"Line1.Parts[2].Count"));
        assert!(names.contains(&"StartButton"));
        assert_eq!(
            names
                .iter()
                .filter(|n| n.starts_with("Line1.Parts"))
                .count(),
            6
        );
        for s in &symbols {
            let a = tree
                .resolve(&s.name)
                .unwrap_or_else(|e| panic!("{}: {e}", s.name));
            assert_eq!(tree.symbol(&s.name, &a), *s, "{}", s.name);
        }
        let speed = symbols
            .iter()
            .find(|s| s.name == "Line1.Conveyor.Speed")
            .expect("speed");
        assert_eq!(
            (speed.access.as_str(), speed.crc),
            ("8A0E0005.A.B", 0x6E44_A73A)
        );
        let items = symbols
            .iter()
            .find(|s| s.name == "Line1.Items")
            .expect("items");
        assert_eq!(items.dims, vec![50]);
        assert_eq!(items.type_name, "UINT");
    }

    #[test]
    fn tags_and_data_types() {
        let tree = sample_tree();
        let tags = tree.tags();
        assert_eq!(
            tags.keys().collect::<Vec<_>>(),
            vec!["Line1", "StartButton"]
        );
        assert_eq!(tags["Line1"].kind, S7Kind::DataBlock);
        assert_eq!(tags["Line1"].type_name, "0x92000005");
        assert_eq!(tags["StartButton"].type_name, "BOOL");
        let types = tree.data_types();
        assert!(types.contains_key("DTL"));
        assert!(types.contains_key("0x92010005"));
        assert_eq!(types["DTL"].members.len(), 8);
        let db = &types["0x92000005"];
        assert_eq!(db.members["Stamp"].type_name, "DTL");
        assert_eq!(db.members["Recipe"].string_length, Some(10));
        assert_eq!(db.members["Recipe"].kind, S7Kind::String);
        assert_eq!(db.members["Grid"].dims, vec![16, 4]);
        assert_eq!(db.members["Parts"].kind, S7Kind::Struct);
    }

    #[test]
    fn index_labels_count_the_last_dimension_fastest() {
        let layout = Layout {
            kind: 14,
            lower: vec![1, 0],
            counts: vec![2, 3],
            ..Layout::default()
        };
        let labels: Vec<String> = (0..6).map(|i| index_label(&layout, i)).collect();
        assert_eq!(labels, vec!["1,0", "1,1", "1,2", "2,0", "2,1", "2,2"]);
        assert_eq!(linear_index(&layout, &[2, 1]), Some(4));
    }

    #[test]
    fn n_dim_bounds_are_stored_innermost_first() {
        // ARRAY[1..2, 5..7]: the stored lists start with the last declared dimension (5..7)
        let mut info = vec![0u8; 4];
        for v in [0u32, 0, 0, 6, 5, 1, 0, 0, 0, 0, 3, 2, 0, 0, 0, 0] {
            info.extend_from_slice(&v.to_le_bytes());
        }
        let layout = Layout::parse(11, &info);
        assert_eq!(layout.lower, vec![1, 5]);
        assert_eq!(layout.counts, vec![2, 3]);
        assert_eq!(linear_index(&layout, &[2, 5]), Some(3));
    }

    #[test]
    fn huge_dimensions_from_the_plc_do_not_overflow() {
        let layout = Layout {
            kind: 11,
            lower: vec![0; 3],
            counts: vec![u32::MAX; 3],
            ..Layout::default()
        };
        let last = i64::from(u32::MAX) - 1;
        assert_eq!(linear_index(&layout, &[last, last, last]), None);
        assert_eq!(layout.total(), u64::MAX);
    }
}
