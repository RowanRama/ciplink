//! Tag Descriptions and metadata authentication: the port of `ciplink/logix_descriptions.py` and of the Python
//! `LogixDriver.get_tag_description(s)` and `authenticate_metadata`.
//!
//! A Description is read for a tag, a member or an array element, trying its candidates in turn, most specific
//! first, until one has a Description: `Array[3]` then `Array`, `Udt[0].Member` then the member's template default
//! (from the Description index) then `Udt[0]` then `Udt`.  Many tags share each multi-service packet; every round
//! requests the next candidate of every unfinished tag at once, identical requests once.
//!
//! Parity: the same requests in the same order as the Python driver, with the same sequence counts (a request
//! takes its count when it is built, before its bytes), the same packing and the same fallbacks.  Python's
//! `ValueError`s (a request that cannot be encoded, bad credentials) classify as device errors, as there.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use indexmap::{IndexMap, IndexSet};

use crate::cip::{GenericMessage, GenericReply, TagResult};
use crate::epath::LogicalValue;
use crate::logix::auth::LogixMetadataCredentials;
use crate::logix::driver::{Logix, LogixDriver, Packet, Request};
use crate::logix::metadata::{
    DescriptionRecord, MetadataValue, TextEncoding, build_description_index_request,
    build_description_request, decode_description_records, decode_description_response,
    decode_metadata_page,
};
use crate::logix::types::{
    DataType, MemberInfo, ProgramInfo, PyObj, TagDef, TagInfo, TypeRef, split_tag_name,
    template_read_request,
};
use crate::packets::{self, INSUFFICIENT_PACKETS, Reply, ReplyKind, response_error};
use crate::value::py_str_repr;
use crate::{Error, ErrorKind, Result, TagError, Value};

/// The default Description language (0x007F, the controller's project language).
pub const DEFAULT_LANGUAGE: u16 = 0x007F;

/// Statuses of an embedded reply the multi-service packet had no room for: the request is read on its own.
const NO_ROOM: [u8; 2] = [INSUFFICIENT_PACKETS, 0x11];
/// Reply bytes budgeted for an embedded Description request.
const DESCRIPTION_REPLY_SIZE: usize = 256;
const MAX_PAGES: usize = 1024;
const SYMBOL_CLASS: u16 = 0x6B;
const PROGRAM_CLASS: u16 = 0x68;
const TEMPLATE_CLASS: u16 = 0x6C;
const READ_TAG: u8 = 0x4C;
const GET_ATTRIBUTE_LIST: u8 = 0x03;
/// Bits of the types a bit of can be addressed (`Tag.3`): integers and bit strings (not BOOL arrays).
const BIT_TYPES: [(&str, u64); 12] = [
    ("SINT", 8),
    ("INT", 16),
    ("DINT", 32),
    ("LINT", 64),
    ("USINT", 8),
    ("UINT", 16),
    ("UDINT", 32),
    ("ULINT", 64),
    ("BYTE", 8),
    ("WORD", 16),
    ("DWORD", 32),
    ("LWORD", 64),
];

/// The object a Description request targets: (class, instance, owner instance, owner word).
type Target = (u16, u32, u32, u16);
/// A Description request: its target and the member/element path below it.
type Key = (Target, String);
/// A candidate path, and (template instance, member identifier) when it ends at a member.
type Candidate = (String, Option<(u16, u16)>);
/// The connection a cache belongs to: (session, target connection id).
type Connection = (u32, Option<Vec<u8>>);

// ------------------------------------------------------------------------------------------------ cache

/// What Python keeps in `plc._cache["descriptions"]`: program references, member identifiers and the
/// Description index per language, valid for one connection.  It lives in the driver's `TemplateCache`, so it is
/// emptied where Python empties every `_cache` dict (`_reset_lazy_tags`, a failed tag cache file).
#[derive(Clone, Debug, Default)]
pub(crate) struct DescriptionCache {
    connection: Option<Connection>,
    programs: HashMap<String, u32>,
    members: HashMap<u16, Arc<IndexMap<String, u16>>>,
    records: HashMap<u16, Arc<Vec<DescriptionRecord>>>,
}

fn connection(l: &Logix) -> Connection {
    (l.conn.session(), l.conn.target_cid().map(<[u8]>::to_vec))
}

/// Runs `f` on the cache of the current connection, emptied first if it belonged to another (Python's `_cache`).
fn with_cache<R>(l: &mut Logix, f: impl FnOnce(&mut DescriptionCache) -> R) -> R {
    let current = connection(l);
    let cache = &mut l.cache.descriptions;
    if cache.connection.as_ref() != Some(&current) {
        *cache = DescriptionCache {
            connection: Some(current),
            ..DescriptionCache::default()
        };
    }
    f(cache)
}

/// Stores a value read on connection `at` (Python stores it in that connection's dict, orphaned if the
/// connection changed meanwhile).
fn store(l: &mut Logix, at: &Connection, f: impl FnOnce(&mut DescriptionCache)) {
    if &connection(l) == at {
        with_cache(l, f);
    }
}

// ------------------------------------------------------------------------------------------------ errors

/// A Python `ValueError` (classified as a device error), from what this crate reports as a RequestError.
fn value_error(err: Error) -> Error {
    match err {
        Error::Request {
            message,
            kind: None,
        } => Error::data(message),
        other => other,
    }
}

fn connection_changed() -> Error {
    Error::response_tag(TagError::new(
        "Connection changed during Description read",
        ErrorKind::Comm,
    ))
}

/// A generic message's error text (Python's `response.error`), "None" without one.
fn generic_error(reply: &GenericReply) -> String {
    reply
        .tag
        .error
        .as_ref()
        .map_or_else(|| "None".into(), |e| e.message.clone())
}

/// Python's `raw[start:end]`.
fn slice(raw: &[u8], start: usize, end: usize) -> &[u8] {
    raw.get(start..end.min(raw.len())).unwrap_or_default()
}

// ------------------------------------------------------------------------------------------------ addresses

/// A tag's or member's definition.
#[derive(Clone)]
enum Def {
    Tag(TagDef),
    Member(MemberInfo),
}

impl Def {
    fn data_type(&self) -> &TypeRef {
        match self {
            Def::Tag(t) => &t.data_type,
            Def::Member(m) => &m.data_type,
        }
    }

    fn type_name(&self) -> Option<&str> {
        self.data_type().name()
    }

    /// A BOOL array, stored as DWORDs (see [`TagInfo::is_bool_array`]).
    fn is_bool_array(&self) -> bool {
        match self {
            Def::Tag(t) => TagInfo::Tag(t).is_bool_array(),
            Def::Member(m) => TagInfo::Member(m).is_bool_array(),
        }
    }

    /// Every dimension (a tag's three, a member's array length), for "is it an array".
    fn dimensions(&self) -> Vec<u64> {
        match self {
            Def::Tag(t) => t.dimensions.iter().map(|&d| u64::from(d)).collect(),
            Def::Member(m) => vec![u64::from(m.array.unwrap_or(0))],
        }
    }
}

/// A step of an address: the tag, a member of the one before, or a bit of it.
enum Step {
    Root,
    Member(Def, String),
    Bit(u64),
}

/// Python's `\s` of a str pattern (`str.isspace`).
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// A dotted part of an address, `name` or `name[i]`, `name[i,j]`, `name[i,j,k]`; None if it is not one.
fn parse_segment(part: &str) -> Option<(&str, Option<&str>)> {
    let end = part
        .find(|c: char| matches!(c, '[' | ']' | '{' | '}' | '.') || is_space(c))
        .unwrap_or(part.len());
    let (name, rest) = part.split_at(end);
    if name.is_empty() {
        return None;
    }
    if rest.is_empty() {
        return Some((name, None));
    }
    let indices = rest.strip_prefix('[')?.strip_suffix(']')?;
    let groups: Vec<&str> = indices.split(',').collect();
    let valid = groups.len() <= 3
        && groups
            .iter()
            .all(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()));
    valid.then_some((name, Some(indices)))
}

/// The element path suffix of `indices` (`[3]`, `[1,2]`), "" without indices; out of range is an error.
fn index_suffix(def: &Def, indices: Option<&str>) -> Result<String> {
    let Some(indices) = indices else {
        return Ok(String::new());
    };
    // digits only (parse_segment); a number too large for u64 is out of range anyway
    let values: Vec<Option<u64>> = indices.split(',').map(|v| v.parse().ok()).collect();
    let mut dimensions: Vec<u64> = match def {
        Def::Tag(t) => t.dimensions[..usize::from(t.dim).min(3)]
            .iter()
            .map(|&d| u64::from(d))
            .collect(),
        Def::Member(m) => vec![u64::from(m.array.unwrap_or(0))],
    };
    if def.is_bool_array() {
        if let Some(last) = dimensions.last_mut() {
            *last *= 32; // a BOOL array: 32 bits per DWORD
        }
    }
    let outside = values.len() != dimensions.len()
        || values
            .iter()
            .zip(&dimensions)
            .any(|(v, &d)| d == 0 || v.is_none_or(|v| v >= d));
    if outside {
        return Err(Error::request(
            "Array index is outside the tag's dimensions",
        ));
    }
    let values: Vec<String> = values.iter().flatten().map(u64::to_string).collect();
    Ok(format!("[{}]", values.join(",")))
}

// ------------------------------------------------------------------------------------------------ requests

fn description_request(key: &Key, language: u16, offset: u32) -> Result<Vec<u8>> {
    let ((class_id, instance_id, a, b), path) = key;
    build_description_request(*instance_id, language, offset, path, *class_id, (*a, *b))
        .map_err(value_error)
}

/// Python's `bytes.decode(encoding)` of a member default, with its UnicodeDecodeError message.
fn decode_text(raw: &[u8], encoding: TextEncoding) -> Result<String> {
    // a one-record reply decoded by the metadata codec, so the text decodes as everywhere else
    let mut page = vec![1, 3, 0, 0, 0, 0, 0, 0];
    page.extend_from_slice(&[0; 14]); // class, instance, owner context, path length
    page.extend_from_slice(&[0, 0, 1, 0]); // language, property
    page.extend_from_slice(&[0; 16]); // record id, context
    page.extend_from_slice(&1u16.to_le_bytes());
    let len = u16::try_from(raw.len()).map_err(|_| Error::data("Description text is too long"))?;
    page.extend_from_slice(&len.to_le_bytes());
    page.extend_from_slice(raw);
    match decode_description_response(&[page], Some(encoding)) {
        Ok(Some(DescriptionRecord {
            value: MetadataValue::Text(text),
            ..
        })) => Ok(text),
        _ => Err(Error::data(py_decode_error(raw, encoding))),
    }
}

/// CPython's UnicodeDecodeError message for `raw` in `encoding`.
fn py_decode_error(raw: &[u8], encoding: TextEncoding) -> String {
    let (codec, start, end, reason) = match encoding {
        TextEncoding::Utf8 => match std::str::from_utf8(raw) {
            Ok(_) => return "Cannot decode metadata text using utf-8".into(),
            Err(err) => {
                let start = err.valid_up_to();
                match err.error_len() {
                    None => (
                        "utf-8",
                        start,
                        raw.len(),
                        "unexpected end of data".to_owned(),
                    ),
                    Some(n) => {
                        let lead = raw.get(start).copied().unwrap_or(0);
                        let reason = if n == 1 && !(0xC2..=0xF4).contains(&lead) {
                            "invalid start byte"
                        } else {
                            "invalid continuation byte"
                        };
                        ("utf-8", start, start + n, reason.to_owned())
                    }
                }
            }
        },
        TextEncoding::Ascii => {
            let Some(at) = raw.iter().position(|b| !b.is_ascii()) else {
                return "Cannot decode metadata text using ascii".into();
            };
            ("ascii", at, at + 1, "ordinal not in range(128)".to_owned())
        }
        TextEncoding::Cp1252 => {
            let Some(at) = raw
                .iter()
                .position(|b| matches!(b, 0x81 | 0x8D | 0x8F | 0x90 | 0x9D))
            else {
                return "Cannot decode metadata text using cp1252".into();
            };
            (
                "charmap",
                at,
                at + 1,
                "character maps to <undefined>".to_owned(),
            )
        }
        TextEncoding::Latin1 => return "Cannot decode metadata text using latin-1".into(),
    };
    // `start` indexes a byte the codec refused; without one (valid text) there is no byte to name
    let Some(byte) = raw.get(start) else {
        return format!("Cannot decode metadata text using {}", encoding.name());
    };
    if end == start + 1 {
        format!("'{codec}' codec can't decode byte 0x{byte:02x} in position {start}: {reason}")
    } else {
        format!(
            "'{codec}' codec can't decode bytes in position {start}-{}: {reason}",
            end - 1
        )
    }
}

// ------------------------------------------------------------------------------------------------ reads

impl Logix {
    fn check_connection(&self, at: &Connection) -> Result<()> {
        if !self.conn.target_connected() || &connection(self) != at {
            return Err(connection_changed());
        }
        Ok(())
    }

    /// The pages of a paged reply; `first` is the data of its first page if it was already read.
    fn pages(
        &mut self,
        builder: &dyn Fn(u32) -> Result<Vec<u8>>,
        mut first: Option<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>> {
        let at = connection(self);
        let mut pages = Vec::new();
        let mut offset: u32 = 0;
        for _ in 0..MAX_PAGES {
            let data = match first.take() {
                Some(data) => data,
                None => {
                    let sequence = self.conn.next_sequence();
                    let message = builder(offset)?;
                    let raw = self.conn.send_connected(sequence, &message)?;
                    let reply = Reply::parse(ReplyKind::SendUnitData, &raw);
                    if !reply.is_valid() {
                        return Err(Error::response_tag(response_error(&reply, None)));
                    }
                    self.check_connection(&at)?;
                    reply.data.unwrap_or_default()
                }
            };
            let page = decode_metadata_page(&data)?;
            if page.first != (offset == 0) || page.offset != offset {
                return Err(Error::response("Out-of-order extended description page"));
            }
            let (last, size) = (page.last, page.data.len());
            pages.push(data);
            if last {
                return Ok(pages);
            }
            if size == 0 {
                return Err(Error::response(
                    "Extended description continuation made no progress",
                ));
            }
            offset = u32::try_from(size)
                .ok()
                .and_then(|n| offset.checked_add(n))
                .ok_or_else(|| Error::data("Extended description offset out of range"))?;
        }
        Err(Error::response("Extended description exceeded 1024 pages"))
    }

    /// The Description of `key`, None without one; `first` is the data of its reply if it was already read.
    fn description_value(
        &mut self,
        key: &Key,
        language: u16,
        encoding: TextEncoding,
        first: Option<Vec<u8>>,
    ) -> Result<Option<String>> {
        let pages = self.pages(&|offset| description_request(key, language, offset), first)?;
        let Some(record) = decode_description_response(&pages, Some(encoding))? else {
            return Ok(None);
        };
        let ((class_id, instance_id, a, b), path) = key;
        if record.class_id != *class_id
            || record.instance_id != *instance_id
            || record.owner_context != (*a, *b)
            || record.path.to_lowercase() != path.to_lowercase()
            || record.language != language
        {
            return Err(Error::response(
                "Extended description reply targets a different tag/language",
            ));
        }
        Ok(match record.value {
            MetadataValue::Text(text) => Some(text),
            _ => None, // decode_description_response returns text records only
        })
    }

    /// The symbol instance of program `name`, from its reference (Get Attribute List 0x0D of its symbol).
    fn program_id(&mut self, name: &str) -> Result<u32> {
        let key = name.to_lowercase();
        let at = connection(self);
        if let Some(id) = with_cache(self, |c| c.programs.get(&key).copied()) {
            return Ok(id);
        }
        let listed = self.info.items.contains_key("programs");
        let mut program = if listed {
            self.info
                .scope
                .programs
                .keys()
                .find(|k| k.to_lowercase() == key)
                .cloned()
        } else {
            None
        };
        if program.is_none() && self.args.lazy_tags {
            if !self.lazy_tag_lists.contains_key(&None) {
                let symbols = self.get_instance_attribute_list_service(None, 0)?;
                let mut by_name = IndexMap::with_capacity(symbols.len());
                for symbol in symbols {
                    by_name.insert(symbol.tag_name.clone(), symbol);
                }
                self.lazy_tag_lists.insert(None, by_name);
            }
            let wanted = format!("Program:{name}").to_lowercase();
            let instance = self.lazy_tag_lists.get(&None).and_then(|symbols| {
                symbols
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == wanted)
                    .map(|(_, s)| s.instance_id)
            });
            if let Some(instance_id) = instance {
                if !listed {
                    self.info.scope.programs.clear();
                    self.info.items.insert("programs".into(), PyObj::None);
                }
                self.info.scope.programs.insert(
                    name.to_owned(),
                    ProgramInfo {
                        instance_id,
                        routines: Vec::new(),
                    },
                );
                program = Some(name.to_owned());
            }
        }
        let instance = program
            .and_then(|p| self.info.scope.programs.get(&p))
            .map(|p| p.instance_id)
            .ok_or_else(|| {
                Error::request_kind(
                    format!("Program does not exist: {name}"),
                    ErrorKind::NotFound,
                )
            })?;
        let reply = self.conn.generic_message(&GenericMessage {
            service: GET_ATTRIBUTE_LIST,
            class_code: LogicalValue::Int(SYMBOL_CLASS.into()),
            instance: LogicalValue::Int(instance.into()),
            request_data: vec![0x01, 0x00, 0x0D, 0x00],
            connected: true,
            ..GenericMessage::default()
        })?;
        if reply.tag.error.is_some() {
            return Err(Error::response(generic_error(&reply)));
        }
        let id = parse_program_reference(reply.data().unwrap_or_default())?;
        store(self, &at, |c| {
            c.programs.insert(key, id);
        });
        Ok(id)
    }

    /// The template instance of the structure of `parent` (a tag's, else looked up in the read templates).
    fn template_id(&self, parent: &Def) -> Result<u16> {
        if let Def::Tag(TagDef {
            template_instance_id: Some(id),
            ..
        }) = parent
        {
            return Ok(*id);
        }
        if let TypeRef::Struct(dt) = parent.data_type() {
            if let Some((id, _)) = self.cache.udts.iter().find(|(_, d)| Arc::ptr_eq(d, dt)) {
                return Ok(*id);
            }
        }
        Err(Error::request("Missing member type definition"))
    }

    /// The member identifiers of template `instance`: stored after its member names (a predefined or module
    /// type numbers them from 1).
    fn member_ids(&mut self, instance: u16, data: &DataType) -> Result<Arc<IndexMap<String, u16>>> {
        let at = connection(self);
        if let Some(ids) = with_cache(self, |c| c.members.get(&instance).cloned()) {
            return Ok(ids);
        }
        let count = usize::from(data.template.member_count);
        if data.internal_tags.len() != count {
            return Err(Error::response("Incomplete member definitions"));
        }
        let identifiers: Vec<u16> = if !(0x100..=0xEFF).contains(&instance) {
            (1..=data.template.member_count).collect()
        } else {
            let mut raw = self.read_template_raw(instance, data.template.object_definition_size)?;
            let mut cursor = count * 8;
            for _ in 0..=count {
                let nul = raw
                    .get(cursor..)
                    .and_then(|rest| rest.iter().position(|&b| b == 0))
                    .ok_or_else(|| Error::response("Incomplete member definitions"))?;
                cursor += nul + 1;
            }
            cursor = (cursor + 3) & !3;
            let required = cursor + count * 2;
            if required > raw.len() {
                let missing = required - raw.len();
                if missing > 21 {
                    return Err(Error::response("Incomplete member identifiers"));
                }
                let offset =
                    u32::try_from(raw.len()).map_err(|_| Error::data("Template is too long"))?;
                let mut request_data = offset.to_le_bytes().to_vec();
                // at most 21 (checked above)
                request_data.extend_from_slice(&(missing as u16).to_le_bytes());
                let reply = self.conn.generic_message(&GenericMessage {
                    service: READ_TAG,
                    class_code: LogicalValue::Int(TEMPLATE_CLASS.into()),
                    instance: LogicalValue::Int(instance.into()),
                    request_data,
                    connected: true,
                    ..GenericMessage::default()
                })?;
                if reply.tag.error.is_some() {
                    return Err(Error::response(generic_error(&reply)));
                }
                let more = reply.data().unwrap_or_default();
                if more.len() != missing {
                    return Err(Error::response("Incomplete member identifiers"));
                }
                raw.extend_from_slice(more);
            }
            raw[cursor..required]
                .chunks_exact(2)
                .map(|w| u16::from_le_bytes([w[0], w[1]]))
                .collect()
        };
        let ids = Arc::new(
            data.internal_tags
                .keys()
                .cloned()
                .zip(identifiers)
                .collect::<IndexMap<_, _>>(),
        );
        store(self, &at, |c| {
            c.members.insert(instance, Arc::clone(&ids));
        });
        Ok(ids)
    }

    /// Reads a raw template, as `Logix::read_template` (Python's `_read_template`).
    fn read_template_raw(&mut self, id: u16, object_definition_size: u32) -> Result<Vec<u8>> {
        let mut read = || -> Result<Vec<u8>> {
            let mut offset: u32 = 0;
            let mut raw = Vec::new();
            loop {
                let request_data = template_read_request(object_definition_size, offset)?;
                let reply = self.conn.generic_message(&GenericMessage {
                    service: READ_TAG,
                    class_code: LogicalValue::Int(TEMPLATE_CLASS.into()),
                    instance: LogicalValue::Int(id.into()),
                    request_data,
                    name: format!(
                        "_read_template(instance_id={id}, object_definition_size={object_definition_size}, \
                         offset={offset})"
                    ),
                    ..GenericMessage::default()
                })?;
                let status = reply.reply.service_status;
                if !matches!(
                    status,
                    Some(packets::SUCCESS | packets::INSUFFICIENT_PACKETS)
                ) {
                    return Err(Error::response("Error reading template"));
                }
                let data = reply.reply.data.unwrap_or_default();
                raw.extend_from_slice(&data);
                if status == Some(packets::SUCCESS) {
                    return Ok(raw);
                }
                if data.is_empty() {
                    return Err(Error::response("Template read made no progress"));
                }
                offset = u32::try_from(data.len())
                    .ok()
                    .and_then(|n| offset.checked_add(n))
                    .ok_or_else(|| Error::data("template offset out of range"))?;
            }
        };
        read().map_err(|err| match err {
            Error::Comm(_) => err,
            _ => Error::response("Failed to read template"),
        })
    }

    /// The template default Description of member `member_id` of template `instance`, from the language's
    /// Description index (read once per connection).
    fn type_value(
        &mut self,
        instance: u16,
        member_id: u16,
        language: u16,
        encoding: TextEncoding,
    ) -> Result<Option<String>> {
        let at = connection(self);
        let records = match with_cache(self, |c| c.records.get(&language).cloned()) {
            Some(records) => records,
            None => {
                let pages = self.pages(
                    &|offset| Ok(build_description_index_request(language, offset)),
                    None,
                )?;
                let records = Arc::new(decode_description_records(&pages, None, None)?);
                store(self, &at, |c| {
                    c.records.insert(language, Arc::clone(&records));
                });
                records
            }
        };
        let matches: Vec<&DescriptionRecord> = records
            .iter()
            .filter(|r| {
                r.class_id == TEMPLATE_CLASS
                    && r.instance_id & 0xFFFF == u32::from(instance)
                    && r.owner_context == (u32::from(member_id), 0)
                    && r.path.is_empty()
                    && r.language == language
                    && r.kind == 1
            })
            .collect();
        match matches.as_slice() {
            [] => Ok(None),
            [record] => match &record.value {
                MetadataValue::Raw(raw) => decode_text(raw, encoding).map(Some),
                MetadataValue::Text(text) => Ok(Some(text.clone())),
                _ => Ok(None),
            },
            _ => Err(Error::response("Ambiguous member description")),
        }
    }

    /// The Description target of `tag_name` and its candidates, most specific first.
    fn resolve(&mut self, tag_name: &str) -> Result<(Target, VecDeque<Candidate>)> {
        if tag_name.is_empty() || tag_name.contains(['{', '}']) {
            return Err(Error::request("Specify a tag, member, or array element"));
        }
        let mut program = None;
        let mut body = tag_name;
        if tag_name
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("program:"))
        {
            let (scope, rest) = match tag_name.split_once('.') {
                Some((scope, rest)) => (scope, Some(rest)),
                None => (tag_name, None),
            };
            let name = &scope[8..];
            match rest {
                Some(rest) if !name.is_empty() => {
                    program = Some(name.to_owned());
                    body = rest;
                }
                _ => return Err(Error::request("Specify a program tag")),
            }
        }
        let parsed: Vec<(&str, Option<&str>)> = body
            .split('.')
            .map(parse_segment)
            .collect::<Option<_>>()
            .ok_or_else(|| Error::request("Invalid tag address"))?;
        let (first, first_indices) = parsed[0]; // split yields at least one part
        let root = match &program {
            Some(p) => format!("Program:{p}.{first}"),
            None => first.to_owned(),
        };
        let (_, base, attrs) = split_tag_name(&root)?;
        let definition = match self.resolve_tag_info(&base, &attrs)? {
            TagInfo::Tag(t) => t.clone(),
            TagInfo::Member(_) => return Err(Error::request("Specify a tag")), // a root has no members
        };
        let mut current = Def::Tag(definition.clone());
        let mut steps: Vec<(Def, Option<&str>, Step)> =
            vec![(current.clone(), first_indices, Step::Root)];
        for (index, &(name, indices)) in parsed.iter().enumerate().skip(1) {
            if name.bytes().all(|b| b.is_ascii_digit()) {
                let bits = BIT_TYPES
                    .iter()
                    .find(|(t, _)| Some(*t) == current.type_name() && !current.is_bool_array())
                    .map(|(_, bits)| *bits);
                let bit = name.parse::<u64>().ok();
                match (bits, bit) {
                    (Some(bits), Some(bit))
                        if index == parsed.len() - 1 && indices.is_none() && bit < bits =>
                    {
                        steps.push((current.clone(), None, Step::Bit(bit)));
                        continue;
                    }
                    _ => return Err(Error::request("Invalid tag bit")),
                }
            }
            let lower = name.to_lowercase();
            let member = match current.data_type() {
                TypeRef::Struct(dt) => dt
                    .internal_tags
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == lower)
                    .map(|(k, m)| (k.clone(), m.clone())),
                TypeRef::Atomic(_) => None,
            };
            let Some((key, member)) = member else {
                return Err(Error::request_kind(
                    format!("Tag doesn't exist - {name}"),
                    ErrorKind::NotFound,
                ));
            };
            let def = Def::Member(member);
            steps.push((def.clone(), indices, Step::Member(current, key)));
            current = def;
        }
        for (index, (def, indices, _)) in steps.iter().enumerate() {
            index_suffix(def, *indices)?;
            if indices.is_none()
                && def.dimensions().iter().any(|&d| d != 0)
                && index < steps.len() - 1
            {
                return Err(Error::request(
                    "Select an array element before a member or bit",
                ));
            }
        }
        let target = match &program {
            Some(p) => (
                PROGRAM_CLASS,
                (u32::from(SYMBOL_CLASS) << 16) | self.program_id(p)?,
                definition.instance_id,
                0,
            ),
            None => (SYMBOL_CLASS, definition.instance_id, 0, 0),
        };
        let mut path = String::new();
        let mut candidates = VecDeque::from([(path.clone(), None)]);
        for (def, indices, step) in &steps {
            match step {
                Step::Root => {}
                Step::Bit(bit) => {
                    path.push_str(&format!(".{bit}"));
                    candidates.push_front((path.clone(), None));
                }
                Step::Member(parent, name) => {
                    let instance = self.template_id(parent)?;
                    let TypeRef::Struct(dt) = parent.data_type() else {
                        return Err(Error::request("Missing member type definition"));
                    };
                    let ids = self.member_ids(instance, &Arc::clone(dt))?;
                    let id = *ids
                        .get(name)
                        .ok_or_else(|| Error::data(py_str_repr(name)))?;
                    path.push_str(&format!(".!{instance:04X}{id:04X}"));
                    candidates.push_front((path.clone(), Some((instance, id))));
                }
            }
            let suffix = index_suffix(def, *indices)?;
            if !suffix.is_empty() {
                path.push_str(&suffix);
                candidates.push_front((path.clone(), None));
            }
        }
        Ok((target, candidates))
    }

    /// The Description of each tag (its text, None without one, or its error), as reading each tag's candidates
    /// in turn until one has a Description.  Only a reply with more pages, or a request the packet had no room
    /// to answer (0x06, 0x11 or a missing reply), is read on its own.
    fn read_descriptions(
        &mut self,
        tag_names: &[&str],
        language: u16,
        encoding: TextEncoding,
    ) -> Vec<Result<Option<String>>> {
        let at = connection(self);
        let mut results: Vec<Result<Option<String>>> = Vec::with_capacity(tag_names.len());
        let mut pending: BTreeMap<usize, (Target, VecDeque<Candidate>)> = BTreeMap::new();
        for (index, name) in tag_names.iter().enumerate() {
            match self.resolve(name) {
                Ok(resolved) => {
                    pending.insert(index, resolved);
                    results.push(Ok(None));
                }
                Err(err) => results.push(Err(err)),
            }
        }
        while !pending.is_empty() {
            if let Err(err) =
                self.description_round(&at, &mut pending, &mut results, language, encoding)
            {
                // e.g. the connection changed: the unfinished tags get the error
                for index in std::mem::take(&mut pending).into_keys() {
                    results[index] = Err(err.clone());
                }
            }
        }
        results
    }

    /// Requests the next candidate of every pending tag; finished tags leave `pending` with their result.
    fn description_round(
        &mut self,
        at: &Connection,
        pending: &mut BTreeMap<usize, (Target, VecDeque<Candidate>)>,
        results: &mut [Result<Option<String>>],
        language: u16,
        encoding: TextEncoding,
    ) -> Result<()> {
        let keys: IndexSet<Key> = pending
            .values()
            .filter_map(|(target, candidates)| {
                candidates.front().map(|(path, _)| (*target, path.clone()))
            })
            .collect();
        let mut requests = Vec::with_capacity(keys.len());
        for (index, key) in keys.iter().enumerate() {
            let sequence = self.conn.next_sequence(); // taken before the request is built, as in Python
            let message = description_request(key, language, 0)?;
            let request = Request {
                sequence,
                message,
                fragmented: false,
                key: Some(index),
            };
            requests.push((request, DESCRIPTION_REPLY_SIZE));
        }
        let mut replies: HashMap<usize, Reply> = HashMap::new();
        let mut embedded: HashSet<usize> = HashSet::new();
        for packet in self.pack_multi_requests(requests, false) {
            let (reply, subs) = self.send_packet(&packet)?;
            match packet {
                Packet::Multi { requests, .. } => {
                    embedded.extend(requests.iter().filter_map(|r| r.key));
                    for (request, sub) in requests.iter().zip(subs) {
                        if let Some(key) = request.key {
                            replies.insert(key, sub);
                        }
                    }
                }
                Packet::Single(request) => {
                    if let Some(key) = request.key {
                        replies.insert(key, reply);
                    }
                }
            }
        }
        self.check_connection(at)?;
        let mut values: Vec<Result<Option<String>>> = Vec::with_capacity(keys.len());
        for (index, key) in keys.iter().enumerate() {
            let reply = replies.remove(&index);
            let no_room = reply
                .as_ref()
                .is_none_or(|r| r.service_status.is_some_and(|s| NO_ROOM.contains(&s)));
            let value = match reply {
                _ if embedded.contains(&index) && no_room => {
                    self.description_value(key, language, encoding, None)
                }
                Some(reply) if reply.is_valid() => {
                    let data = reply.data.unwrap_or_default();
                    self.description_value(key, language, encoding, Some(data))
                }
                Some(reply) => Err(Error::response_tag(response_error(&reply, None))),
                None => Err(Error::response("None")), // every request sent alone has its reply
            };
            values.push(value);
        }
        let indexes: Vec<usize> = pending.keys().copied().collect();
        for index in indexes {
            let Some((target, candidates)) = pending.get_mut(&index) else {
                continue;
            };
            let Some((path, member)) = candidates.pop_front() else {
                continue;
            };
            let key = (*target, path);
            let done = candidates.is_empty();
            let mut value = keys
                .get_index_of(&key)
                .and_then(|i| values.get(i).cloned())
                .unwrap_or(Ok(None));
            if let (Ok(None), Some((instance, member_id))) = (&value, member) {
                value = self.type_value(instance, member_id, language, encoding);
            }
            if !matches!(value, Ok(None)) || done {
                results[index] = value;
                pending.remove(&index);
            }
        }
        self.check_connection(at)
    }

    /// `get_tag_descriptions` once the connection is open.
    fn descriptions(
        &mut self,
        tag_names: &[&str],
        language: u16,
        encoding: TextEncoding,
    ) -> Vec<TagResult> {
        let values = if self.micro800 {
            let err = Error::request("Extended descriptions require a Logix controller");
            vec![Err(err); tag_names.len()]
        } else {
            self.read_descriptions(tag_names, language, encoding)
        };
        tag_names
            .iter()
            .zip(values)
            .map(|(name, value)| {
                let (value, error) = match value {
                    Ok(Some(text)) => (Some(Value::String(text)), None),
                    Ok(None) => (
                        None,
                        Some(TagError::new(
                            format!("No description returned for language 0x{language:04x}"),
                            ErrorKind::NotFound,
                        )),
                    ),
                    Err(err) => (None, Some(err.to_tag_error(err.default_kind(), None))),
                };
                TagResult {
                    tag: format!("{name}.@Description"),
                    value,
                    data_type: Some("STRING".into()),
                    error,
                }
            })
            .collect()
    }

    /// The metadata authentication handshake: certificate challenge (0x4B), then its completion (0x4C).
    fn authenticate(&mut self, credentials: Option<&LogixMetadataCredentials>) -> Result<()> {
        let bundled;
        let credentials = match credentials {
            Some(c) => c,
            None => {
                bundled = LogixMetadataCredentials::bundled().map_err(value_error)?;
                &bundled
            }
        };
        if self.micro800 {
            return Err(Error::request(
                "Metadata authentication requires a Logix controller",
            ));
        }
        let challenge = self.handshake(
            0x4B,
            credentials.certificate().to_vec(),
            "Metadata certificate challenge",
            "Certificate challenge rejected: ",
        )?;
        if slice(challenge.reply.raw.as_deref().unwrap_or_default(), 46, 50) != [0xCB, 0, 0, 0] {
            return Err(Error::response(
                "Unexpected certificate challenge reply header",
            ));
        }
        let at = connection(self);
        let proof = credentials
            .answer_challenge(challenge.data().unwrap_or_default())
            .map_err(value_error)?;
        self.check_authenticated_connection(&at)?;
        let mut request_data = vec![0x14, 0x00];
        request_data.extend_from_slice(&proof);
        let completion = self.handshake(
            0x4C,
            request_data,
            "Metadata challenge completion",
            "Challenge completion rejected: ",
        )?;
        if slice(completion.reply.raw.as_deref().unwrap_or_default(), 46, 50) != [0xCC, 0, 0, 0] {
            return Err(Error::response("Unexpected metadata completion reply"));
        }
        credentials
            .validate_completion(completion.data().unwrap_or_default())
            .map_err(value_error)?;
        self.check_authenticated_connection(&at)
    }

    fn handshake(
        &mut self,
        service: u8,
        request_data: Vec<u8>,
        name: &str,
        rejected: &str,
    ) -> Result<GenericReply> {
        let reply = self.conn.generic_message(&GenericMessage {
            service,
            class_code: LogicalValue::Int(0x64),
            instance: LogicalValue::Int(1),
            request_data,
            name: name.into(),
            connected: true,
            ..GenericMessage::default()
        })?;
        if let Some(err) = &reply.tag.error {
            let message = format!("{rejected}{}", err.message);
            return Err(Error::response_tag(response_error(
                &reply.reply,
                Some(&message),
            )));
        }
        Ok(reply)
    }

    fn check_authenticated_connection(&self, at: &Connection) -> Result<()> {
        if !self.conn.target_connected() || &connection(self) != at {
            return Err(Error::response(
                "CIP connection changed during metadata authentication",
            ));
        }
        Ok(())
    }
}

/// The program symbol instance of a program reference (attribute 0x0D: a path to class 0x68).
fn parse_program_reference(raw: &[u8]) -> Result<u32> {
    let invalid = || Error::response("Invalid program reference");
    if slice(raw, 0, 6) != [0x01, 0x00, 0x0D, 0x00, 0x00, 0x00] || raw.len() < 11 {
        return Err(invalid());
    }
    let path = &raw[7..];
    if path.len() != usize::from(raw[6]) * 2 || path[..2] != [0x20, 0x68] {
        return Err(invalid());
    }
    let instance = match (path.len(), path[2], path[3]) {
        (4, 0x24, id) => u32::from(id),
        (6, 0x25, 0) => u32::from(u16::from_le_bytes([path[4], path[5]])),
        (8, 0x26, 0) => u32::from_le_bytes([path[4], path[5], path[6], path[7]]),
        _ => return Err(invalid()),
    };
    if !(1..=0xFFFF).contains(&instance) {
        return Err(Error::response("Unsupported program reference"));
    }
    Ok(instance)
}

// ------------------------------------------------------------------------------------------------ driver API

impl LogixDriver {
    /// The Description of a tag, member, array element or bit (`"Tag"`, `"Udt[0].Member"`, `"Array[3].1"`), in
    /// `language` (0x007F is the project language), its text decoded with `encoding`.  A missing Description is
    /// a NotFound error in the result.  Err only if the CIP connection cannot be opened.
    pub fn get_tag_description(
        &self,
        tag_name: &str,
        language: u16,
        encoding: TextEncoding,
    ) -> Result<TagResult> {
        let mut state = self.lock();
        state.conn.ensure_forward_open("get_tag_description")?;
        let mut results = state.descriptions(&[tag_name], language, encoding);
        results
            .pop()
            .ok_or_else(|| Error::data("no Description result"))
    }

    /// The Descriptions of several tags, in the order of `tag_names`: the same results as
    /// [`get_tag_description`](Self::get_tag_description) of each, but many tags share each multi-service
    /// packet.
    pub fn get_tag_descriptions(
        &self,
        tag_names: &[&str],
        language: u16,
        encoding: TextEncoding,
    ) -> Result<Vec<TagResult>> {
        let mut state = self.lock();
        state.conn.ensure_forward_open("get_tag_descriptions")?;
        Ok(state.descriptions(tag_names, language, encoding))
    }

    /// Authenticates the current CIP connection for metadata reads, with `credentials` or the bundled ones.
    /// The result's value is `true` on success; it applies to this connection only (call again after a
    /// reconnect).  No controller values or permissions are changed.
    pub fn authenticate_metadata(
        &self,
        credentials: Option<&LogixMetadataCredentials>,
    ) -> TagResult {
        let result = self.lock().authenticate(credentials);
        let (value, error) = match result {
            Ok(()) => (Some(Value::Bool(true)), None),
            Err(err) => (None, Some(err.to_tag_error(err.default_kind(), None))),
        };
        TagResult {
            tag: "metadata_authentication".into(),
            value,
            data_type: Some("BOOL".into()),
            error,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn segments_follow_the_python_pattern() {
        assert_eq!(parse_segment("Tag"), Some(("Tag", None)));
        assert_eq!(parse_segment("Tag[1,2,3]"), Some(("Tag", Some("1,2,3"))));
        for bad in [
            "",
            "[1]",
            "Tag[]",
            "Tag[1,2,3,4]",
            "Tag[-1]",
            "Tag[1][2]",
            "Ta g",
            "Tag[1]x",
            "Tag\x1c",
        ] {
            assert_eq!(parse_segment(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn program_references_in_three_formats() {
        let parse = |hex: &str| {
            let raw: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            parse_program_reference(&raw)
        };
        assert_eq!(parse("01000d000000022068241a"), Ok(26));
        assert_eq!(parse("01000d0000000320682500da5a"), Ok(23258));
        assert_eq!(parse("01000d0000000420682600da5a0000"), Ok(23258));
        assert!(parse("01000d00000003206825000000").is_err());
        assert!(parse("01000d000000042068260000000100").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn decode_error_of_text_without_a_bad_byte_does_not_panic() {
        for encoding in [
            TextEncoding::Ascii,
            TextEncoding::Cp1252,
            TextEncoding::Utf8,
        ] {
            for raw in [&b""[..], b"abc"] {
                assert!(py_decode_error(raw, encoding).starts_with("Cannot decode metadata text"));
            }
        }
    }

    #[test]
    fn decode_errors_read_like_python() {
        assert_eq!(
            py_decode_error(b"\x80\x82\xff", TextEncoding::Utf8),
            "'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte"
        );
        assert_eq!(
            py_decode_error(b"a\xe2\x82", TextEncoding::Utf8),
            "'utf-8' codec can't decode bytes in position 1-2: unexpected end of data"
        );
        assert_eq!(
            py_decode_error(b"\xe2\x82A", TextEncoding::Utf8),
            "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte"
        );
        assert_eq!(
            py_decode_error(b"ab\xe9", TextEncoding::Ascii),
            "'ascii' codec can't decode byte 0xe9 in position 2: ordinal not in range(128)"
        );
        assert_eq!(
            py_decode_error(b"\x81", TextEncoding::Cp1252),
            "'charmap' codec can't decode byte 0x81 in position 0: character maps to <undefined>"
        );
        assert_eq!(
            decode_text(b"caf\xe9", TextEncoding::Cp1252).unwrap(),
            "caf\u{e9}"
        );
    }
}
