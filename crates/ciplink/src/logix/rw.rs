//! The read/write engine of the Logix driver: the port of the Python `LogixDriver.read` and `write` and their
//! helpers (`_parse_requested_tags`, `_read_build_requests`, `_write_build_multi_requests`, `_send_requests`,
//! the fragmented services, the AOI member reads and the >65535 element splits).
//!
//! A call parses each tag request (elements `{n}`, bits of integers and bit strings, BOOL arrays as DWORD bits, AOI locals
//! refused), builds the requests (a request takes its sequence count when it is built, sent or not, as the Python
//! packets do), packs them in multi-service packets with `Logix::pack_multi_requests` (reads with a tag table
//! version check first in every packet), sends them and matches the replies to the requests by their keys.
//!
//! Parity: the same requests in the same order as the Python driver, with the same results, type names, error
//! messages and kinds.  The Python driver memoizes successful parses per tag list; the Rust driver parses every
//! call again, which sends nothing more and gives the same requests.

use std::collections::HashMap;

use crate::cip::TagResult;
use crate::epath::tag_request_path;
use crate::logix::driver::{AOI_LOCAL, Logix, LogixDriver, Packet, Request};
use crate::logix::types::{
    MemberInfo, TagDef, TagInfo, TypeClass, TypeRef, encode_value, get_array_index,
    parse_read_reply, read_reply_size, split_tag_name, tag_info, tag_key, tag_return_size,
};
use crate::packets::{
    self, INSUFFICIENT_PACKETS, ReadModifyWrite, Reply, ReplyKind, TagTableVersion,
    parse_multi_service_reply, parse_tag_table_version, response_error,
};
use crate::types::Elementary;
use crate::value::py_str_repr;
use crate::{Error, ErrorKind, Result, TagError, Value};

/// What a trend pen samples: the tag its path names (the word of a BOOL array element, the integer of a bit),
/// that tag's type, and the bit of a BOOL.
pub(crate) struct PenTarget {
    pub plc_tag: String,
    pub data_type: TypeRef,
    pub bit: Option<u32>,
}

/// Most elements one Read/Write Tag service carries (its element count is a UINT).
const MAX_SERVICE_ELEMENTS: usize = 65535;
/// Reply bytes of a write in a multi-service packet: sequence and reply header.
const WRITE_REPLY_SIZE: usize = 6;
/// Chunks a split read or write may make; more is refused instead of allocating them (Python would try).
const MAX_CHUNKS: usize = 65535;
const INTEGER_TYPES: [&str; 8] = [
    "SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT",
];
/// Bit strings: a value of one bool per bit whose bits are addressed like an integer's (`Word.3`).
const BIT_STRING_TYPES: [&str; 4] = ["BYTE", "WORD", "DWORD", "LWORD"];

/// Read or write: BOOL array (DWORD) bits are read from the word's bit 0, written from the requested bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rw {
    Read,
    Write,
}

/// The name of a request and of its result (Python's `request_id`): the n-th tag of the call, a chunk of a
/// >65535 element request, the read of a member of a whole AOI, or a Read-Modify-Write mask.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    Tag(usize),
    Chunk(usize, usize),
    Member(usize, String),
    Mask(usize),
}

/// An owned tag or member definition.
#[derive(Clone, Debug)]
enum Info {
    Tag(TagDef),
    Member(MemberInfo),
}

impl Info {
    fn of(info: TagInfo<'_>) -> Self {
        match info {
            TagInfo::Tag(t) => Info::Tag(t.clone()),
            TagInfo::Member(m) => Info::Member(m.clone()),
        }
    }

    fn view(&self) -> TagInfo<'_> {
        match self {
            Info::Tag(t) => TagInfo::Tag(t),
            Info::Member(m) => TagInfo::Member(m),
        }
    }

    fn data_type_name(&self) -> Option<&str> {
        self.view().data_type_name()
    }

    /// A BOOL array (DWORD words); a scalar DWORD is a bit string, like BYTE, WORD and LWORD.
    fn is_bool_array(&self) -> bool {
        self.view().is_bool_array()
    }
}

/// A parsed tag request (Python's `parsed_tag` dict).
#[derive(Clone, Debug)]
struct Parsed {
    key: Key,
    /// The tag as requested, without its element count.
    user_tag: String,
    /// The tag the request addresses.
    plc_tag: String,
    bit: Option<i128>,
    elements: usize,
    info: Info,
    /// The symbol instance ID the request addresses (the base tag's, for a member).
    instance_id: Option<u32>,
    bool_elements: Option<usize>,
    /// The encoded request path, None to encode it from `plc_tag` when the request is built.
    path: Option<Vec<u8>>,
    value: Option<Value>,
    error: Option<TagError>,
}

/// A tag of the call: its parse, and the chunks or AOI member reads it was replaced by.
#[derive(Debug)]
struct Entry {
    parsed: std::result::Result<Parsed, TagError>,
    chunks: Option<Vec<Parsed>>,
    members: Option<Vec<Parsed>>,
}

impl Entry {
    fn error(&self) -> Option<TagError> {
        match &self.parsed {
            Err(e) => Some(e.clone()),
            Ok(p) => p.error.clone(),
        }
    }
}

fn item<'a>(entries: &'a [Entry], key: &Key) -> Option<&'a Parsed> {
    match key {
        Key::Tag(i) => entries.get(*i)?.parsed.as_ref().ok(),
        Key::Chunk(i, n) => entries.get(*i)?.chunks.as_ref()?.get(*n),
        Key::Member(i, name) => entries
            .get(*i)?
            .members
            .as_ref()?
            .iter()
            .find(|m| matches!(&m.key, Key::Member(_, n) if n == name)),
        Key::Mask(_) => None,
    }
}

fn item_mut<'a>(entries: &'a mut [Entry], key: &Key) -> Option<&'a mut Parsed> {
    match key {
        Key::Tag(i) => entries.get_mut(*i)?.parsed.as_mut().ok(),
        Key::Chunk(i, n) => entries.get_mut(*i)?.chunks.as_mut()?.get_mut(*n),
        Key::Member(i, name) => entries
            .get_mut(*i)?
            .members
            .as_mut()?
            .iter_mut()
            .find(|m| matches!(&m.key, Key::Member(_, n) if n == name)),
        Key::Mask(_) => None,
    }
}

/// What a built request does.
#[derive(Clone, Debug)]
enum Kind {
    Read,
    ReadFragmented,
    Write,
    WriteFragmented { type_code: Vec<u8>, value: Vec<u8> },
    Mask { ids: Vec<Key> },
}

/// A built request (the Python request packet's attributes); requests name theirs by index.
#[derive(Clone, Debug)]
struct ReqInfo {
    key: Key,
    tag: String,
    elements: usize,
    info: Info,
    path: Vec<u8>,
    kind: Kind,
}

/// Results by key and the tag table versions the checks read.
#[derive(Default)]
struct Sent {
    results: HashMap<Key, TagResult>,
    versions: Vec<Option<TagTableVersion>>,
}

/// A built write: the tag table version the definitions were loaded at, the entries and the packets.
type Built = (Option<TagTableVersion>, Vec<Entry>, Vec<Packet<usize>>);

/// A pending Read-Modify-Write: its target tag, masks, request and sequence count.
type BitWrite = (String, ReadModifyWrite, ReqInfo, u16);

/// The outcome of a request: (value, type name) or its error.
type Outcome = std::result::Result<(Option<Value>, Option<String>), TagError>;

fn tag_result(tag: &str, outcome: Outcome) -> TagResult {
    match outcome {
        Ok((value, data_type)) => TagResult {
            tag: tag.to_owned(),
            value,
            data_type,
            error: None,
        },
        Err(error) => TagResult {
            tag: tag.to_owned(),
            value: None,
            data_type: None,
            error: Some(error),
        },
    }
}

fn comm(message: &str) -> TagError {
    TagError::new(message, ErrorKind::Comm)
}

/// Python's `int()` of base 10 text: whitespace, a sign, digits with single underscores; a huge number saturates.
fn py_int(text: &str) -> Option<i128> {
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
    let mut value: i128 = 0;
    for b in digits.bytes().filter(u8::is_ascii_digit) {
        value = value
            .saturating_mul(10)
            .saturating_add(i128::from(b - b'0'));
    }
    Some(if negative { -value } else { value })
}

fn int_error(text: &str) -> Error {
    Error::data(format!(
        "invalid literal for int() with base 10: {}",
        py_str_repr(text)
    ))
}

/// Python's message for a request path that cannot be encoded: the repr of its segments.
fn epath_error(tag: &str, instance_id: Option<u32>, use_ids: bool) -> String {
    const DATA: &str = "DataSegment(name='')";
    const LOGICAL: &str = "LogicalSegment(name=None)";
    let indexes = |part: &str| -> usize {
        if !part.contains('[') {
            return 0;
        }
        let trimmed = match part.char_indices().last() {
            Some((i, _)) => &part[..i],
            None => part,
        };
        trimmed
            .find('[')
            .map_or(0, |open| trimmed[open + 1..].split(',').count())
    };
    let mut parts: Vec<&str> = tag.split('.').collect();
    let mut segments = Vec::new();
    if parts[0].starts_with("Program:") && parts.len() > 1 {
        segments.push(DATA);
        parts.remove(0);
    }
    if use_ids && instance_id.is_some_and(|id| id != 0) {
        segments.extend([LOGICAL, LOGICAL]);
    } else {
        segments.push(DATA);
    }
    segments.extend(std::iter::repeat_n(LOGICAL, indexes(parts[0])));
    for attr in &parts[1..] {
        segments.push(DATA);
        segments.extend(std::iter::repeat_n(LOGICAL, indexes(attr)));
    }
    format!("Error packing [{}] as PADDED_EPATH", segments.join(", "))
}

/// The request path of `tag`, with Python's errors: an index that is not a number, or a path that cannot be
/// encoded, are generic errors (the parse wraps them).
fn request_path(tag: &str, instance_id: Option<u32>, use_ids: bool) -> Result<Vec<u8>> {
    tag_request_path(tag, instance_id, use_ids).map_err(|err| match err {
        Error::Data(_) => Error::data(epath_error(tag, instance_id, use_ids)),
        other => Error::data(other.to_string()),
    })
}

/// Python's `_tag_error(err, kind, message)` of a RequestError raised with a plain message or a TagError.
fn request_error(err: &Error, kind: ErrorKind) -> TagError {
    err.to_tag_error(kind, None)
}

impl Logix {
    // -------------------------------------------------------------------------------------------- parse

    /// Parses every tag of a call (Python's `_parse_requested_tags`): a RequestError fails its tag, a
    /// CommError fails the call.
    fn parse_requested(&mut self, tags: &[&str], rw: Rw) -> Result<Vec<Entry>> {
        let mut entries = Vec::with_capacity(tags.len());
        for (i, tag) in tags.iter().enumerate() {
            let parsed = match self.parse_tag_request(tag, rw, i) {
                Ok(p) => Ok(p),
                Err(err @ Error::Comm(_)) => return Err(err),
                Err(err) => {
                    log::error!("Failed to parse tag request: {tag}: {err}");
                    Err(request_error(&err, ErrorKind::BadRequest))
                }
            };
            entries.push(Entry {
                parsed,
                chunks: None,
                members: None,
            });
        }
        Ok(entries)
    }

    /// `_parse_new_tag_request`: CommErrors and RequestErrors pass, anything else is
    /// `RequestError("Failed to parse tag request {tag!r}: {err}")` of kind BadRequest.
    fn parse_tag_request(&mut self, tag: &str, rw: Rw, index: usize) -> Result<Parsed> {
        let mut current = tag.to_owned();
        match self.parse_new(&mut current, rw, index) {
            Ok(p) => Ok(p),
            Err(err @ (Error::Comm(_) | Error::Request { .. })) => Err(err),
            Err(err) => Err(Error::request_kind(
                format!(
                    "Failed to parse tag request {}: {err}",
                    py_str_repr(&current)
                ),
                ErrorKind::BadRequest,
            )),
        }
    }

    /// The parse; `tag` follows Python's `tag` variable, named by the error of a failed parse.
    fn parse_new(&mut self, tag: &mut String, rw: Rw, index: usize) -> Result<Parsed> {
        let (mut elements, implicit) = if tag.ends_with('}') && tag.contains('{') {
            let parts: Vec<&str> = tag.split('{').collect();
            if parts.len() != 2 {
                return Err(Error::data("too many values to unpack (expected 2)"));
            }
            let (name, count) = (parts[0].to_owned(), parts[1].to_owned());
            *tag = name;
            let text = &count[..count.len() - 1];
            (py_int(text).ok_or_else(|| int_error(text))?, false)
        } else {
            (1, true)
        };
        if elements < 1 {
            return Err(Error::request("Element count must be positive"));
        }
        let user_tag = tag.clone();
        // Python's split raises IndexError for a program name alone: a generic error
        let (full, base, mut attrs) =
            split_tag_name(tag).map_err(|e| Error::data(e.to_string()))?;
        *tag = full;
        let mut bit: Option<i128> = None;
        if attrs
            .last()
            .is_some_and(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
        {
            let digits = attrs.pop().unwrap_or_default();
            bit = py_int(&digits);
            *tag = if attrs.is_empty() {
                base.clone()
            } else {
                format!("{base}.{}", attrs.join("."))
            };
        }

        let mut info = Info::of(self.resolve_tag_info(&base, &attrs)?);
        if self.args.lazy_tags {
            // the first use of an AOI type probes it
            if let TagInfo::Tag(base_tag) = tag_info(&self.tags, &base, &[])? {
                let base_tag = base_tag.clone();
                self.probe_aois(std::slice::from_ref(&base_tag))?;
            }
            info = Info::of(tag_info(&self.tags, &base, &attrs)?);
        }
        for i in 0..attrs.len() {
            // a local tag of an AOI, or in one, is not requested
            let parent = tag_info(&self.tags, &base, &attrs[..i])?;
            if let (Some(probe), TypeRef::Struct(dt)) =
                (self.aoi_probe_of(parent), parent.data_type())
            {
                if probe
                    .refused
                    .contains(&tag_key(&dt.internal_tags, &attrs[i]))
                {
                    return Err(Error::request_kind(AOI_LOCAL, ErrorKind::Access));
                }
            }
        }
        let instance_id = match (&info, attrs.is_empty()) {
            (Info::Tag(t), true) => Some(t.instance_id),
            _ => match tag_info(&self.tags, &base, &[])? {
                TagInfo::Tag(t) => Some(t.instance_id),
                TagInfo::Member(_) => None,
            },
        };

        let mut bool_elements = None;
        if info.is_bool_array() {
            let (name, idx) = get_array_index(tag).map_err(|e| Error::data(e.to_string()))?;
            if let Some(idx) = idx {
                *tag = format!("{name}[{}]", idx.div_euclid(32));
            }
            let idx = i128::from(idx.unwrap_or(0));
            bit = Some(match rw {
                Rw::Read => idx.rem_euclid(32),
                Rw::Write => idx,
            });
            if !implicit && elements != 1 {
                bool_elements = Some(elements);
            }
            let total = bit.unwrap_or(0).rem_euclid(32).saturating_add(elements);
            elements = total / 32 + i128::from(total % 32 != 0);
        }
        if let (Some(b), false) = (bit, info.is_bool_array()) {
            let name = info.data_type_name();
            if !name.is_some_and(|n| INTEGER_TYPES.contains(&n) || BIT_STRING_TYPES.contains(&n)) {
                return Err(Error::request(format!(
                    "Bit access is not supported on {}",
                    name.unwrap_or("None")
                )));
            }
            let size = name
                .and_then(Elementary::from_name)
                .map_or(0, Elementary::size);
            if b >= (size * 8) as i128 {
                return Err(Error::request("Bit index is outside the tag's data type"));
            }
        }
        // a bad index fails here, per tag
        let path = request_path(tag, instance_id, self.use_instance_ids)?;
        let elements = usize::try_from(elements).unwrap_or(usize::MAX);
        Ok(Parsed {
            key: Key::Tag(index),
            user_tag,
            plc_tag: tag.clone(),
            bit,
            elements,
            info,
            instance_id,
            bool_elements: bool_elements.map(|n| usize::try_from(n).unwrap_or(usize::MAX)),
            path: Some(path),
            value: None,
            error: None,
        })
    }

    // -------------------------------------------------------------------------------------------- expand/split

    /// `_expand_aoi_reads`: the read of a whole AOI whose probe found it refused becomes the reads of its readable
    /// members; returns the keys of the reads to build, in order.
    fn expand_aoi_reads(&self, entries: &mut [Entry]) -> Vec<Key> {
        let mut keys = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter_mut().enumerate() {
            let Ok(p) = &entry.parsed else {
                keys.push(Key::Tag(i));
                continue;
            };
            let probe = if p.error.is_some() {
                None
            } else {
                self.aoi_probe_of(p.info.view())
            };
            let probe = match probe {
                Some(probe) if !probe.whole_read && p.bit.is_none() && p.elements == 1 => probe,
                _ => {
                    keys.push(Key::Tag(i));
                    continue;
                }
            };
            let TypeRef::Struct(dt) = p.info.view().data_type() else {
                keys.push(Key::Tag(i));
                continue;
            };
            let dim = match &p.info {
                Info::Tag(t) => usize::from(t.dim),
                Info::Member(m) => usize::from(m.array.is_some_and(|n| n > 0)),
            };
            let mut path = p.plc_tag.clone();
            if dim > 0 && !path.ends_with(']') {
                // an array without an index reads its first element
                path = format!("{path}[{}]", vec!["0"; dim].join(","));
            }
            let mut members = Vec::with_capacity(probe.readable.len());
            for member in &probe.readable {
                let Some(member_info) = dt.internal_tags.get(member) else {
                    continue;
                };
                let plc_tag = format!("{path}.{member}");
                let mut read = Parsed {
                    key: Key::Member(i, member.clone()),
                    user_tag: p.user_tag.clone(),
                    plc_tag: plc_tag.clone(),
                    bit: p.bit,
                    elements: usize::from(member_info.array.filter(|&n| n > 0).unwrap_or(1)),
                    info: Info::Member(member_info.clone()),
                    instance_id: p.instance_id,
                    bool_elements: p.bool_elements,
                    path: None,
                    value: None,
                    error: None,
                };
                match request_path(&plc_tag, p.instance_id, self.use_instance_ids) {
                    Ok(bytes) => read.path = Some(bytes),
                    Err(err) => read.error = Some(request_error(&err, ErrorKind::BadRequest)),
                }
                keys.push(read.key.clone());
                members.push(read);
            }
            entry.members = Some(members);
        }
        keys
    }

    /// `_split_large_requests`: one-dimensional array requests of more than 65535 elements become chunks of at
    /// most 65535, each addressing its own first element; returns the keys with each split one replaced by its
    /// chunks.
    fn split_large_requests(entries: &mut [Entry], keys: Vec<Key>, rw: Rw) -> Vec<Key> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let Key::Tag(i) = key else {
                out.push(key);
                continue;
            };
            let Some(p) = item(entries, &key) else {
                out.push(key);
                continue;
            };
            if p.error.is_some() || p.elements <= MAX_SERVICE_ELEMENTS {
                out.push(key);
                continue;
            }
            match Self::chunks(p, i, rw) {
                Ok(chunks) => {
                    out.extend(chunks.iter().map(|c| c.key.clone()));
                    entries[i].chunks = Some(chunks);
                }
                Err(err) => {
                    if let Some(p) = item_mut(entries, &key) {
                        p.error = Some(request_error(&err, ErrorKind::BadRequest));
                    }
                    out.push(key);
                }
            }
        }
        out
    }

    fn chunks(p: &Parsed, i: usize, rw: Rw) -> Result<Vec<Parsed>> {
        let large =
            || Error::request("Large element counts require a one-dimensional non-BOOL array");
        let is_array = matches!(p.info.view().type_class(), Some(TypeClass::Array(..)));
        let dim = match &p.info {
            Info::Tag(t) => t.dim,
            Info::Member(_) => 1,
        };
        if !is_array || dim > 1 || p.info.is_bool_array() {
            return Err(large());
        }
        let (array_tag, start) =
            get_array_index(&p.plc_tag).map_err(|e| Error::data(e.to_string()))?;
        let start = usize::try_from(start.unwrap_or(0)).map_err(|_| large())?;
        let count = p.elements;
        if count.div_ceil(MAX_SERVICE_ELEMENTS) > MAX_CHUNKS {
            return Err(large());
        }
        let bad_value = |message: String| Error::request_kind(message, ErrorKind::BadValue);
        if rw == Rw::Write && !matches!(p.value, Some(Value::Bytes(_))) {
            let len = match &p.value {
                Some(Value::Array(items)) => items.len(),
                _ => 0,
            };
            if !matches!(p.value, Some(Value::Array(_))) || len < count {
                return Err(bad_value(
                    "Insufficient data for requested array elements".into(),
                ));
            }
            if len > count {
                return Err(bad_value(format!(
                    "Too many values for requested elements, expected {count} and got {len}"
                )));
            }
        }
        let element_size =
            tag_return_size(p.info.view(), 1).map_err(|e| Error::data(e.to_string()))?;
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < count {
            let chunk_count = MAX_SERVICE_ELEMENTS.min(count - offset);
            let mut chunk = Parsed {
                key: Key::Chunk(i, chunks.len()),
                plc_tag: format!("{array_tag}[{}]", start + offset),
                elements: chunk_count,
                path: None, // encoded for the chunk's index
                value: None,
                ..p.clone()
            };
            if rw == Rw::Write {
                let (begin, end) = (offset, offset + chunk_count);
                chunk.value = match &p.value {
                    Some(Value::Bytes(bytes)) => {
                        if bytes.len() < count.saturating_mul(element_size) {
                            return Err(bad_value(
                                "Insufficient bytes for requested array elements".into(),
                            ));
                        }
                        let (b, e) = (begin * element_size, end * element_size);
                        Some(Value::Bytes(
                            bytes[b.min(bytes.len())..e.min(bytes.len())].to_vec(),
                        ))
                    }
                    Some(Value::Array(items)) => Some(Value::Array(items[begin..end].to_vec())),
                    other => other.clone(),
                };
            }
            chunks.push(chunk);
            offset += chunk_count;
        }
        Ok(chunks)
    }

    // -------------------------------------------------------------------------------------------- build

    fn path_of(&self, p: &Parsed) -> Result<Vec<u8>> {
        match &p.path {
            Some(path) => Ok(path.clone()),
            None => request_path(&p.plc_tag, p.instance_id, self.use_instance_ids),
        }
    }

    /// `_read_build_requests`: the reads, the fragmented ones last (results are matched by key), packed with the
    /// version checks.
    fn read_build_requests(
        &mut self,
        entries: &mut [Entry],
        keys: &[Key],
        infos: &mut Vec<ReqInfo>,
    ) -> Vec<Packet<usize>> {
        let mut sized = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(p) = item(entries, key).cloned() else {
                continue;
            };
            if let Some(err) = &p.error {
                log::error!("Skipping making request, error: {err}");
                continue;
            }
            match self.read_build_single_request(&p, infos) {
                Ok(sized_request) => sized.push(sized_request),
                Err(err) => {
                    if let Some(p) = item_mut(entries, key) {
                        p.error = Some(request_error(&err, ErrorKind::BadRequest));
                    }
                }
            }
        }
        // stable: the small reads share packets ahead of the fragmented ones
        sized.sort_by_key(|(r, _): &(Request<usize>, usize)| r.fragmented);
        let checks = self.version_checks();
        self.pack_multi_requests(sized, checks)
    }

    /// `_read_build_single_request`: a Read Tag, or a Read Tag Fragmented if its reply is too big (the regular
    /// request is built first and takes a sequence count).
    fn read_build_single_request(
        &mut self,
        p: &Parsed,
        infos: &mut Vec<ReqInfo>,
    ) -> Result<(Request<usize>, usize)> {
        let sequence = self.conn.next_sequence();
        let path = self.path_of(p)?;
        let reply_size = read_reply_size(p.info.view(), p.elements)?;
        let elements = u16::try_from(p.elements)
            .map_err(|_| Error::data(format!("Error packing {} as UINT", p.elements)))?;
        let fragmented = reply_size > usize::from(self.conn.connection_size());
        let (sequence, message, kind) = if fragmented {
            let sequence = self.conn.next_sequence();
            (
                sequence,
                packets::read_tag_fragmented_message(&path, elements, 0),
                Kind::ReadFragmented,
            )
        } else {
            (
                sequence,
                packets::read_tag_message(&path, elements),
                Kind::Read,
            )
        };
        infos.push(ReqInfo {
            key: p.key.clone(),
            tag: p.plc_tag.clone(),
            elements: p.elements,
            info: p.info.clone(),
            path,
            kind,
        });
        let request = Request {
            sequence,
            message,
            fragmented,
            key: Some(infos.len() - 1),
        };
        Ok((request, reply_size))
    }

    /// `_write_build_multi_requests`: bit writes become Read-Modify-Write masks (one per word, flushed before
    /// a full write so the caller's order holds), the others Write Tag requests.
    fn write_build_requests(
        &mut self,
        entries: &mut [Entry],
        keys: &[Key],
        infos: &mut Vec<ReqInfo>,
    ) -> Vec<Packet<usize>> {
        let mut sized: Vec<(Request<usize>, usize)> = Vec::new();
        // target tag: (mask, the request it will be, its key, the tags it writes)
        let mut bit_writes: Vec<BitWrite> = Vec::new();
        let mut bit_requests = 0usize;

        for key in keys {
            let Some(p) = item(entries, key).cloned() else {
                continue;
            };
            if p.error.is_some() {
                continue;
            }
            let bool_array = p.info.is_bool_array();
            let partial = bool_array
                && p.bool_elements.is_some_and(|n| n != 0)
                && (p.bit.unwrap_or(0).rem_euclid(32) != 0
                    || p.bool_elements.unwrap_or(0) % 32 != 0);
            let result = if (p.bit.is_some() && p.bool_elements.is_none()) || partial {
                self.add_bit_writes(&p, partial, &mut bit_writes, bit_requests)
            } else {
                // a full write may overlap pending masks: they go first, in the caller's order
                self.flush_bit_writes(&mut bit_writes, &mut bit_requests, &mut sized, infos);
                match self.write_build_single_request(&p, infos) {
                    Ok(request) => {
                        sized.push((request, WRITE_REPLY_SIZE));
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            };
            if let Err(error) = result {
                if let Some(p) = item_mut(entries, key) {
                    p.error = Some(error);
                }
            }
        }
        self.flush_bit_writes(&mut bit_writes, &mut bit_requests, &mut sized, infos);
        self.pack_multi_requests(sized, false)
    }

    fn add_bit_writes(
        &mut self,
        p: &Parsed,
        partial: bool,
        bit_writes: &mut Vec<BitWrite>,
        bit_requests: usize,
    ) -> std::result::Result<(), TagError> {
        let bad = |message: String| TagError::new(message, ErrorKind::BadValue);
        let value = p.value.clone().unwrap_or(Value::Array(Vec::new()));
        let values = if partial {
            let wanted = p.bool_elements.unwrap_or(0);
            let Value::Array(values) = value else {
                return Err(bad("BOOL array writes require a sequence of values".into()));
            };
            if values.len() < wanted {
                return Err(bad("Insufficient data for requested BOOL elements".into()));
            }
            if values.len() > wanted {
                return Err(bad(format!(
                    "Too many values for requested BOOL elements, expected {wanted} and got {}",
                    values.len()
                )));
            }
            values
        } else {
            vec![value]
        };
        // masks only check truthiness, 'False' or 2.5 would set the bit
        let mut bools = Vec::with_capacity(values.len());
        for v in &values {
            match v.as_bool() {
                Some(b) => bools.push(b),
                None => return Err(bad(format!("Invalid value for BOOL - {}", v.py_repr()))),
            }
        }
        let data_type = p
            .info
            .data_type_name()
            .and_then(Elementary::from_name)
            .ok_or_else(|| bad("Bit access is not supported on this type".into()))?;
        for (index, set) in bools.into_iter().enumerate() {
            let mut target = p.plc_tag.clone();
            let mut target_bit = p.bit.unwrap_or(0);
            if p.info.is_bool_array() {
                let (word_tag, word_index) =
                    get_array_index(&target).map_err(|e| request_error(&e, ErrorKind::BadValue))?;
                let at = p.bit.unwrap_or(0).rem_euclid(32) + index as i128;
                let word_offset = at.div_euclid(32);
                target_bit = at.rem_euclid(32);
                target = format!(
                    "{word_tag}[{}]",
                    i128::from(word_index.unwrap_or(0)) + word_offset
                );
            }
            if !bit_writes.iter().any(|(t, ..)| *t == target) {
                // the parsed path is used only for its own tag, a BOOL array mask may be on another word
                let same_path = target == p.plc_tag;
                let sequence = self.conn.next_sequence();
                let path = if same_path {
                    self.path_of(p)
                } else {
                    request_path(&target, p.instance_id, self.use_instance_ids)
                }
                .map_err(|e| request_error(&e, ErrorKind::BadValue))?;
                let info = ReqInfo {
                    key: Key::Mask(bit_requests + bit_writes.len()),
                    tag: target.clone(),
                    elements: 0,
                    info: p.info.clone(),
                    path,
                    kind: Kind::Mask { ids: Vec::new() },
                };
                bit_writes.push((
                    target.clone(),
                    ReadModifyWrite::new(data_type),
                    info,
                    sequence,
                ));
            }
            if let Some((_, mask, info, _)) = bit_writes.iter_mut().find(|(t, ..)| *t == target) {
                mask.set_bit(u32::try_from(target_bit).unwrap_or(u32::MAX), set);
                if let Kind::Mask { ids } = &mut info.kind {
                    ids.push(p.key.clone());
                }
            }
        }
        Ok(())
    }

    fn flush_bit_writes(
        &mut self,
        bit_writes: &mut Vec<BitWrite>,
        bit_requests: &mut usize,
        sized: &mut Vec<(Request<usize>, usize)>,
        infos: &mut Vec<ReqInfo>,
    ) {
        for (_, mask, info, sequence) in bit_writes.drain(..) {
            *bit_requests += 1;
            // the masks fit 64 bits: their bits were checked against the type's size
            let message = match mask.message(&info.path) {
                Ok(message) => message,
                Err(err) => {
                    log::error!("Read-Modify-Write mask not built: {err}");
                    continue;
                }
            };
            infos.push(info);
            let request = Request {
                sequence,
                message,
                fragmented: false,
                key: Some(infos.len() - 1),
            };
            sized.push((request, WRITE_REPLY_SIZE));
        }
    }

    /// `_write_build_single_request`: a Write Tag, or a Write Tag Fragmented if its message is too big.
    fn write_build_single_request(
        &mut self,
        p: &Parsed,
        infos: &mut Vec<ReqInfo>,
    ) -> std::result::Result<Request<usize>, TagError> {
        let invalid = |err: &Error| {
            err.to_tag_error(
                ErrorKind::BadValue,
                Some(format!(
                    "Invalid Tag Request - RequestError({})",
                    py_str_repr(&err.to_string())
                )),
            )
        };
        let value = p.value.clone().unwrap_or(Value::Array(Vec::new()));
        let write_value = encode_value(
            &value,
            p.elements,
            p.bool_elements,
            p.info.view().type_class(),
        )
        .map_err(|e| invalid(&e))?;
        // the request takes its sequence count before it checks its data type
        let sequence = self.conn.next_sequence();
        let type_code = match p.info.view().data_type() {
            TypeRef::Struct(dt) => packets::write_type_code("", Some(dt.template.structure_handle)),
            TypeRef::Atomic(Some(e)) => packets::write_type_code(e.name(), None),
            TypeRef::Atomic(None) => Err(Error::request("Unsupported data type: None")),
        }
        .map_err(|e| invalid(&e))?;
        let path = self
            .path_of(p)
            .map_err(|e| request_error(&e, ErrorKind::BadValue))?;
        let elements = u16::try_from(p.elements).map_err(|_| {
            invalid(&Error::request(format!(
                "Error packing {} as UINT",
                p.elements
            )))
        })?;
        let message = packets::write_tag_message(&path, &type_code, elements, &write_value);
        let fragmented = 2 + message.len() > usize::from(self.conn.connection_size());
        let (sequence, message, kind) = if fragmented {
            let sequence = self.conn.next_sequence();
            let message =
                packets::write_tag_fragmented_message(&path, &type_code, elements, 0, &write_value);
            let kind = Kind::WriteFragmented {
                type_code,
                value: write_value,
            };
            (sequence, message, kind)
        } else {
            (sequence, message, Kind::Write)
        };
        infos.push(ReqInfo {
            key: p.key.clone(),
            tag: p.plc_tag.clone(),
            elements: p.elements,
            info: p.info.clone(),
            path,
            kind,
        });
        Ok(Request {
            sequence,
            message,
            fragmented,
            key: Some(infos.len() - 1),
        })
    }

    // -------------------------------------------------------------------------------------------- send

    /// `_send_requests`: sends the packets in order; each request gets a result by its key, each version check a
    /// version. A partial reply (0x06) to a Read Tag is read again as a fragmented read, checked after it if
    /// its packet was. CommErrors fail the call.
    fn send_requests(
        &mut self,
        packets: &[Packet<usize>],
        infos: &mut Vec<ReqInfo>,
        out: &mut Sent,
    ) -> Result<()> {
        for packet in packets {
            match packet {
                Packet::Single(req) if req.is_version_check() => {
                    let raw = self.conn.send_connected(req.sequence, &req.message)?;
                    let mut reply = Reply::parse(ReplyKind::SendUnitData, &raw);
                    out.versions.push(parse_tag_table_version(&mut reply));
                }
                Packet::Single(req) => {
                    let Some(idx) = req.key else { continue };
                    let outcome = match infos[idx].kind.clone() {
                        Kind::ReadFragmented => {
                            self.send_read_fragmented(&infos[idx], req.sequence)?
                        }
                        Kind::WriteFragmented { type_code, value } => {
                            self.send_write_fragmented(&infos[idx], &type_code, &value)?
                        }
                        kind => {
                            let raw = self.conn.send_connected(req.sequence, &req.message)?;
                            let reply = Reply::parse(ReplyKind::SendUnitData, &raw);
                            if matches!(kind, Kind::Read)
                                && reply.service_status == Some(INSUFFICIENT_PACKETS)
                            {
                                // a read sent alone is already followed by its check
                                self.read_again_fragmented(idx, false, infos, out)?;
                                continue;
                            }
                            outcome(&reply, &infos[idx])
                        }
                    };
                    let info = &infos[idx];
                    out.results
                        .insert(info.key.clone(), tag_result(&info.tag, outcome));
                }
                Packet::Multi { sequence, requests } => {
                    let message = match packet.message() {
                        Ok(message) => message,
                        Err(err) => {
                            log::error!("Error sending request: {err}");
                            let error = request_error(&err, ErrorKind::Comm);
                            for idx in requests.iter().filter_map(|r| r.key) {
                                let info = &infos[idx];
                                out.results.insert(
                                    info.key.clone(),
                                    tag_result(&info.tag, Err(error.clone())),
                                );
                            }
                            continue;
                        }
                    };
                    let raw = self.conn.send_connected(*sequence, &message)?;
                    let multi = parse_multi_service_reply(&raw, requests.len());
                    let checked = requests.first().is_some_and(|r| r.is_version_check());
                    for (req, mut reply) in requests.iter().zip(multi.replies) {
                        let Some(idx) = req.key else {
                            out.versions.push(parse_tag_table_version(&mut reply));
                            continue;
                        };
                        if matches!(infos[idx].kind, Kind::Read)
                            && reply.service_status == Some(INSUFFICIENT_PACKETS)
                        {
                            self.read_again_fragmented(idx, checked, infos, out)?;
                            continue;
                        }
                        let info = &infos[idx];
                        out.results.insert(
                            info.key.clone(),
                            tag_result(&info.tag, outcome(&reply, info)),
                        );
                    }
                    let error = if multi.reply.error().is_some() {
                        response_error(&multi.reply, None)
                    } else {
                        comm("No reply")
                    };
                    for idx in requests.iter().filter_map(|r| r.key) {
                        let info = &infos[idx];
                        out.results
                            .entry(info.key.clone())
                            .or_insert_with(|| tag_result(&info.tag, Err(error.clone())));
                    }
                }
            }
        }
        Ok(())
    }

    /// A partial reply to a Read Tag: read again as a fragmented read (and a version check after it).
    fn read_again_fragmented(
        &mut self,
        idx: usize,
        checked: bool,
        infos: &mut Vec<ReqInfo>,
        out: &mut Sent,
    ) -> Result<()> {
        let sequence = self.conn.next_sequence();
        let mut info = infos[idx].clone();
        info.kind = Kind::ReadFragmented;
        // elements came from a u16 when the read was built
        let elements = u16::try_from(info.elements).unwrap_or(u16::MAX);
        let message = packets::read_tag_fragmented_message(&info.path, elements, 0);
        infos.push(info);
        let mut packets = vec![Packet::Single(Request {
            sequence,
            message,
            fragmented: true,
            key: Some(infos.len() - 1),
        })];
        if checked {
            packets.push(Packet::Single(Request::version_check(&mut self.conn)));
        }
        self.send_requests(&packets, infos, out)
    }

    /// `_send_read_fragmented`: reads fragment after fragment until the controller says it is complete; a failed
    /// fragment keeps the controller's error.
    fn send_read_fragmented(&mut self, info: &ReqInfo, first_sequence: u16) -> Result<Outcome> {
        let expected = tag_return_size(info.info.view(), info.elements).unwrap_or(usize::MAX);
        let elements = u16::try_from(info.elements).unwrap_or(u16::MAX);
        let mut sequence = first_sequence;
        let mut offset: usize = 0;
        let mut first_type: Option<Vec<u8>> = None;
        let mut bytes = Vec::new();
        loop {
            let Ok(at) = u32::try_from(offset) else {
                return Ok(Err(comm(
                    "Fragmented read made no progress or exceeded the expected size",
                )));
            };
            let message = packets::read_tag_fragmented_message(&info.path, elements, at);
            let raw = self.conn.send_connected(sequence, &message)?;
            let mut reply = Reply::parse(ReplyKind::SendUnitData, &raw);
            let data = reply.data.clone().unwrap_or_default();
            let split = if data.starts_with(&[0xA0, 0x02]) {
                4
            } else {
                2
            };
            let (data_type, value) = data.split_at(split.min(data.len()));
            if reply.is_valid() && first_type.as_deref().is_some_and(|t| t != data_type) {
                reply.parse_error = Some("Data type changed during fragmented read".into());
            }
            if !reply.is_valid() {
                log::error!(
                    "Fragment failed with error: {}",
                    reply.error().unwrap_or_default()
                );
                return Ok(Err(response_error(&reply, None))); // keeps the PLC's error
            }
            if first_type.is_none() {
                first_type = Some(data_type.to_vec());
            }
            bytes.extend_from_slice(value);
            if reply.service_status != Some(INSUFFICIENT_PACKETS) {
                let mut joined = data_type.to_vec();
                joined.extend_from_slice(&bytes);
                return Ok(
                    match parse_read_reply(&joined, info.info.view(), info.elements) {
                        Ok((value, data_type)) => Ok((Some(value), data_type)),
                        Err(err) => Err(comm(&format!("Failed to parse reply - {err}"))),
                    },
                );
            }
            offset += value.len();
            if value.is_empty() || offset >= expected {
                return Ok(Err(comm(
                    "Fragmented read made no progress or exceeded the expected size",
                )));
            }
            sequence = self.conn.next_sequence();
        }
    }

    /// `_send_write_fragmented`: writes the value in segments that fit the connection; stops at the first failed
    /// segment, keeping the controller's error. Each segment takes a sequence count (the built request's is not
    /// used).
    fn send_write_fragmented(
        &mut self,
        info: &ReqInfo,
        type_code: &[u8],
        value: &[u8],
    ) -> Result<Outcome> {
        let elements = u16::try_from(info.elements).unwrap_or(u16::MAX);
        let header = packets::write_tag_fragmented_message(&info.path, type_code, elements, 0, &[]);
        let size = usize::from(self.conn.connection_size());
        let Some(segment_size) = size.checked_sub(2 + header.len()).filter(|&n| n > 0) else {
            return Ok(Err(comm("Fragmented write header exceeds connection_size")));
        };
        let mut result = Ok((None, None));
        for (i, segment) in value.chunks(segment_size).enumerate() {
            let sequence = self.conn.next_sequence();
            let offset = u32::try_from(i * segment_size)
                .map_err(|_| Error::data("fragment offset out of range"))?;
            let message = packets::write_tag_fragmented_message(
                &info.path, type_code, elements, offset, segment,
            );
            let raw = self.conn.send_connected(sequence, &message)?;
            let reply = Reply::parse(ReplyKind::SendUnitData, &raw);
            if !reply.is_valid() {
                result = Err(response_error(&reply, None)); // stops at the first failed segment
                break;
            }
        }
        Ok(result)
    }

    // -------------------------------------------------------------------------------------------- merge

    /// `_merge_chunk_results`: the results of the chunks of a split request as its result.
    fn merge_chunk_results(entries: &[Entry], results: &mut HashMap<Key, TagResult>, rw: Rw) {
        for (i, entry) in entries.iter().enumerate() {
            let (Some(chunks), Ok(p)) = (&entry.chunks, &entry.parsed) else {
                continue;
            };
            let mut values = Vec::new();
            let mut error: Option<TagError> = None;
            for chunk in chunks {
                let result = results.remove(&chunk.key);
                let failed = chunk.error.clone().or_else(|| match &result {
                    None => Some(comm("Missing array chunk response")),
                    Some(r) => r.error.clone(),
                });
                match failed {
                    Some(e) => {
                        error.get_or_insert(e);
                    }
                    None if rw == Rw::Read => match result.and_then(|r| r.value) {
                        Some(Value::Array(items)) => values.extend(items),
                        Some(v) => values.push(v),
                        None => {}
                    },
                    None => {}
                }
            }
            let value = if rw == Rw::Read && error.is_none() {
                Some(Value::Array(values))
            } else {
                p.value.clone()
            };
            results.insert(
                Key::Tag(i),
                TagResult {
                    tag: p.user_tag.clone(),
                    value,
                    data_type: Some(format!(
                        "{}[{}]",
                        p.info.data_type_name().unwrap_or("None"),
                        p.elements
                    )),
                    error,
                },
            );
        }
    }

    /// `_merge_aoi_results`: the member reads of an AOI read as its result, a dict of its readable members.
    fn merge_aoi_results(entries: &[Entry], results: &mut HashMap<Key, TagResult>) {
        for (i, entry) in entries.iter().enumerate() {
            let (Some(members), Ok(p)) = (&entry.members, &entry.parsed) else {
                continue;
            };
            let mut values = indexmap::IndexMap::new();
            let mut error: Option<TagError> = None;
            for member in members {
                let Key::Member(_, name) = &member.key else {
                    continue;
                };
                let result = results.remove(&member.key);
                let cause = match &result {
                    None => Some(member.error.clone().unwrap_or_else(|| comm("No reply"))),
                    Some(r) => r.error.clone(),
                };
                match cause {
                    Some(cause) => {
                        if error.is_none() {
                            let mut e = cause.clone();
                            e.message = format!("{name} - {}", cause.message);
                            error = Some(e);
                        }
                    }
                    None => {
                        let value = result.and_then(|r| r.value);
                        values.insert(name.clone(), value.unwrap_or(Value::Array(Vec::new())));
                    }
                }
            }
            results.insert(
                Key::Tag(i),
                TagResult {
                    tag: p.user_tag.clone(),
                    value: Some(Value::Struct(values)),
                    data_type: p.info.data_type_name().map(str::to_owned),
                    error,
                },
            );
        }
    }

    // -------------------------------------------------------------------------------------------- read

    fn refused(&self, tags: &[&str]) -> Vec<TagResult> {
        let error = self.refused_error();
        tags.iter()
            .map(|t| TagResult {
                tag: (*t).to_owned(),
                value: None,
                data_type: None,
                error: Some(error.clone()),
            })
            .collect()
    }

    /// What a trend pen of `tag` samples, parsed like a read of it.
    pub(crate) fn pen_target(&mut self, tag: &str) -> Result<PenTarget> {
        self.conn.ensure_forward_open("trend")?;
        let p = self.parse_tag_request(tag, Rw::Read, 0)?;
        if p.elements != 1 || p.bool_elements.is_some() {
            return Err(Error::request(format!(
                "Cannot trend {tag}: a pen is one value, not an element count"
            )));
        }
        let bit = match (&p.info, p.bit) {
            // a bit of an integer, or a BOOL array element's bit in its word
            (_, Some(b)) => u32::try_from(b).ok(),
            (Info::Member(m), None) => m.bit.map(u32::from),
            (Info::Tag(t), None) => t.bit_position.map(u32::from),
        };
        Ok(PenTarget {
            data_type: p.info.view().data_type().clone(),
            plc_tag: p.plc_tag,
            bit,
        })
    }

    /// `read`: two attempts, the second after the tag definitions were loaded again because the tag table
    /// changed during the first.
    pub(crate) fn read_tags(&mut self, tags: &[&str]) -> Result<Vec<TagResult>> {
        self.conn.ensure_forward_open("read")?;
        if tags.is_empty() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let mut results = HashMap::new();
        for attempt in 0..2 {
            if self.backoff_error().is_some() {
                return Ok(self.refused(tags));
            }
            // before the parse: a reload in between is a retry
            let loaded_at = self.tag_table_version;
            entries = self.parse_requested(tags, Rw::Read)?;
            let keys = self.expand_aoi_reads(&mut entries);
            let keys = Self::split_large_requests(&mut entries, keys, Rw::Read);
            let mut infos = Vec::new();
            let packets = self.read_build_requests(&mut entries, &keys, &mut infos);
            let mut sent = Sent::default();
            self.send_requests(&packets, &mut infos, &mut sent)?;
            results = sent.results;
            Self::merge_chunk_results(&entries, &mut results, Rw::Read);
            Self::merge_aoi_results(&entries, &mut results);
            if !Logix::tag_table_changed(&sent.versions, loaded_at) {
                break;
            }
            if sent.versions.contains(&None) {
                // e.g. a download in progress (0x05) or the controller locked (0x10)
                self.back_off("the tag table version was not read");
                return Ok(self.refused(tags));
            }
            if attempt == 0 {
                if !self.refresh_tag_table()? {
                    return Ok(self.refused(tags));
                }
            } else {
                // no third read, the next call loads the definitions again
                let error = TagError::new(
                    "Tag table changed on the controller during the read and again during its retry, discarded",
                    ErrorKind::TableChanged,
                );
                for result in results.values_mut() {
                    result.value = None;
                    result.data_type = None;
                    result.error = Some(error.clone());
                }
            }
        }

        let mut out = Vec::with_capacity(tags.len());
        for (i, (tag, entry)) in tags.iter().zip(&entries).enumerate() {
            if let Some(error) = entry.error() {
                out.push(TagResult {
                    tag: (*tag).to_owned(),
                    value: None,
                    data_type: None,
                    error: Some(error),
                });
                continue;
            }
            let (Ok(p), Some(result)) = (&entry.parsed, results.remove(&Key::Tag(i))) else {
                out.push(invalid_request(tag, &format!("KeyError({i})")));
                continue;
            };
            out.push(match read_result(p, result) {
                Ok(result) => result,
                Err(repr) => invalid_request(tag, &repr),
            });
        }
        Ok(out)
    }

    // -------------------------------------------------------------------------------------------- write

    /// Parses and builds a write: (the tag table version the definitions were loaded at, entries, packets).
    fn write_build(&mut self, items: &[(&str, Value)], infos: &mut Vec<ReqInfo>) -> Result<Built> {
        let loaded_at = self.tag_table_version; // before the parse, as in read
        let tags: Vec<&str> = items.iter().map(|(t, _)| *t).collect();
        let mut entries = self.parse_requested(&tags, Rw::Write)?;
        for (entry, (_, value)) in entries.iter_mut().zip(items) {
            if let Ok(p) = &mut entry.parsed {
                p.value = Some(value.clone());
            }
        }
        let keys: Vec<Key> = (0..entries.len()).map(Key::Tag).collect();
        let keys = Self::split_large_requests(&mut entries, keys, Rw::Write);
        infos.clear();
        let packets = self.write_build_requests(&mut entries, &keys, infos);
        Ok((loaded_at, entries, packets))
    }

    /// `write`: the version is checked before the writes (a change loads the definitions again first) and
    /// after them (a change gives every result an error); writes are never retried.
    pub(crate) fn write_tags(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        self.conn.ensure_forward_open("write")?;
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let tags: Vec<&str> = items.iter().map(|(t, _)| *t).collect();
        if self.backoff_error().is_some() {
            return Ok(self.refused(&tags));
        }
        let mut infos = Vec::new();
        let (mut loaded_at, mut entries, mut packets) = self.write_build(items, &mut infos)?;
        // never in a packet with a write: before and after them
        let checks = self.version_checks() && !packets.is_empty();
        if checks {
            let Some(version) = self.read_tag_table_version()? else {
                self.back_off("the tag table version was not read");
                return Ok(self.refused(&tags));
            };
            if Some(version) != loaded_at {
                if !self.refresh_tag_table()? {
                    return Ok(self.refused(&tags));
                }
                (loaded_at, entries, packets) = self.write_build(items, &mut infos)?;
            }
        }
        let mut sent = Sent::default();
        self.send_requests(&packets, &mut infos, &mut sent)?;
        let version = if checks {
            self.read_tag_table_version()?
        } else {
            loaded_at
        };
        let changed = checks && Logix::tag_table_changed(&[version], loaded_at);
        if changed && version.is_none() {
            self.back_off("the tag table version was not read after the write");
        } else if changed {
            self.refresh_tag_table()?;
        }

        // a mask can carry bits of several requests and a BOOL slice can span several masks
        let mut results = sent.results;
        for packet in &packets {
            let requests = match packet {
                Packet::Single(r) => std::slice::from_ref(r),
                Packet::Multi { requests, .. } => requests.as_slice(),
            };
            for idx in requests.iter().filter_map(|r| r.key) {
                let info = &infos[idx];
                let Kind::Mask { ids } = &info.kind else {
                    continue;
                };
                let Some(result) = results.remove(&info.key) else {
                    continue;
                };
                for id in ids {
                    if results.get(id).is_none_or(|r| r.error.is_none()) {
                        results.insert(id.clone(), result.clone());
                    }
                }
            }
        }
        Self::merge_chunk_results(&entries, &mut results, Rw::Write);
        if changed {
            let error = TagError::new(
                "Tag table changed on the controller during the write, it may have written another tag",
                ErrorKind::TableChanged,
            );
            for result in results.values_mut() {
                result.error = Some(error.clone());
            }
        }

        let mut out = Vec::with_capacity(items.len());
        for (i, ((tag, value), entry)) in items.iter().zip(&entries).enumerate() {
            if let Some(error) = entry.error() {
                out.push(TagResult {
                    tag: (*tag).to_owned(),
                    value: None,
                    data_type: None,
                    error: Some(error),
                });
                continue;
            }
            let (Ok(p), Some(result)) = (&entry.parsed, results.get(&Key::Tag(i))) else {
                out.push(invalid_request(tag, &format!("KeyError({i})")));
                continue;
            };
            let data_type = if p.bit.is_some() && p.bool_elements.is_none() {
                Some("BOOL".to_owned())
            } else if let Some(n) = p.bool_elements.filter(|&n| n > 0) {
                Some(format!("BOOL[{n}]"))
            } else if p.elements > 1 {
                Some(format!(
                    "{}[{}]",
                    p.info.data_type_name().unwrap_or("None"),
                    p.elements
                ))
            } else {
                p.info.data_type_name().map(str::to_owned)
            };
            out.push(TagResult {
                tag: p.user_tag.clone(),
                value: Some(value.clone()),
                data_type,
                error: result.error.clone(),
            });
        }
        Ok(out)
    }
}

/// The outcome of a reply to a regular request: a read's value, or the reply's error.
fn outcome(reply: &Reply, info: &ReqInfo) -> Outcome {
    if !reply.is_valid() {
        return Err(response_error(reply, None));
    }
    match info.kind {
        Kind::Read | Kind::ReadFragmented => {
            let data = reply.data.as_deref().unwrap_or_default();
            match parse_read_reply(data, info.info.view(), info.elements) {
                Ok((value, data_type)) => Ok((Some(value), data_type)),
                Err(err) => Err(comm(&format!("Failed to parse reply - {err}"))),
            }
        }
        _ => Ok((None, None)),
    }
}

fn invalid_request(tag: &str, repr: &str) -> TagResult {
    TagResult {
        tag: tag.to_owned(),
        value: None,
        data_type: None,
        error: Some(TagError::new(
            format!("Invalid tag request - {repr}"),
            ErrorKind::BadRequest,
        )),
    }
}

/// A read's result for the caller: a bit of an integer or bit string as a BOOL, BOOL array (DWORD) bits as BOOL or
/// `BOOL[n]`; Err is the repr of the exception Python would raise.
fn read_result(p: &Parsed, result: TagResult) -> std::result::Result<TagResult, String> {
    if !result.is_ok() {
        return Ok(TagResult {
            tag: p.user_tag.clone(),
            value: None,
            data_type: None,
            error: result.error,
        });
    }
    if !p.info.is_bool_array() {
        let Some(bit) = p.bit else {
            return Ok(result);
        };
        let set = match result.value.as_ref() {
            // a bit string's value is its bits
            Some(Value::Array(bits)) => usize::try_from(bit)
                .ok()
                .and_then(|b| bits.get(b))
                .and_then(Value::as_bool)
                .ok_or_else(|| "IndexError('list index out of range')".to_owned())?,
            value => {
                let number = value
                    .and_then(Value::as_i128)
                    .ok_or_else(|| "TypeError('unsupported operand type(s) for &')".to_owned())?;
                u32::try_from(bit)
                    .ok()
                    .and_then(|b| 1i128.checked_shl(b))
                    .is_some_and(|mask| number & mask != 0)
            }
        };
        return Ok(TagResult {
            tag: p.user_tag.clone(),
            value: Some(Value::Bool(set)),
            data_type: Some("BOOL".into()),
            error: result.error,
        });
    }
    let bit = usize::try_from(p.bit.unwrap_or(0)).unwrap_or(usize::MAX);
    let bools = match &result.value {
        Some(Value::Array(items)) => items.as_slice(),
        _ => return Err("TypeError('object is not subscriptable')".into()),
    };
    let (value, data_type) = match p.bool_elements {
        Some(n) => {
            let start = bit.min(bools.len());
            let end = bit.saturating_add(n).min(bools.len());
            (
                Value::Array(bools[start..end].to_vec()),
                format!("BOOL[{n}]"),
            )
        }
        None => match bools.get(bit) {
            Some(v) => (v.clone(), "BOOL".to_owned()),
            None => return Err("IndexError('list index out of range')".into()),
        },
    };
    Ok(TagResult {
        tag: p.user_tag.clone(),
        value: Some(value),
        data_type: Some(data_type),
        error: result.error,
    })
}

impl LogixDriver {
    /// Reads tags, e.g. `["Tag", "Array{10}", "Udt.Member", "Dint.3", "BoolArray[40]", "Program:Main.Tag"]`.
    /// One result per tag, in order; a failed tag has its error in its result. Reads are packed in multi-service
    /// packets, a reply too big for the connection is read fragmented, more than 65535 elements are read in
    /// chunks; a structure's value has its members, an AOI whose whole read is refused the members readable.
    ///
    /// With instance IDs, every packet starts with a tag table version check: if the table changed, the tag
    /// definitions are loaded again and the tags read once more; a second change gives every result an error.
    /// If the version is not read, or the reload fails, every result is refused for the next 2 seconds.
    /// Err only for a connection failure (CommError) or a CIP connection that could not be opened.
    pub fn read(&self, tags: &[&str]) -> Result<Vec<TagResult>> {
        self.lock().read_tags(tags)
    }

    /// Writes tags: (tag, value) pairs, in order, one result each (its value is the value given). Bits of
    /// integers and BOOL array elements are written with Read-Modify-Write masks, in the caller's order with the
    /// other writes; values that do not fit the tag's type are refused before anything is sent.
    ///
    /// With instance IDs, the tag table version is checked right before the writes (a change loads the tag
    /// definitions again first) and right after them (a change gives every result an error). Writes are never
    /// retried. Err only for a connection failure or a CIP connection that could not be opened.
    pub fn write(&self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        self.lock().write_tags(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_int_saturates_and_follows_python_rules() {
        assert_eq!(py_int(" 7 "), Some(7));
        assert_eq!(py_int("-3"), Some(-3));
        assert_eq!(py_int("1_0"), Some(10));
        assert_eq!(py_int("x"), None);
        assert_eq!(py_int(""), None);
        assert_eq!(py_int("9".repeat(60).as_str()), Some(i128::MAX));
    }

    #[test]
    fn epath_errors_list_the_segments_like_python() {
        assert_eq!(
            epath_error("n[-1]", Some(0), true),
            "Error packing [DataSegment(name=''), LogicalSegment(name=None)] as PADDED_EPATH"
        );
        assert_eq!(
            epath_error("Program:M.n[-1].b", Some(5), true),
            "Error packing [DataSegment(name=''), LogicalSegment(name=None), LogicalSegment(name=None), \
             LogicalSegment(name=None), DataSegment(name='')] as PADDED_EPATH"
        );
        assert_eq!(
            epath_error("a.b[-2,3]", None, true),
            "Error packing [DataSegment(name=''), DataSegment(name=''), LogicalSegment(name=None), \
             LogicalSegment(name=None)] as PADDED_EPATH"
        );
    }
}
