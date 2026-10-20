//! The tag cache file: what a tag list upload read (the symbol lists, the raw templates with their makeups and
//! the AOI probes) and the controller serial, scope and tag table version it was read at, so the next connect
//! can skip the upload (see `LogixOptions::tag_cache_file` for when the file is used).
//!
//! A compact binary file, every integer little-endian:
//!
//! ```text
//! header   magic "CIPLTAGC" (8) | format version u16 | reserved u16 (0) | body length u32 | FNV-1a 64 of body u64
//! body     scope opt-str | serial opt-str | table version (u8 flag, i16 i16 i32 i32 i32 when 1)
//!          u32 scopes   { scope opt-str, u32 symbols { instance id u32, name str, symbol type u16, symbol
//!                         address u32, object address u32, software control u32, external access str,
//!                         dimensions 3 x u32 } }
//!          u32 templates { id u16, makeup, u32 length, raw template bytes }
//!          u32 probes    { id u16, makeup, whole read u8, u32 readable { str }, u32 refused { str } }
//! makeup   object definition size u32 | structure size u32 | member count u16 | structure handle u16
//! str      u32 length, UTF-8 | opt-str  u8 flag (0 None, 1 a str follows)
//! ```
//!
//! The encoding is canonical (equal contents give equal bytes), so a file is rewritten only when its contents
//! change.  Files are written to a temporary file and renamed over the old one.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::logix::driver::AoiProbe;
use crate::logix::types::{Symbol, TemplateMakeup};
use crate::packets::TagTableVersion;

/// First bytes of a tag cache file.
pub const MAGIC: [u8; 8] = *b"CIPLTAGC";
/// Version of the layout; a file of another version is not used (and replaced).
pub const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 24;
/// The smallest encodings, which bound the counts read from a file.
const MIN_SYMBOL_LEN: usize = 4 + 4 + 2 + 4 + 4 + 4 + 4 + 12;
const MIN_TEMPLATE_LEN: usize = 2 + 12 + 4;
const MIN_PROBE_LEN: usize = 2 + 12 + 1 + 4 + 4;
const MIN_SCOPE_LEN: usize = 1 + 4;

/// The contents of a tag cache file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TagCacheFile {
    /// The `get_tag_list` program the upload was for: None for the controller only, `"*"` for every scope.
    pub scope: Option<String>,
    /// The controller's serial number.
    pub serial: Option<String>,
    /// The tag table version read before the upload, None if the controller reports none.
    pub table_version: Option<TagTableVersion>,
    /// The symbol lists by scope, in upload order: the controller (None) then programs.
    pub symbols: Vec<(Option<String>, Vec<Symbol>)>,
    /// The raw templates used by the tags, by template instance id, with their makeups.
    pub templates: Vec<(u16, TemplateMakeup, Vec<u8>)>,
    /// The AOI probes, by template instance id, with the makeup they were made at.
    pub probes: Vec<(u16, TemplateMakeup, AoiProbe)>,
}

/// Why a tag cache file cannot be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TagCacheError {
    /// Not a tag cache file, or a damaged one: no magic, a short file, a checksum or encoding mismatch.
    Damaged(String),
    /// A tag cache file of another format version.
    OtherVersion(u16),
}

impl fmt::Display for TagCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagCacheError::Damaged(why) => write!(f, "not a tag cache file or damaged: {why}"),
            TagCacheError::OtherVersion(v) => write!(f, "tag cache file format {v}"),
        }
    }
}

impl std::error::Error for TagCacheError {}

/// FNV-1a, 64 bits: catches a damaged or truncated body (not an integrity check against tampering).
fn checksum(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// ------------------------------------------------------------------------------------------------ encoding

struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    /// A length or count; the file format caps them at u32 (nothing a controller reports comes near).
    fn len(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
    fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.0.extend_from_slice(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn opt_str(&mut self, s: Option<&str>) {
        match s {
            None => self.u8(0),
            Some(s) => {
                self.u8(1);
                self.str(s);
            }
        }
    }
    fn makeup(&mut self, m: &TemplateMakeup) {
        self.u32(m.object_definition_size);
        self.u32(m.structure_size);
        self.u16(m.member_count);
        self.u16(m.structure_handle);
    }
    fn strs(&mut self, items: &[String]) {
        self.len(items.len());
        for s in items {
            self.str(s);
        }
    }
}

impl TagCacheFile {
    /// The file's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let symbols: usize = self.symbols.iter().map(|(_, s)| s.len()).sum();
        let templates: usize = self.templates.iter().map(|(_, _, d)| d.len()).sum();
        let mut out = Out(Vec::with_capacity(
            HEADER_LEN
                + 64
                + symbols * (MIN_SYMBOL_LEN + 24)
                + templates
                + self.templates.len() * 18,
        ));
        out.0.extend_from_slice(&[0; HEADER_LEN]);
        out.opt_str(self.scope.as_deref());
        out.opt_str(self.serial.as_deref());
        match self.table_version {
            None => out.u8(0),
            Some((a, b, c, d, e)) => {
                out.u8(1);
                out.0.extend_from_slice(&a.to_le_bytes());
                out.0.extend_from_slice(&b.to_le_bytes());
                for v in [c, d, e] {
                    out.0.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
        out.len(self.symbols.len());
        for (scope, symbols) in &self.symbols {
            out.opt_str(scope.as_deref());
            out.len(symbols.len());
            for s in symbols {
                out.u32(s.instance_id);
                out.str(&s.tag_name);
                out.u16(s.symbol_type);
                out.u32(s.symbol_address);
                out.u32(s.symbol_object_address);
                out.u32(s.software_control);
                out.str(&s.external_access);
                for d in s.dimensions {
                    out.u32(d);
                }
            }
        }
        out.len(self.templates.len());
        for (id, makeup, data) in &self.templates {
            out.u16(*id);
            out.makeup(makeup);
            out.bytes(data);
        }
        out.len(self.probes.len());
        for (id, makeup, probe) in &self.probes {
            out.u16(*id);
            out.makeup(makeup);
            out.u8(u8::from(probe.whole_read));
            out.strs(&probe.readable);
            out.strs(&probe.refused);
        }
        let mut bytes = out.0;
        let body_len = u32::try_from(bytes.len() - HEADER_LEN).unwrap_or(u32::MAX);
        let sum = checksum(&bytes[HEADER_LEN..]);
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&body_len.to_le_bytes());
        bytes[16..24].copy_from_slice(&sum.to_le_bytes());
        bytes
    }

    /// Parses a file's bytes.
    pub fn decode(data: &[u8]) -> Result<Self, TagCacheError> {
        let damaged = |why: &str| TagCacheError::Damaged(why.to_owned());
        if data.len() < HEADER_LEN || data[..8] != MAGIC {
            return Err(damaged("no tag cache file header"));
        }
        let mut header = Cursor { data, pos: 8 };
        let version = header.u16()?;
        if version != FORMAT_VERSION {
            return Err(TagCacheError::OtherVersion(version));
        }
        if header.u16()? != 0 {
            return Err(damaged("reserved bytes set"));
        }
        let body_len = header.len()?;
        let sum = u64::from_le_bytes(header.array()?);
        let body = &data[HEADER_LEN..];
        if body.len() != body_len {
            return Err(damaged("length mismatch"));
        }
        if checksum(body) != sum {
            return Err(damaged("checksum mismatch"));
        }
        let mut r = Cursor { data: body, pos: 0 };
        let scope = r.opt_str()?;
        let serial = r.opt_str()?;
        let table_version = match r.u8()? {
            0 => None,
            1 => Some((
                i16::from_le_bytes(r.array()?),
                i16::from_le_bytes(r.array()?),
                i32::from_le_bytes(r.array()?),
                i32::from_le_bytes(r.array()?),
                i32::from_le_bytes(r.array()?),
            )),
            _ => return Err(damaged("bad table version flag")),
        };
        let scopes = r.count(MIN_SCOPE_LEN)?;
        let mut symbols = Vec::with_capacity(scopes);
        for _ in 0..scopes {
            let scope = r.opt_str()?;
            let n = r.count(MIN_SYMBOL_LEN)?;
            let mut list = Vec::with_capacity(n);
            for _ in 0..n {
                list.push(Symbol {
                    instance_id: r.u32()?,
                    tag_name: r.str()?,
                    symbol_type: r.u16()?,
                    symbol_address: r.u32()?,
                    symbol_object_address: r.u32()?,
                    software_control: r.u32()?,
                    external_access: r.str()?,
                    dimensions: [r.u32()?, r.u32()?, r.u32()?],
                });
            }
            symbols.push((scope, list));
        }
        let n = r.count(MIN_TEMPLATE_LEN)?;
        let mut templates = Vec::with_capacity(n);
        for _ in 0..n {
            let id = r.u16()?;
            let makeup = r.makeup()?;
            let len = r.len()?;
            templates.push((id, makeup, r.take(len)?.to_vec()));
        }
        let n = r.count(MIN_PROBE_LEN)?;
        let mut probes = Vec::with_capacity(n);
        for _ in 0..n {
            let id = r.u16()?;
            let makeup = r.makeup()?;
            let whole_read = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(damaged("bad flag")),
            };
            let readable = r.strs()?;
            let refused = r.strs()?;
            probes.push((
                id,
                makeup,
                AoiProbe {
                    whole_read,
                    readable,
                    refused,
                },
            ));
        }
        if r.pos != body.len() {
            return Err(damaged("data after the contents"));
        }
        Ok(TagCacheFile {
            scope,
            serial,
            table_version,
            symbols,
            templates,
            probes,
        })
    }
}

/// A bounds-checked reader of a file's bytes.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TagCacheError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| TagCacheError::Damaged("truncated".into()))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], TagCacheError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, TagCacheError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TagCacheError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, TagCacheError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn len(&mut self) -> Result<usize, TagCacheError> {
        usize::try_from(self.u32()?).map_err(|_| TagCacheError::Damaged("length".into()))
    }
    /// A count of items at least `min_len` bytes each, which must fit in what is left.
    fn count(&mut self, min_len: usize) -> Result<usize, TagCacheError> {
        let n = self.len()?;
        if n.saturating_mul(min_len) > self.data.len() - self.pos {
            return Err(TagCacheError::Damaged("count past the end".into()));
        }
        Ok(n)
    }
    fn str(&mut self) -> Result<String, TagCacheError> {
        let len = self.len()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| TagCacheError::Damaged("not UTF-8".into()))
    }
    fn opt_str(&mut self) -> Result<Option<String>, TagCacheError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.str().map(Some),
            _ => Err(TagCacheError::Damaged("bad flag".into())),
        }
    }
    fn strs(&mut self) -> Result<Vec<String>, TagCacheError> {
        let n = self.count(4)?;
        (0..n).map(|_| self.str()).collect()
    }
    fn makeup(&mut self) -> Result<TemplateMakeup, TagCacheError> {
        Ok(TemplateMakeup {
            object_definition_size: self.u32()?,
            structure_size: self.u32()?,
            member_count: self.u16()?,
            structure_handle: self.u16()?,
        })
    }
}

/// Writes `bytes` to a temporary file next to `path`, flushed to disk, and renames it over `path`.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let absolute = std::path::absolute(path)?;
    let dir = absolute.parent().unwrap_or(Path::new("."));
    let name = absolute
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &absolute)
    };
    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample() -> TagCacheFile {
        let makeup = TemplateMakeup {
            object_definition_size: 30,
            structure_size: 12,
            member_count: 3,
            structure_handle: 0xBEEF,
        };
        TagCacheFile {
            scope: Some("*".into()),
            serial: Some("c0ffee01".into()),
            table_version: Some((-3, 1, 10, -10, 20)),
            symbols: vec![
                (
                    None,
                    vec![Symbol {
                        instance_id: 70000,
                        tag_name: "caf\u{e9}".into(),
                        symbol_type: 0x8123,
                        symbol_address: 1,
                        symbol_object_address: 2,
                        software_control: 1 << 26,
                        external_access: "Read/Write".into(),
                        dimensions: [3, 0, 0],
                    }],
                ),
                (Some("MainProgram".into()), vec![]),
            ],
            templates: vec![(0x123, makeup, vec![1, 2, 3, 4]), (0x124, makeup, vec![])],
            probes: vec![(
                0x124,
                makeup,
                AoiProbe {
                    whole_read: true,
                    readable: vec!["Cmd".into()],
                    refused: vec![String::new(), "Count".into()],
                },
            )],
        }
    }

    #[test]
    fn decode_gives_back_what_was_encoded() {
        for file in [sample(), TagCacheFile::default()] {
            assert_eq!(TagCacheFile::decode(&file.encode()), Ok(file));
        }
    }

    #[test]
    fn equal_contents_encode_to_equal_bytes() {
        assert_eq!(sample().encode(), sample().encode());
        let mut other = sample();
        other.serial = Some("c0ffee02".into());
        assert_ne!(sample().encode(), other.encode());
    }

    #[test]
    fn every_truncation_and_bit_flip_is_rejected() {
        let bytes = sample().encode();
        for len in 0..bytes.len() {
            assert!(TagCacheFile::decode(&bytes[..len]).is_err(), "length {len}");
        }
        for i in 0..bytes.len() {
            if (8..10).contains(&i) {
                continue; // the format version, see below
            }
            let mut damaged = bytes.clone();
            damaged[i] ^= 0x10;
            assert!(
                matches!(
                    TagCacheFile::decode(&damaged),
                    Err(TagCacheError::Damaged(_))
                ),
                "byte {i}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(TagCacheFile::decode(&longer).is_err());
    }

    #[test]
    fn another_format_version_is_reported_as_such() {
        let mut bytes = sample().encode();
        bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            TagCacheFile::decode(&bytes),
            Err(TagCacheError::OtherVersion(2))
        );
    }

    #[test]
    fn other_files_are_not_tag_cache_files() {
        for data in [&b""[..], b"{\"version\": 2}", b"CIPLTAGC", &[0u8; 64]] {
            assert!(matches!(
                TagCacheFile::decode(data),
                Err(TagCacheError::Damaged(_))
            ));
        }
    }

    #[test]
    fn hostile_counts_fail_without_allocating() {
        // a valid header over a body claiming 2^32-1 scopes
        let mut body = vec![0u8, 0, 0];
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&checksum(&body).to_le_bytes());
        bytes.extend_from_slice(&body);
        assert!(matches!(
            TagCacheFile::decode(&bytes),
            Err(TagCacheError::Damaged(_))
        ));
    }

    #[test]
    fn write_atomic_replaces_the_file() {
        let dir = std::env::temp_dir().join(format!("ciplink-tag-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tags");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert!(write_atomic(&dir.join("missing").join("tags"), b"x").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
