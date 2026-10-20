//! Logix metadata records: Description requests and the paged vendor replies of the metadata class.
//!
//! Port of `ciplink/logix_metadata.py`. A `DataError` there is [`Error::Data`] here, a `ValueError`
//! [`Error::Request`].

use indexmap::IndexMap;

use crate::reader::Reader;
use crate::types::Elementary;
use crate::{Error, Result, Value};

/// The vendor service that reads metadata records.
pub const DESCRIPTION_SERVICE: u8 = 0x53;
/// The CIP class of the metadata object.
pub const METADATA_CLASS: u16 = 0x349;

const READ_PREFIX: [u8; 10] = [0x53, 0x04, 0x21, 0x00, 0x49, 0x03, 0x25, 0x00, 0x00, 0x00];

/// Builds a Description request for one symbol (`class_id` 0x6B for a tag), a member or element `path` below
/// it, in `language`, continuing at byte `offset` of a paged reply. `owner_context` is (owner instance, owner
/// word); `(0, 0)` for a controller-scope tag.
pub fn build_description_request(
    instance_id: u32,
    language: u16,
    offset: u32,
    path: &str,
    class_id: u16,
    owner_context: (u32, u16),
) -> Result<Vec<u8>> {
    if instance_id == 0 {
        return Err(Error::request(
            "Symbol instance_id must be a positive UDINT",
        ));
    }
    let raw_path = path.as_bytes();
    let path_len = u16::try_from(raw_path.len())
        .map_err(|_| Error::request("Description path is too long"))?;
    let mut out = Vec::with_capacity(READ_PREFIX.len() + 30 + raw_path.len());
    out.extend_from_slice(&READ_PREFIX);
    page_header(&mut out, offset);
    for word in [0x0F, 0xFF, class_id] {
        out.extend_from_slice(&u16::to_le_bytes(word));
    }
    out.extend_from_slice(&instance_id.to_le_bytes());
    out.extend_from_slice(&owner_context.0.to_le_bytes());
    out.extend_from_slice(&owner_context.1.to_le_bytes());
    out.extend_from_slice(&path_len.to_le_bytes());
    out.extend_from_slice(raw_path);
    out.extend_from_slice(&language.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    Ok(out)
}

/// Builds a request for the index of all Descriptions in `language`, continuing at byte `offset`.
pub fn build_description_index_request(language: u16, offset: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(READ_PREFIX.len() + 16);
    out.extend_from_slice(&READ_PREFIX);
    page_header(&mut out, offset);
    for word in [0x0C, 0xFF, language, 1] {
        out.extend_from_slice(&u16::to_le_bytes(word));
    }
    out
}

fn page_header(out: &mut Vec<u8>, offset: u32) {
    out.extend_from_slice(&[1, u8::from(offset == 0), 0, 0]);
    out.extend_from_slice(&offset.to_le_bytes());
}

/// One page of a metadata reply (after the CIP reply and status header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataPage<'a> {
    /// The first page of a reply.
    pub first: bool,
    /// The last page of a reply.
    pub last: bool,
    /// Payload bytes on the pages before this one.
    pub offset: u32,
    /// The payload after the eight-byte page header.
    pub data: &'a [u8],
}

/// Parses the vendor page header. Flags 1 and 2 mark the first and last pages; pages split records anywhere,
/// so they must be assembled before any record is parsed.
pub fn decode_metadata_page(data: &[u8]) -> Result<MetadataPage<'_>> {
    let (Some(header), Some(rest)) = (data.get(..8), data.get(8..)) else {
        return Err(Error::data("Truncated Logix metadata page header"));
    };
    let (version, flags) = (header[0], header[1]);
    let reserved = u16::from_le_bytes([header[2], header[3]]);
    if version != 1 || flags & !3 != 0 || reserved != 0 {
        return Err(Error::data("Unsupported Logix metadata page header"));
    }
    Ok(MetadataPage {
        first: flags & 1 != 0,
        last: flags & 2 != 0,
        offset: u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
        data: rest,
    })
}

/// Validates a complete, ordered reply and joins the payloads of its pages.
pub fn assemble_metadata_pages<P: AsRef<[u8]>>(pages: &[P]) -> Result<Vec<u8>> {
    if pages.is_empty() {
        return Err(Error::data("No Logix metadata pages"));
    }
    let mut out = Vec::new();
    for (index, raw) in pages.iter().enumerate() {
        let page = decode_metadata_page(raw.as_ref())?;
        if page.first != (index == 0) || u64::from(page.offset) != out.len() as u64 {
            return Err(Error::data("Out-of-order Logix metadata page"));
        }
        if page.last != (index == pages.len() - 1) {
            return Err(Error::data(
                "Incomplete response or data after final metadata page",
            ));
        }
        if !page.last && page.data.is_empty() {
            return Err(Error::data("Logix metadata continuation made no progress"));
        }
        out.extend_from_slice(page.data);
    }
    Ok(out)
}

/// The text encoding of metadata strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextEncoding {
    /// UTF-8 (the default; the controller captures are ASCII).
    Utf8,
    /// 7-bit ASCII.
    Ascii,
    /// ISO 8859-1.
    Latin1,
    /// Windows code page 1252.
    Cp1252,
}

impl TextEncoding {
    /// The Python codec name, as used in error messages.
    pub fn name(self) -> &'static str {
        match self {
            TextEncoding::Utf8 => "utf-8",
            TextEncoding::Ascii => "ascii",
            TextEncoding::Latin1 => "latin-1",
            TextEncoding::Cp1252 => "cp1252",
        }
    }

    fn decode(self, raw: &[u8]) -> Option<String> {
        match self {
            TextEncoding::Utf8 => String::from_utf8(raw.to_vec()).ok(),
            TextEncoding::Ascii => raw
                .iter()
                .map(|&b| b.is_ascii().then_some(char::from(b)))
                .collect(),
            TextEncoding::Latin1 => Some(raw.iter().map(|&b| char::from(b)).collect()),
            TextEncoding::Cp1252 => raw.iter().map(|&b| cp1252(b)).collect(),
        }
    }
}

fn cp1252(byte: u8) -> Option<char> {
    const HIGH: [u16; 32] = [
        0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
        0x0152, 0, 0x017D, 0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC,
        0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
    ];
    match byte {
        0x80..=0x9F => match HIGH[usize::from(byte - 0x80)] {
            0 => None,
            code => char::from_u32(u32::from(code)),
        },
        _ => Some(char::from(byte)),
    }
}

/// The value of a metadata record.
#[derive(Clone, Debug, PartialEq)]
pub enum MetadataValue {
    /// Kind 1 text, decoded.
    Text(String),
    /// Kind 1 text left undecoded (no encoding given).
    Raw(Vec<u8>),
    /// Kind 2: `values` of the CIP atomic type `type_code`.
    Atomic {
        /// The CIP type code (0xC1..=0xCB).
        type_code: u16,
        /// The decoded elements.
        values: Vec<Value>,
    },
    /// No value (a kind 4 Description: none in this language).
    None,
}

/// One field of a definition reply.
#[derive(Clone, Debug, PartialEq)]
pub struct DefinitionField {
    /// The value kind: 1 text, 2 atomic.
    pub kind: u16,
    /// The decoded value.
    pub value: MetadataValue,
    /// The value bytes as sent, including its length or type prefix.
    pub raw_value: Vec<u8>,
    /// The three context words, kept as sent.
    pub context: [u32; 3],
}

/// One Description record.
#[derive(Clone, Debug, PartialEq)]
pub struct DescriptionRecord {
    /// The value kind: 1 text, 4 none.
    pub kind: u16,
    /// The text, or [`MetadataValue::None`] for kind 4.
    pub value: MetadataValue,
    /// The value bytes as sent (empty for kind 4).
    pub raw_value: Vec<u8>,
    /// The class of the described object.
    pub class_id: u16,
    /// The instance of the described object.
    pub instance_id: u32,
    /// The language code.
    pub language: u16,
    /// Always 1 (Description).
    pub property_id: u16,
    /// The controller's record identifier.
    pub record_id: u32,
    /// The owner (instance, word).
    pub owner_context: (u32, u16),
    /// The member or element path below the object.
    pub path: String,
    /// The three context words, kept as sent.
    pub context: [u32; 3],
}

/// A cursor whose short reads are all "Truncated Logix metadata record".
struct Cursor<'a>(Reader<'a>);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.remaining() < n {
            return Err(Error::data("Truncated Logix metadata record"));
        }
        if n == 0 {
            return Ok(&[]); // Reader::take reports BufferEmpty for an empty read at the end
        }
        self.0.take(n)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A value of `kind` and the bytes it took.
    fn value(
        &mut self,
        kind: u16,
        encoding: Option<TextEncoding>,
    ) -> Result<(MetadataValue, Vec<u8>)> {
        let start = self.0.position();
        let value = match kind {
            1 => {
                let len = self.u16()?;
                let raw = self.take(usize::from(len))?;
                match encoding {
                    None => MetadataValue::Raw(raw.to_vec()),
                    Some(encoding) => {
                        MetadataValue::Text(encoding.decode(raw).ok_or_else(|| {
                            Error::data(format!(
                                "Cannot decode metadata text using {}",
                                encoding.name()
                            ))
                        })?)
                    }
                }
            }
            2 => {
                let type_code = self.u16()?;
                let count = self.u16()?;
                let typ = u8::try_from(type_code)
                    .ok()
                    .filter(|code| (0xC1..0xCC).contains(code))
                    .and_then(Elementary::from_code)
                    .ok_or_else(|| {
                        Error::data(format!(
                            "Unsupported metadata atomic type 0x{type_code:04x}"
                        ))
                    })?;
                let raw = self.take(usize::from(count) * typ.size())?;
                let mut reader = Reader::new(raw);
                let mut values = Vec::with_capacity(usize::from(count));
                while !reader.is_empty() {
                    values.push(typ.decode(&mut reader)?);
                }
                MetadataValue::Atomic { type_code, values }
            }
            _ => {
                return Err(Error::data(format!(
                    "Unsupported metadata value kind {kind}"
                )));
            }
        };
        Ok((value, self.0.buffer()[start..self.0.position()].to_vec()))
    }
}

/// Parses the fields of a definition reply, keyed by field identifier in reply order. Text is decoded with
/// `encoding` (`None` keeps the bytes); unknown context words are kept as sent.
pub fn decode_definition_response<P: AsRef<[u8]>>(
    pages: &[P],
    encoding: Option<TextEncoding>,
) -> Result<IndexMap<u16, DefinitionField>> {
    let data = assemble_metadata_pages(pages)?;
    let mut cursor = Cursor(Reader::new(&data));
    let mut fields = IndexMap::new();
    while !cursor.is_empty() {
        let identifier = cursor.u16()?;
        let context = [cursor.u32()?, cursor.u32()?, cursor.u32()?];
        let kind = cursor.u16()?;
        if fields.contains_key(&identifier) {
            return Err(Error::data(format!(
                "Duplicate metadata definition field {identifier}"
            )));
        }
        let (value, raw_value) = cursor.value(kind, encoding)?;
        fields.insert(
            identifier,
            DefinitionField {
                kind,
                value,
                raw_value,
                context,
            },
        );
    }
    Ok(fields)
}

/// Returns the one text Description of a reply, or `None` when the reply holds no record.
pub fn decode_description_response<P: AsRef<[u8]>>(
    pages: &[P],
    encoding: Option<TextEncoding>,
) -> Result<Option<DescriptionRecord>> {
    let mut records = decode_description_records(pages, encoding, Some(1))?;
    match records.pop() {
        None => Ok(None),
        Some(_) if !records.is_empty() => {
            Err(Error::data("Unexpected additional Description records"))
        }
        Some(record) if record.kind != 1 => Err(Error::data("Response is not a text Description")),
        Some(record) => Ok(Some(record)),
    }
}

/// Parses every Description record of a reply; more than `max_records` records is an error.
pub fn decode_description_records<P: AsRef<[u8]>>(
    pages: &[P],
    encoding: Option<TextEncoding>,
    max_records: Option<usize>,
) -> Result<Vec<DescriptionRecord>> {
    let data = assemble_metadata_pages(pages)?;
    let mut cursor = Cursor(Reader::new(&data));
    let mut records = Vec::new();
    while !cursor.is_empty() {
        if max_records.is_some_and(|max| records.len() >= max) {
            return Err(Error::data("Unexpected additional Description records"));
        }
        let class_id = cursor.u16()?;
        let instance_id = cursor.u32()?;
        let owner_context = (cursor.u32()?, cursor.u16()?);
        let path = match cursor.value(1, Some(TextEncoding::Utf8))?.0 {
            MetadataValue::Text(path) => path,
            _ => String::new(), // unreachable: kind 1 with an encoding is text
        };
        let language = cursor.u16()?;
        let property_id = cursor.u16()?;
        let record_id = cursor.u32()?;
        let context = [cursor.u32()?, cursor.u32()?, cursor.u32()?];
        let kind = cursor.u16()?;
        if property_id != 1 || !(kind == 1 || kind == 4) {
            return Err(Error::data("Response is not a Description record"));
        }
        let (value, raw_value) = if kind == 1 {
            cursor.value(kind, encoding)?
        } else {
            (MetadataValue::None, Vec::new())
        };
        records.push(DescriptionRecord {
            kind,
            value,
            raw_value,
            class_id,
            instance_id,
            language,
            property_id,
            record_id,
            owner_context,
            path,
            context,
        });
    }
    Ok(records)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn page(data: &[u8], first: bool, last: bool, offset: u32) -> Vec<u8> {
        let mut out = vec![1, u8::from(first) | (u8::from(last) << 1), 0, 0];
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn continuation_request_clears_the_first_flag_and_carries_the_offset() {
        let request = build_description_request(1063, 0x7F, 490, "", 0x6B, (0, 0)).unwrap();
        assert_eq!(request[10..18], [1, 0, 0, 0, 0xEA, 1, 0, 0]);
    }

    #[test]
    fn empty_page_list_and_stalled_continuation_are_rejected() {
        assert!(assemble_metadata_pages::<Vec<u8>>(&[]).is_err());
        let stalled = [page(b"", true, false, 0), page(b"", false, true, 0)];
        assert_eq!(
            assemble_metadata_pages(&stalled),
            Err(Error::data("Logix metadata continuation made no progress"))
        );
    }

    #[test]
    fn cp1252_rejects_its_undefined_bytes() {
        assert_eq!(
            TextEncoding::Cp1252.decode(b"caf\xe9\x80").as_deref(),
            Some("caf\u{e9}\u{20ac}")
        );
        assert_eq!(TextEncoding::Cp1252.decode(b"\x81"), None);
        assert_eq!(TextEncoding::Ascii.decode(b"\x80"), None);
    }
}
