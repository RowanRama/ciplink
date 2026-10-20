//! The simulated SLC 500 / MicroLogix: data files answered over PCCC (Execute PCCC, 0x4B on class 0x67).

use crate::cip::{Faults, reply};
use crate::config::{ConfigError, FileConfig, SlcConfig};
use crate::identity::Identity;
use crate::path::{attribute, class_instance, parse_request};
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileType {
    O,
    I,
    S,
    B,
    T,
    C,
    R,
    N,
    F,
    St,
    A,
    L,
}

impl FileType {
    const ALL: [FileType; 12] = [
        FileType::O,
        FileType::I,
        FileType::S,
        FileType::B,
        FileType::T,
        FileType::C,
        FileType::R,
        FileType::N,
        FileType::F,
        FileType::St,
        FileType::A,
        FileType::L,
    ];

    fn name(self) -> &'static str {
        match self {
            FileType::O => "O",
            FileType::I => "I",
            FileType::S => "S",
            FileType::B => "B",
            FileType::T => "T",
            FileType::C => "C",
            FileType::R => "R",
            FileType::N => "N",
            FileType::F => "F",
            FileType::St => "ST",
            FileType::A => "A",
            FileType::L => "L",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|t| t.name().eq_ignore_ascii_case(name))
    }

    /// The PCCC file type code.
    fn code(self) -> u8 {
        match self {
            FileType::O => 0x82,
            FileType::I => 0x83,
            FileType::S => 0x84,
            FileType::B => 0x85,
            FileType::T => 0x86,
            FileType::C => 0x87,
            FileType::R => 0x88,
            FileType::N => 0x89,
            FileType::F => 0x8A,
            FileType::St => 0x8D,
            FileType::A => 0x8E,
            FileType::L => 0x91,
        }
    }

    fn element_size(self) -> usize {
        match self {
            FileType::T | FileType::C | FileType::R => 6,
            FileType::F | FileType::L => 4,
            FileType::St => 84,
            _ => 2,
        }
    }

    /// The status bits of word 0 of a T, C or R element, from bit 15 down.
    fn bits(self) -> &'static [&'static str] {
        match self {
            FileType::T => &["EN", "TT", "DN"],
            FileType::C => &["CU", "CD", "DN", "OV", "UN", "UA"],
            FileType::R => &["EN", "EU", "DN", "EM", "ER", "UL", "IN", "FD"],
            _ => &[],
        }
    }

    /// The names of words 1 and 2 of a T, C or R element.
    fn words(self) -> [&'static str; 2] {
        match self {
            FileType::R => ["LEN", "POS"],
            _ => ["PRE", "ACC"],
        }
    }
}

#[derive(Clone, Debug)]
struct DataFile {
    file_type: FileType,
    data: Vec<u8>,
}

/// The layout of the file directory (system file 0) of a processor family, as the driver reads it.
struct Sys0 {
    file_position: usize,
    row_size: usize,
    file_type: u8,
    size_element: u16,
    size_const: usize,
}

/// A simulated SLC 500 or MicroLogix processor.
#[derive(Clone, Debug)]
pub struct Slc {
    pub(crate) identity: Identity,
    processor_type: String,
    files: BTreeMap<u16, DataFile>,
    datalog: VecDeque<String>,
}

const STS_ILLEGAL: u8 = 0x10;
const STS_EXTENDED: u8 = 0xF0;
/// Extended status: the address does not point to something usable.
const EXT_BAD_ADDRESS: u8 = 0x06;

impl Slc {
    /// Builds a processor from its configuration.
    pub fn new(config: &SlcConfig) -> Result<Self, ConfigError> {
        let defaults = [
            (0, "O", 8),
            (1, "I", 8),
            (2, "S", 83),
            (3, "B", 32),
            (4, "T", 16),
            (5, "C", 16),
            (6, "R", 8),
            (7, "N", 100),
            (8, "F", 50),
        ];
        let configs: Vec<FileConfig> = if config.files.is_empty() {
            defaults
                .iter()
                .map(|&(n, t, e)| FileConfig::new(n, t, e))
                .collect()
        } else {
            config.files.clone()
        };
        let mut files = BTreeMap::new();
        for f in &configs {
            let fail =
                |m: String| ConfigError::new(format!("file {}{}: {m}", f.file_type, f.number));
            let file_type = FileType::from_name(&f.file_type)
                .ok_or_else(|| fail("unknown file type".into()))?;
            if f.number > 255
                || files.contains_key(&f.number)
                || f.values.len() > f.elements as usize
            {
                return Err(fail(
                    "number above 255, defined twice or more values than elements".into(),
                ));
            }
            let size = file_type.element_size();
            let mut data = vec![0u8; size * f.elements as usize];
            for (i, value) in f.values.iter().enumerate() {
                encode_element(file_type, value, &mut data[i * size..(i + 1) * size])
                    .map_err(fail)?;
            }
            files.insert(f.number, DataFile { file_type, data });
        }
        if config.processor_type.len() > 11 {
            return Err(ConfigError::new("processor_type is at most 11 characters"));
        }
        Ok(Slc {
            identity: Identity::build(&config.identity)?,
            processor_type: config.processor_type.clone(),
            files,
            datalog: config.datalog.iter().cloned().collect(),
        })
    }

    /// The value of a data file element, e.g. `N7:0`, `ST9:1` or `T4:0`, as JSON.
    pub fn value(&self, address: &str) -> Result<Json, ConfigError> {
        let (number, element) = self.element(address)?;
        let file = &self.files[&number];
        let size = file.file_type.element_size();
        Ok(decode_element(
            file.file_type,
            &file.data[element * size..(element + 1) * size],
        ))
    }

    /// Sets a data file element from JSON.
    pub fn set_value(&mut self, address: &str, value: &Json) -> Result<(), ConfigError> {
        let (number, element) = self.element(address)?;
        let Some(file) = self.files.get_mut(&number) else {
            return Err(ConfigError::new(format!("no file {number}")));
        };
        let size = file.file_type.element_size();
        encode_element(
            file.file_type,
            value,
            &mut file.data[element * size..(element + 1) * size],
        )
        .map_err(|e| ConfigError::new(format!("{address}: {e}")))
    }

    /// The file number and element of an address `<type><file>:<element>`.
    fn element(&self, address: &str) -> Result<(u16, usize), ConfigError> {
        let fail = || ConfigError::new(format!("invalid address {address:?}"));
        let (file, element) = address.split_once(':').ok_or_else(fail)?;
        let digits = file.find(|c: char| c.is_ascii_digit()).ok_or_else(fail)?;
        let number: u16 = file[digits..].parse().map_err(|_| fail())?;
        let element: usize = element.parse().map_err(|_| fail())?;
        let data_file = self.files.get(&number).ok_or_else(fail)?;
        if !data_file
            .file_type
            .name()
            .eq_ignore_ascii_case(&file[..digits])
            || element >= data_file.data.len() / data_file.file_type.element_size()
        {
            return Err(fail());
        }
        Ok((number, element))
    }

    /// Answers a CIP message: Execute PCCC and the identity object.
    pub(crate) fn message(&mut self, message: &[u8], limit: usize, faults: &Faults) -> Vec<u8> {
        let service = message.first().copied().unwrap_or(0);
        let Some(request) = parse_request(message) else {
            return reply(service, 0x04, &[], &[]);
        };
        let class = class_instance(&request.path).map(|(c, _)| c);
        if let Some((general, extended)) = faults.service_status(service, class) {
            return reply(service, general, &extended, &[]);
        }
        let out = match (class_instance(&request.path), service) {
            (Some((0x67, 1)), 0x4B) => match self.pccc(request.data) {
                Some(data) => reply(service, 0, &[], &data),
                None => reply(service, 0x13, &[], &[]),
            },
            (Some((0x01, 1)), 0x01) => reply(service, 0, &[], &self.identity.attributes_all()),
            (Some((0x01, 1)), 0x0E) => {
                match attribute(&request.path).and_then(|a| self.identity.attribute(a)) {
                    Some(data) => reply(service, 0, &[], &data),
                    None => reply(service, 0x14, &[], &[]),
                }
            }
            (Some((0x01 | 0x67, _)), _) => reply(service, 0x08, &[], &[]),
            _ => reply(service, 0x05, &[], &[]),
        };
        if out.len() > limit {
            return reply(service, 0x11, &[], &[]);
        }
        out
    }

    /// An Execute PCCC request: requestor ID, command, status, transaction number, function and its data.
    fn pccc(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let id_size = usize::from(*data.first()?);
        if id_size == 0 || data.len() < id_size + 4 {
            return None;
        }
        let (requestor, command) = data.split_at(id_size);
        let (cmd, tns) = (command[0], [command[2], command[3]]);
        let result = match (cmd, command.get(4)) {
            (0x0F, Some(&function)) => self.command_0f(function, &command[5..]),
            (0x06, Some(0x03)) => Ok(self.diagnostic_status()),
            _ => Err((STS_ILLEGAL, None)),
        };
        let mut out = requestor.to_vec();
        out.push(cmd | 0x40);
        match result {
            Ok(reply_data) => {
                out.push(0);
                out.extend(tns);
                out.extend(reply_data);
            }
            Err((sts, ext)) => {
                out.push(sts);
                out.extend(tns);
                out.extend(ext);
            }
        }
        Some(out)
    }

    fn command_0f(&mut self, function: u8, params: &[u8]) -> Result<Vec<u8>, (u8, Option<u8>)> {
        let bad = (STS_EXTENDED, Some(EXT_BAD_ADDRESS));
        let mut p = Params {
            data: params,
            pos: 0,
        };
        let size = usize::from(p.byte().ok_or(bad)?);
        let file = p.address().ok_or(bad)?;
        let type_code = p.byte().ok_or(bad)?;
        let element = usize::from(p.address().ok_or(bad)?);
        match function {
            0xA1 if file == 0 => self.read_directory(size, type_code, element).ok_or(bad),
            0xA2 if type_code == 0xA5 => {
                let entry = self.datalog.pop_front().ok_or((STS_ILLEGAL, None))?;
                Ok(entry.into_bytes())
            }
            0xA1 | 0xA2 => {
                let sub = if function == 0xA2 {
                    usize::from(p.address().ok_or(bad)?)
                } else {
                    0
                };
                let (f, start) = self
                    .locate(file, type_code, element, sub, size)
                    .ok_or(bad)?;
                Ok(f.data[start..start + size].to_vec())
            }
            0xAA | 0xAB => {
                let sub = usize::from(p.address().ok_or(bad)?);
                let mask = if function == 0xAB {
                    let m = p.data.get(p.pos..p.pos + 2).ok_or(bad)?;
                    p.pos += 2;
                    u16::from_le_bytes([m[0], m[1]])
                } else {
                    0xFFFF
                };
                let value = p.data.get(p.pos..p.pos + size).ok_or(bad)?;
                let (_, start) = self
                    .locate(file, type_code, element, sub, size)
                    .ok_or(bad)?;
                let f = self.files.get_mut(&file).ok_or(bad)?;
                // the mask applies to every 16-bit word written
                for (i, chunk) in value.chunks(2).enumerate() {
                    let at = start + 2 * i;
                    if chunk.len() == 2 {
                        let old = u16::from_le_bytes([f.data[at], f.data[at + 1]]);
                        let new = (old & !mask) | (u16::from_le_bytes([chunk[0], chunk[1]]) & mask);
                        f.data[at..at + 2].copy_from_slice(&new.to_le_bytes());
                    } else {
                        f.data[at] = (f.data[at] & !(mask as u8)) | (chunk[0] & mask as u8);
                    }
                }
                Ok(Vec::new())
            }
            _ => Err((STS_ILLEGAL, None)),
        }
    }

    /// The file and byte offset of `size` bytes at element/sub-element (a word), None if not in the file.
    fn locate(
        &self,
        file: u16,
        type_code: u8,
        element: usize,
        sub: usize,
        size: usize,
    ) -> Option<(&DataFile, usize)> {
        let f = self.files.get(&file)?;
        if f.file_type.code() != type_code {
            return None;
        }
        let start = element * f.file_type.element_size() + sub * 2;
        (start + size <= f.data.len()).then_some((f, start))
    }

    fn sys0(&self) -> Sys0 {
        let prefix: String = self.processor_type.chars().take(4).collect();
        match prefix.as_str() {
            "1761" => Sys0 {
                file_position: 93,
                row_size: 8,
                file_type: 0x00,
                size_element: 0x23,
                size_const: 0,
            },
            "1762" | "1763" | "1764" => Sys0 {
                file_position: 233,
                row_size: 10,
                file_type: 0x02,
                size_element: 0x28,
                size_const: 19968,
            },
            "1766" => Sys0 {
                file_position: 233,
                row_size: 10,
                file_type: 0x03,
                size_element: 0x2B,
                size_const: 19968,
            },
            _ => Sys0 {
                file_position: 79,
                row_size: 10,
                file_type: 0x01,
                size_element: 0x23,
                size_const: 0,
            },
        }
    }

    /// The file directory: a header, then a row per file number (type code and size in bytes, 0x81 for an
    /// unused number).
    fn directory(&self) -> Vec<u8> {
        let sys0 = self.sys0();
        let last = self.files.keys().next_back().copied().unwrap_or(0) as usize;
        let mut out = vec![0u8; sys0.file_position + (last + 1) * sys0.row_size];
        for number in 0..=last {
            let row = sys0.file_position + number * sys0.row_size;
            match self.files.get(&(number as u16)) {
                Some(f) => {
                    out[row] = f.file_type.code();
                    out[row + 1..row + 3].copy_from_slice(&(f.data.len() as u16).to_le_bytes());
                }
                None => out[row] = 0x81,
            }
        }
        out
    }

    /// Reads of system file 0: its size at the processor's size element, else `size` bytes from a word offset.
    fn read_directory(&self, size: usize, type_code: u8, element: usize) -> Option<Vec<u8>> {
        let sys0 = self.sys0();
        if type_code != sys0.file_type {
            return None;
        }
        let directory = self.directory();
        if element == usize::from(sys0.size_element) && (2..=8).contains(&size) {
            let mut out = ((directory.len() + sys0.size_const) as u16)
                .to_le_bytes()
                .to_vec();
            out.resize(size, 0);
            return Some(out);
        }
        directory
            .get(element * 2..element * 2 + size)
            .map(<[u8]>::to_vec)
    }

    /// The diagnostic status reply: 5 status bytes, then the catalog number in 11 characters.
    fn diagnostic_status(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0xEE, 0x31, 0x5B, 0x30];
        out.extend(format!("{:<11}", self.processor_type).as_bytes());
        out.extend([0u8; 8]);
        out
    }
}

struct Params<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Params<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// A PCCC address field: one byte, or 0xFF and a 16-bit value.
    fn address(&mut self) -> Option<u16> {
        match self.byte()? {
            0xFF => {
                let b = self.data.get(self.pos..self.pos + 2)?;
                self.pos += 2;
                Some(u16::from_le_bytes([b[0], b[1]]))
            }
            b => Some(u16::from(b)),
        }
    }
}

/// SLC strings store each pair of characters swapped within its word.
fn swap_pairs(data: &mut [u8]) {
    for pair in data.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
}

fn json_i64(value: &Json) -> Result<i64, String> {
    match value {
        Json::Bool(b) => Ok(i64::from(*b)),
        _ => value
            .as_i64()
            .ok_or_else(|| format!("expected an integer, got {value}")),
    }
}

fn encode_element(file_type: FileType, value: &Json, out: &mut [u8]) -> Result<(), String> {
    match file_type {
        FileType::F => {
            let x = value
                .as_f64()
                .ok_or_else(|| format!("expected a number, got {value}"))?;
            out.copy_from_slice(&(x as f32).to_le_bytes());
        }
        FileType::L => {
            let n =
                i32::try_from(json_i64(value)?).map_err(|_| format!("{value} is out of range"))?;
            out.copy_from_slice(&n.to_le_bytes());
        }
        FileType::St | FileType::A => {
            let text = value
                .as_str()
                .ok_or_else(|| format!("expected a string, got {value}"))?;
            let mut bytes: Vec<u8> = text.bytes().collect();
            if file_type == FileType::A {
                bytes.resize(2, b' ');
                bytes.truncate(2);
                swap_pairs(&mut bytes);
                out.copy_from_slice(&bytes);
            } else {
                if bytes.len() > 82 {
                    return Err("string longer than 82 characters".into());
                }
                out[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
                let mut data = bytes;
                data.resize(82, 0);
                swap_pairs(&mut data);
                out[2..].copy_from_slice(&data);
            }
        }
        FileType::T | FileType::C | FileType::R => match value {
            Json::Array(words) if words.len() == 3 => {
                for (i, w) in words.iter().enumerate() {
                    let n = json_i64(w)?;
                    let word = i16::try_from(n)
                        .map(|v| v as u16)
                        .or_else(|_| u16::try_from(n))
                        .map_err(|_| format!("{n} is out of range"))?;
                    out[2 * i..2 * i + 2].copy_from_slice(&word.to_le_bytes());
                }
            }
            Json::Object(fields) => {
                let mut word0 = u16::from_le_bytes([out[0], out[1]]);
                for (key, v) in fields {
                    if let Some(i) = file_type
                        .words()
                        .iter()
                        .position(|w| w.eq_ignore_ascii_case(key))
                    {
                        let n = i16::try_from(json_i64(v)?)
                            .map_err(|_| format!("{key} is out of range"))?;
                        out[2 + 2 * i..4 + 2 * i].copy_from_slice(&n.to_le_bytes());
                    } else if let Some(i) = file_type
                        .bits()
                        .iter()
                        .position(|b| b.eq_ignore_ascii_case(key))
                    {
                        let bit = 1u16 << (15 - i);
                        if json_i64(v)? != 0 {
                            word0 |= bit
                        } else {
                            word0 &= !bit
                        }
                    } else {
                        return Err(format!("unknown field {key}"));
                    }
                }
                out[..2].copy_from_slice(&word0.to_le_bytes());
            }
            _ => return Err(format!("expected an object or 3 words, got {value}")),
        },
        _ => {
            let n = json_i64(value)?;
            let word = i16::try_from(n)
                .map(|v| v as u16)
                .or_else(|_| u16::try_from(n))
                .map_err(|_| format!("{n} is out of range"))?;
            out.copy_from_slice(&word.to_le_bytes());
        }
    }
    Ok(())
}

fn decode_element(file_type: FileType, data: &[u8]) -> Json {
    let word = |i: usize| i16::from_le_bytes([data[2 * i], data[2 * i + 1]]);
    match file_type {
        FileType::F => Json::from(f64::from(f32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))),
        FileType::L => Json::from(i32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        FileType::A | FileType::St => {
            let (length, mut text) = if file_type == FileType::A {
                (2, data.to_vec())
            } else {
                (
                    usize::from(u16::from_le_bytes([data[0], data[1]])).min(82),
                    data[2..].to_vec(),
                )
            };
            swap_pairs(&mut text);
            Json::String(text[..length].iter().map(|&b| char::from(b)).collect())
        }
        FileType::T | FileType::C | FileType::R => {
            let mut object = serde_json::Map::new();
            for (i, name) in file_type.words().iter().enumerate() {
                object.insert((*name).into(), json!(word(i + 1)));
            }
            let word0 = word(0) as u16;
            for (i, name) in file_type.bits().iter().enumerate() {
                object.insert((*name).into(), json!(word0 & (1 << (15 - i)) != 0));
            }
            Json::Object(object)
        }
        _ => Json::from(word(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_values_roundtrip() {
        let mut out = [0u8; 84];
        encode_element(FileType::St, &json!("Hello"), &mut out).expect("st");
        assert_eq!(&out[..8], &[5, 0, b'e', b'H', b'l', b'l', 0, b'o']);
        assert_eq!(decode_element(FileType::St, &out), json!("Hello"));
        let mut t = [0u8; 6];
        encode_element(
            FileType::T,
            &json!({"PRE": 100, "ACC": 5, "DN": true}),
            &mut t,
        )
        .expect("t");
        assert_eq!(t, [0x00, 0x20, 100, 0, 5, 0]);
        assert_eq!(
            decode_element(FileType::T, &t),
            json!({"PRE": 100, "ACC": 5, "EN": false, "TT": false, "DN": true})
        );
        let mut b = [0u8; 2];
        encode_element(FileType::B, &json!(0xFFFF), &mut b).expect("b");
        assert_eq!(decode_element(FileType::B, &b), json!(-1));
    }
}
