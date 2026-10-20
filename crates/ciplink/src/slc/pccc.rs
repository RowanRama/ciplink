//! PCCC (SLC 500 / MicroLogix) data file addresses, PCCC string types, request messages and reply decoding.
//!
//! Pure functions, no I/O: builders return the CIP message the driver sends in a connected SendUnitData
//! packet (from the PCCC Execute service on), decoders take the raw encapsulated reply (or the data after
//! [`SLC_REPLY_START`]). Ported from `ciplink/cip/pccc.py` and `ciplink/slc_driver.py`.

use indexmap::IndexMap;

use crate::reader::Reader;
use crate::types::Elementary;
use crate::value::py_bytes_repr;
use crate::{Error, Result, Value};

/// PCCC command code of typed data file reads and writes.
pub const SLC_CMD_CODE: u8 = 0x0F;
/// Function code: protected typed logical read with 3 address fields.
pub const SLC_FNC_READ: u8 = 0xA2;
/// Function code: protected typed logical masked write with 3 address fields.
pub const SLC_FNC_WRITE: u8 = 0xAB;
/// Offset of the PCCC reply data in a raw encapsulated SendUnitData reply.
pub const SLC_REPLY_START: usize = 61;
/// Offset of the PCCC status byte in a raw encapsulated SendUnitData reply.
pub const PCCC_STATUS_OFFSET: usize = 58;
/// Request path of the PCCC object (class 0x67, instance 1).
pub const PCCC_PATH: [u8; 3] = [0x67, 0x24, 0x01];
/// Most bytes the driver asks for in one read of the file directory (SYS0).
pub const FILE_DIRECTORY_CHUNK: u8 = 0x50;
/// `PCCC_CT["PRE"]`: the preset word of a timer or counter.
pub const CT_PRE: u16 = 1;
/// `PCCC_CT["ACC"]`: the accumulator word of a timer or counter.
pub const CT_ACC: u16 = 2;

/// A data file type (`PCCC_DATA_TYPE` / `PCCC_DATA_SIZE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    /// Output.
    O,
    /// Input.
    I,
    /// Status.
    S,
    /// Binary.
    B,
    /// Timer.
    T,
    /// Counter.
    C,
    /// Control.
    R,
    /// Integer.
    N,
    /// Float.
    F,
    /// String.
    ST,
    /// ASCII.
    A,
    /// Long integer.
    L,
    /// Message.
    MG,
    /// PID.
    PD,
    /// Programmable limit switch.
    PLS,
}

const FILE_TYPES: [FileType; 15] = [
    FileType::O,
    FileType::I,
    FileType::S,
    FileType::B,
    FileType::T,
    FileType::C,
    FileType::R,
    FileType::N,
    FileType::F,
    FileType::ST,
    FileType::A,
    FileType::L,
    FileType::MG,
    FileType::PD,
    FileType::PLS,
];

impl FileType {
    /// The file type of a name as Python spells it (`"N"`, `"ST"`, ...), upper case only.
    pub fn from_name(name: &str) -> Option<Self> {
        FILE_TYPES.into_iter().find(|t| t.name() == name)
    }

    /// The file type of a PCCC data type code.
    pub fn from_code(code: u8) -> Option<Self> {
        FILE_TYPES.into_iter().find(|t| t.code() == code)
    }

    /// The name (`"N"`, `"ST"`, ...).
    pub fn name(self) -> &'static str {
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
            FileType::ST => "ST",
            FileType::A => "A",
            FileType::L => "L",
            FileType::MG => "MG",
            FileType::PD => "PD",
            FileType::PLS => "PLS",
        }
    }

    /// The PCCC data type code sent in requests and found in the file directory.
    pub fn code(self) -> u8 {
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
            FileType::ST => 0x8D,
            FileType::A => 0x8E,
            FileType::L => 0x91,
            FileType::MG => 0x92,
            FileType::PD => 0x93,
            FileType::PLS => 0x94,
        }
    }

    /// Bytes per element.
    pub fn element_size(self) -> usize {
        match self {
            FileType::N | FileType::B | FileType::S | FileType::A | FileType::O | FileType::I => 2,
            FileType::L | FileType::F => 4,
            FileType::T | FileType::C | FileType::R => 6,
            FileType::ST => 84,
            FileType::MG => 50,
            FileType::PD => 46,
            FileType::PLS => 12,
        }
    }
}

/// The bit or word number of a timer/counter sub-element name (`PCCC_CT`), case insensitive.
pub fn ct_bit(name: &str) -> Option<u16> {
    CT_NAMES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|&(_, v)| v)
}

const CT_NAMES: [(&str, u16); 10] = [
    ("PRE", 1),
    ("ACC", 2),
    ("EN", 15),
    ("TT", 14),
    ("DN", 13),
    ("CU", 15),
    ("CD", 14),
    ("OV", 12),
    ("UN", 11),
    ("UA", 10),
];

/// A parsed data file address (Python's `parse_tag` dict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// File type.
    pub file_type: FileType,
    /// File number (`O` is always 0, `I` 1, `S` 2).
    pub file_number: u16,
    /// Element (word) number.
    pub element_number: u16,
    /// Word within an I/O slot (`I:0.1`), `Some(0)` for an I/O address without one, None for other files.
    pub pos_number: Option<u16>,
    /// Bit number of a bit address, `PCCC_CT` value of a timer/counter sub-element; `Some(0)` for an I/O
    /// word address and None for other word addresses, like Python.
    pub sub_element: Option<u16>,
    /// A bit (or timer/counter sub-element) address, Python's `address_field == 3`.
    pub bit: bool,
    /// Element count from a `{n}` suffix, 1 without one (0 for `{0}`).
    pub element_count: usize,
    /// The address as given, without the element count suffix (an `S:` bit address keeps it, like Python).
    pub tag: String,
}

/// Parses a data file address: `N7:0`, `N7:0/5`, `B3/10`, `T4:0.ACC`, `I:0.1/3`, `S:1/15`, `ST9:0`, `A10:0`,
/// `F8:0{4}` and the like. None if the address is not valid, like Python's `parse_tag`.
pub fn parse_tag(tag: &str) -> Option<Address> {
    let chars: Vec<char> = tag.chars().collect();
    let base = tag.find('{').map_or(tag, |i| &tag[..i]);
    parse_ct(&chars, tag)
        .or_else(|| parse_lfbn(&chars, base))
        .or_else(|| parse_io(&chars, base))
        .or_else(|| parse_st_a(&chars, base, FileType::ST))
        .or_else(|| parse_st_a(&chars, base, FileType::A))
        .or_else(|| parse_s(&chars, tag, base))
        .or_else(|| parse_b(&chars, base))
}

/// A cursor over the address characters, matching the way Python's regexes do (IGNORECASE, `\d` greedy).
struct Cur<'a> {
    s: &'a [char],
    i: usize,
}

impl Cur<'_> {
    fn eat(&mut self, c: char) -> bool {
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// One letter, case insensitive the way Python's `re.IGNORECASE` folds (long s is S, dotless i is I).
    fn letter(&mut self, upper: char) -> bool {
        let Some(&c) = self.s.get(self.i) else {
            return false;
        };
        let matched = c.to_ascii_uppercase() == upper
            || (upper == 'S' && c == '\u{17f}')
            || (upper == 'I' && c == '\u{131}');
        if matched {
            self.i += 1;
        }
        matched
    }

    /// One of the letters, the file type it stands for.
    fn file_letter(&mut self, options: &[(char, FileType)]) -> Option<FileType> {
        options
            .iter()
            .find(|(c, _)| self.letter(*c))
            .map(|&(_, t)| t)
    }

    fn digit_run(&self) -> usize {
        self.s[self.i..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count()
    }

    /// `\d{min,max}` followed by a non-digit (or the end); a longer run cannot match any of the patterns.
    fn digits(&mut self, max: usize) -> Option<u32> {
        let n = self.digit_run();
        if n == 0 || n > max {
            return None;
        }
        let value = number(&self.s[self.i..self.i + n]);
        self.i += n;
        u32::try_from(value).ok()
    }

    /// An optional `{n}` suffix: Some(None) when absent, None when malformed.
    fn count(&mut self, only_1_or_2: bool) -> Option<Option<usize>> {
        if !self.eat('{') {
            return Some(None);
        }
        let n = self.digit_run();
        if n == 0 || (only_1_or_2 && (n != 1 || !matches!(self.s[self.i], '1' | '2'))) {
            return None;
        }
        let value = number(&self.s[self.i..self.i + n]);
        self.i += n;
        self.eat('}').then_some(Some(value))
    }

    fn done(&self) -> bool {
        self.i == self.s.len()
    }
}

/// The value of ASCII digits, saturating (a count too big for memory fails later anyway).
fn number(digits: &[char]) -> usize {
    digits.iter().fold(0usize, |acc, c| {
        acc.saturating_mul(10)
            .saturating_add(c.to_digit(10).map_or(0, |d| d as usize))
    })
}

fn word_address(
    file_type: FileType,
    file: u32,
    element: u32,
    count: Option<usize>,
    tag: &str,
) -> Address {
    Address {
        file_type,
        file_number: file as u16,
        element_number: element as u16,
        pos_number: None,
        sub_element: None,
        bit: false,
        element_count: count.unwrap_or(1),
        tag: tag.to_owned(),
    }
}

/// `CT_RE`: `[CT]\d{1,3}:\d{1,3}.(ACC|PRE|...)`, where `.` is any character but a newline.
fn parse_ct(s: &[char], tag: &str) -> Option<Address> {
    let mut c = Cur { s, i: 0 };
    let file_type = c.file_letter(&[('C', FileType::C), ('T', FileType::T)])?;
    let file = c.digits(3)?;
    if !c.eat(':') {
        return None;
    }
    // the element regex backtracks: the separator may be a digit, so try the longest element first
    let run = c.digit_run();
    let (element, sub) = (1..=run.min(3)).rev().find_map(|k| {
        let sep = *s.get(c.i + k)?;
        if sep == '\n' {
            return None;
        }
        let rest: String = s[c.i + k + 1..].iter().collect();
        let sub = ct_bit(&rest)?;
        Some((number(&s[c.i..c.i + k]), sub))
    })?;
    if !(1..=255).contains(&file) || element > 255 {
        return None;
    }
    Some(Address {
        sub_element: Some(sub),
        bit: true,
        ..word_address(file_type, file, element as u32, None, tag)
    })
}

/// `LFBN_RE`: `[LFBN]\d{1,3}:\d{1,3}(/\d{1,2})?({n})?`.
fn parse_lfbn(s: &[char], base: &str) -> Option<Address> {
    let mut c = Cur { s, i: 0 };
    let file_type = c.file_letter(&[
        ('L', FileType::L),
        ('F', FileType::F),
        ('B', FileType::B),
        ('N', FileType::N),
    ])?;
    let file = c.digits(3)?;
    if !c.eat(':') {
        return None;
    }
    let element = c.digits(3)?;
    let sub = if c.eat('/') { Some(c.digits(2)?) } else { None };
    let count = c.count(false)?;
    if !c.done() || !(1..=255).contains(&file) || element > 255 || sub.is_some_and(|b| b > 15) {
        return None;
    }
    Some(Address {
        sub_element: sub.map(|b| b as u16),
        bit: sub.is_some(),
        ..word_address(file_type, file, element, count, base)
    })
}

/// `IO_RE`: `[IO]\d{0,3}:\d{1,3}(.\d{1,3})?(/\d{1,2})?({n})?`, the file number is implied by the type.
fn parse_io(s: &[char], base: &str) -> Option<Address> {
    let mut c = Cur { s, i: 0 };
    let file_type = c.file_letter(&[('I', FileType::I), ('O', FileType::O)])?;
    if c.digit_run() > 0 {
        c.digits(3)?;
    }
    if !c.eat(':') {
        return None;
    }
    let element = c.digits(3)?;
    let pos = if c.eat('.') { c.digits(3)? } else { 0 };
    let sub = if c.eat('/') { Some(c.digits(2)?) } else { None };
    let count = c.count(false)?;
    if !c.done() || element > 255 || sub.is_some_and(|b| b > 15) {
        return None;
    }
    let file = if file_type == FileType::O { 0 } else { 1 };
    Some(Address {
        pos_number: Some(pos as u16),
        sub_element: Some(sub.unwrap_or(0) as u16),
        bit: sub.is_some(),
        ..word_address(file_type, file, element, count, base)
    })
}

/// `ST_RE` (`ST\d{1,3}:\d{1,4}({[12]})?`) and `A_RE` (`A\d{1,3}:\d{1,4}({n})?`).
fn parse_st_a(s: &[char], base: &str, file_type: FileType) -> Option<Address> {
    let mut c = Cur { s, i: 0 };
    let letters = if file_type == FileType::ST {
        c.letter('S') && c.letter('T')
    } else {
        c.letter('A')
    };
    if !letters {
        return None;
    }
    let file = c.digits(3)?;
    if !c.eat(':') {
        return None;
    }
    let element = c.digits(4)?;
    let count = c.count(file_type == FileType::ST)?;
    if !c.done() || !(1..=255).contains(&file) || element > 255 {
        return None;
    }
    Some(word_address(file_type, file, element, count, base))
}

/// `S_RE`: `S:\d{1,3}(/\d{1,2})?({n})?`, always file 2. A bit address keeps the count in its name.
fn parse_s(s: &[char], tag: &str, base: &str) -> Option<Address> {
    let mut c = Cur { s, i: 0 };
    if !(c.letter('S') && c.eat(':')) {
        return None;
    }
    let element = c.digits(3)?;
    let sub = if c.eat('/') { Some(c.digits(2)?) } else { None };
    let count = c.count(false)?;
    if !c.done() || element > 255 || sub.is_some_and(|b| b > 15) {
        return None;
    }
    let name = if sub.is_some() { tag } else { base };
    Some(Address {
        sub_element: sub.map(|b| b as u16),
        bit: sub.is_some(),
        ..word_address(FileType::S, 2, element, count, name)
    })
}

/// `B_RE`: `B\d{1,3}/\d{1,4}({n})?`, a bit number counted across the whole file.
fn parse_b(s: &[char], base: &str) -> Option<Address> {
    let mut c = Cur { s, i: 0 };
    if !c.letter('B') {
        return None;
    }
    let file = c.digits(3)?;
    if !c.eat('/') {
        return None;
    }
    let bit = c.digits(4)?;
    let count = c.count(false)?;
    if !c.done() || !(1..=255).contains(&file) || bit > 4095 {
        return None;
    }
    Some(Address {
        sub_element: Some((bit % 16) as u16),
        bit: true,
        ..word_address(FileType::B, file, bit / 16, count, base)
    })
}

/// Python's `get_bit`: the bit at `idx` of `value` (two's complement for negative values).
pub fn get_bit(value: i64, idx: u32) -> bool {
    (value >> idx.min(63)) & 1 != 0
}

// --- PCCC strings ---

/// Swaps the bytes of each 16-bit word (padding an odd length with a null): SLC processors store strings
/// as words, `"AB"` is stored as `0x4241`.
pub fn slc_string_swap(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.len() % 2 == 1 {
        out.push(0);
    }
    for pair in out.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    out
}

/// Python's truthiness of a value (the PCCC string encoders treat a falsy value as an empty string).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Real(x) => *x != 0.0,
        Value::LReal(x) => *x != 0.0,
        Value::String(s) => !s.is_empty(),
        Value::Bytes(b) => !b.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Struct(m) => !m.is_empty(),
        other => other.as_i128() != Some(0),
    }
}

/// `(value or "").encode("iso-8859-1")`, None if that fails in Python.
fn latin1_or_empty(value: &Value) -> Option<Vec<u8>> {
    if !truthy(value) {
        return Some(Vec::new());
    }
    let Value::String(text) = value else {
        return None;
    };
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect()
}

fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Encodes an ASCII (`A`) file element: 2 characters, truncated or padded with spaces, byte swapped.
pub fn encode_pccc_ascii(value: &Value) -> Result<Vec<u8>> {
    let mut data = latin1_or_empty(value).ok_or_else(|| packing_error(value, "PCCC_ASCII"))?;
    data.truncate(2);
    data.resize(2, b' ');
    Ok(slc_string_swap(&data))
}

/// Decodes an ASCII (`A`) file element: up to 2 bytes, byte swapped (a lone byte is padded with a null).
pub fn decode_pccc_ascii(reader: &mut Reader<'_>) -> String {
    let n = reader.remaining().min(2);
    let bytes = reader.take(n).unwrap_or_default();
    latin1_decode(&slc_string_swap(bytes))
}

/// Encodes a string (`ST`) file element: UINT length (at most 82) and 82 byte-swapped data bytes.
pub fn encode_pccc_string(value: &Value) -> Result<Vec<u8>> {
    let mut data = latin1_or_empty(value).ok_or_else(|| packing_error(value, "PCCC_STRING"))?;
    data.truncate(82);
    let len = data.len() as u16; // at most 82
    data.resize(82, 0);
    let mut out = Vec::with_capacity(84);
    out.extend(len.to_le_bytes());
    out.extend(slc_string_swap(&data));
    Ok(out)
}

/// Decodes a string (`ST`) file element: the UINT length, then up to 82 data bytes; the text is cut to the
/// length. `BufferEmpty` when nothing is left, `Data` for a 1-byte buffer.
pub fn decode_pccc_string(reader: &mut Reader<'_>) -> Result<String> {
    let start = reader.position();
    let len = match reader.u16() {
        Ok(len) => usize::from(len),
        Err(Error::BufferEmpty) => return Err(Error::BufferEmpty),
        Err(_) => {
            return Err(Error::Data(format!(
                "Error unpacking {} as PCCC_STRING",
                py_bytes_repr(&reader.buffer()[start..])
            )));
        }
    };
    let n = reader.remaining().min(82);
    let raw = reader.take(n).unwrap_or_default();
    let swapped = slc_string_swap(raw);
    Ok(latin1_decode(&swapped[..len.min(swapped.len())]))
}

fn packing_error(value: &Value, type_name: &str) -> Error {
    Error::Data(format!("Error packing {} as {type_name}", value.py_repr()))
}

/// Encodes one element of a file type (`PCCCDataTypes[file_type].encode`).
fn encode_element(file_type: FileType, value: &Value) -> Result<Vec<u8>> {
    match file_type {
        FileType::N
        | FileType::B
        | FileType::T
        | FileType::C
        | FileType::S
        | FileType::O
        | FileType::I => Elementary::Int.encode(value),
        FileType::F => Elementary::Real.encode(value),
        FileType::R | FileType::L => Elementary::DInt.encode(value),
        FileType::A => encode_pccc_ascii(value),
        FileType::ST => encode_pccc_string(value),
        FileType::MG | FileType::PD | FileType::PLS => Err(Error::data(format!(
            "no data type for file type {}",
            file_type.name()
        ))),
    }
}

/// Decodes one element of a file type (`PCCCDataTypes[file_type].decode`).
fn decode_element(file_type: FileType, data: &[u8]) -> Result<Value> {
    let mut reader = Reader::new(data);
    match file_type {
        FileType::N
        | FileType::B
        | FileType::T
        | FileType::C
        | FileType::S
        | FileType::O
        | FileType::I => Elementary::Int.decode(&mut reader),
        FileType::F => Elementary::Real.decode(&mut reader),
        FileType::R | FileType::L => Elementary::DInt.decode(&mut reader),
        FileType::A => Ok(Value::String(decode_pccc_ascii(&mut reader))),
        FileType::ST => decode_pccc_string(&mut reader).map(Value::String),
        FileType::MG | FileType::PD | FileType::PLS => Err(Error::data(format!(
            "no data type for file type {}",
            file_type.name()
        ))),
    }
}

/// Python's `str(value)`: a string as is, anything else as its repr.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.py_repr(),
    }
}

// --- read / write ---

/// The requestor ID sent in every PCCC Execute request: the driver's vendor ID and serial number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requestor {
    /// Vendor ID, as sent.
    pub vid: [u8; 2],
    /// Vendor serial number, as sent.
    pub vsn: [u8; 4],
}

impl Default for Requestor {
    /// The Python driver's defaults (`vid` `09 10`, `vsn` `09 10 19 71`).
    fn default() -> Self {
        Requestor {
            vid: [0x09, 0x10],
            vsn: [0x09, 0x10, 0x19, 0x71],
        }
    }
}

/// The start of every PCCC message: the PCCC Execute service (0x4B) to the PCCC object, then the requestor
/// ID (`SLCDriver._msg_start`).
pub fn msg_start(requestor: &Requestor) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend([0x4B, 0x02, 0x20]);
    out.extend(PCCC_PATH);
    out.push(0x07);
    out.extend(requestor.vid);
    out.extend(requestor.vsn);
    out
}

/// A PCCC address field: one byte, or 0xFF and a UINT for 255 and up.
fn push_addr(out: &mut Vec<u8>, value: u16) {
    if value >= 255 {
        out.push(0xFF);
        out.extend(value.to_le_bytes());
    } else {
        out.push(value as u8); // below 255
    }
}

fn usint(value: i128) -> Result<u8> {
    u8::try_from(value).map_err(|_| Error::Data(format!("Error packing {value} as USINT")))
}

/// Parses an address for `read()` / `write()`: `RequestError` for an invalid address or a bit address with
/// an element count.
fn request_address(tag: &str, method: &str) -> Result<Address> {
    match parse_tag(tag) {
        Some(addr) if !(addr.bit && addr.element_count > 1) => Ok(addr),
        _ => Err(Error::request(format!(
            "Error parsing the tag passed to {method}() - {tag}"
        ))),
    }
}

/// Builds the read message of a data file address (`SLCDriver._read_tag`): returns the parsed address
/// (for [`parse_read_reply`]) and the message. `RequestError` for a bad address, `DataError` when the
/// byte count exceeds 255.
pub fn read_request(tag: &str, requestor: &Requestor, sequence: u16) -> Result<(Address, Vec<u8>)> {
    let addr = request_address(tag, "read")?;
    let size = (addr.file_type.element_size() as i128).saturating_mul(addr.element_count as i128);
    let size = usint(size)?;
    let mut msg = msg_start(requestor);
    msg.extend([SLC_CMD_CODE, 0x00]);
    msg.extend(sequence.to_le_bytes());
    msg.extend([SLC_FNC_READ, size]);
    push_addr(&mut msg, addr.file_number);
    msg.push(addr.file_type.code());
    push_addr(&mut msg, addr.element_number);
    push_addr(&mut msg, addr.pos_number.unwrap_or(0));
    Ok((addr, msg))
}

/// Builds the masked write message of a data file address and value (`SLCDriver._write_tag`).
/// `RequestError` for a bad address or value, `DataError` when the data exceeds 255 bytes.
pub fn write_request(
    tag: &str,
    value: &Value,
    requestor: &Requestor,
    sequence: u16,
) -> Result<(Address, Vec<u8>)> {
    let addr = request_address(tag, "write")?;
    let data = writeable_value(&addr, value)?;
    let mut sub_element = addr.pos_number.unwrap_or(0);
    if matches!(addr.file_type, FileType::T | FileType::C)
        && matches!(addr.sub_element, Some(CT_PRE | CT_ACC))
    {
        sub_element = addr.sub_element.unwrap_or(0); // PRE/ACC are words 1/2 of the element
    }
    let size = usint(data.len() as i128 - 2)?; // data bytes after the 2-byte mask
    let mut msg = msg_start(requestor);
    msg.extend([SLC_CMD_CODE, 0x00]);
    msg.extend(sequence.to_le_bytes());
    msg.extend([SLC_FNC_WRITE, size]);
    push_addr(&mut msg, addr.file_number);
    msg.push(addr.file_type.code());
    push_addr(&mut msg, addr.element_number);
    push_addr(&mut msg, sub_element);
    msg.extend(data);
    Ok((addr, msg))
}

/// The items of a multi-element write value, Python's `len()` / iteration (a string is its characters).
fn items(value: &Value) -> Result<Vec<Value>> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.into())).collect()),
        other => Err(Error::request(format!(
            "object {} has no len()",
            other.py_repr()
        ))),
    }
}

/// The 2-byte mask and data of a masked write (`writeable_value`). Bytes are sent as given. A bit address
/// writes its mask (set) or zero (clear), by the value's truthiness; a timer/counter `.PRE` / `.ACC` writes
/// the word. `RequestError` if the value does not fit the file type or has too few elements.
pub fn writeable_value(addr: &Address, value: &Value) -> Result<Vec<u8>> {
    if let Value::Bytes(bytes) = value {
        return Ok(bytes.clone());
    }
    let bit_position = if addr.bit {
        addr.sub_element.unwrap_or(0)
    } else {
        0
    };
    let mut mask = if addr.bit {
        1u16.checked_shl(u32::from(bit_position)).unwrap_or(0)
    } else {
        0xFFFF
    };
    let count = addr.element_count.max(1);
    let mut value = value.clone();
    if count > 1 {
        let mut list = items(&value)?;
        if list.len() < count {
            return Err(Error::request(format!(
                "Insufficient data for requested elements, expected {count} and got {}",
                list.len()
            )));
        }
        list.truncate(count);
        value = match value {
            Value::String(_) => Value::String(
                list.iter()
                    .filter_map(|v| match v {
                        Value::String(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => Value::Array(list),
        };
    }
    let encoded = (|| -> Result<Vec<u8>> {
        if count > 1 {
            let mut out = Vec::new();
            for item in items(&value)? {
                out.extend(encode_element(addr.file_type, &item)?);
            }
            Ok(out)
        } else if addr.bit {
            if matches!(addr.file_type, FileType::T | FileType::C)
                && matches!(bit_position, CT_PRE | CT_ACC)
            {
                mask = 0xFFFF;
                encode_element(addr.file_type, &value)
            } else if truthy(&value) {
                Ok(mask.to_le_bytes().to_vec())
            } else {
                Ok(vec![0, 0])
            }
        } else {
            encode_element(addr.file_type, &value)
        }
    })();
    let data = encoded.map_err(|err| {
        Error::request(format!(
            "Failed to create a writeable value for {} from {} - {err}",
            addr.tag,
            py_str(&value)
        ))
    })?;
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend(mask.to_le_bytes());
    out.extend(data);
    Ok(out)
}

/// Decodes the data of a read reply (the bytes after [`SLC_REPLY_START`]) for an address
/// (`_parse_read_reply`): a single value, a list for several elements, a bool for a bit address and the word
/// for a timer/counter `.PRE` / `.ACC`. `ResponseError` if the data does not decode.
pub fn parse_read_reply(addr: &Address, data: &[u8]) -> Result<Value> {
    parse_read_data(addr, data).map_err(|_| Error::response("Failed parsing tag read reply"))
}

fn parse_read_data(addr: &Address, data: &[u8]) -> Result<Value> {
    let size = addr.file_type.element_size();
    let slice = |from: usize| &data[from.min(data.len())..(from + size).min(data.len())];
    if addr.bit {
        let bit_position = addr.sub_element.unwrap_or(0);
        if matches!(addr.file_type, FileType::T | FileType::C) {
            match bit_position {
                CT_PRE => return decode_element(addr.file_type, slice(2)),
                CT_ACC => return decode_element(addr.file_type, slice(4)),
                _ => {}
            }
        }
        let word = decode_element(addr.file_type, slice(0))?;
        let word = word
            .as_i128()
            .ok_or_else(|| Error::data("bit of a non-integer value"))?;
        return Ok(Value::Bool(get_bit(word as i64, u32::from(bit_position))));
    }
    let mut values = data
        .chunks(size)
        .map(|chunk| decode_element(addr.file_type, chunk))
        .collect::<Result<Vec<_>>>()?;
    match values.len() {
        0 => Err(Error::data("no data")),
        1 => Ok(values.remove(0)),
        _ => Ok(Value::Array(values)),
    }
}

/// The PCCC status of a raw reply whose CIP status is success (`request_status` after the packet check):
/// None for success, else the status text (with the EXT STS byte for 0xF0).
pub fn request_status(raw: &[u8]) -> Option<String> {
    let Some(&status) = raw.get(PCCC_STATUS_OFFSET) else {
        return Some("Unknown Status".into());
    };
    if status == 0 {
        return None;
    }
    let mut msg = match pccc_error_text(status) {
        Some(text) => text.to_owned(),
        None => format!("Unknown Status (0x{status:02x})"),
    };
    if status == 0xF0
        && let Some(ext) = raw.get(SLC_REPLY_START)
    {
        msg.push_str(&format!(" (EXT STS 0x{ext:02x})"));
    }
    Some(msg)
}

/// `PCCC_ERROR_CODE` text of a PCCC status byte.
pub fn pccc_error_text(status: u8) -> Option<&'static str> {
    Some(match status {
        0x10 => {
            "Illegal Command or Format, Address may not exist or not enough elements in data file"
        }
        0x20 => "PLC Has a Problem and Will Not Communicate",
        0x30 => "Remote Node Host is Missing, Disconnected, or Shut Down",
        0x40 => "Host Could Not Complete Function Due To Hardware Fault",
        0x50 => "Addressing problem or Memory Protect Rungs",
        0x60 => "Function not allows due to command protection selection",
        0x70 => "Processor is in Program mode",
        0x80 => "Compatibility mode file missing or communication zone problem",
        0x90 => "Remote node cannot buffer command",
        0xF0 => "Error code in EXT STS Byte",
        _ => return None,
    })
}

// --- diagnostics, data log, file directory ---

/// The diagnostic status request (CMD 0x06, FNC 0x03) that reports the processor type.
pub fn processor_type_request(requestor: &Requestor, sequence: u16) -> Vec<u8> {
    let mut msg = msg_start(requestor);
    msg.extend([0x06, 0x00]);
    msg.extend(sequence.to_le_bytes());
    msg.push(0x03);
    msg
}

/// The processor type (catalog number, e.g. `1766-LEC`) in a raw diagnostic status reply: UTF-8 with bad
/// bytes dropped, whitespace stripped, None when empty.
pub fn parse_processor_type(raw: &[u8]) -> Option<String> {
    let from = (SLC_REPLY_START + 5).min(raw.len());
    let to = (SLC_REPLY_START + 16).min(raw.len());
    let text: String = raw[from..to].utf8_chunks().map(|c| c.valid()).collect();
    // Python's str.strip(): Unicode whitespace plus the separators 0x1c-0x1f
    let text = text.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c));
    (!text.is_empty()).then(|| text.to_owned())
}

/// The request that reads one entry of a data log queue (`_get_datalog`); its requestor ID and transaction
/// code are fixed, from a capture.
pub fn datalog_request(queue: u8) -> Vec<u8> {
    vec![
        0x4B, 0x02, 0x20, 0x67, 0x24, 0x01, 0x07, 0x4D, 0x00, 0xA1, 0x4E, 0xC3, 0x30, 0x0F, 0x00,
        0x30, 0x00, 0xA2, 0x6D, 0x00, 0xA5, queue, 0x00,
    ]
}

/// The data log entry of a raw reply: text if it is UTF-8, else the bytes.
pub fn parse_datalog(raw: &[u8]) -> Value {
    let entry = &raw[SLC_REPLY_START.min(raw.len())..];
    match std::str::from_utf8(entry) {
        Ok(text) => Value::String(text.to_owned()),
        Err(_) => Value::Bytes(entry.to_vec()),
    }
}

/// Where the file directory (SYS0) of a processor family lives (`_get_sys0_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sys0Info {
    /// Offset of the first file row in the directory.
    pub file_position: usize,
    /// Bytes per file row.
    pub row_size: usize,
    /// File type code used to read the directory.
    pub file_type: u8,
    /// Element holding the directory size.
    pub size_element: u8,
    /// Byte count of the size read.
    pub size_len: u8,
    /// Constant the processor adds to the reported size (0 if none).
    pub size_const: u16,
}

/// The file directory layout for a processor type (by its first 4 characters: 1761, 1762/1763/1764, 1766,
/// else SLC 5/05).
pub fn sys0_info(plc_type: &str) -> Sys0Info {
    let prefix: String = plc_type.chars().take(4).collect();
    let info = |file_position, row_size, file_type, size_element, size_len, size_const| Sys0Info {
        file_position,
        row_size,
        file_type,
        size_element,
        size_len,
        size_const,
    };
    match prefix.as_str() {
        "1761" => info(93, 8, 0x00, 0x23, 0x04, 0),
        "1763" | "1762" | "1764" => info(233, 10, 0x02, 0x28, 0x08, 19968),
        "1766" => info(233, 10, 0x03, 0x2B, 0x08, 19968),
        _ => info(79, 10, 0x01, 0x23, 0x04, 0),
    }
}

/// The request for the size of the file directory (`_get_file_directory_size`).
pub fn file_directory_size_request(
    info: &Sys0Info,
    requestor: &Requestor,
    sequence: u16,
) -> Vec<u8> {
    let mut msg = msg_start(requestor);
    msg.extend([SLC_CMD_CODE, 0x00]);
    msg.extend(sequence.to_le_bytes());
    msg.extend([0xA1, info.size_len, 0x00, info.file_type, info.size_element]);
    msg
}

/// The file directory size in a raw reply, less the family's constant (may be negative, like Python); None
/// if the reply has no UINT.
pub fn parse_file_directory_size(raw: &[u8], info: &Sys0Info) -> Option<i32> {
    let data = raw.get(SLC_REPLY_START..)?;
    let size = Reader::new(data).u16().ok()?;
    Some(i32::from(size) - i32::from(info.size_const))
}

/// The request for `size` bytes of the file directory at word `offset` (`_read_whole_file_directory`; the
/// driver asks for at most [`FILE_DIRECTORY_CHUNK`] bytes and advances `offset` by half the bytes returned).
/// `DataError` for an offset beyond 65535.
pub fn file_directory_read_request(
    file_type: u8,
    offset: usize,
    size: u8,
    requestor: &Requestor,
    sequence: u16,
) -> Result<Vec<u8>> {
    let offset = u16::try_from(offset)
        .map_err(|_| Error::Data(format!("Error packing {offset} as UINT")))?;
    let mut msg = msg_start(requestor);
    msg.extend([SLC_CMD_CODE, 0x00]);
    msg.extend(sequence.to_le_bytes());
    msg.extend([0xA1, size, 0x00, file_type]);
    push_addr(&mut msg, offset);
    Ok(msg)
}

/// A data file in the file directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataFile {
    /// Number of elements.
    pub elements: usize,
    /// Size in bytes.
    pub length: u16,
}

/// The data files in a file directory (`_parse_file0`), named like `N7`, in directory order. Numbering
/// counts reserved (0x81) rows and starts the input file at 1 when the output row is missing. `DataError`
/// (or `BufferEmpty`) for a row cut short; `DataError` for a zero row size.
pub fn parse_file_directory(
    file_position: usize,
    row_size: usize,
    data: &[u8],
) -> Result<IndexMap<String, DataFile>> {
    if row_size == 0 {
        return Err(Error::data("file directory row size must not be zero"));
    }
    let mut files = IndexMap::new();
    let mut file_num = 0usize;
    let mut pos = file_position;
    while pos < data.len() {
        let code = data[pos];
        let file_type = FileType::from_code(code);
        if file_type == Some(FileType::I) && file_num == 0 {
            file_num = 1; // O0 row missed (#281): I is always data file 1
        }
        if let Some(file_type) = file_type {
            let length = match Elementary::UInt.decode(&mut Reader::new(&data[pos + 1..]))? {
                Value::UInt(n) => n,
                _ => 0,
            };
            files.insert(
                format!("{}{file_num}", file_type.name()),
                DataFile {
                    elements: usize::from(length) / file_type.element_size(),
                    length,
                },
            );
        }
        if file_type.is_some() || code == 0x81 {
            file_num += 1;
        }
        pos = pos.saturating_add(row_size);
    }
    Ok(files)
}
