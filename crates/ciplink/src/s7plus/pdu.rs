//! S7comm-plus frames and PDUs (spec 5, 6, 9 to 13, 17): `72`-frames, request and response headers, one
//! builder and one parser per function, the object tree. Pure apart from [`read_pdu`], which reads frames from
//! any `Read`.
//!
//! A "PDU" here is what the spec's hex examples show: the protocol version byte followed by the concatenated
//! data parts, without the `72 vv LL LL` headers and the trailer.

use std::io::Read;

use super::codec::{
    Cursor, FLAG_ADDRESS_ARRAY, MAX_DEPTH, Payload, Scalar, WireValue, dt, put_vlq32, put_vlq64,
};
use crate::{Error, Result};

/// Function codes (spec 6.3).
pub mod function {
    #![allow(missing_docs)]
    pub const ERROR: u16 = 0x04B1;
    pub const EXPLORE: u16 = 0x04BB;
    pub const CREATE_OBJECT: u16 = 0x04CA;
    pub const DELETE_OBJECT: u16 = 0x04D4;
    pub const SET_MULTI_VARIABLES: u16 = 0x0542;
    pub const GET_MULTI_VARIABLES: u16 = 0x054C;
    pub const GET_VAR_SUB_STREAMED: u16 = 0x0586;
    pub const ERROR2: u16 = 0x05A9;
    pub const INIT_SSL: u16 = 0x05B3;
}

/// Opcode of a request.
pub const OPCODE_REQUEST: u8 = 0x31;
/// Opcode of a response.
pub const OPCODE_RESPONSE: u8 = 0x32;
/// Protocol version of InitSsl and CreateObject.
pub const VERSION_1: u8 = 0x01;
/// Protocol version after the session is created.
pub const VERSION_2: u8 = 0x02;
/// Version byte of a system-event frame (no trailer).
pub const VERSION_EVENT: u8 = 0xFE;
/// Session ID of InitSsl and CreateObject ("null server session").
pub const NULL_SESSION: u32 = 0x120;
/// Largest data part one frame carries (16-bit length).
pub const MAX_FRAME_DATA: usize = 0xFFFF;
/// Largest PDU accepted from the PLC (the largest seen is 466 KB).
pub const MAX_PDU: usize = 16 << 20;
/// Data bytes per frame the PLC sends (spec 5); the simulator splits its responses the same way.
pub const PLC_FRAME_DATA: usize = 979;

/// The object qualifier (spec 9.1) including its end-of-list byte.
pub const QUALIFIER: [u8; 23] = [
    0x00, 0x00, 0x04, 0xE8, 0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x89, 0x6A, 0x00, 0x13,
    0x00, 0x89, 0x6B, 0x00, 0x04, 0x00, 0x00,
];

/// Object IDs and attributes the client uses.
pub mod ids {
    #![allow(missing_docs)]
    pub const OBJECT_ROOT: u32 = 201;
    pub const SYSTEM_LIMITS: u32 = 1037;
    pub const DB_VALUE_ACTUAL: u32 = 2550;
    pub const CONTROLLER_AREA_VALUE_ACTUAL: u32 = 3736;
    pub const DB_AREA_BASE: u32 = 0x8A0E_0000;
    pub const AREA_I: u32 = 80;
    pub const AREA_Q: u32 = 81;
    pub const AREA_M: u32 = 82;
    pub const PLC_PROGRAM: u32 = 3;
    pub const TYPE_INFO_CONTAINER: u32 = 537;
    pub const CLASS_DB: u32 = 2574;
    pub const CLASS_TYPE_INFO: u32 = 511;
    pub const ATTR_NAME: u32 = 233;
    pub const ATTR_SESSION_VERSION: u32 = 306;
    pub const ATTR_PROTECTION_LEVEL: u32 = 1842;
    pub const AS_ROOT: u32 = 1;
    pub const CPU_PROXY: u32 = 49;
    pub const CPU_COMMON: u32 = 50;
    pub const RELEASE_MANAGEMENT_ROOT: u32 = 0x894A_0000;
    pub const ATTR_IDENTIFICATION: u32 = 3753;
    pub const ATTR_ENGINEERING_VERSION: u32 = 2459;
    pub const ATTR_PROJECT: u32 = 8342;
}

fn malformed(what: &str) -> Error {
    Error::comm(format!("S7comm-plus PDU malformed: {what}"))
}

/// The low 16 bits of a return value or item error as the signed error code (spec 12).
pub fn error_code(value: u64) -> i16 {
    value as u16 as i16
}

// ------------------------------------------------------------------------------------------------ frames

/// One PDU as sent: `72 vv LL LL <data> 72 vv 00 00` in one frame (the client never splits, spec 5).
pub fn frame(pdu: &[u8]) -> Result<Vec<u8>> {
    let (&version, data) = pdu.split_first().ok_or_else(|| malformed("empty PDU"))?;
    let len = u16::try_from(data.len())
        .map_err(|_| Error::request("S7comm-plus request larger than one frame"))?;
    let mut out = Vec::with_capacity(data.len() + 8);
    out.extend_from_slice(&[0x72, version]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&[0x72, version, 0, 0]);
    Ok(out)
}

/// A PDU split the way the PLC sends it: frames of at most `chunk` data bytes, the trailer after the last.
pub fn frame_split(pdu: &[u8], chunk: usize) -> Vec<u8> {
    let (version, data) = pdu.split_first().map_or((0, &[][..]), |(v, d)| (*v, d));
    let chunk = chunk.clamp(1, MAX_FRAME_DATA);
    let mut out = Vec::with_capacity(data.len() + 4 * (data.len() / chunk + 2));
    for part in data.chunks(chunk) {
        out.extend_from_slice(&[0x72, version]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&[0x72, version, 0, 0]);
    out
}

fn read_exact(r: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| {
        Error::comm(format!(
            "S7comm-plus connection broken while receiving: {e}"
        ))
    })
}

/// Reads frames up to the trailer that ends a PDU and returns the PDU (version byte + data parts). System-event
/// frames (`fe`) are skipped; one with a negative return value is an error. More than `max` bytes is an error.
pub fn read_pdu(r: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut pdu: Vec<u8> = Vec::new();
    loop {
        let mut header = [0u8; 4];
        read_exact(r, &mut header)?;
        if header[0] != 0x72 {
            return Err(malformed("frame marker not 72"));
        }
        let version = header[1];
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if version == VERSION_EVENT {
            let mut data = vec![0u8; len];
            read_exact(r, &mut data)?;
            if let Some(rv) = parse_system_event(&data)
                && rv < 0
            {
                return Err(Error::comm(format!(
                    "S7comm-plus system event with return value {rv}"
                )));
            }
            log::debug!("S7comm-plus system event ignored ({len} bytes)");
            continue;
        }
        match pdu.first() {
            None => pdu.push(version),
            Some(&v) if v != version => {
                return Err(malformed("protocol version changed within a PDU"));
            }
            Some(_) => {}
        }
        if len == 0 {
            if pdu.len() == 1 {
                return Err(malformed("empty PDU"));
            }
            return Ok(pdu);
        }
        if pdu.len() + len > max {
            return Err(Error::comm(format!(
                "S7comm-plus PDU larger than {max} bytes"
            )));
        }
        let start = pdu.len();
        pdu.resize(start + len, 0);
        read_exact(r, &mut pdu[start..])?;
    }
}

/// Element of the system-event struct that holds the return value (unverified).
const EVENT_RETURN_ELEMENT: u32 = 40305;

/// A system-event frame (spec 5, open questions): four reserved u32, then a fixed-width struct holding the
/// return value, or a short text when `return_value` is None.
pub fn system_event_frame(return_value: Option<i64>) -> Vec<u8> {
    let mut data = vec![0u8; 16];
    match return_value {
        Some(rv) => {
            data.extend_from_slice(&[0x00, dt::STRUCT, 0, 0, 0, 0]);
            data.extend_from_slice(&EVENT_RETURN_ELEMENT.to_be_bytes());
            data.extend_from_slice(&[0x00, dt::LINT]);
            data.extend_from_slice(&rv.to_be_bytes());
            data.extend_from_slice(&[0, 0, 0, 0]);
        }
        None => data.extend_from_slice(b"event"),
    }
    let mut out = vec![0x72, VERSION_EVENT];
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&data);
    out
}

/// The return value of a system-event data part, None if it carries text or nothing recognisable.
pub fn parse_system_event(data: &[u8]) -> Option<i64> {
    let mut c = Cursor::new(data.get(16..)?);
    if c.u8().ok()? != 0 || c.u8().ok()? != dt::STRUCT {
        return None;
    }
    c.u32().ok()?;
    loop {
        let element = c.u32().ok()?;
        if element == 0 {
            return None;
        }
        let _flags = c.u8().ok()?;
        let datatype = c.u8().ok()?;
        let value = match datatype {
            dt::LINT => c.u64().ok()? as i64,
            dt::DINT | dt::UDINT | dt::DWORD => i64::from(c.u32().ok()? as i32),
            _ => return None,
        };
        if element == EVENT_RETURN_ELEMENT {
            return Some(value);
        }
    }
}

// ------------------------------------------------------------------------------------------------ headers

/// The request header (spec 6.1) of a PDU being built.
pub fn request_header(
    version: u8,
    function: u16,
    sequence: u16,
    session: u32,
    flags: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(version);
    out.push(OPCODE_REQUEST);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&function.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&session.to_be_bytes());
    out.push(flags);
    out
}

/// A parsed request header and its body.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestHeader<'a> {
    /// Protocol version.
    pub version: u8,
    /// Function code.
    pub function: u16,
    /// Sequence number.
    pub sequence: u16,
    /// Session ID.
    pub session: u32,
    /// Transport flags.
    pub flags: u8,
    /// The function-specific body.
    pub body: &'a [u8],
}

/// Splits a request PDU into its header fields and body.
pub fn parse_request_header(pdu: &[u8]) -> Result<RequestHeader<'_>> {
    let mut c = Cursor::new(pdu);
    let version = c.u8()?;
    if c.u8()? != OPCODE_REQUEST {
        return Err(malformed("not a request"));
    }
    c.take(2)?;
    let function = c.u16()?;
    c.take(2)?;
    let sequence = c.u16()?;
    let session = c.u32()?;
    let flags = c.u8()?;
    Ok(RequestHeader {
        version,
        function,
        sequence,
        session,
        flags,
        body: c.rest(),
    })
}

/// A parsed response header (spec 6.2) and its body after the return value.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<'a> {
    /// Protocol version.
    pub version: u8,
    /// Function code.
    pub function: u16,
    /// Sequence number.
    pub sequence: u16,
    /// Transport flags.
    pub flags: u8,
    /// Return value (spec 12).
    pub return_value: u64,
    /// The function-specific body.
    pub body: &'a [u8],
}

/// Parses a response header. An Error PDU (functions 04B1 / 05A9) or another opcode is an error.
pub fn parse_response(pdu: &[u8]) -> Result<Response<'_>> {
    let mut c = Cursor::new(pdu);
    let version = c.u8()?;
    let opcode = c.u8()?;
    c.take(2)?;
    let function = c.u16()?;
    if function == function::ERROR || function == function::ERROR2 {
        return Err(Error::comm(format!(
            "S7comm-plus Error PDU (function 0x{function:04X})"
        )));
    }
    if opcode != OPCODE_RESPONSE {
        return Err(malformed(&format!(
            "opcode 0x{opcode:02X} is not a response"
        )));
    }
    c.take(2)?;
    let sequence = c.u16()?;
    let flags = c.u8()?;
    let return_value = c.vlq64()?;
    Ok(Response {
        version,
        function,
        sequence,
        flags,
        return_value,
        body: c.rest(),
    })
}

/// A response PDU: header, return value and `body`.
pub fn response(
    version: u8,
    function: u16,
    sequence: u16,
    flags: u8,
    return_value: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 20);
    out.push(version);
    out.push(OPCODE_RESPONSE);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&function.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.push(flags);
    put_vlq64(&mut out, return_value);
    out.extend_from_slice(body);
    out
}

fn end(c: &mut Cursor<'_>, n: usize) -> Result<()> {
    c.zeros(n, "end of PDU")?;
    if c.remaining() != 0 {
        return Err(malformed("bytes after the end of the PDU"));
    }
    Ok(())
}

fn qualifier(c: &mut Cursor<'_>) -> Result<()> {
    if c.take(QUALIFIER.len())? != QUALIFIER {
        return Err(malformed("object qualifier"));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ items

/// An item address (spec 11.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItemAddress {
    /// Symbol CRC; 0 does not check.
    pub crc: u32,
    /// Access area.
    pub area: u32,
    /// Access sub-area.
    pub sub_area: u32,
    /// LIDs (the access sequence after the area).
    pub lids: Vec<u32>,
}

impl ItemAddress {
    /// The fields this address adds to a request's field count.
    pub fn field_count(&self) -> usize {
        4 + self.lids.len()
    }

    /// Appends the address.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_vlq32(out, self.crc);
        put_vlq32(out, self.area);
        put_vlq32(out, self.lids.len() as u32 + 1);
        put_vlq32(out, self.sub_area);
        for lid in &self.lids {
            put_vlq32(out, *lid);
        }
    }

    /// Decodes one address.
    pub fn decode(c: &mut Cursor<'_>) -> Result<Self> {
        let crc = c.vlq32()?;
        let area = c.vlq32()?;
        let ids = c.vlq32()?;
        let sub_area = c.vlq32()?;
        let n = ids
            .checked_sub(1)
            .ok_or_else(|| malformed("item address without IDs"))? as usize;
        let mut lids = Vec::with_capacity(n.min(c.remaining()));
        for _ in 0..n {
            lids.push(c.vlq32()?);
        }
        Ok(ItemAddress {
            crc,
            area,
            sub_area,
            lids,
        })
    }

    /// The access sequence as the spec writes it: `8A0E0005.A.B`.
    pub fn access(&self) -> String {
        let mut out = format!("{:X}", self.area);
        for lid in &self.lids {
            out.push_str(&format!(".{lid:X}"));
        }
        out
    }
}

fn put_count(out: &mut Vec<u8>, n: usize) {
    put_vlq32(out, n as u32);
}

// ------------------------------------------------------------------------------------------------ requests

/// InitSsl request (spec 3): cleartext, version 1, sequence 1.
pub fn init_ssl() -> Vec<u8> {
    let mut out = request_header(VERSION_1, function::INIT_SSL, 1, NULL_SESSION, 0x30);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// CreateObject request of the server session (spec 10.2), the captured bytes with `sequence`.
pub fn create_object(sequence: u16) -> Vec<u8> {
    let mut out = request_header(
        VERSION_1,
        function::CREATE_OBJECT,
        sequence,
        NULL_SESSION,
        0x36,
    );
    out.extend_from_slice(&0x11Du32.to_be_bytes());
    WireValue::scalar(Scalar::UDInt(0)).encode(&mut out);
    out.extend_from_slice(&[0, 0, 0, 0]);
    let session = Object {
        rid: 211,
        class: 287,
        attrs: vec![(300, WireValue::scalar(Scalar::Rid(0x80C3_C901)))],
        children: vec![Object {
            rid: 211,
            class: 255,
            ..Object::default()
        }],
        ..Object::default()
    };
    session.encode(&mut out);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// The session-setup SetMultiVariables (spec 10.4): attribute 306 of the session written back as received.
pub fn session_setup(sequence: u16, session: u32, version_value: &[u8]) -> Vec<u8> {
    let mut out = request_header(
        VERSION_2,
        function::SET_MULTI_VARIABLES,
        sequence,
        session,
        0x34,
    );
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x01]);
    put_vlq32(&mut out, ids::ATTR_SESSION_VERSION);
    out.push(0x01);
    out.extend_from_slice(version_value);
    out.push(0x00);
    out.extend_from_slice(&QUALIFIER);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// GetMultiVariables (spec 11.1).
pub fn get_multi(sequence: u16, session: u32, items: &[ItemAddress], integrity: u32) -> Vec<u8> {
    let mut out = request_header(
        VERSION_2,
        function::GET_MULTI_VARIABLES,
        sequence,
        session,
        0x34,
    );
    out.extend_from_slice(&[0, 0, 0, 0]);
    put_count(&mut out, items.len());
    put_count(&mut out, items.iter().map(ItemAddress::field_count).sum());
    for item in items {
        item.encode(&mut out);
    }
    out.extend_from_slice(&QUALIFIER);
    put_vlq32(&mut out, integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// SetMultiVariables tag write (spec 17.1): addresses, then the values numbered 1..n.
pub fn set_multi(
    sequence: u16,
    session: u32,
    items: &[(ItemAddress, WireValue)],
    integrity: u32,
) -> Vec<u8> {
    let mut out = request_header(
        VERSION_2,
        function::SET_MULTI_VARIABLES,
        sequence,
        session,
        0x34,
    );
    out.extend_from_slice(&[0, 0, 0, 0]);
    put_count(&mut out, items.len());
    put_count(&mut out, items.iter().map(|(a, _)| a.field_count()).sum());
    for (address, _) in items {
        address.encode(&mut out);
    }
    for (i, (_, value)) in items.iter().enumerate() {
        put_count(&mut out, i + 1);
        value.encode(&mut out);
    }
    out.push(0x00);
    out.extend_from_slice(&QUALIFIER);
    put_vlq32(&mut out, integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// The fields of an Explore request (spec 13.1).
#[derive(Clone, Debug, PartialEq)]
pub struct Explore {
    /// RID of the object to explore.
    pub rid: u32,
    /// Explore request ID (0 in every capture).
    pub request_id: u32,
    /// Include children recursively.
    pub children: bool,
    /// Include parent objects.
    pub parents: bool,
    /// One filter value, or none.
    pub filter: Option<WireValue>,
    /// Attributes to return; empty returns all.
    pub attributes: Vec<u32>,
}

impl Explore {
    /// Explore of `rid` with children, no parents, no filter.
    pub fn children(rid: u32, attributes: &[u32]) -> Self {
        Explore {
            rid,
            request_id: 0,
            children: true,
            parents: false,
            filter: None,
            attributes: attributes.to_vec(),
        }
    }

    /// The DB-only Explore of the PLC program (spec 13.2): filter "instance of class 2574", attribute 233.
    pub fn data_blocks() -> Self {
        let element = |id, v| (id, v);
        let filter = Scalar::Struct(Box::new(super::codec::Struct::Normal {
            id: 1246,
            elements: vec![
                element(1247, WireValue::scalar(Scalar::DInt(8))),
                element(1249, WireValue::scalar(Scalar::UDInt(0))),
                element(
                    1250,
                    WireValue::array(dt::UDINT, vec![Scalar::UDInt(0); 32]),
                ),
                element(1251, WireValue::scalar(Scalar::Rid(ids::CLASS_DB))),
            ],
        }));
        Explore {
            filter: Some(WireValue::scalar(filter)),
            ..Explore::children(ids::PLC_PROGRAM, &[ids::ATTR_NAME])
        }
    }
}

/// Explore request.
pub fn explore(sequence: u16, session: u32, request: &Explore, integrity: u32) -> Vec<u8> {
    let mut out = request_header(VERSION_2, function::EXPLORE, sequence, session, 0x34);
    out.extend_from_slice(&request.rid.to_be_bytes());
    put_vlq32(&mut out, request.request_id);
    out.push(u8::from(request.children));
    out.push(0x01);
    out.push(u8::from(request.parents));
    match &request.filter {
        Some(filter) => {
            out.push(0x01);
            filter.encode(&mut out);
            out.push(0x00);
        }
        None => out.push(0x00),
    }
    put_count(&mut out, request.attributes.len());
    for a in &request.attributes {
        put_vlq32(&mut out, *a);
    }
    put_vlq32(&mut out, integrity);
    out.extend_from_slice(&[0, 0, 0, 0, 0]);
    out
}

/// GetVarSubStreamed of one attribute of `object` (spec 13.8).
pub fn get_var(
    sequence: u16,
    session: u32,
    object: u32,
    attribute: u32,
    integrity: u32,
) -> Vec<u8> {
    let mut out = request_header(
        VERSION_2,
        function::GET_VAR_SUB_STREAMED,
        sequence,
        session,
        0x34,
    );
    out.extend_from_slice(&object.to_be_bytes());
    WireValue {
        flags: FLAG_ADDRESS_ARRAY,
        datatype: dt::UDINT,
        payload: Payload::Array(vec![Scalar::UDInt(attribute)]),
    }
    .encode(&mut out);
    out.extend_from_slice(&QUALIFIER);
    out.extend_from_slice(&[0x00, 0x01]);
    put_vlq32(&mut out, integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// DeleteObject of the session (spec 10.8).
pub fn delete_object(sequence: u16, session: u32, object: u32, integrity: u32) -> Vec<u8> {
    let mut out = request_header(VERSION_2, function::DELETE_OBJECT, sequence, session, 0x34);
    out.extend_from_slice(&object.to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&QUALIFIER);
    put_vlq32(&mut out, integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// The body of a parsed request.
#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    /// InitSsl.
    InitSsl,
    /// CreateObject.
    CreateObject {
        /// Request ID (285).
        request_id: u32,
        /// The request value.
        value: WireValue,
        /// The objects to create.
        objects: Vec<Object>,
    },
    /// SetMultiVariables: the session setup (object = session, fields = attribute IDs) or a tag write
    /// (object 0, fields = item addresses).
    SetMulti {
        /// Object to write into: the session, or 0 for tags.
        object: u32,
        /// The address fields, flat.
        fields: Vec<u32>,
        /// Item number and value.
        values: Vec<(u32, WireValue)>,
        /// Integrity ID; None for the session setup.
        integrity: Option<u32>,
    },
    /// GetMultiVariables.
    GetMulti {
        /// Link ID (0 for reads).
        link: u32,
        /// The items.
        items: Vec<ItemAddress>,
        /// Integrity ID.
        integrity: u32,
    },
    /// Explore.
    Explore {
        /// The request fields.
        request: Explore,
        /// Integrity ID.
        integrity: u32,
    },
    /// GetVarSubStreamed.
    GetVar {
        /// Object ID.
        object: u32,
        /// Attribute ID.
        attribute: u32,
        /// Integrity ID.
        integrity: u32,
    },
    /// DeleteObject.
    DeleteObject {
        /// Object ID.
        object: u32,
        /// Integrity ID.
        integrity: u32,
    },
}

impl Request {
    /// The integrity ID the request carries.
    pub fn integrity(&self) -> Option<u32> {
        match self {
            Request::InitSsl | Request::CreateObject { .. } => None,
            Request::SetMulti { integrity, .. } => *integrity,
            Request::GetMulti { integrity, .. }
            | Request::Explore { integrity, .. }
            | Request::GetVar { integrity, .. }
            | Request::DeleteObject { integrity, .. } => Some(*integrity),
        }
    }
}

/// Splits the flat address fields of a tag-write SetMultiVariables into item addresses.
pub fn split_addresses(fields: &[u32], count: usize) -> Result<Vec<ItemAddress>> {
    let mut out = Vec::with_capacity(count.min(fields.len()));
    let mut rest = fields;
    for _ in 0..count {
        let [crc, area, ids, sub_area, tail @ ..] = rest else {
            return Err(malformed("item address fields"));
        };
        let n = ids
            .checked_sub(1)
            .ok_or_else(|| malformed("item address IDs"))? as usize;
        if tail.len() < n {
            return Err(malformed("item address fields"));
        }
        out.push(ItemAddress {
            crc: *crc,
            area: *area,
            sub_area: *sub_area,
            lids: tail[..n].to_vec(),
        });
        rest = &tail[n..];
    }
    if !rest.is_empty() {
        return Err(malformed("item address field count"));
    }
    Ok(out)
}

/// Parses a request body by the header's function.
pub fn parse_request(header: &RequestHeader<'_>) -> Result<Request> {
    let mut c = Cursor::new(header.body);
    let c = &mut c;
    Ok(match header.function {
        function::INIT_SSL => {
            end(c, 4)?;
            Request::InitSsl
        }
        function::CREATE_OBJECT => {
            let request_id = c.u32()?;
            let value = WireValue::decode(c)?;
            c.zeros(4, "CreateObject reserved")?;
            let objects = Object::decode_list(c)?;
            end(c, 4)?;
            Request::CreateObject {
                request_id,
                value,
                objects,
            }
        }
        function::SET_MULTI_VARIABLES => {
            let object = c.u32()?;
            let n_values = c.vlq32()? as usize;
            let n_fields = c.vlq32()? as usize;
            let mut fields = Vec::with_capacity(n_fields.min(c.remaining()));
            for _ in 0..n_fields {
                fields.push(c.vlq32()?);
            }
            let mut values = Vec::with_capacity(n_values.min(c.remaining()));
            for _ in 0..n_values {
                let item = c.vlq32()?;
                values.push((item, WireValue::decode(c)?));
            }
            if c.u8()? != 0 {
                return Err(malformed("SetMultiVariables fill byte"));
            }
            qualifier(c)?;
            let integrity = if c.remaining() == 4 {
                None
            } else {
                Some(c.vlq32()?)
            };
            end(c, 4)?;
            Request::SetMulti {
                object,
                fields,
                values,
                integrity,
            }
        }
        function::GET_MULTI_VARIABLES => {
            let link = c.u32()?;
            let n = c.vlq32()? as usize;
            let fields = c.vlq32()? as usize;
            let mut items = Vec::with_capacity(n.min(c.remaining()));
            for _ in 0..n {
                items.push(ItemAddress::decode(c)?);
            }
            if items.iter().map(ItemAddress::field_count).sum::<usize>() != fields {
                return Err(malformed("GetMultiVariables field count"));
            }
            qualifier(c)?;
            let integrity = c.vlq32()?;
            end(c, 4)?;
            Request::GetMulti {
                link,
                items,
                integrity,
            }
        }
        function::EXPLORE => {
            let rid = c.u32()?;
            let request_id = c.vlq32()?;
            let children = c.u8()? != 0;
            c.u8()?;
            let parents = c.u8()? != 0;
            let filter = match c.u8()? {
                0 => None,
                1 => {
                    let v = WireValue::decode(c)?;
                    if c.u8()? != 0 {
                        return Err(malformed("Explore filter end"));
                    }
                    Some(v)
                }
                _ => return Err(malformed("Explore filter count")),
            };
            let n = c.vlq32()? as usize;
            let mut attributes = Vec::with_capacity(n.min(c.remaining()));
            for _ in 0..n {
                attributes.push(c.vlq32()?);
            }
            let integrity = c.vlq32()?;
            end(c, 5)?;
            Request::Explore {
                request: Explore {
                    rid,
                    request_id,
                    children,
                    parents,
                    filter,
                    attributes,
                },
                integrity,
            }
        }
        function::GET_VAR_SUB_STREAMED => {
            let object = c.u32()?;
            let address = WireValue::decode(c)?;
            let attribute = match address.as_array() {
                Some([Scalar::UDInt(a)]) => *a,
                _ => return Err(malformed("GetVarSubStreamed address")),
            };
            qualifier(c)?;
            if c.take(2)? != [0x00, 0x01] {
                return Err(malformed("GetVarSubStreamed fixed bytes"));
            }
            let integrity = c.vlq32()?;
            end(c, 4)?;
            Request::GetVar {
                object,
                attribute,
                integrity,
            }
        }
        function::DELETE_OBJECT => {
            let object = c.u32()?;
            if c.u8()? != 0 {
                return Err(malformed("DeleteObject byte"));
            }
            qualifier(c)?;
            let integrity = c.vlq32()?;
            end(c, 4)?;
            Request::DeleteObject { object, integrity }
        }
        other => {
            return Err(malformed(&format!("unsupported function 0x{other:04X}")));
        }
    })
}

// ------------------------------------------------------------------------------------------------ objects

/// One vartype element (spec 13.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VarType {
    /// Access ID of the member.
    pub lid: u32,
    /// Member CRC.
    pub crc: u32,
    /// Softdatatype.
    pub softdatatype: u8,
    /// Attribute flags.
    pub flags: u16,
    /// Bit-offset info.
    pub bit_info: u8,
    /// The offset info, raw (its size follows from the offset-info type, flags >> 12).
    pub offset_info: Vec<u8>,
}

/// Size of the offset info of each offset-info type (spec 13.5).
pub fn offset_info_size(kind: u8) -> usize {
    match kind {
        1 | 8 => 4,
        2 | 9 => 12,
        3 | 10 => 20,
        4 | 11 => 68,
        5 | 12 => 32,
        6 | 13 => 48,
        7 | 14 => 96,
        15 => 40,
        _ => 104, // 0: array of FB instances
    }
}

/// A vartype list (`AB`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VartypeList {
    /// The first ID (LE u32 at the start of the first block).
    pub first_id: u32,
    /// The elements.
    pub elements: Vec<VarType>,
}

/// An object (spec 9): `A1` header, attributes, vartype and varname lists, children, `A2`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object {
    /// Relation ID (the object's RID).
    pub rid: u32,
    /// Class ID.
    pub class: u32,
    /// Class flags.
    pub flags: u32,
    /// Attribute ID.
    pub aid: u32,
    /// Attributes in wire order.
    pub attrs: Vec<(u32, WireValue)>,
    /// The vartype list, if any.
    pub vartypes: Option<VartypeList>,
    /// The varname list, if any.
    pub varnames: Option<Vec<String>>,
    /// Nested objects.
    pub children: Vec<Object>,
}

impl Object {
    /// The value of attribute `id`.
    pub fn attr(&self, id: u32) -> Option<&WireValue> {
        self.attrs.iter().find(|(a, _)| *a == id).map(|(_, v)| v)
    }

    /// Calls `f` for this object and every descendant, depth first.
    pub fn walk<'a>(&'a self, f: &mut impl FnMut(&'a Object)) {
        f(self);
        for child in &self.children {
            child.walk(f);
        }
    }

    /// Decodes the `A1 ... A2` objects at the cursor (stops at the first other byte).
    pub fn decode_list(c: &mut Cursor<'_>) -> Result<Vec<Object>> {
        let mut out = Vec::new();
        while c.peek() == Some(0xA1) {
            c.u8()?;
            out.push(Self::decode_body(c, 0, &mut |_, _, _| {})?);
        }
        Ok(out)
    }

    /// Decodes an object after its `A1` tag; `span` sees each attribute's ID and value position.
    fn decode_body(
        c: &mut Cursor<'_>,
        depth: usize,
        span: &mut dyn FnMut(u32, usize, usize),
    ) -> Result<Object> {
        if depth >= MAX_DEPTH {
            return Err(malformed("objects nested too deep"));
        }
        let mut o = Object {
            rid: c.u32()?,
            class: c.vlq32()?,
            flags: c.vlq32()?,
            aid: c.vlq32()?,
            ..Object::default()
        };
        loop {
            match c.u8()? {
                0xA2 => return Ok(o),
                0xA3 => {
                    let id = c.vlq32()?;
                    let start = c.pos();
                    let value = WireValue::decode(c)?;
                    span(id, start, c.pos());
                    o.attrs.push((id, value));
                }
                0xA1 => o.children.push(Self::decode_body(c, depth + 1, span)?),
                0xAB => o.vartypes = Some(decode_vartypes(c)?),
                0xAC => o.varnames = Some(decode_varnames(c)?),
                tag => {
                    return Err(malformed(&format!("unknown object element 0x{tag:02X}")));
                }
            }
        }
    }

    /// Appends the object (`A1 ... A2`): attributes, vartype list, varname list, children.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(0xA1);
        out.extend_from_slice(&self.rid.to_be_bytes());
        put_vlq32(out, self.class);
        put_vlq32(out, self.flags);
        put_vlq32(out, self.aid);
        for (id, value) in &self.attrs {
            out.push(0xA3);
            put_vlq32(out, *id);
            value.encode(out);
        }
        if let Some(list) = &self.vartypes {
            out.push(0xAB);
            encode_vartypes(list, out);
        }
        if let Some(names) = &self.varnames {
            out.push(0xAC);
            encode_varnames(names, out);
        }
        for child in &self.children {
            child.encode(out);
        }
        out.push(0xA2);
    }
}

fn decode_vartypes(c: &mut Cursor<'_>) -> Result<VartypeList> {
    let mut list = VartypeList::default();
    let mut first = true;
    loop {
        let len = usize::from(c.u16()?);
        if len == 0 {
            return Ok(list);
        }
        let mut block = Cursor::new(c.take(len)?);
        if first {
            list.first_id = block.u32_le()?;
            first = false;
        }
        while block.remaining() > 0 {
            let lid = block.u32_le()?;
            let crc = block.u32_le()?;
            let softdatatype = block.u8()?;
            let flags = block.u16()?;
            let bit_info = block.u8()?;
            let size = offset_info_size((flags >> 12) as u8);
            let offset_info = block.take(size)?.to_vec();
            list.elements.push(VarType {
                lid,
                crc,
                softdatatype,
                flags,
                bit_info,
                offset_info,
            });
        }
    }
}

fn decode_varnames(c: &mut Cursor<'_>) -> Result<Vec<String>> {
    let mut names = Vec::new();
    loop {
        let len = usize::from(c.u16()?);
        if len == 0 {
            return Ok(names);
        }
        let mut block = Cursor::new(c.take(len)?);
        while block.remaining() > 0 {
            let n = usize::from(block.u8()?);
            names.push(String::from_utf8_lossy(block.take(n)?).into_owned());
            if block.u8()? != 0 {
                return Err(malformed("varname terminator"));
            }
        }
    }
}

/// Largest block a list is split into when encoding.
const LIST_BLOCK: usize = 0xFF00;

fn encode_blocks(
    entries: impl Iterator<Item = Vec<u8>>,
    first: Option<[u8; 4]>,
    out: &mut Vec<u8>,
) {
    let mut block: Vec<u8> = first.map(|f| f.to_vec()).unwrap_or_default();
    let flush = |block: &mut Vec<u8>, out: &mut Vec<u8>| {
        if !block.is_empty() {
            out.extend_from_slice(&(block.len() as u16).to_be_bytes());
            out.append(block);
        }
    };
    for entry in entries {
        if block.len() + entry.len() > LIST_BLOCK {
            flush(&mut block, out);
        }
        block.extend_from_slice(&entry);
    }
    flush(&mut block, out);
    out.extend_from_slice(&[0, 0]);
}

fn encode_vartypes(list: &VartypeList, out: &mut Vec<u8>) {
    let entries = list.elements.iter().map(|e| {
        let mut b = Vec::with_capacity(12 + e.offset_info.len());
        b.extend_from_slice(&e.lid.to_le_bytes());
        b.extend_from_slice(&e.crc.to_le_bytes());
        b.push(e.softdatatype);
        b.extend_from_slice(&e.flags.to_be_bytes());
        b.push(e.bit_info);
        b.extend_from_slice(&e.offset_info);
        b
    });
    encode_blocks(entries, Some(list.first_id.to_le_bytes()), out);
}

fn encode_varnames(names: &[String], out: &mut Vec<u8>) {
    let entries = names.iter().map(|n| {
        let bytes = &n.as_bytes()[..n.len().min(255)];
        let mut b = Vec::with_capacity(bytes.len() + 2);
        b.push(bytes.len() as u8);
        b.extend_from_slice(bytes);
        b.push(0);
        b
    });
    encode_blocks(entries, None, out);
}

// ------------------------------------------------------------------------------------------------ responses

fn header_ok(r: &Response<'_>, function: u16) -> Result<()> {
    if r.function != function {
        return Err(malformed(&format!(
            "response function 0x{:04X}, expected 0x{function:04X}",
            r.function
        )));
    }
    Ok(())
}

/// What a CreateObject response gives the client.
#[derive(Clone, Debug, PartialEq)]
pub struct CreateObjectReply {
    /// The object IDs; the first is the session ID.
    pub object_ids: Vec<u32>,
    /// The response objects.
    pub objects: Vec<Object>,
    /// Attribute 306 (ServerSessionVersion) as received, for the session setup.
    pub session_version: Option<Vec<u8>>,
}

/// Parses a CreateObject response body.
pub fn parse_create_object(r: &Response<'_>) -> Result<CreateObjectReply> {
    header_ok(r, function::CREATE_OBJECT)?;
    let mut c = Cursor::new(r.body);
    let n = usize::from(c.u8()?);
    let mut object_ids = Vec::with_capacity(n);
    for _ in 0..n {
        object_ids.push(c.vlq32()?);
    }
    let mut objects = Vec::new();
    let mut version = None;
    if r.flags & 0x02 != 0 {
        while c.peek() == Some(0xA1) {
            c.u8()?;
            let mut span = |id, start, stop| {
                if id == ids::ATTR_SESSION_VERSION && version.is_none() {
                    version = Some((start, stop));
                }
            };
            objects.push(Object::decode_body(&mut c, 0, &mut span)?);
        }
    }
    end(&mut c, 4)?;
    Ok(CreateObjectReply {
        object_ids,
        objects,
        session_version: version.map(|(a, b)| r.body[a..b].to_vec()),
    })
}

/// A CreateObject response body (for the simulator).
pub fn create_object_body(object_ids: &[u32], objects: &[Object]) -> Vec<u8> {
    let mut out = vec![object_ids.len() as u8];
    for id in object_ids {
        put_vlq32(&mut out, *id);
    }
    for o in objects {
        o.encode(&mut out);
    }
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

fn decode_errors(c: &mut Cursor<'_>) -> Result<Vec<(u32, u64)>> {
    let mut errors = Vec::new();
    loop {
        let item = c.vlq32()?;
        if item == 0 {
            return Ok(errors);
        }
        errors.push((item, c.vlq64()?));
    }
}

fn encode_errors(errors: &[(u32, u64)], out: &mut Vec<u8>) {
    for (item, error) in errors {
        put_vlq32(out, *item);
        put_vlq64(out, *error);
    }
    out.push(0);
}

/// A GetMultiVariables response (spec 11.3).
#[derive(Clone, Debug, PartialEq)]
pub struct GetMultiReply {
    /// Item number (1-based) and value.
    pub values: Vec<(u32, WireValue)>,
    /// Item number and item error.
    pub errors: Vec<(u32, u64)>,
    /// Integrity ID.
    pub integrity: u32,
}

/// Parses a GetMultiVariables response body.
pub fn parse_get_multi(r: &Response<'_>) -> Result<GetMultiReply> {
    header_ok(r, function::GET_MULTI_VARIABLES)?;
    let mut c = Cursor::new(r.body);
    let mut values = Vec::new();
    loop {
        let item = c.vlq32()?;
        if item == 0 {
            break;
        }
        values.push((item, WireValue::decode(&mut c)?));
    }
    let errors = decode_errors(&mut c)?;
    let integrity = c.vlq32()?;
    end(&mut c, 4)?;
    Ok(GetMultiReply {
        values,
        errors,
        integrity,
    })
}

/// A GetMultiVariables response body.
pub fn get_multi_body(reply: &GetMultiReply) -> Vec<u8> {
    let mut out = Vec::new();
    for (item, value) in &reply.values {
        put_vlq32(&mut out, *item);
        value.encode(&mut out);
    }
    out.push(0);
    encode_errors(&reply.errors, &mut out);
    put_vlq32(&mut out, reply.integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// A SetMultiVariables response (spec 17.2).
#[derive(Clone, Debug, PartialEq)]
pub struct SetMultiReply {
    /// Item number and item error of each failed item.
    pub errors: Vec<(u32, u64)>,
    /// Integrity ID (0 for the session setup).
    pub integrity: u32,
}

/// Parses a SetMultiVariables response body.
pub fn parse_set_multi(r: &Response<'_>) -> Result<SetMultiReply> {
    header_ok(r, function::SET_MULTI_VARIABLES)?;
    let mut c = Cursor::new(r.body);
    let errors = decode_errors(&mut c)?;
    let integrity = c.vlq32()?;
    end(&mut c, 4)?;
    Ok(SetMultiReply { errors, integrity })
}

/// A SetMultiVariables response body.
pub fn set_multi_body(reply: &SetMultiReply) -> Vec<u8> {
    let mut out = Vec::new();
    encode_errors(&reply.errors, &mut out);
    put_vlq32(&mut out, reply.integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// An Explore response (spec 13.1).
#[derive(Clone, Debug, PartialEq)]
pub struct ExploreReply {
    /// RID of the explored object's parent.
    pub parent: u32,
    /// Integrity ID.
    pub integrity: u32,
    /// The objects.
    pub objects: Vec<Object>,
}

/// Parses an Explore response body.
pub fn parse_explore(r: &Response<'_>) -> Result<ExploreReply> {
    header_ok(r, function::EXPLORE)?;
    let mut c = Cursor::new(r.body);
    let parent = c.u32()?;
    let integrity = c.vlq32()?;
    let objects = Object::decode_list(&mut c)?;
    end(&mut c, 4)?;
    Ok(ExploreReply {
        parent,
        integrity,
        objects,
    })
}

/// An Explore response body.
pub fn explore_body(reply: &ExploreReply) -> Vec<u8> {
    let mut out = reply.parent.to_be_bytes().to_vec();
    put_vlq32(&mut out, reply.integrity);
    for o in &reply.objects {
        o.encode(&mut out);
    }
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// Parses a GetVarSubStreamed response body: the value and the integrity ID.
pub fn parse_get_var(r: &Response<'_>) -> Result<(WireValue, u32)> {
    header_ok(r, function::GET_VAR_SUB_STREAMED)?;
    let mut c = Cursor::new(r.body);
    c.u8()?;
    let value = WireValue::decode(&mut c)?;
    let integrity = c.vlq32()?;
    end(&mut c, 4)?;
    Ok((value, integrity))
}

/// A GetVarSubStreamed response body.
pub fn get_var_body(value: &WireValue, integrity: u32) -> Vec<u8> {
    let mut out = vec![0x00];
    value.encode(&mut out);
    put_vlq32(&mut out, integrity);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// Parses a DeleteObject response body: the deleted object ID.
pub fn parse_delete_object(r: &Response<'_>) -> Result<u32> {
    header_ok(r, function::DELETE_OBJECT)?;
    let mut c = Cursor::new(r.body);
    let object = c.u32()?;
    if r.return_value & 0x4000_0000_0000_0000 != 0 {
        // an error object follows the object ID (spec 12) [R]; nothing in it is used
        Object::decode_list(&mut c)?;
    }
    end(&mut c, 4)?;
    Ok(object)
}

/// A DeleteObject response body.
pub fn delete_object_body(object: u32) -> Vec<u8> {
    let mut out = object.to_be_bytes().to_vec();
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// Parses an InitSsl response body (5 zero bytes).
pub fn parse_init_ssl(r: &Response<'_>) -> Result<()> {
    header_ok(r, function::INIT_SSL)?;
    let mut c = Cursor::new(r.body);
    end(&mut c, 5)
}

/// The InitSsl response body.
pub fn init_ssl_body() -> Vec<u8> {
    vec![0; 5]
}

/// Parses any response by its function, for logs and tests: Ok if the whole PDU decodes.
pub fn parse_any_response(pdu: &[u8]) -> Result<Response<'_>> {
    let r = parse_response(pdu)?;
    match r.function {
        function::INIT_SSL => parse_init_ssl(&r)?,
        function::CREATE_OBJECT => {
            parse_create_object(&r)?;
        }
        function::SET_MULTI_VARIABLES => {
            parse_set_multi(&r)?;
        }
        function::GET_MULTI_VARIABLES => {
            parse_get_multi(&r)?;
        }
        function::EXPLORE => {
            parse_explore(&r)?;
        }
        function::GET_VAR_SUB_STREAMED => {
            parse_get_var(&r)?;
        }
        function::DELETE_OBJECT => {
            parse_delete_object(&r)?;
        }
        other => return Err(malformed(&format!("unsupported function 0x{other:04X}"))),
    }
    Ok(r)
}

/// Rebuilds a parsed request with the builders above (byte-for-byte checks of captured requests).
pub fn build_request(header: &RequestHeader<'_>, request: &Request) -> Result<Vec<u8>> {
    let (seq, session) = (header.sequence, header.session);
    Ok(match request {
        Request::InitSsl => init_ssl(),
        Request::CreateObject { .. } => create_object(seq),
        Request::SetMulti {
            object,
            fields,
            values,
            integrity,
        } => match integrity {
            None => {
                let [(1, value)] = values.as_slice() else {
                    return Err(malformed("session setup values"));
                };
                if fields.as_slice() != [ids::ATTR_SESSION_VERSION] || *object != session {
                    return Err(malformed("session setup address"));
                }
                session_setup(seq, session, &value.to_bytes())
            }
            Some(integrity) => {
                let addresses = split_addresses(fields, values.len())?;
                let items: Vec<_> = addresses
                    .into_iter()
                    .zip(values.iter().map(|(_, v)| v.clone()))
                    .collect();
                set_multi(seq, session, &items, *integrity)
            }
        },
        Request::GetMulti {
            items, integrity, ..
        } => get_multi(seq, session, items, *integrity),
        Request::Explore { request, integrity } => explore(seq, session, request, *integrity),
        Request::GetVar {
            object,
            attribute,
            integrity,
        } => get_var(seq, session, *object, *attribute, *integrity),
        Request::DeleteObject { object, integrity } => {
            delete_object(seq, session, *object, *integrity)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    const SESSION: u32 = 0x7000_0A10;

    fn item(crc: u32, area: u32, sub_area: u32, lids: &[u32]) -> ItemAddress {
        ItemAddress {
            crc,
            area,
            sub_area,
            lids: lids.to_vec(),
        }
    }

    #[test]
    fn init_ssl_is_the_spec_request() {
        assert_eq!(init_ssl(), hex("0131000005b300000001000001203000000000"));
        let framed = frame(&init_ssl()).expect("frame");
        assert_eq!(
            framed,
            hex("7201 0012 31000005b300000001000001203000000000 72010000")
        );
    }

    #[test]
    fn create_object_is_the_captured_request() {
        assert_eq!(
            create_object(2),
            hex(
                "0131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3822c001280c3c901a1000000\
                 d3817f0000a2a200000000"
            )
        );
    }

    #[test]
    fn create_object_response_gives_session_and_version_bytes() {
        let pdu = hex(
            "0132000004ca0000000236b088d0808084da80110287808094108780809411a100000120821f0100a381690015133030\
             3a30313233343536373839414243444546a3822b000402a3822d0015245365727665723a204f4d53505f31342e30302e\
             30302e30335f36362e30332e30302e3031a3822f100214101112131415161718191a1b1c1d1e1f20212223a382320017\
             0000013a823b00048701823c00048701823d000484818540823e000484818540823f00151a313b36455337203558582d\
             58585858582d584142303b56332e31824000150a323b313233343536373882410003000300a200000000",
        );
        let r = parse_response(&pdu).expect("header");
        assert_eq!(r.return_value, 0x6022_8000_012D_0011);
        let reply = parse_create_object(&r).expect("body");
        assert_eq!(reply.object_ids, vec![0x7000_0A10, 0x7000_0A11]);
        let version = reply.session_version.expect("306");
        // the session setup of spec 10.4 writes these bytes back
        let setup = session_setup(3, SESSION, &version);
        assert_eq!(
            setup,
            hex(
                "0231000005420000000370000a103470000a10010182320100170000013a823b00048701823c00048701823d00048481\
                 8540823e000484818540823f00151a313b36455337203558582d58585858582d584142303b56332e31824000150a323b\
                 31323334353637388241000300030000000004e88969001200000000896a001300896b0004000000000000"
            )
        );
        assert_eq!(
            create_object_body(&reply.object_ids, &reply.objects),
            r.body.to_vec(),
            "the CreateObject body re-encodes byte for byte"
        );
    }

    #[test]
    fn session_setup_response_parses() {
        let pdu = hex("023200000542000000033400000000000000");
        let r = parse_response(&pdu).expect("header");
        assert_eq!(
            parse_set_multi(&r).expect("body"),
            SetMultiReply {
                errors: vec![],
                integrity: 0
            }
        );
    }

    #[test]
    fn system_limits_request_and_response() {
        let items: Vec<_> = [1000, 1001, 0, 1, 2]
            .iter()
            .map(|&lid| item(0, ids::OBJECT_ROOT, ids::SYSTEM_LIMITS, &[lid]))
            .collect();
        assert_eq!(
            get_multi(4, SESSION, &items, 1),
            hex(
                "02310000054c0000000470000a103400000000051900814902880d876800814902880d876900814902880d0000814902\
                 880d0100814902880d02000004e88969001200000000896a001300896b000400000100000000"
            )
        );
        let pdu = hex(
            "02320000054c00000004340001000880640200088064030008817a0400088f50050008a0800000000500000000",
        );
        let reply = parse_get_multi(&parse_response(&pdu).expect("header")).expect("body");
        assert_eq!(reply.integrity, 5);
        assert!(reply.errors.is_empty());
        let values: Vec<_> = reply
            .values
            .iter()
            .map(|(i, v)| (*i, v.as_scalar().and_then(Scalar::as_i128)))
            .collect();
        assert_eq!(
            values,
            vec![
                (1, Some(100)),
                (2, Some(100)),
                (3, Some(250)),
                (4, Some(2000)),
                (5, Some(524_288))
            ]
        );
    }

    #[test]
    fn protection_level_request_and_response() {
        assert_eq!(
            get_var(5, SESSION, SESSION, ids::ATTR_PROTECTION_LEVEL, 2),
            hex(
                "0231000005860000000570000a103470000a102004018e32000004e88969001200000000896a001300896b0004000000\
                 010200000000"
            )
        );
        let pdu = hex("023200000586000000053400000004000700000000");
        let (value, integrity) =
            parse_get_var(&parse_response(&pdu).expect("header")).expect("body");
        assert_eq!(value, WireValue::scalar(Scalar::UDInt(0)));
        assert_eq!(integrity, 7);
    }

    #[test]
    fn delete_object_request_and_response() {
        assert_eq!(
            delete_object(14, SESSION, SESSION, 1),
            hex(
                "0231000004d40000000e70000a103470000a1000000004e88969001200000000896a001300896b000400000100000000"
            )
        );
        let pdu = hex("0232000004d40000000e349088f08080828e802d70000a1000000000");
        let r = parse_response(&pdu).expect("header");
        assert_eq!(r.return_value, 0x2023_8000_0087_002D);
        assert_eq!(parse_delete_object(&r).expect("body"), SESSION);
    }

    #[test]
    fn explore_requests_are_the_spec_bytes() {
        let blocks = Explore::children(ids::PLC_PROGRAM, &[233, 2521, 4288]);
        assert_eq!(
            explore(11, SESSION, &blocks, 8),
            hex("0231000004bb0000000b70000a10340000000300010100000381699359a140080000000000")
        );
        assert_eq!(
            explore(14, SESSION, &Explore::data_blocks(), 0x0b),
            hex(
                "0231000004bb0000000e70000a10340000000300010100010017000004de895f0008088961000400896210042000000000\
                 000000000000000000000000000000000000000000000000000000008963001200000a0e00000181690b0000000000"
            )
        );
        assert_eq!(
            explore(
                13,
                SESSION,
                &Explore::children(ids::TYPE_INFO_CONTAINER, &[]),
                0x0a
            ),
            hex("0231000004bb0000000d70000a1034000002190001010000000a0000000000")
        );
        let languages = Explore {
            children: false,
            parents: true,
            ..Explore::children(114, &[2717])
        };
        assert_eq!(
            explore(10, SESSION, &languages, 7),
            hex("0231000004bb0000000a70000a103400000072000001010001951d070000000000")
        );
        let comments = Explore::children(0x8A0E_0005, &[233, 2546, 2544]);
        assert_eq!(
            explore(11, SESSION, &comments, 8),
            hex("0231000004bb0000000b70000a10348a0e0005000101000003816993729370080000000000")
        );
    }

    #[test]
    fn lid1_read_request_and_response() {
        let items = [item(0, 0x8A0E_0005, ids::DB_VALUE_ACTUAL, &[1])];
        assert_eq!(
            get_multi(12, SESSION, &items, 9),
            hex(
                "02310000054c0000000c70000a10340000000001050088d0b8800502937601000004e88969001200000000896a001300\
                 896b000400000900000000"
            )
        );
        let pdu = hex("02320000054c0000000c34000100129200000500001500000000");
        let reply = parse_get_multi(&parse_response(&pdu).expect("header")).expect("body");
        assert_eq!(
            reply.values,
            vec![(1, WireValue::scalar(Scalar::Rid(0x9200_0005)))]
        );
        assert_eq!(reply.integrity, 0x15);
    }

    fn read_example_items() -> Vec<ItemAddress> {
        let db = 0x8A0E_0005;
        let s = ids::DB_VALUE_ACTUAL;
        vec![
            item(0x6E44_A73A, db, s, &[0xA, 0xB]),
            item(0x2556_A63B, db, s, &[0xA, 0x9]),
            item(0xDA02_6CFF, db, s, &[0xC]),
            item(0x646C_6642, db, s, &[0xD]),
            item(0x8C4E_AA1D, db, s, &[0xE]),
            item(0xA8FA_43BE, db, s, &[0xF]),
            item(0xFCA8_4867, db, s, &[0x10]),
            item(
                0xB285_B00A,
                ids::AREA_I,
                ids::CONTROLLER_AREA_VALUE_ACTUAL,
                &[0xC],
            ),
            item(0, db, s, &[0x7FFF]),
        ]
    }

    #[test]
    fn the_nine_item_read_of_the_spec() {
        assert_eq!(
            get_multi(0x28, SESSION, &read_example_items(), 0x1e),
            hex(
                "02310000054c0000002870000a103400000000092f86f292ce3a88d0b880050393760a0b82aadacc3b88d0b880050393\
                 760a098dd089d97f88d0b880050293760c86a3b1cc4288d0b880050293760d88e2bad41d88d0b880050293760e8ac7e9\
                 873e88d0b880050293760f8fe5a1906788d0b88005029376108b9496e00a50029d180c0088d0b8800502937681ff7f00\
                 0004e88969001200000000896a001300896b000400001e00000000"
            )
        );
        let pdu = hex(
            "02320000054c00000028349089f0808082c2801301000e3fc0000002000101030008fd54040005cbad070510020c0a04\
             4d6978310000000000000610030600040002004f004b000000000700170200004310ff4ad6dfd5774c020c07ea0b1204\
             10222e05f5e100080001000009c0d3d18080a5c5ff01004600000000",
        );
        let r = parse_response(&pdu).expect("header");
        assert_eq!(r.return_value, 0x2027_8000_00A1_0013);
        let reply = parse_get_multi(&r).expect("body");
        assert_eq!(reply.values.len(), 8);
        assert_eq!(reply.errors, vec![(9, 0x814E_8800_0962_FF01)]);
        assert_eq!(error_code(reply.errors[0].1), -255);
        assert_eq!(reply.integrity, 70);
        assert_eq!(reply.values[0].1, WireValue::scalar(Scalar::Real(1.5)));
        assert_eq!(reply.values[2].1, WireValue::scalar(Scalar::DInt(-300)));
        assert_eq!(get_multi_body(&reply), r.body.to_vec());
    }

    #[test]
    fn the_bool_write_of_the_spec() {
        let items = [(
            item(0x2556_A63B, 0x8A0E_0005, ids::DB_VALUE_ACTUAL, &[0xA, 0x9]),
            WireValue::scalar(Scalar::Bool(true)),
        )];
        assert_eq!(
            set_multi(42, SESSION, &items, 1),
            hex(
                "0231000005420000002a70000a103400000000010682aadacc3b88d0b880050393760a090100010100000004e8896900\
                 1200000000896a001300896b000400000100000000"
            )
        );
        let pdu = hex("0232000005420000002a3400002b00000000");
        let reply = parse_set_multi(&parse_response(&pdu).expect("header")).expect("body");
        assert_eq!(reply.integrity, 43);
        assert!(reply.errors.is_empty());
    }

    #[test]
    fn the_three_item_write_of_the_spec() {
        let db = 0x8A0E_0005;
        let s = ids::DB_VALUE_ACTUAL;
        let mut string = vec![Scalar::USInt(10), Scalar::USInt(4)];
        string.extend(b"Mix2".iter().map(|&b| Scalar::USInt(b)));
        string.extend(std::iter::repeat_n(Scalar::USInt(0), 6));
        let items = [
            (
                item(0x6E44_A73A, db, s, &[0xA, 0xB]),
                WireValue::scalar(Scalar::Real(2.25)),
            ),
            (
                item(0x8C4E_AA1D, db, s, &[0xE]),
                WireValue::array(dt::USINT, string),
            ),
            (item(0, db, s, &[0x7FFF]), WireValue::scalar(Scalar::Int(5))),
        ];
        let pdu = set_multi(43, SESSION, &items, 2);
        assert_eq!(
            pdu,
            hex(
                "0231000005420000002b70000a103400000000031086f292ce3a88d0b880050393760a0b88e2bad41d88d0b880050293\
                 760e0088d0b8800502937681ff7f01000e401000000210020c0a044d697832000000000000030007000500000004e889\
                 69001200000000896a001300896b000400000200000000"
            )
        );
        let header = parse_request_header(&pdu).expect("header");
        let request = parse_request(&header).expect("parse");
        assert_eq!(build_request(&header, &request).expect("rebuild"), pdu);
        let response =
            hex("0232000005420000002b349089f0808082c2801303c0d3d18080a5c5ff01002d00000000");
        let reply = parse_set_multi(&parse_response(&response).expect("header")).expect("body");
        assert_eq!(reply.errors, vec![(3, 0x814E_8800_0962_FF01)]);
        assert_eq!(reply.integrity, 45);
    }

    #[test]
    fn the_dtl_type_info_object_parses() {
        let bytes = hex(
            "a102000043837f2000a38169001500a38308000c80000003a38314000400a38411000588bfe9adb6ffaaf74ca38b5e00\
             040ca38b5f000800a384630017000006068c0700040c8c0800040c8c0900040c00a3831a000500a3831c000b0001a383\
             1d000400a3831e000404ab0084040000800900000093973bd7351a8000000000000a000000147f4ed7341a8000020002\
             000b0000006de7eef6341a8000030003000c0000004101e2c2341a8000040004000d00000084d6a870341a8000050005\
             000e0000006086d75e341a8000060006000f0000006ea81211341a8000070007001000000073001b76361a8000080008\
             000000ac003d045945415200054d4f4e5448000344415900075745454b4441590004484f555200064d494e5554450006\
             5345434f4e44000a4e414e4f5345434f4e44000000a2",
        );
        let mut c = Cursor::new(&bytes);
        let objects = Object::decode_list(&mut c).expect("decode");
        assert_eq!(c.remaining(), 0);
        let o = &objects[0];
        assert_eq!((o.rid, o.class, o.flags), (0x0200_0043, 511, 0x20));
        let list = o.vartypes.as_ref().expect("AB");
        assert_eq!(list.first_id, 0x8000_0004);
        assert_eq!(list.elements.len(), 8);
        assert_eq!(list.elements[0].lid, 9);
        assert_eq!(list.elements[0].crc, 0xD73B_9793);
        assert_eq!(list.elements[0].softdatatype, 53);
        assert_eq!(list.elements[0].flags, 0x1A80);
        assert_eq!(list.elements[7].lid, 0x10);
        assert_eq!(list.elements[7].softdatatype, 54);
        let names = o.varnames.as_ref().expect("AC");
        assert_eq!(names[0], "YEAR");
        assert_eq!(names[7], "NANOSECOND");
        assert_eq!(
            o.attr(529).and_then(WireValue::as_scalar),
            Some(&Scalar::ULInt(1_224_779_910_406_829_900))
        );
        let mut again = Vec::new();
        o.encode(&mut again);
        assert_eq!(again, bytes, "re-encodes byte for byte");
    }

    #[test]
    fn frames_reassemble_with_uneven_continuations() {
        let pdu: Vec<u8> = std::iter::once(VERSION_2)
            .chain((0..3000u32).map(|i| i as u8))
            .collect();
        for chunk in [PLC_FRAME_DATA, 975, 1, 4000] {
            let wire = frame_split(&pdu, chunk);
            assert_eq!(read_pdu(&mut wire.as_slice(), MAX_PDU).expect("read"), pdu);
        }
        // uneven sizes, as the PLC sends them
        let mut wire = Vec::new();
        let data = &pdu[1..];
        let (a, rest) = data.split_at(972);
        let (b, c) = rest.split_at(979);
        for part in [a, b, c] {
            wire.extend_from_slice(&[0x72, 0x02]);
            wire.extend_from_slice(&(part.len() as u16).to_be_bytes());
            wire.extend_from_slice(part);
        }
        wire.extend_from_slice(&[0x72, 0x02, 0, 0]);
        assert_eq!(read_pdu(&mut wire.as_slice(), MAX_PDU).expect("read"), pdu);
    }

    #[test]
    fn system_events_are_skipped_unless_negative() {
        let pdu = hex("023200000542000000033400000000000000");
        let mut wire = system_event_frame(None);
        wire.extend(system_event_frame(Some(5)));
        wire.extend(frame(&pdu).expect("frame"));
        assert_eq!(read_pdu(&mut wire.as_slice(), MAX_PDU).expect("read"), pdu);
        let mut bad = system_event_frame(Some(-1));
        bad.extend(frame(&pdu).expect("frame"));
        assert!(matches!(
            read_pdu(&mut bad.as_slice(), MAX_PDU),
            Err(Error::Comm(_))
        ));
        assert_eq!(
            parse_system_event(&system_event_frame(Some(-7))[4..]),
            Some(-7)
        );
    }

    #[test]
    fn broken_frames_are_errors() {
        let pdu = hex("023200000542000000033400000000000000");
        let wire = frame(&pdu).expect("frame");
        assert!(
            read_pdu(&mut &wire[..wire.len() - 2], MAX_PDU).is_err(),
            "truncated"
        );
        assert!(read_pdu(&mut wire.as_slice(), 4).is_err(), "over the cap");
        let mut marker = wire.clone();
        marker[0] = 0x73;
        assert!(read_pdu(&mut marker.as_slice(), MAX_PDU).is_err(), "marker");
        assert!(
            read_pdu(&mut &[0x72, 0x02, 0, 0][..], MAX_PDU).is_err(),
            "empty"
        );
        let mut mixed = frame_split(&pdu, 4);
        mixed[9] = 0x01; // second frame with another version
        assert!(read_pdu(&mut mixed.as_slice(), MAX_PDU).is_err(), "version");
    }

    #[test]
    fn error_pdus_and_truncated_bodies_are_errors() {
        let error = response(VERSION_2, function::ERROR, 3, 0x34, 0, &[0, 0, 0, 0]);
        assert!(matches!(parse_response(&error), Err(Error::Comm(_))));
        let error2 = response(VERSION_2, function::ERROR2, 3, 0x34, 0, &[0, 0, 0, 0]);
        assert!(parse_response(&error2).is_err());
        let pdu = hex("02320000054c0000000c34000100129200000500001500000000");
        let short = &pdu[..pdu.len() - 3];
        assert!(parse_get_multi(&parse_response(short).expect("header")).is_err());
        let r = parse_response(&pdu).expect("header");
        assert!(parse_set_multi(&r).is_err(), "wrong function");
        let request = get_multi(1, SESSION, &[], 1);
        assert!(
            parse_response(&request).is_err(),
            "a request is not a response"
        );
    }

    #[test]
    fn a_delete_object_error_object_follows_the_object_id() {
        // spec 12: with bit 0x4000000000000000 an error object follows the deleted object ID [R]
        let mut body = SESSION.to_be_bytes().to_vec();
        Object {
            rid: 1,
            class: 2,
            ..Object::default()
        }
        .encode(&mut body);
        body.extend_from_slice(&[0, 0, 0, 0]);
        let pdu = response(
            VERSION_2,
            function::DELETE_OBJECT,
            14,
            0x34,
            0x4000_0000_0000_0001,
            &body,
        );
        let r = parse_response(&pdu).expect("header");
        assert_eq!(parse_delete_object(&r).expect("delete"), SESSION);
    }

    #[test]
    fn requests_parse_and_rebuild_byte_for_byte() {
        let pdus = [
            init_ssl(),
            create_object(2),
            get_multi(0x28, SESSION, &read_example_items(), 0x1e),
            explore(14, SESSION, &Explore::data_blocks(), 0x0b),
            get_var(5, SESSION, SESSION, ids::ATTR_PROTECTION_LEVEL, 2),
            delete_object(14, SESSION, SESSION, 1),
            session_setup(3, SESSION, &hex("0017 0000013a 823b 0004 87 01 00")),
        ];
        for pdu in pdus {
            let header = parse_request_header(&pdu).expect("header");
            let request = parse_request(&header).expect("parse");
            assert_eq!(build_request(&header, &request).expect("rebuild"), pdu);
        }
    }

    #[test]
    fn response_builders_roundtrip() {
        let reply = ExploreReply {
            parent: 1,
            integrity: 9,
            objects: vec![Object {
                rid: 0x8A0E_0005,
                class: ids::CLASS_DB,
                flags: 0x20,
                attrs: vec![(233, WireValue::scalar(Scalar::WString("Line1".into())))],
                ..Object::default()
            }],
        };
        let pdu = response(
            VERSION_2,
            function::EXPLORE,
            9,
            0x34,
            0,
            &explore_body(&reply),
        );
        assert_eq!(
            parse_explore(&parse_response(&pdu).expect("h")).expect("b"),
            reply
        );
        let set = SetMultiReply {
            errors: vec![(2, 0x8009_8900_12C9_FFEF)],
            integrity: 11,
        };
        let pdu = response(
            VERSION_2,
            function::SET_MULTI_VARIABLES,
            9,
            0x34,
            1,
            &set_multi_body(&set),
        );
        assert_eq!(
            parse_set_multi(&parse_response(&pdu).expect("h")).expect("b"),
            set
        );
        let pdu = response(
            VERSION_2,
            function::DELETE_OBJECT,
            9,
            0x34,
            0,
            &delete_object_body(7),
        );
        assert_eq!(
            parse_delete_object(&parse_response(&pdu).expect("h")).expect("b"),
            7
        );
        let pdu = response(VERSION_1, function::INIT_SSL, 1, 0x70, 0, &init_ssl_body());
        assert_eq!(pdu, hex("0132000005b30000000170000000000000"));
        parse_any_response(&pdu).expect("InitSsl");
    }

    #[test]
    fn long_vartype_lists_split_into_blocks() {
        let element = VarType {
            lid: 9,
            crc: 1,
            softdatatype: 7,
            flags: 0x8000,
            bit_info: 0,
            offset_info: vec![0; 4],
        };
        let o = Object {
            rid: 0x9200_0005,
            class: ids::CLASS_TYPE_INFO,
            vartypes: Some(VartypeList {
                first_id: 0x8000_0004,
                elements: vec![element; 10_000],
            }),
            varnames: Some(vec!["Abc".to_string(); 10_000]),
            ..Object::default()
        };
        let mut bytes = Vec::new();
        o.encode(&mut bytes);
        let back = Object::decode_list(&mut Cursor::new(&bytes)).expect("decode");
        assert_eq!(back, vec![o]);
    }
}
