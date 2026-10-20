//! EtherNet/IP encapsulation and CIP request/reply packets, as pure functions without I/O.
//!
//! Requests are built in two layers: a CIP message (`*_message`, the bytes a multi-service packet embeds) and
//! the encapsulation framing around it (`*_request`). Replies parse into a [`Reply`] whose validity and error
//! text follow the Python driver exactly.

use num_bigint::BigUint;

use crate::epath::{LogicalValue, Segment, encode_epath, message_router_path, request_path};
use crate::identity::ListIdentity;
use crate::reader::Reader;
use crate::status::{
    encap_status_text, extended_status_code, extended_status_text, service_status_text, status_kind,
};
use crate::types::Elementary;
use crate::value::{py_bytes_repr, py_str_repr};
use crate::{Error, ErrorKind, Result, TagError};

/// Encapsulation command ListIdentity.
pub const LIST_IDENTITY: [u8; 2] = [0x63, 0x00];
/// Encapsulation command RegisterSession.
pub const REGISTER_SESSION: [u8; 2] = [0x65, 0x00];
/// Encapsulation command UnRegisterSession.
pub const UNREGISTER_SESSION: [u8; 2] = [0x66, 0x00];
/// Encapsulation command SendRRData (unconnected messages).
pub const SEND_RR_DATA: [u8; 2] = [0x6F, 0x00];
/// Encapsulation command SendUnitData (connected messages).
pub const SEND_UNIT_DATA: [u8; 2] = [0x70, 0x00];

/// Connection Manager class code.
pub const CONNECTION_MANAGER: u8 = 0x06;
/// Forward Open service.
pub const FORWARD_OPEN: u8 = 0x54;
/// Large Forward Open service.
pub const LARGE_FORWARD_OPEN: u8 = 0x5B;
/// Forward Close service.
pub const FORWARD_CLOSE: u8 = 0x4E;

/// Read Tag service.
pub const READ_TAG: u8 = 0x4C;
/// Read Tag Fragmented service.
pub const READ_TAG_FRAGMENTED: u8 = 0x52;
/// Write Tag service.
pub const WRITE_TAG: u8 = 0x4D;
/// Write Tag Fragmented service.
pub const WRITE_TAG_FRAGMENTED: u8 = 0x53;
/// Read-Modify-Write Tag service.
pub const READ_MODIFY_WRITE: u8 = 0x4E;
/// Multiple Service Packet service.
pub const MULTIPLE_SERVICE: u8 = 0x0A;

/// General status: success.
pub const SUCCESS: u8 = 0x00;
/// General status: partial data, more packets follow.
pub const INSUFFICIENT_PACKETS: u8 = 0x06;

/// Services whose replies may carry status 0x06 (partial data) and still be valid.
pub const MULTI_PACKET_SERVICES: [u8; 5] = [0x52, 0x53, 0x55, 0x0A, 0x03];

/// The service codes the Python `Services` map knows; a reply's service is None for any other.
const KNOWN_SERVICES: [u8; 29] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0D, 0x0E, 0x10, 0x11, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x4C, 0x52, 0x4D, 0x53, 0x4E, 0x55,
];

/// Get Attribute List of controller object 0xAC attributes 1, 2, 3, 4 and 10: the tag table version.
pub const TAG_TABLE_VERSION_SERVICE: [u8; 18] = [
    0x03, 0x02, 0x20, 0xAC, 0x24, 0x01, 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
    0x0A, 0x00,
];
/// Bytes the tag table version request takes in a multi-service packet (offset plus service).
pub const TAG_TABLE_VERSION_REQUEST_SIZE: usize = 2 + TAG_TABLE_VERSION_SERVICE.len();
/// Bytes its reply takes: 6 of header and offset, the count, and per attribute 4 of id and status plus its value.
pub const TAG_TABLE_VERSION_REPLY_SIZE: usize = 6 + 2 + (4 + 2) * 2 + (4 + 4) * 3;

/// The tag table version: attributes 1 and 2 (INT) and 3, 4 and 10 (DINT) of the controller object.
pub type TagTableVersion = (i16, i16, i32, i32, i32);

const CIP_TIMEOUT: [u8; 2] = [0x0A, 0x00];
const PRIORITY: u8 = 0x0A;
const TIMEOUT_TICKS: u8 = 0x04;
const TIMEOUT_MULTIPLIER: u8 = 0x07;
const TRANSPORT_CLASS: u8 = 0xA3;
const RPI: [u8; 4] = [0x01, 0x40, 0x20, 0x00];
const NET_PARAMS: u32 = 0x4200;

/// Session values every encapsulation header carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encap {
    /// Session handle (0 before RegisterSession).
    pub session: u32,
    /// Sender context, echoed by the target.
    pub context: [u8; 8],
    /// Options field.
    pub option: u32,
}

fn uint(value: usize) -> Result<[u8; 2]> {
    u16::try_from(value)
        .map(u16::to_le_bytes)
        .map_err(|_| Error::data(format!("Error packing {value} as UINT")))
}

/// The 24-byte encapsulation header followed by its data.
fn encapsulate(command: [u8; 2], encap: &Encap, data: &[u8]) -> Result<Vec<u8>> {
    let length =
        u16::try_from(data.len()).map_err(|_| Error::comm("Failed to build request header"))?;
    let mut out = Vec::with_capacity(24 + data.len());
    out.extend(command);
    out.extend(length.to_le_bytes());
    out.extend(encap.session.to_le_bytes());
    out.extend([0; 4]);
    out.extend(encap.context);
    out.extend(encap.option.to_le_bytes());
    out.extend(data);
    Ok(out)
}

/// Common packet format: an address item and a data item.
fn common_packet(
    address_type: [u8; 2],
    address: &[u8],
    data_type: [u8; 2],
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(16 + address.len() + message.len());
    out.extend([0; 4]); // interface handle, 0 for CIP
    out.extend(CIP_TIMEOUT);
    out.extend([0x02, 0x00]); // item count
    out.extend(address_type);
    out.extend(uint(address.len())?);
    out.extend(address);
    out.extend(data_type);
    out.extend(uint(message.len())?);
    out.extend(message);
    Ok(out)
}

/// A RegisterSession request.
pub fn register_session_request(
    encap: &Encap,
    protocol_version: u16,
    option_flags: u16,
) -> Vec<u8> {
    let mut data = protocol_version.to_le_bytes().to_vec();
    data.extend(option_flags.to_le_bytes());
    // invariant: 4 bytes of data always fit the header's length field
    encapsulate(REGISTER_SESSION, encap, &data).unwrap_or_default()
}

/// An UnRegisterSession request (the target sends no reply).
pub fn unregister_session_request(encap: &Encap) -> Vec<u8> {
    // invariant: no data always fits the header's length field
    encapsulate(UNREGISTER_SESSION, encap, &[]).unwrap_or_default()
}

/// A ListIdentity request.
pub fn list_identity_request(encap: &Encap) -> Vec<u8> {
    // invariant: no data always fits the header's length field
    encapsulate(LIST_IDENTITY, encap, &[]).unwrap_or_default()
}

/// A SendRRData request carrying an unconnected CIP message.
pub fn send_rr_data_request(encap: &Encap, message: &[u8]) -> Result<Vec<u8>> {
    let cpf = common_packet([0, 0], &[], [0xB2, 0x00], message)?;
    encapsulate(SEND_RR_DATA, encap, &cpf)
}

/// A SendUnitData request carrying a connected CIP message, prefixed with its sequence count.
pub fn send_unit_data_request(
    encap: &Encap,
    target_cid: &[u8],
    sequence: u16,
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(2 + message.len());
    data.extend(sequence.to_le_bytes());
    data.extend(message);
    let cpf = common_packet([0xA1, 0x00], target_cid, [0xB1, 0x00], &data)?;
    encapsulate(SEND_UNIT_DATA, encap, &cpf)
}

/// A generic CIP message: service, request path (class, instance, optional attribute) and request data.
pub fn generic_message(
    service: u8,
    class_code: LogicalValue,
    instance: LogicalValue,
    attribute: Option<LogicalValue>,
    request_data: &[u8],
) -> Result<Vec<u8>> {
    let path = request_path(class_code, instance, attribute)?;
    let mut out = Vec::with_capacity(1 + path.len() + request_data.len());
    out.push(service);
    out.extend(path);
    out.extend(request_data);
    Ok(out)
}

/// A generic unconnected message, wrapped in an Unconnected Send with `route_path` when `unconnected_send`
/// (the route path is only used then).
pub fn generic_unconnected_message(
    service: u8,
    class_code: LogicalValue,
    instance: LogicalValue,
    attribute: Option<LogicalValue>,
    request_data: &[u8],
    route_path: &[u8],
    unconnected_send: bool,
) -> Result<Vec<u8>> {
    let message = generic_message(service, class_code, instance, attribute, request_data)?;
    Ok(if unconnected_send {
        crate::epath::wrap_unconnected_send(&message, route_path)
    } else {
        message
    })
}

fn tag_service(service: u8, path: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + path.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    out.push(service);
    out.extend(path);
    for part in parts {
        out.extend(*part);
    }
    out
}

/// A Read Tag message for a tag's request path.
pub fn read_tag_message(path: &[u8], elements: u16) -> Vec<u8> {
    tag_service(READ_TAG, path, &[&elements.to_le_bytes()])
}

/// A Read Tag Fragmented message. Python embeds it in a multi-service packet without the offset.
pub fn read_tag_fragmented_message(path: &[u8], elements: u16, offset: u32) -> Vec<u8> {
    tag_service(
        READ_TAG_FRAGMENTED,
        path,
        &[&elements.to_le_bytes(), &offset.to_le_bytes()],
    )
}

/// The data type field of a write: `A0 02` and the structure handle of a UDT, else the atomic type's code
/// as a UINT. Fails with a RequestError for an unknown type name.
pub fn write_type_code(data_type_name: &str, struct_handle: Option<u16>) -> Result<Vec<u8>> {
    if let Some(handle) = struct_handle {
        let mut out = vec![0xA0, 0x02];
        out.extend(handle.to_le_bytes());
        return Ok(out);
    }
    let typ = Elementary::from_name(data_type_name).ok_or_else(|| {
        Error::request(format!(
            "Unsupported data type: {}",
            py_str_repr(data_type_name)
        ))
    })?;
    Ok(u16::from(typ.code()).to_le_bytes().to_vec())
}

/// A Write Tag message; `type_code` comes from [`write_type_code`].
pub fn write_tag_message(path: &[u8], type_code: &[u8], elements: u16, value: &[u8]) -> Vec<u8> {
    tag_service(
        WRITE_TAG,
        path,
        &[type_code, &elements.to_le_bytes(), value],
    )
}

/// A Write Tag Fragmented message for the bytes of `value` at byte `offset`.
pub fn write_tag_fragmented_message(
    path: &[u8],
    type_code: &[u8],
    elements: u16,
    offset: u32,
    value: &[u8],
) -> Vec<u8> {
    tag_service(
        WRITE_TAG_FRAGMENTED,
        path,
        &[
            type_code,
            &elements.to_le_bytes(),
            &offset.to_le_bytes(),
            value,
        ],
    )
}

/// The OR and AND masks of a Read-Modify-Write of bits of an integer tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadModifyWrite {
    data_type: Elementary,
    or_mask: BigUint,
    and_mask: BigUint,
}

impl ReadModifyWrite {
    /// Masks that change nothing, sized by `data_type`.
    pub fn new(data_type: Elementary) -> Self {
        ReadModifyWrite {
            data_type,
            or_mask: BigUint::default(),
            and_mask: BigUint::from(u64::MAX),
        }
    }

    /// Sets or clears a bit (a DWORD's bit index counts modulo 32, as a BOOL array member).
    pub fn set_bit(&mut self, bit: u32, value: bool) {
        let bit = u64::from(if self.data_type == Elementary::DWord {
            bit % 32
        } else {
            bit
        });
        self.or_mask.set_bit(bit, value);
        self.and_mask.set_bit(bit, value);
    }

    /// The Read-Modify-Write message; a DataError if a mask outgrew 64 bits.
    pub fn message(&self, path: &[u8]) -> Result<Vec<u8>> {
        let size = self.data_type.size();
        let mask = |m: &BigUint| -> Result<Vec<u8>> {
            let value =
                u64::try_from(m).map_err(|_| Error::data(format!("Error packing {m} as ULINT")))?;
            Ok(value.to_le_bytes()[..size.min(8)].to_vec())
        };
        let or = mask(&self.or_mask)?;
        let and = mask(&self.and_mask)?;
        Ok(tag_service(
            READ_MODIFY_WRITE,
            path,
            &[&uint(size)?, &or, &and],
        ))
    }
}

/// A Multiple Service Packet message embedding `messages` (each a service's message without sequence count).
pub fn multi_service_message<M: AsRef<[u8]>>(messages: &[M]) -> Result<Vec<u8>> {
    let mut out = vec![MULTIPLE_SERVICE, 0x02, 0x20, 0x02, 0x24, 0x01];
    out.extend(uint(messages.len())?);
    let mut offset = 2 + 2 * messages.len();
    for msg in messages {
        out.extend(uint(offset)?);
        offset += msg.as_ref().len();
    }
    for msg in messages {
        out.extend(msg.as_ref());
    }
    Ok(out)
}

/// The connection parameters of a Forward Open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardOpen {
    /// T->O connection ID.
    pub cid: [u8; 4],
    /// Connection serial number.
    pub csn: [u8; 2],
    /// Originator vendor ID.
    pub vid: [u8; 2],
    /// Originator serial number.
    pub vsn: [u8; 4],
    /// Connection size in bytes.
    pub connection_size: u32,
    /// Large Forward Open (32-bit network parameters).
    pub large: bool,
}

fn route(cip_path: &[Segment], pad_length: bool) -> Result<Vec<u8>> {
    let mut segments = cip_path.to_vec();
    segments.extend(message_router_path());
    encode_epath(&segments, true, true, pad_length)
}

/// The request data of a (Large) Forward Open to the Message Router at the end of `cip_path`.
pub fn forward_open_data(params: &ForwardOpen, cip_path: &[Segment]) -> Result<Vec<u8>> {
    let net_params = if params.large {
        ((params.connection_size & 0xFFFF) | (NET_PARAMS << 16))
            .to_le_bytes()
            .to_vec()
    } else {
        // invariant: masked to 16 bits
        let value = (params.connection_size & 0x01FF) | NET_PARAMS;
        (value as u16).to_le_bytes().to_vec()
    };
    let mut out = vec![PRIORITY, TIMEOUT_TICKS, 0, 0, 0, 0];
    out.extend(params.cid);
    out.extend(params.csn);
    out.extend(params.vid);
    out.extend(params.vsn);
    out.extend([TIMEOUT_MULTIPLIER, 0, 0, 0]);
    out.extend(RPI);
    out.extend(&net_params);
    out.extend(RPI);
    out.extend(&net_params);
    out.push(TRANSPORT_CLASS);
    out.extend(route(cip_path, false)?);
    Ok(out)
}

/// The request data of a Forward Close (its route path size is followed by a pad byte).
pub fn forward_close_data(
    csn: &[u8; 2],
    vid: &[u8; 2],
    vsn: &[u8; 4],
    cip_path: &[Segment],
) -> Result<Vec<u8>> {
    let mut out = vec![PRIORITY, TIMEOUT_TICKS];
    out.extend(csn);
    out.extend(vid);
    out.extend(vsn);
    out.extend(route(cip_path, true)?);
    Ok(out)
}

/// Which reply a [`Reply`] was parsed as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind {
    /// The encapsulation header only (UnRegisterSession).
    Encapsulation,
    /// SendRRData: reply service at 40, status at 42, data after the extended status.
    SendRRData,
    /// SendUnitData: reply service at 46, status at 48, data after the extended status.
    SendUnitData,
    /// RegisterSession: the session handle at 4..8.
    RegisterSession,
    /// ListIdentity: the identity item from 26 on.
    ListIdentity,
}

/// A parsed reply. Fields stay None from the first one that could not be parsed.
#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    /// How it was parsed.
    pub kind: ReplyKind,
    /// The raw reply, None when nothing was received.
    pub raw: Option<Vec<u8>>,
    /// Encapsulation command (the first two bytes).
    pub command: Option<Vec<u8>>,
    /// Encapsulation status.
    pub command_status: Option<i32>,
    /// Session handle of a RegisterSession reply.
    pub session: Option<u32>,
    /// Service replied to (reply service & 0x7F), None if not a known service.
    pub service: Option<u8>,
    /// CIP general status.
    pub service_status: Option<u8>,
    /// Reply data after the status and extended status.
    pub data: Option<Vec<u8>>,
    /// Identity of a ListIdentity reply.
    pub identity: Option<ListIdentity>,
    /// Why the reply could not be parsed or used.
    pub parse_error: Option<String>,
}

/// A slice like Python's `raw[start:end]`, empty when out of range.
fn slice(raw: &[u8], start: usize, end: usize) -> &[u8] {
    raw.get(start..end.min(raw.len())).unwrap_or_default()
}

/// Reads `n` bytes from `stream` like the Python decoders: an empty message (BufferEmptyError) when nothing
/// is left, else "Error unpacking <buffer> as <name>" when too few are.
fn read<'a>(r: &mut Reader<'a>, n: usize, name: &str) -> std::result::Result<&'a [u8], String> {
    match r.take(n) {
        Ok(bytes) => Ok(bytes),
        Err(Error::BufferEmpty) => Err(String::new()),
        Err(_) => Err(format!(
            "Error unpacking {} as {name}",
            py_bytes_repr(r.buffer())
        )),
    }
}

fn read_u8(buf: &[u8]) -> std::result::Result<u8, String> {
    read(&mut Reader::new(buf), 1, "USINT").map(|b| b[0])
}

fn read_u16(r: &mut Reader<'_>, name: &str) -> std::result::Result<u16, String> {
    read(r, 2, name).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(r: &mut Reader<'_>, name: &str) -> std::result::Result<u32, String> {
    read(r, 4, name).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

impl Reply {
    /// The reply to a request that got no response.
    pub fn no_response(kind: ReplyKind) -> Self {
        Reply {
            kind,
            raw: None,
            command: None,
            command_status: None,
            session: None,
            service: None,
            service_status: None,
            data: None,
            identity: None,
            parse_error: Some("No response data received".into()),
        }
    }

    /// Parses a raw reply.
    pub fn parse(kind: ReplyKind, raw: &[u8]) -> Self {
        let mut reply = Reply {
            raw: Some(raw.to_vec()),
            parse_error: None,
            ..Reply::no_response(kind)
        };
        reply.command = Some(slice(raw, 0, 2).to_vec());
        match read_u32(&mut Reader::new(slice(raw, 8, 12)), "DINT") {
            Ok(status) => reply.command_status = Some(status as i32),
            Err(err) => reply.fail(err),
        }
        let encap_ok = reply.command_status == Some(0);
        match kind {
            ReplyKind::Encapsulation => {}
            ReplyKind::RegisterSession => {
                match read_u32(&mut Reader::new(slice(raw, 4, 8)), "UDINT") {
                    Ok(session) => reply.session = Some(session),
                    Err(err) => reply.fail(err),
                }
            }
            ReplyKind::SendRRData if encap_ok => reply.parse_cip(raw, 40),
            ReplyKind::SendUnitData if encap_ok => reply.parse_cip(raw, 46),
            ReplyKind::ListIdentity if encap_ok => {
                let data = slice(raw, 26, raw.len());
                reply.data = Some(data.to_vec());
                match ListIdentity::decode(&mut Reader::new(data)) {
                    Ok(identity) => reply.identity = Some(identity),
                    Err(Error::BufferEmpty) => reply.fail(String::new()),
                    // Python's struct decode wraps a partial read as an error about the whole item buffer
                    Err(_) => reply.fail(format!(
                        "Error unpacking {} as ListIdentityObject",
                        py_bytes_repr(data)
                    )),
                }
            }
            _ => {}
        }
        reply
    }

    fn fail(&mut self, err: String) {
        self.parse_error = Some(format!("Failed to parse reply - {err}"));
    }

    /// Service at `at`, general status at `at + 2`, extended status size at `at + 3`.
    fn parse_cip(&mut self, raw: &[u8], at: usize) {
        self.service = raw
            .get(at)
            .map(|s| s & 0x7F)
            .filter(|s| KNOWN_SERVICES.contains(s));
        let result = read_u8(slice(raw, at + 2, at + 3)).and_then(|status| {
            self.service_status = Some(status);
            read_u8(slice(raw, at + 3, at + 4))
        });
        match result {
            Ok(words) => {
                self.data = Some(slice(raw, at + 4 + 2 * usize::from(words), raw.len()).to_vec())
            }
            Err(err) => self.fail(err),
        }
    }

    /// True if the reply parsed, the encapsulation status is success and, for CIP replies, the general status
    /// is success (or partial data of a multi-packet service, connected only).
    pub fn is_valid(&self) -> bool {
        let base =
            self.parse_error.is_none() && self.command.is_some() && self.command_status == Some(0);
        base && match self.kind {
            ReplyKind::SendUnitData => {
                self.service_status == Some(SUCCESS)
                    || (self.service_status == Some(INSUFFICIENT_PACKETS)
                        && self
                            .service
                            .is_some_and(|s| MULTI_PACKET_SERVICES.contains(&s)))
            }
            ReplyKind::SendRRData => self.service_status == Some(SUCCESS),
            ReplyKind::RegisterSession => self.session.is_some(),
            ReplyKind::Encapsulation | ReplyKind::ListIdentity => true,
        }
    }

    /// The error message, None if valid.
    ///
    /// Python's error property raises when an extended status is truncated; this gives the status text alone.
    pub fn error(&self) -> Option<String> {
        if self.is_valid() {
            return None;
        }
        if let Some(err) = &self.parse_error {
            return Some(err.clone());
        }
        if let Some(status) = self.command_status.filter(|&s| s != 0) {
            return Some(encap_text(status));
        }
        if let Some(status) = self.service_status.filter(|&s| s != 0) {
            let at = match self.kind {
                ReplyKind::SendRRData => 42,
                ReplyKind::SendUnitData => 48,
                _ => return Some("Unknown Error".into()),
            };
            let text = service_status_text(status);
            let raw = self.raw.as_deref().unwrap_or_default();
            return Some(match extended_status_text(raw, at) {
                Some(ext) => format!("{text} - {ext}"),
                None => text,
            });
        }
        Some("Unknown Error".into())
    }
}

/// The encapsulation status text, formatting a negative (DINT) status like Python's `{:#06x}`.
fn encap_text(status: i32) -> String {
    if status >= 0 {
        return encap_status_text(status as u32);
    }
    let digits = format!("{:x}", status.unsigned_abs());
    format!("Unknown encapsulation status (-0x{digits:0>3})")
}

/// A Multiple Service Packet reply and the replies of its services.
#[derive(Clone, Debug, PartialEq)]
pub struct MultiServiceReply {
    /// The reply as a whole.
    pub reply: Reply,
    /// One reply per service, each parsed as a SendUnitData reply (padded so its service is at 46); empty
    /// when the whole reply failed.
    pub replies: Vec<Reply>,
}

/// Parses a Multiple Service Packet reply to `count` services. Its services follow only a general status of
/// 0x00, 0x06 or 0x1E (an embedded service failed).
pub fn parse_multi_service_reply(raw: &[u8], count: usize) -> MultiServiceReply {
    let mut reply = Reply::parse(ReplyKind::SendUnitData, raw);
    let mut replies = Vec::new();
    if matches!(reply.service_status, Some(0x00 | 0x06 | 0x1E)) {
        match split_multi(reply.data.as_deref(), count) {
            Ok(parts) => replies = parts,
            Err(err) => {
                reply.parse_error = Some(format!("Failed to parse multi-service reply - {err}"))
            }
        }
    }
    MultiServiceReply { reply, replies }
}

fn split_multi(data: Option<&[u8]>, count: usize) -> std::result::Result<Vec<Reply>, String> {
    let data = data.ok_or("Error unpacking None as UINT")?;
    let num = read_u16(&mut Reader::new(data), "UINT")?;
    if usize::from(num) != count {
        return Err("reply count does not match the requested services".into());
    }
    let mut bounds = Vec::with_capacity(count + 1);
    for i in 0..count {
        bounds.push(usize::from(read_u16(
            &mut Reader::new(slice(data, 2 + 2 * i, 4 + 2 * i)),
            "UINT",
        )?));
    }
    bounds.push(data.len());
    if bounds.windows(2).any(|w| w[1] < w[0] + 4) {
        return Err("invalid service reply offsets".into()); // a reply has at least a 4-byte header
    }
    Ok(bounds
        .windows(2)
        .map(|w| {
            let mut padded = vec![0; 46];
            padded.extend(slice(data, w[0], w[1]));
            Reply::parse(ReplyKind::SendUnitData, &padded)
        })
        .collect())
}

/// The tag table version of a valid Get Attribute List reply; on a malformed one, None with the reason
/// recorded in `reply.parse_error` (which makes the reply invalid).
pub fn parse_tag_table_version(reply: &mut Reply) -> Option<TagTableVersion> {
    if !reply.is_valid() {
        return None;
    }
    let data = reply.data.clone().unwrap_or_default();
    match decode_tag_table_version(&data) {
        Ok(version) => Some(version),
        Err(err) => {
            reply.fail(err);
            None
        }
    }
}

fn decode_tag_table_version(data: &[u8]) -> std::result::Result<TagTableVersion, String> {
    let mut r = Reader::new(data);
    read_u16(&mut r, "UINT")?; // attribute count
    let mut values = [0i32; 5];
    for (i, (attribute, size)) in [(1u16, 2), (2, 2), (3, 4), (4, 4), (10, 4)]
        .into_iter()
        .enumerate()
    {
        let id = read_u16(&mut r, "UINT")?;
        let status = read_u16(&mut r, "UINT")?;
        if (id, status) != (attribute, 0) {
            return Err(format!("attribute {attribute} was not returned"));
        }
        values[i] = if size == 2 {
            i32::from(read_u16(&mut r, "INT")? as i16)
        } else {
            read_u32(&mut r, "DINT")? as i32
        };
    }
    // invariant: the INT attributes were read as i16 above
    Ok((
        values[0] as i16,
        values[1] as i16,
        values[2],
        values[3],
        values[4],
    ))
}

/// The error of a failed reply as a [`TagError`]: COMM when the reply was lost, unparseable or an
/// encapsulation error, else classified by its general and first extended status. `message` replaces the
/// reply's error text (a valid reply's is "None", as in Python).
pub fn response_error(reply: &Reply, message: Option<&str>) -> TagError {
    let message = message
        .map(str::to_owned)
        .or_else(|| reply.error())
        .unwrap_or_else(|| "None".into());
    let status = match reply.service_status {
        Some(status) if reply.parse_error.is_none() && reply.command_status == Some(0) => status,
        _ => return TagError::new(message, ErrorKind::Comm),
    };
    let at = if reply.command.as_deref() == Some(&SEND_RR_DATA[..]) {
        42
    } else {
        48
    };
    let ext = extended_status_code(reply.raw.as_deref().unwrap_or_default(), at);
    TagError {
        message,
        kind: status_kind(status, ext),
        status: Some(status),
        ext,
    }
}
