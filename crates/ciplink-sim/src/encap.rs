//! EtherNet/IP encapsulation: sessions, the common packet format, the Connection Manager (Forward Open, Large
//! Forward Open, Forward Close, Unconnected Send) and connected messages.

use crate::cip::{Faults, reply};
use crate::identity::Identity;
use crate::logix::Logix;
use crate::path::{Seg, attribute, class_instance, parse_path, parse_request};
use crate::slc::Slc;
use std::time::Duration;

/// Reply size limit of unconnected (UCMM) messages.
const UCMM_LIMIT: usize = 504;
const HEADER: usize = 24;
/// The most bytes of a connected reply message that fit an encapsulation frame, whose length is 16 bits: the
/// common packet format around it (header 8, address item 8, data item header 4) and the sequence count 2.
const MAX_CONNECTED_REPLY: usize = u16::MAX as usize - 22;

const LIST_SERVICES: u16 = 0x0004;
const LIST_IDENTITY: u16 = 0x0063;
const LIST_INTERFACES: u16 = 0x0064;
const REGISTER_SESSION: u16 = 0x0065;
const UNREGISTER_SESSION: u16 = 0x0066;
const SEND_RR_DATA: u16 = 0x006F;
const SEND_UNIT_DATA: u16 = 0x0070;

/// Encapsulation status: invalid or unsupported command, bad data, invalid session, invalid length, version.
const INVALID_COMMAND: u32 = 0x01;
const BAD_DATA: u32 = 0x03;
const INVALID_SESSION: u32 = 0x64;
const INVALID_LENGTH: u32 = 0x65;
const UNSUPPORTED_VERSION: u32 = 0x69;

pub(crate) enum Device {
    Logix(Box<Logix>),
    Slc(Box<Slc>),
}

impl Device {
    fn identity(&self) -> &Identity {
        match self {
            Device::Logix(l) => &l.identity,
            Device::Slc(s) => &s.identity,
        }
    }

    fn slot(&self) -> u8 {
        match self {
            Device::Logix(l) => l.slot,
            Device::Slc(_) => 0,
        }
    }

    fn large_forward_open(&self) -> bool {
        match self {
            Device::Logix(l) => l.large_forward_open,
            Device::Slc(_) => false,
        }
    }

    fn max_connection_size(&self) -> usize {
        match self {
            Device::Logix(l) => usize::from(l.max_connection_size),
            Device::Slc(_) => 504,
        }
    }

    fn module(&self, slot: u8) -> Option<&Identity> {
        match self {
            Device::Logix(l) => l.modules.iter().find(|(s, _)| *s == slot).map(|(_, i)| i),
            Device::Slc(_) => None,
        }
    }

    fn network_device(&self, ip: &[u8]) -> Option<&Identity> {
        match self {
            Device::Logix(l) => l
                .network
                .iter()
                .find(|(a, _)| a.as_bytes() == ip)
                .map(|(_, i)| i),
            Device::Slc(_) => None,
        }
    }

    /// Answers a message received on a connection (its O->T ID); a Logix sees the connection while it answers
    /// (metadata authentication is per connection), and None for unconnected messages.
    fn message_on(
        &mut self,
        connection: u32,
        message: &[u8],
        limit: usize,
        faults: &Faults,
    ) -> Vec<u8> {
        if let Device::Logix(l) = self {
            l.connection = Some(connection);
        }
        let out = self.message(message, limit, faults);
        if let Device::Logix(l) = self {
            l.connection = None;
        }
        out
    }

    /// An unconnected message to the device itself: the Port Object (a Logix's backplane and EtherNet/IP
    /// ports, Get_Attribute_Single only), anything else is the device's.
    fn unconnected_message(&mut self, message: &[u8], faults: &Faults) -> Vec<u8> {
        match (&*self, parse_request(message)) {
            (Device::Logix(l), Some(r))
                if matches!(class_instance(&r.path), Some((0xF4 | 0xF5, _))) =>
            {
                port_object(l, r.service, &r.path)
            }
            _ => self.message(message, UCMM_LIMIT, faults),
        }
    }

    fn message(&mut self, message: &[u8], limit: usize, faults: &Faults) -> Vec<u8> {
        match self {
            Device::Logix(l) => l.message(message, limit, faults),
            Device::Slc(s) => s.message(message, limit, faults),
        }
    }
}

/// The Port Object (class 0xF4) and TCP/IP Interface Object (class 0xF5) of a Logix: port 1 the backplane
/// (its node range is the chassis), port 2 the EtherNet/IP port, which reports no node range.
fn port_object(logix: &Logix, service: u8, path: &[Seg]) -> Vec<u8> {
    if service != 0x0E {
        return reply(service, 0x08, &[], &[]);
    }
    let (class, instance) = class_instance(path).unwrap_or_default();
    if class == 0xF5 {
        return match (instance, attribute(path)) {
            (1, Some(5)) => {
                let (ip, mask) = logix.ip;
                let mut data = [u32::from(ip), u32::from(mask), 0, 0, 0]
                    .map(u32::to_le_bytes)
                    .concat();
                data.extend([0, 0]); // no domain name
                reply(service, 0, &[], &data)
            }
            (1, _) => reply(service, 0x14, &[], &[]),
            _ => reply(service, 0x16, &[], &[]),
        };
    }
    let short_string = |s: &str| [&[s.len() as u8], s.as_bytes()].concat();
    let ip = logix.ip.0.to_string();
    let data = match (instance, attribute(path)) {
        (0, Some(2 | 3)) => Some(2u16.to_le_bytes().to_vec()), // max instance, instance count
        (1, Some(1)) => Some(1u16.to_le_bytes().to_vec()),
        (1, Some(2)) => Some(1u16.to_le_bytes().to_vec()),
        (1, Some(4)) => Some(short_string("Backplane")),
        (1, Some(7)) => Some(vec![0x01, logix.slot]),
        (1, Some(8)) => Some(
            [0u16, u16::from(logix.chassis_size).saturating_sub(1)]
                .map(u16::to_le_bytes)
                .concat(),
        ),
        (2, Some(1)) => Some(4u16.to_le_bytes().to_vec()),
        (2, Some(2)) => Some(2u16.to_le_bytes().to_vec()),
        (2, Some(3)) => Some(vec![0x02, 0x00, 0x20, 0xF6, 0x24, 0x01]), // the Ethernet Link Object
        (2, Some(4)) => Some(short_string("A")),
        (2, Some(7)) => {
            let mut segment = [&[0x12, ip.len() as u8], ip.as_bytes()].concat();
            segment.resize(segment.len().next_multiple_of(2), 0);
            Some(segment)
        }
        (0..=2, _) => None,
        _ => return reply(service, 0x16, &[], &[]), // object does not exist
    };
    match data {
        Some(data) => reply(service, 0, &[], &data),
        None => reply(service, 0x14, &[], &[]), // attribute not supported
    }
}

/// Called before each request with the request's index: edits the controller between requests.
pub(crate) type Hook = Box<dyn FnMut(&mut Logix, u64) + Send>;

/// The state shared by every connection to a simulator.
pub(crate) struct Inner {
    pub device: Device,
    pub faults: Faults,
    pub hook: Option<Hook>,
    pub log: Vec<Vec<u8>>,
    pub recording: bool,
    pub requests: u64,
    next_session: u32,
    next_connection: u32,
}

/// A CIP connection opened by a Forward Open.
#[derive(Clone, Debug)]
struct Connection {
    o_t: u32,
    t_o: u32,
    serial: u16,
    vendor: u16,
    originator_serial: u32,
    /// O->T and T->O connection sizes: the most bytes of a request and of a reply (sequence count included).
    request_size: usize,
    reply_size: usize,
    /// The sequence count and reply of the last request: a class 3 target answers a request that repeats the
    /// sequence count with the last reply without executing it again, so a driver that reuses a sequence
    /// count sees its write skipped, as on a controller.
    last: Option<(u16, Vec<u8>)>,
}

/// The state of one client connection (a TCP connection or an in-memory transport).
#[derive(Debug, Default)]
pub(crate) struct Session {
    pub handle: u32,
    pub port: u16,
    connections: Vec<Connection>,
}

impl Session {
    pub(crate) fn new(port: u16) -> Self {
        Session {
            handle: 0,
            port,
            connections: Vec::new(),
        }
    }
}

/// What a request gets back.
pub(crate) enum Outcome {
    Reply(Vec<u8>),
    /// No reply: UnRegisterSession closes the connection, a dropped reply or a frame that is not one leaves
    /// it open.
    Silent,
    Close,
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn encap(command: u16, session: u32, status: u32, context: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.extend(command.to_le_bytes());
    out.extend((data.len() as u16).to_le_bytes());
    out.extend(session.to_le_bytes());
    out.extend(status.to_le_bytes());
    out.extend(context);
    out.extend(0u32.to_le_bytes());
    out.extend(data);
    out
}

/// The items of a common packet format (interface handle, timeout, item count, items).
fn cpf_items(data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let count = usize::from(u16_at(data, 6)?);
    let mut pos = 8;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = u16_at(data, pos)?;
        let size = usize::from(u16_at(data, pos + 2)?);
        items.push((kind, data.get(pos + 4..pos + 4 + size)?));
        pos += 4 + size;
    }
    (pos == data.len()).then_some(items)
}

fn cpf(items: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = vec![0u8; 6];
    out.extend((items.len() as u16).to_le_bytes());
    for (kind, data) in items {
        out.extend(kind.to_le_bytes());
        out.extend((data.len() as u16).to_le_bytes());
        out.extend(*data);
    }
    out
}

impl Inner {
    pub(crate) fn new(device: Device) -> Self {
        Inner {
            device,
            faults: Faults::default(),
            hook: None,
            log: Vec::new(),
            recording: false,
            requests: 0,
            next_session: 0x0001_0001,
            next_connection: 0x4F00_0001,
        }
    }

    /// Handles one request frame; returns what to send back and the delay to wait first.
    pub(crate) fn handle(&mut self, session: &mut Session, frame: &[u8]) -> (Outcome, Duration) {
        if self.recording {
            self.log.push(frame.to_vec());
        }
        let index = self.requests;
        self.requests += 1;
        if let (Some(hook), Device::Logix(logix)) = (&mut self.hook, &mut self.device) {
            hook(logix, index);
        }
        let mut outcome = self.frame(session, frame);
        if matches!(outcome, Outcome::Reply(_)) && self.faults.drop_replies > 0 {
            self.faults.drop_replies -= 1;
            outcome = Outcome::Silent;
        }
        (outcome, self.faults.delay)
    }

    fn frame(&mut self, session: &mut Session, frame: &[u8]) -> Outcome {
        if frame.len() < HEADER {
            return Outcome::Close;
        }
        let command = u16::from_le_bytes([frame[0], frame[1]]);
        let length = usize::from(u16::from_le_bytes([frame[2], frame[3]]));
        let handle = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let context = &frame[12..20];
        let data = &frame[HEADER..];
        let answer = |status: u32, data: &[u8]| {
            Outcome::Reply(encap(command, handle, status, context, data))
        };
        if data.len() != length {
            return answer(INVALID_LENGTH, &[]);
        }
        match command {
            LIST_SERVICES => {
                let mut item = 1u16.to_le_bytes().to_vec(); // version
                item.extend(0x0120u16.to_le_bytes()); // supports CIP over TCP and UDP class 0/1
                item.extend(b"Communications\0\0");
                let mut out = 1u16.to_le_bytes().to_vec();
                out.extend(0x0100u16.to_le_bytes());
                out.extend((item.len() as u16).to_le_bytes());
                out.extend(item);
                answer(0, &out)
            }
            LIST_IDENTITY => answer(0, &self.device.identity().list_identity(session.port)),
            LIST_INTERFACES => answer(0, &0u16.to_le_bytes()),
            REGISTER_SESSION => {
                if data.len() != 4 {
                    return answer(INVALID_LENGTH, &[]);
                }
                if u16_at(data, 0) != Some(1) {
                    return answer(UNSUPPORTED_VERSION, data);
                }
                if session.handle != 0 {
                    return answer(INVALID_COMMAND, data);
                }
                session.handle = self.next_session;
                self.next_session = self.next_session.wrapping_add(0x0001_0001).max(1);
                Outcome::Reply(encap(command, session.handle, 0, context, data))
            }
            UNREGISTER_SESSION => {
                session.handle = 0;
                session.connections.clear();
                Outcome::Close
            }
            SEND_RR_DATA | SEND_UNIT_DATA => {
                if session.handle == 0 || handle != session.handle {
                    return answer(INVALID_SESSION, &[]);
                }
                let Some(items) = cpf_items(data) else {
                    return answer(BAD_DATA, &[]);
                };
                let body = if command == SEND_RR_DATA {
                    match items.as_slice() {
                        [(0x0000, []), (0x00B2, message)] => {
                            let out = self.unconnected(session, message);
                            cpf(&[(0x0000, &[]), (0x00B2, &out)])
                        }
                        _ => return answer(BAD_DATA, &[]),
                    }
                } else {
                    match items.as_slice() {
                        [(0x00A1, id), (0x00B1, message)]
                            if id.len() == 4 && message.len() >= 2 =>
                        {
                            let o_t = u32::from_le_bytes([id[0], id[1], id[2], id[3]]);
                            let sequence = u16::from_le_bytes([message[0], message[1]]);
                            let (t_o, out) = self.connected(session, o_t, sequence, &message[2..]);
                            let mut data = message[..2].to_vec(); // the sequence count is echoed
                            data.extend(out);
                            cpf(&[(0x00A1, &t_o.to_le_bytes()), (0x00B1, &data)])
                        }
                        _ => return answer(BAD_DATA, &[]),
                    }
                };
                answer(0, &body)
            }
            _ => answer(INVALID_COMMAND, &[]),
        }
    }

    fn connected(
        &mut self,
        session: &mut Session,
        o_t: u32,
        sequence: u16,
        message: &[u8],
    ) -> (u32, Vec<u8>) {
        let service = message.first().copied().unwrap_or(0);
        let Some(c) = session.connections.iter_mut().find(|c| c.o_t == o_t) else {
            return (0, reply(service, 0x01, &[0x0107], &[]));
        };
        if let Some((last, out)) = &c.last
            && *last == sequence
        {
            return (c.t_o, out.clone());
        }
        let out = if message.len() + 2 > c.request_size {
            // a request bigger than the connection is refused, as a driver that packs too much would be
            reply(service, 0x15, &[], &[])
        } else {
            self.device.message_on(
                o_t,
                message,
                c.reply_size.saturating_sub(2).min(MAX_CONNECTED_REPLY),
                &self.faults,
            )
        };
        c.last = Some((sequence, out.clone()));
        (c.t_o, out)
    }

    fn unconnected(&mut self, session: &mut Session, message: &[u8]) -> Vec<u8> {
        let service = message.first().copied().unwrap_or(0);
        let Some(request) = parse_request(message) else {
            return reply(service, 0x04, &[], &[]);
        };
        if class_instance(&request.path) != Some((0x06, 1)) {
            return self.device.unconnected_message(message, &self.faults);
        }
        if let Some((general, extended)) = self.faults.service_status(service, Some(0x06)) {
            return reply(service, general, &extended, &[]);
        }
        let result = match service {
            0x54 | 0x5B => self.forward_open(session, service == 0x5B, request.data),
            0x4E => self.forward_close(session, request.data),
            0x52 => return self.unconnected_send(request.data),
            _ => Err((0x08, Vec::new())),
        };
        match result {
            Ok(data) => reply(service, 0, &[], &data),
            Err((general, extended)) => reply(service, general, &extended, &[]),
        }
    }

    /// A route to this device: none, or the backplane port and its slot, then the Message Router.
    fn check_route(&self, path: &[u8]) -> Result<(), (u8, Vec<u16>)> {
        let segments = parse_path(path).ok_or((0x01, vec![0x0315]))?;
        let ports = match segments.as_slice() {
            [ports @ .., Seg::Class(0x02), Seg::Instance(1)] => ports,
            _ => return Err((0x01, vec![0x0315])),
        };
        match ports {
            [] => Ok(()),
            [Seg::Port { port: 1, link }] if link.as_slice() == [self.device.slot()] => Ok(()),
            _ => Err((0x01, vec![0x0312])),
        }
    }

    fn forward_open(
        &mut self,
        session: &mut Session,
        large: bool,
        data: &[u8],
    ) -> Result<Vec<u8>, (u8, Vec<u16>)> {
        if large && !self.device.large_forward_open() {
            return Err((0x08, Vec::new()));
        }
        let short = || (0x13, Vec::new());
        let params = if large { 4 } else { 2 };
        let t_o = u32_at(data, 6).ok_or_else(short)?;
        let serial = u16_at(data, 10).ok_or_else(short)?;
        let vendor = u16_at(data, 12).ok_or_else(short)?;
        let originator_serial = u32_at(data, 14).ok_or_else(short)?;
        let o_t_rpi = u32_at(data, 22).ok_or_else(short)?;
        let read_params = |at: usize| -> Option<usize> {
            if large {
                u32_at(data, at).map(|p| (p & 0xFFFF) as usize)
            } else {
                u16_at(data, at).map(|p| usize::from(p & 0x01FF))
            }
        };
        let o_t_size = read_params(26).ok_or_else(short)?;
        let t_o_rpi = u32_at(data, 26 + params).ok_or_else(short)?;
        let t_o_size = read_params(30 + params).ok_or_else(short)?;
        let path_at = 30 + 2 * params + 1; // after the transport class trigger
        let words = usize::from(*data.get(path_at).ok_or_else(short)?);
        let path = data
            .get(path_at + 1..path_at + 1 + 2 * words)
            .ok_or_else(short)?;
        let max = self.device.max_connection_size();
        if o_t_size > max || t_o_size > max {
            return Err((0x01, vec![0x0109, max as u16]));
        }
        self.check_route(path)?;
        if session.connections.iter().any(|c| {
            (c.serial, c.vendor, c.originator_serial) == (serial, vendor, originator_serial)
        }) {
            return Err((0x01, vec![0x0100]));
        }
        let o_t = self.next_connection;
        self.next_connection = self.next_connection.wrapping_add(1);
        session.connections.push(Connection {
            o_t,
            t_o,
            serial,
            vendor,
            originator_serial,
            request_size: o_t_size,
            reply_size: t_o_size,
            last: None,
        });
        let mut out = Vec::with_capacity(26);
        out.extend(o_t.to_le_bytes());
        out.extend(t_o.to_le_bytes());
        out.extend(serial.to_le_bytes());
        out.extend(vendor.to_le_bytes());
        out.extend(originator_serial.to_le_bytes());
        out.extend(o_t_rpi.to_le_bytes());
        out.extend(t_o_rpi.to_le_bytes());
        out.extend([0, 0]); // application reply size, reserved
        Ok(out)
    }

    fn forward_close(
        &mut self,
        session: &mut Session,
        data: &[u8],
    ) -> Result<Vec<u8>, (u8, Vec<u16>)> {
        let short = || (0x13, Vec::new());
        let serial = u16_at(data, 2).ok_or_else(short)?;
        let vendor = u16_at(data, 4).ok_or_else(short)?;
        let originator_serial = u32_at(data, 6).ok_or_else(short)?;
        let words = usize::from(*data.get(10).ok_or_else(short)?);
        let path = data.get(12..12 + 2 * words).ok_or_else(short)?;
        self.check_route(path)?;
        let index = session
            .connections
            .iter()
            .position(|c| {
                (c.serial, c.vendor, c.originator_serial) == (serial, vendor, originator_serial)
            })
            .ok_or((0x01, vec![0x0107]))?;
        session.connections.remove(index);
        let mut out = Vec::with_capacity(10);
        out.extend(serial.to_le_bytes());
        out.extend(vendor.to_le_bytes());
        out.extend(originator_serial.to_le_bytes());
        out.extend([0, 0]);
        Ok(out)
    }

    /// Unconnected Send: the embedded message is answered by the device in the slot its route names.
    fn unconnected_send(&mut self, data: &[u8]) -> Vec<u8> {
        let fail = |general, extended: &[u16]| reply(0x52, general, extended, &[]);
        let Some(size) = u16_at(data, 2).map(usize::from) else {
            return fail(0x13, &[]);
        };
        let Some(message) = data.get(4..4 + size) else {
            return fail(0x13, &[]);
        };
        let route_at = 4 + size + size % 2;
        let Some(words) = data.get(route_at).map(|w| usize::from(*w)) else {
            return fail(0x13, &[]);
        };
        let Some(route) = data.get(route_at + 2..route_at + 2 + 2 * words) else {
            return fail(0x13, &[]);
        };
        let identity = match parse_path(route).as_deref() {
            Some([Seg::Port { port: 1, link }]) if link.len() == 1 => {
                if link[0] == self.device.slot() {
                    return self.device.unconnected_message(message, &self.faults);
                }
                match self.device.module(link[0]) {
                    Some(identity) => identity,
                    None => return fail(0x01, &[0x0312]),
                }
            }
            // a device on the EtherNet/IP network; at any other address the bridge's request times out
            Some([Seg::Port { port: 2, link }]) => match self.device.network_device(link) {
                Some(identity) => identity,
                None => return fail(0x01, &[0x0204]),
            },
            _ => return fail(0x01, &[0x0312]),
        };
        let service = message.first().copied().unwrap_or(0);
        match parse_request(message).map(|r| (class_instance(&r.path), r.service)) {
            Some((Some((0x01, 1)), 0x01)) => reply(service, 0, &[], &identity.attributes_all()),
            Some((Some((0x01, 1)), _)) => reply(service, 0x08, &[], &[]),
            _ => reply(service, 0x05, &[], &[]),
        }
    }
}
