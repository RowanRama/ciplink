//! The Modbus protocol state on the session core, and the public [`ModbusDriver`].

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::address::{Area, Target, WordOrder, resolve};
use super::frame::{
    MBAP_HEADER, RTU_MAX, mbap_frame, parse_mbap, rtu_crc_ok, rtu_frame, rtu_reply_len,
};
use super::link::{Endpoint, Link, ModbusConnector, modbus_connector};
use super::map::TagMap;
use super::pdu::{self, ReplyError};
use super::plan::{Block, Limits, Span, plan};
use super::value::{decode_bits, decode_registers, encode_bits, encode_bool, encode_registers};
use crate::cip::TagResult;
use crate::session::{
    ConnectionCallback, ConnectionState, Handle, Protocol, Session, SessionOptions,
    SubscribeOptions, Subscription,
};
use crate::{Error, ErrorKind, Result, TagError, Value};

/// How a Modbus driver reads and writes.
#[derive(Clone, Debug, PartialEq)]
pub struct ModbusOptions {
    /// Tag names, types and descriptions; None: plain addresses only.
    pub map: Option<TagMap>,
    /// Reply timeout. Default 1 s (Modbus devices answer in milliseconds; a dead RTU unit holds the bus this long).
    pub socket_timeout: Duration,
    /// Most registers in one read, 1..=125. Default 125.
    pub max_registers: u16,
    /// Most coils or discrete inputs in one read, 1..=2000. Default 2000.
    pub max_bits: u16,
    /// Most unrequested registers or bits between two tags read in one request. Default 8.
    pub max_gap: u16,
    /// Word order of tags without one. Default ABCD.
    pub word_order: WordOrder,
    /// Always FC15/FC16, never FC05/FC06. Default false.
    pub write_multiple: bool,
    /// The keep-alive reads this plain address instead of sending FC08. Default None.
    pub keep_alive_address: Option<String>,
}

impl Default for ModbusOptions {
    fn default() -> Self {
        ModbusOptions {
            map: None,
            socket_timeout: Duration::from_secs(1),
            max_registers: pdu::MAX_READ_REGISTERS,
            max_bits: pdu::MAX_READ_BITS,
            max_gap: 8,
            word_order: WordOrder::Abcd,
            write_multiple: false,
            keep_alive_address: None,
        }
    }
}

/// Read Device Identification (FC43 / MEI 14) objects; None where the device has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Object 0.
    pub vendor_name: String,
    /// Object 1.
    pub product_code: String,
    /// Object 2 (major.minor revision).
    pub revision: String,
    /// Object 3.
    pub vendor_url: Option<String>,
    /// Object 4.
    pub product_name: Option<String>,
    /// Object 5.
    pub model_name: Option<String>,
    /// Object 6.
    pub user_application_name: Option<String>,
}

// ------------------------------------------------------------------------------------------------ link I/O

/// Why a request got no usable reply.
enum LinkError {
    /// Nothing (more) within the deadline.
    Timeout,
    /// RTU: a reply with a bad CRC, unit or function; the link stays.
    BadFrame(String),
    /// The socket or port failed, the peer closed it, or the stream is out of step: the link is dropped.
    Broken(String),
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn broken(e: &io::Error) -> LinkError {
    LinkError::Broken(format!("connection broken: {e}"))
}

/// Fills `buf` from `link` before `deadline`.
fn read_full(link: &mut dyn Link, buf: &mut [u8], deadline: Instant) -> Result<(), LinkError> {
    let mut at = 0;
    while at < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(LinkError::Timeout);
        }
        link.set_timeout(left).map_err(|e| broken(&e))?;
        match link.read(&mut buf[at..]) {
            Ok(0) => return Err(LinkError::Broken("connection closed by the peer".into())),
            Ok(n) => at += n,
            Err(e) if is_timeout(&e) => return Err(LinkError::Timeout),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(broken(&e)),
        }
    }
    Ok(())
}

fn send(link: &mut dyn Link, frame: &[u8], timeout: Duration) -> Result<(), LinkError> {
    link.set_timeout(timeout).map_err(|e| broken(&e))?;
    link.write_all(frame)
        .and_then(|()| link.flush())
        .map_err(|e| broken(&e))
}

fn seconds(d: Duration) -> String {
    format!("{} s", d.as_secs_f64())
}

// ------------------------------------------------------------------------------------------------ state

/// A read's data: registers or bits.
enum Data {
    Registers(Vec<u16>),
    Bits(Vec<bool>),
}

/// Why one request of a read failed.
enum Failure {
    /// The device's exception code.
    Exception(u8),
    /// Anything else, already a per-tag error.
    Other(TagError),
}

/// The Modbus protocol state: the link, the map and the options. Runs on the session thread.
pub(crate) struct Modbus {
    endpoint: Endpoint,
    /// The path's unit.
    unit: u8,
    map: Arc<TagMap>,
    /// The options; their `map` is moved to `map`.
    options: ModbusOptions,
    connector: ModbusConnector,
    link: Option<Box<dyn Link>>,
    /// Mirrors `link.is_some()` for [`ModbusDriver::connected`] without the lock.
    opened: Arc<AtomicBool>,
    transaction: u16,
    /// The last byte sent or received, for t3.5.
    last_io: Instant,
    /// RTU: drain stale input before the next request.
    drain: bool,
}

impl Modbus {
    fn set_link(&mut self, link: Option<Box<dyn Link>>) {
        self.opened.store(link.is_some(), Ordering::SeqCst);
        self.link = link;
        self.drain = false;
    }

    fn limits(&self) -> Limits {
        Limits {
            max_registers: self.options.max_registers,
            max_bits: self.options.max_bits,
            max_gap: self.options.max_gap,
        }
    }

    fn serial_baud(&self) -> Option<u32> {
        match self.endpoint {
            Endpoint::Rtu { baud, .. } => Some(baud),
            _ => None,
        }
    }

    /// t3.5, the silence between RTU frames on a serial line: 3.5 characters up to 19200 baud, 1.75 ms above.
    fn t35(&self) -> Duration {
        match self.serial_baud() {
            Some(baud) if baud <= 19200 => Duration::from_secs_f64(3.5 * 11.0 / f64::from(baud)),
            Some(_) => Duration::from_micros(1750),
            None => Duration::ZERO,
        }
    }

    /// Time `bytes` take on the serial line (zero over TCP).
    fn wire_time(&self, bytes: usize) -> Duration {
        self.serial_baud().map_or(Duration::ZERO, |baud| {
            Duration::from_secs_f64(bytes as f64 * 11.0 / f64::from(baud))
        })
    }

    fn resolve(&self, name: &str) -> Result<Target, TagError> {
        resolve(name, &self.map, self.unit, self.options.word_order)
    }

    /// One request/reply: frames `pdu` for `unit`, sends it, reads the reply and returns the reply PDU (an
    /// exception PDU included; empty for an RTU broadcast). Over TCP every failure drops the link. Over RTU a
    /// timeout or bad frame is Err(Comm) with the link kept (read and write make it a per-tag result).
    fn transact(&mut self, unit: u8, request: &[u8]) -> Result<Vec<u8>> {
        if request.is_empty() || request.len() > 253 {
            return Err(Error::request("a Modbus PDU is 1 to 253 bytes"));
        }
        if self.link.is_none() {
            return Err(Error::comm("not connected: call open() first"));
        }
        let result = if self.endpoint.is_rtu() {
            self.rtu_transact(unit, request)
        } else {
            self.tcp_transact(unit, request)
        };
        result.map_err(|error| match error {
            LinkError::Timeout => Error::comm(format!(
                "no reply from unit {unit} within {}",
                seconds(self.options.socket_timeout)
            )),
            LinkError::BadFrame(message) => Error::comm(message),
            LinkError::Broken(message) => {
                self.set_link(None);
                Error::comm(message)
            }
        })
    }

    fn tcp_transact(&mut self, unit: u8, request: &[u8]) -> Result<Vec<u8>, LinkError> {
        self.transaction = self.transaction.wrapping_add(1);
        let id = self.transaction;
        let timeout = self.options.socket_timeout;
        let result = (|| {
            let link = self
                .link
                .as_deref_mut()
                .ok_or_else(|| LinkError::Broken("not connected".into()))?;
            send(link, &mbap_frame(id, unit, request), timeout)?;
            let deadline = Instant::now() + timeout;
            // a reply with another transaction id is a late one to an earlier request: skip it
            for _ in 0..64 {
                let mut header = [0u8; MBAP_HEADER];
                read_full(link, &mut header, deadline)?;
                let mbap = parse_mbap(&header).map_err(|e| LinkError::Broken(e.to_string()))?;
                let mut reply = vec![0u8; mbap.pdu_len];
                read_full(link, &mut reply, deadline)?;
                if mbap.transaction == id {
                    return Ok(reply);
                }
                log::debug!(
                    "modbus: skipped a reply to transaction {} (waiting for {id})",
                    mbap.transaction
                );
            }
            Err(LinkError::Broken("too many stale replies".into()))
        })();
        // over TCP a timeout drops the link too: the session reconnects
        if let Err(LinkError::Timeout) = result {
            self.set_link(None);
        }
        result
    }

    /// After a failed request: reads and discards input until the line has been silent for
    /// max(t3.5, socket_timeout / 4), so a slightly late reply is gone before the next request.
    fn drain_input(&mut self) -> Result<(), LinkError> {
        let quiet = self.t35().max(self.options.socket_timeout / 4);
        let Some(link) = self.link.as_deref_mut() else {
            return Ok(());
        };
        let stop = Instant::now() + quiet.max(Duration::from_secs(1));
        link.set_timeout(quiet).map_err(|e| broken(&e))?;
        let mut sink = [0u8; RTU_MAX];
        loop {
            match link.read(&mut sink) {
                Ok(0) => return Err(LinkError::Broken("connection closed by the peer".into())),
                Ok(n) => log::debug!("modbus: drained {n} stale bytes"),
                Err(e) if is_timeout(&e) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(broken(&e)),
            }
            if Instant::now() >= stop {
                return Ok(());
            }
        }
    }

    fn rtu_transact(&mut self, unit: u8, request: &[u8]) -> Result<Vec<u8>, LinkError> {
        if self.drain {
            self.drain_input()?;
            self.drain = false;
        }
        let wait = (self.last_io + self.t35()).saturating_duration_since(Instant::now());
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        let frame = rtu_frame(unit, request);
        let timeout = self.options.socket_timeout + self.wire_time(frame.len() + RTU_MAX);
        let link = self
            .link
            .as_deref_mut()
            .ok_or_else(|| LinkError::Broken("not connected".into()))?;
        // RTU replies carry no transaction id: a late reply still in the input would be taken as this
        // request's reply, and every reply after it would be one behind
        link.discard_input().map_err(|e| broken(&e))?;
        send(link, &frame, timeout)?;
        self.last_io = Instant::now();
        if unit == 0 {
            return Ok(Vec::new()); // broadcast: no reply
        }
        let deadline = Instant::now() + timeout;
        let result = read_rtu_reply(link, unit, request[0], deadline);
        self.last_io = Instant::now();
        if matches!(result, Err(LinkError::Timeout | LinkError::BadFrame(_))) {
            self.drain = true;
        }
        result
    }
}

/// Reads one RTU reply to `function` from `unit` (by its length) and returns its PDU.
fn read_rtu_reply(
    link: &mut dyn Link,
    unit: u8,
    function: u8,
    deadline: Instant,
) -> Result<Vec<u8>, LinkError> {
    let bad = || LinkError::BadFrame(format!("bad reply from unit {unit}"));
    let mut buf = Vec::with_capacity(RTU_MAX);
    loop {
        if buf.len() >= 2 && (buf[0] != unit || buf[1] & 0x7F != function) {
            return Err(bad());
        }
        let need = rtu_reply_len(&buf).map_err(|_| bad())?;
        if need <= buf.len() {
            break;
        }
        let have = buf.len();
        buf.resize(need, 0);
        read_full(link, &mut buf[have..], deadline)?;
    }
    if !rtu_crc_ok(&buf) {
        return Err(LinkError::BadFrame(format!("bad CRC from unit {unit}")));
    }
    Ok(buf[1..buf.len() - 2].to_vec())
}

fn failed(tag: &str, data_type: Option<&str>, error: TagError) -> TagResult {
    TagResult {
        tag: tag.to_owned(),
        value: None,
        data_type: data_type.map(str::to_owned),
        error: Some(error),
    }
}

fn span(target: &Target) -> Span {
    Span {
        unit: target.unit,
        area: target.area,
        start: target.address,
        count: target.size(),
        step: if target.area.is_bits() || target.bit.is_some() {
            1
        } else {
            target.data_type.registers().max(1)
        },
    }
}

impl Modbus {
    /// True when an Err from `transact` is one request's failure (RTU, the link kept), not the whole call's.
    fn per_request(&self, error: &Error) -> bool {
        self.endpoint.is_rtu() && self.link.is_some() && matches!(error, Error::Comm(_))
    }

    /// One read request. Err only when the whole call fails (the link is lost).
    fn read_block(&mut self, block: &Block) -> Result<Result<Data, Failure>> {
        let request = pdu::read_request(block.area, block.start, block.count);
        let reply = match self.transact(block.unit, &request) {
            Ok(reply) => reply,
            Err(error) if self.per_request(&error) => {
                return Ok(Err(Failure::Other(
                    error.to_tag_error(ErrorKind::Comm, None),
                )));
            }
            Err(error) => return Err(error),
        };
        let function = block.area.read_function();
        let data = if block.area.is_bits() {
            pdu::parse_bits(function, &reply, block.count).map(Data::Bits)
        } else {
            pdu::parse_registers(function, &reply, block.count).map(Data::Registers)
        };
        Ok(data.map_err(|e| match e {
            ReplyError::Exception(code) => Failure::Exception(code),
            ReplyError::Bad => Failure::Other(self.rejected(block.unit)),
        }))
    }

    /// A reply that framed well but does not answer the request: over RTU it may be a late reply to an earlier
    /// request with the real one still coming, so the next request drains first.
    fn rejected(&mut self, unit: u8) -> TagError {
        if self.endpoint.is_rtu() {
            self.drain = true;
        }
        pdu::bad_reply(unit)
    }

    fn read_tags(&mut self, tags: &[&str]) -> Result<Vec<TagResult>> {
        let mut results: Vec<Option<TagResult>> = vec![None; tags.len()];
        let mut targets: Vec<(usize, Target)> = Vec::with_capacity(tags.len());
        for (i, tag) in tags.iter().enumerate() {
            match self.resolve(tag) {
                Ok(t) if t.unit == 0 && self.endpoint.is_rtu() => {
                    let error = TagError::new(
                        format!("'{tag}': unit 0 is broadcast and cannot be read"),
                        ErrorKind::BadRequest,
                    );
                    results[i] = Some(failed(tag, Some(t.type_name()), error));
                }
                Ok(t) => targets.push((i, t)),
                Err(error) => results[i] = Some(failed(tag, None, error)),
            }
        }
        let spans: Vec<Span> = targets.iter().map(|(_, t)| span(t)).collect();
        let limits = self.limits();
        let mut data: Vec<(Block, Data)> = Vec::new();
        let mut errors: Vec<Option<TagError>> = vec![None; targets.len()];
        for block in plan(&spans, limits) {
            if block.targets.iter().all(|&t| errors[t].is_some()) {
                continue; // the rest of a long target that already failed
            }
            match self.read_block(&block)? {
                Ok(d) => data.push((block, d)),
                Err(Failure::Exception(code @ (2 | 3))) if block.targets.len() > 1 => {
                    log::debug!(
                        "modbus: exception {code} on a read of {} targets at {} {}; reading each alone",
                        block.targets.len(),
                        block.area,
                        block.start
                    );
                    for &t in &block.targets {
                        for alone in plan(&spans[t..=t], limits) {
                            let alone = Block {
                                targets: vec![t],
                                ..alone
                            };
                            match self.read_block(&alone)? {
                                Ok(d) => data.push((alone, d)),
                                Err(failure) => {
                                    errors[t] = Some(failure_error(failure, alone.unit));
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(failure) => {
                    let error = failure_error(failure, block.unit);
                    for &t in &block.targets {
                        errors[t] = Some(error.clone());
                    }
                }
            }
        }
        for (k, (i, target)) in targets.iter().enumerate() {
            let tag = tags[*i];
            let type_name = target.type_name();
            results[*i] = Some(match errors[k].take() {
                Some(error) => failed(tag, Some(type_name), error),
                None => match gather(&data, k, target) {
                    Some(value) => TagResult {
                        tag: tag.to_owned(),
                        value: Some(value),
                        data_type: Some(type_name.to_owned()),
                        error: None,
                    },
                    None => failed(tag, Some(type_name), pdu::bad_reply(target.unit)),
                },
            });
        }
        Ok(results.into_iter().flatten().collect())
    }

    /// The request of a write, checked locally; Err is the item's result.
    fn write_request(
        &self,
        tag: &str,
        target: &Target,
        value: &Value,
    ) -> Result<Vec<u8>, TagError> {
        let bad_value = |m: String| TagError::new(format!("'{tag}': {m}"), ErrorKind::BadValue);
        let too_long = |n: usize, max: u16| {
            TagError::new(
                format!("'{tag}': {n} values do not fit one write request (at most {max})"),
                ErrorKind::BadRequest,
            )
        };
        let multiple = self.options.write_multiple;
        if target.area == Area::Coil {
            let bits = encode_bits(target, value).map_err(bad_value)?;
            let max = pdu::MAX_WRITE_BITS.min(self.options.max_bits);
            return match bits.as_slice() {
                [one] if !multiple => Ok(pdu::write_coil(target.address, *one)),
                _ if bits.len() > usize::from(max) => Err(too_long(bits.len(), max)),
                _ => Ok(pdu::write_coils(target.address, &bits)),
            };
        }
        if let Some(bit) = target.bit {
            let on = encode_bool(value).map_err(bad_value)?;
            let (and, or) = pdu::bit_masks(bit, on);
            return Ok(pdu::mask_write(target.address, and, or));
        }
        let regs = encode_registers(target, value).map_err(bad_value)?;
        let max = pdu::MAX_WRITE_REGISTERS.min(self.options.max_registers);
        match regs.as_slice() {
            [one] if !multiple => Ok(pdu::write_register(target.address, *one)),
            _ if regs.len() > usize::from(max) => Err(too_long(regs.len(), max)),
            _ => Ok(pdu::write_registers(target.address, &regs)),
        }
    }

    /// One write item. Err only when the whole call fails (the link is lost).
    fn write_item(&mut self, tag: &str, value: &Value) -> Result<TagResult> {
        let target = match self.resolve(tag) {
            Ok(target) => target,
            Err(error) => return Ok(failed(tag, None, error)),
        };
        let type_name = target.type_name();
        if !target.writable {
            let error = TagError::new(format!("'{tag}' is read-only"), ErrorKind::Access);
            return Ok(failed(tag, Some(type_name), error));
        }
        let request = match self.write_request(tag, &target, value) {
            Ok(request) => request,
            Err(error) => return Ok(failed(tag, Some(type_name), error)),
        };
        let reply = match self.transact(target.unit, &request) {
            Ok(reply) => reply,
            Err(error) if self.per_request(&error) => {
                let message = format!("{error} (the write may have been applied)");
                let error = TagError::new(message, ErrorKind::Comm);
                return Ok(failed(tag, Some(type_name), error));
            }
            Err(error) => return Err(error),
        };
        let broadcast = target.unit == 0 && self.endpoint.is_rtu();
        let checked = if broadcast {
            Ok(())
        } else {
            pdu::check_write_reply(&request, &reply)
        };
        Ok(match checked {
            Ok(()) => TagResult {
                tag: tag.to_owned(),
                value: Some(value.clone()),
                data_type: Some(type_name.to_owned()),
                error: None,
            },
            Err(ReplyError::Exception(code)) => {
                let mut error = pdu::exception_error(code, target.unit, true);
                if code == 1 && request[0] == 22 {
                    error.message.push_str(
                        ": the device does not support FC22 (mask write), which a bit write needs",
                    );
                }
                failed(tag, Some(type_name), error)
            }
            Err(ReplyError::Bad) => {
                let mut error = self.rejected(target.unit);
                if self.endpoint.is_rtu() {
                    error.message.push_str(" (the write may have been applied)");
                }
                failed(tag, Some(type_name), error)
            }
        })
    }

    /// Read Device Identification pages of `code` (1 basic, 2 regular) into `objects`; the conformity level.
    fn device_id_pages(
        &mut self,
        unit: u8,
        code: u8,
        objects: &mut BTreeMap<u8, Vec<u8>>,
    ) -> Result<u8> {
        let mut object = 0u8;
        let mut seen = 0usize;
        loop {
            let reply = self.transact(unit, &pdu::read_device_id(code, object))?;
            let page = match pdu::parse_device_id(&reply) {
                Ok(page) => page,
                Err(ReplyError::Exception(code)) => {
                    return Err(pdu::exception_response(code, unit));
                }
                Err(ReplyError::Bad) => {
                    self.rejected(unit);
                    return Err(Error::comm("bad reply"));
                }
            };
            seen += page.objects.len();
            objects.extend(page.objects);
            match page.next {
                None => return Ok(page.conformity),
                Some(next) if next > object && seen < 256 => object = next,
                Some(_) => return Err(Error::comm("bad reply")),
            }
        }
    }

    fn device_info(&mut self, unit: Option<u8>) -> Result<DeviceInfo> {
        let unit = unit.unwrap_or(self.unit);
        let mut objects = BTreeMap::new();
        let conformity = self.device_id_pages(unit, 1, &mut objects)?;
        if matches!(conformity, 0x02 | 0x03 | 0x82 | 0x83) {
            self.device_id_pages(unit, 2, &mut objects)?;
        }
        let mut text = |id: u8| {
            objects
                .remove(&id)
                .map(|v| String::from_utf8_lossy(&v).into_owned())
        };
        Ok(DeviceInfo {
            vendor_name: text(0).unwrap_or_default(),
            product_code: text(1).unwrap_or_default(),
            revision: text(2).unwrap_or_default(),
            vendor_url: text(3),
            product_name: text(4),
            model_name: text(5),
            user_application_name: text(6),
        })
    }

    fn send_pdu(&mut self, unit: Option<u8>, request: &[u8]) -> Result<Vec<u8>> {
        let unit = unit.unwrap_or(self.unit);
        let reply = self.transact(unit, request)?;
        match reply.as_slice() {
            [function, code, ..] if function & 0x80 != 0 => {
                Err(pdu::exception_response(*code, unit))
            }
            _ => Ok(reply),
        }
    }
}

fn failure_error(failure: Failure, unit: u8) -> TagError {
    match failure {
        Failure::Exception(code) => pdu::exception_error(code, unit, false),
        Failure::Other(error) => error,
    }
}

/// The value of target `k` from the blocks that serve it; None if they do not cover it.
fn gather(data: &[(Block, Data)], k: usize, target: &Target) -> Option<Value> {
    let start = usize::from(target.address);
    let end = start + usize::from(target.size());
    let mut regs = Vec::new();
    let mut bits = Vec::new();
    for (block, d) in data.iter().filter(|(b, _)| b.targets.contains(&k)) {
        let first = usize::from(block.start);
        let from = start.max(first) - first;
        let to = end.min(first + usize::from(block.count)) - first;
        match d {
            Data::Registers(r) => regs.extend_from_slice(r.get(from..to)?),
            Data::Bits(b) => bits.extend_from_slice(b.get(from..to)?),
        }
    }
    if target.area.is_bits() {
        (bits.len() == end - start).then(|| decode_bits(target, &bits))
    } else {
        (regs.len() == end - start).then(|| decode_registers(target, &regs))
    }
}

impl Protocol for Modbus {
    fn open(&mut self) -> Result<bool> {
        self.set_link(None);
        let link = (self.connector)(&self.endpoint, self.options.socket_timeout)?;
        self.set_link(Some(link));
        self.last_io = Instant::now();
        Ok(true)
    }

    fn close(&mut self) -> Result<()> {
        self.set_link(None);
        Ok(())
    }

    fn drop_link(&mut self) {
        self.set_link(None);
    }

    fn connected(&self) -> bool {
        self.link.is_some()
    }

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>> {
        self.read_tags(tags)
    }

    fn write(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        let mut results = Vec::with_capacity(items.len());
        for (i, (tag, value)) in items.iter().enumerate() {
            match self.write_item(tag, value) {
                Ok(result) => results.push(result),
                // the first item: nothing else was sent, the call fails as a read would
                Err(error) if i == 0 => return Err(error),
                // the link was lost mid-batch: Ok, so the caller sees which items were already applied
                Err(error) => {
                    let message = format!("{error} (the write may have been applied)");
                    results.push(failed(tag, None, TagError::new(message, ErrorKind::Comm)));
                    for (tag, _) in &items[i + 1..] {
                        let message = format!("'{tag}': not sent: {error}");
                        results.push(failed(tag, None, TagError::new(message, ErrorKind::Comm)));
                    }
                    break;
                }
            }
        }
        Ok(results)
    }

    fn keep_alive(&mut self) -> Result<()> {
        let result = match self.options.keep_alive_address.clone() {
            Some(address) => {
                let target = self
                    .resolve(&address)
                    .map_err(|e| Error::request(e.message))?;
                let max = if target.area.is_bits() {
                    self.options.max_bits
                } else {
                    self.options.max_registers
                };
                let request =
                    pdu::read_request(target.area, target.address, target.size().min(max));
                self.transact(target.unit, &request)
            }
            None => self.transact(self.unit, &pdu::diagnostics_echo()),
        };
        // any reply, an exception included, proves the link
        result.map(drop).inspect_err(|_| self.set_link(None))
    }
}

// ------------------------------------------------------------------------------------------------ driver

/// A Modbus TCP, RTU or RTU-over-TCP driver.
///
/// Tag names come from the map file ([`ModbusOptions::map`]); anything not in it is a plain address
/// (`hr100:float32`, `co5`, `ir10{4}`, `hr20.3`, `di7@2`; 0-based protocol addresses). Thread-safe, on a
/// [session](crate::session) as [`LogixDriver`](crate::logix::driver::LogixDriver) is: reads queued together
/// from several threads are planned into the fewest Modbus requests. A driver from [`new`](Self::new)
/// reconnects in the background and, over TCP, sends a keep-alive (FC08) when idle; one from
/// [`with_connector`](Self::with_connector) does neither.
pub struct ModbusDriver {
    session: Session<Modbus>,
    map: Arc<TagMap>,
    opened: Arc<AtomicBool>,
    name: String,
}

impl ModbusDriver {
    /// A driver for `path` (`tcp://host[:port][?unit=N]`,
    /// `rtu://PORT[?baud=..&parity=..&data=..&stop=..&unit=N]` or `rtu+tcp://host[:port][?unit=N]`); not
    /// connected until [`open`](Self::open). It reconnects; keep-alive 30 s over TCP, off on a serial port.
    pub fn new(path: &str, options: ModbusOptions) -> Result<Self> {
        Self::with_session(
            path,
            options,
            Self::default_session(path)?,
            modbus_connector(),
        )
    }

    /// A driver opening its link with `connector`, without reconnect or keep-alive ([`SessionOptions::off`]).
    pub fn with_connector(
        path: &str,
        options: ModbusOptions,
        connector: ModbusConnector,
    ) -> Result<Self> {
        Self::with_session(path, options, SessionOptions::off(), connector)
    }

    /// A driver with explicit session options, opening its link with `connector`.
    pub fn with_session(
        path: &str,
        mut options: ModbusOptions,
        session: SessionOptions,
        connector: ModbusConnector,
    ) -> Result<Self> {
        let (endpoint, unit) = Endpoint::parse(path)?;
        if !(1..=pdu::MAX_READ_REGISTERS).contains(&options.max_registers) {
            return Err(Error::request(format!(
                "max_registers {} is not 1..=125",
                options.max_registers
            )));
        }
        if !(1..=pdu::MAX_READ_BITS).contains(&options.max_bits) {
            return Err(Error::request(format!(
                "max_bits {} is not 1..=2000",
                options.max_bits
            )));
        }
        if options.socket_timeout.is_zero() {
            return Err(Error::request("socket_timeout must be more than zero"));
        }
        let map = Arc::new(options.map.take().unwrap_or_default());
        if let Some(address) = &options.keep_alive_address {
            resolve(address, &map, unit, options.word_order)
                .map_err(|e| Error::request(format!("keep_alive_address: {}", e.message)))?;
        }
        let opened = Arc::new(AtomicBool::new(false));
        let name = match &endpoint {
            Endpoint::Rtu { .. } => format!("{endpoint}&unit={unit}"),
            _ => format!("{endpoint}?unit={unit}"),
        };
        let state = Modbus {
            endpoint,
            unit,
            map: Arc::clone(&map),
            options,
            connector,
            link: None,
            opened: Arc::clone(&opened),
            transaction: 0,
            last_io: Instant::now(),
            drain: false,
        };
        Ok(ModbusDriver {
            session: Session::new(state, session),
            map,
            opened,
            name,
        })
    }

    /// The session options [`new`](Self::new) uses for `path`: reconnect, keep-alive 30 s for `tcp://` and
    /// `rtu+tcp://`, none for `rtu://`.
    pub fn default_session(path: &str) -> Result<SessionOptions> {
        let (endpoint, _) = Endpoint::parse(path)?;
        Ok(SessionOptions {
            keep_alive: match endpoint {
                Endpoint::Rtu { .. } => None,
                _ => Some(Duration::from_secs(30)),
            },
            ..SessionOptions::default()
        })
    }

    /// Connects the socket or opens the serial port; sends nothing. Ok(true) on success.
    pub fn open(&self) -> Result<bool> {
        self.session.open().wait()
    }

    /// Drops the link. Queued requests fail with `CommError("driver closed")`, subscriptions end and
    /// reconnecting stops. The driver can be opened again.
    pub fn close(&self) -> Result<()> {
        self.session.close()
    }

    /// Stops the session and callback threads and fails pending requests without closing the link (what drop
    /// does). The next request starts the session thread again.
    pub fn stop(&self) {
        self.session.stop();
    }

    /// True while a socket or port is held. Never waits.
    pub fn connected(&self) -> bool {
        self.opened.load(Ordering::SeqCst)
    }

    /// Where the link is: closed, connected, or reconnecting in the background. Never waits.
    pub fn connection_state(&self) -> ConnectionState {
        self.session.state()
    }

    /// Sets (or with None removes) the connection callback; see
    /// [`LogixDriver::set_connection_callback`](crate::logix::driver::LogixDriver::set_connection_callback).
    pub fn set_connection_callback(&self, callback: Option<ConnectionCallback>) {
        self.session.set_connection_callback(callback);
    }

    /// Reads tags: map names, elements (`Totals[2]`), bits (`Drive_Status.5`) or plain addresses. Each tag
    /// gets its own result (a Modbus exception is its error); Err only when the link failed.
    pub fn read(&self, tags: &[&str]) -> Result<Vec<TagResult>> {
        self.read_async(tags).wait()
    }

    /// [`read`](Self::read) without waiting.
    pub fn read_async(&self, tags: &[&str]) -> Handle<Vec<TagResult>> {
        self.session.read(tags)
    }

    /// Writes tags, one request each, in order: FC05/15 for coils, FC06/16 for registers, FC22 for a bit of a
    /// register. Each item gets its own result; Err only when the link failed.
    pub fn write(&self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        self.write_async(items).wait()
    }

    /// [`write`](Self::write) without waiting.
    pub fn write_async(&self, items: &[(&str, Value)]) -> Handle<Vec<TagResult>> {
        self.session.write(items)
    }

    /// Reads `tags` every `options.interval` and delivers those that changed (see [`Subscription`]).
    pub fn subscribe(&self, tags: &[&str], options: SubscribeOptions) -> Result<Subscription> {
        self.session.subscribe(tags, options)
    }

    /// The reply timeout.
    pub fn socket_timeout(&self) -> Duration {
        self.session.lock().options.socket_timeout
    }

    /// Sets the reply timeout (more than zero).
    pub fn set_socket_timeout(&self, timeout: Duration) -> Result<()> {
        if timeout.is_zero() {
            return Err(Error::request("socket_timeout must be more than zero"));
        }
        self.session.lock().options.socket_timeout = timeout;
        Ok(())
    }

    /// The map (empty without one). No lock, no I/O.
    pub fn map(&self) -> &TagMap {
        &self.map
    }

    /// Read Device Identification (FC43 / MEI 14) of `unit` (None: the path's unit): basic objects, then
    /// regular ones if the device has them. A device without it gives its exception as a ResponseError.
    pub fn device_info(&self, unit: Option<u8>) -> Result<DeviceInfo> {
        self.session.call(move |p| p.device_info(unit)).wait()
    }

    /// Sends one raw PDU (function code and data) to `unit` (None: the path's unit) and returns the reply PDU;
    /// an exception reply is a ResponseError with its code. For functions the driver does not wrap.
    pub fn send_pdu(&self, unit: Option<u8>, pdu: &[u8]) -> Result<Vec<u8>> {
        let pdu = pdu.to_vec();
        self.session.call(move |p| p.send_pdu(unit, &pdu)).wait()
    }
}

impl fmt::Display for ModbusDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ModbusDriver({})", self.name)
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
