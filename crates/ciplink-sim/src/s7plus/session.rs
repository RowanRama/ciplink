//! One connection's S7comm-plus session: header checks, sequence and integrity counters, and one handler per
//! function (spec 6, 10, 11, 13, 17). Pure: PDU in, PDU out.

use super::config::S7PlusConfig;
use super::model::{self, AREA_CLASSES, Address, DB_AREA, Model};
use super::wire::{self, Cursor, Value, WireError, WireResult, dt};
use super::{Faults, S7PlusFault};
use std::time::Duration;

const INIT_SSL: u16 = 0x05B3;
const CREATE_OBJECT: u16 = 0x04CA;
const DELETE_OBJECT: u16 = 0x04D4;
const EXPLORE: u16 = 0x04BB;
const SET_MULTI: u16 = 0x0542;
const GET_MULTI: u16 = 0x054C;
const GET_VAR_SUB: u16 = 0x0586;
const ERROR_PDU: u16 = 0x04B1;

const NULL_SESSION: u32 = 0x120;
/// CreateObject / DeleteObject return values seen on success (spec 10.3, 10.8).
const RV_CREATED: u64 = 0x6022_8000_012D_0011;
const RV_DELETED: u64 = 0x2023_8000_0087_002D;
/// GetMultiVariables / SetMultiVariables with at least one failed item (spec 11.4).
const RV_ITEM_FAILED: u64 = 0x2027_8000_00A1_0013;
/// A negative return value with an item error list (fault `NegativeItemErrors`).
const RV_ITEM_FAILED_NEGATIVE: u64 = 0x8027_8000_00A1_FFFF;
/// Invented negative return values: too many items, unknown object or attribute, Error PDU.
const RV_TOO_MANY: u64 = 0x8027_8000_0000_FFF1;
const RV_UNKNOWN: u64 = 0x8027_8000_0000_FF01;

/// Per connection state.
pub(crate) struct Conn {
    next_sequence: u16,
    get_integrity: u32,
    set_integrity: u32,
    created: bool,
    setup: bool,
    /// The ServerSessionVersion struct sent to this connection, for the setup check.
    version: Vec<u8>,
}

impl Conn {
    pub(crate) fn new() -> Conn {
        Conn {
            next_sequence: 1,
            get_integrity: 1,
            set_integrity: 1,
            created: false,
            setup: false,
            version: Vec::new(),
        }
    }
}

/// What to do with a request.
pub(crate) struct Outcome {
    /// The reply PDU (version byte + data), None to send nothing.
    pub reply: Option<Vec<u8>>,
    /// A system-event (`fe`) frame to send before the reply.
    pub event: Option<Vec<u8>>,
    pub delay: Duration,
    /// Close the connection (protocol error) instead of replying.
    pub close: bool,
}

impl Outcome {
    fn close() -> Outcome {
        Outcome {
            reply: None,
            event: None,
            delay: Duration::ZERO,
            close: true,
        }
    }
}

/// The device: configuration, program and faults (shared by every connection).
pub(crate) struct Device {
    pub config: S7PlusConfig,
    pub model: Model,
    pub faults: Faults,
    pub requests: u64,
    pub recording: bool,
    pub log: Vec<Vec<u8>>,
}

struct Header {
    version: u8,
    function: u16,
    sequence: u16,
    session: u32,
}

fn header(cur: &mut Cursor<'_>) -> WireResult<Header> {
    let version = cur.u8()?;
    let opcode = cur.u8()?;
    cur.u16()?;
    let function = cur.u16()?;
    cur.u16()?;
    let sequence = cur.u16()?;
    let session = cur.u32()?;
    cur.u8()?;
    if opcode != 0x31 {
        return Err(WireError(format!("opcode {opcode:#04x}")));
    }
    Ok(Header {
        version,
        function,
        sequence,
        session,
    })
}

/// A response PDU: header, return value, body.
fn response(h: &Header, flags: u8, rv: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 20);
    out.extend_from_slice(&[h.version, 0x32, 0, 0]);
    out.extend_from_slice(&h.function.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&h.sequence.to_be_bytes());
    out.push(flags);
    wire::put_vlq64(&mut out, rv);
    out.extend_from_slice(body);
    out
}

/// The cleartext InitSsl response for a request (spec 3), None if the request is not one.
pub(crate) fn init_ssl(pdu: &[u8], conn: &mut Conn) -> Option<Vec<u8>> {
    let mut cur = Cursor::new(pdu);
    let h = header(&mut cur).ok()?;
    if h.version != 1 || h.function != INIT_SSL || h.sequence != 1 || h.session != NULL_SESSION {
        return None;
    }
    conn.next_sequence = 2;
    // transport flags 0x70, return value 0, five zero bytes
    Some(response(&h, 0x70, 0, &[0; 5]))
}

fn skip_qualifier(cur: &mut Cursor<'_>) -> WireResult<()> {
    cur.u32()?;
    loop {
        if cur.vlq32()? == 0 {
            return Ok(());
        }
        Value::decode(cur)?;
    }
}

fn end(cur: &mut Cursor<'_>, zeros: usize) -> WireResult<()> {
    if cur.take(zeros)?.iter().any(|&b| b != 0) {
        return Err(WireError("end bytes not zero".into()));
    }
    Ok(())
}

fn addresses(cur: &mut Cursor<'_>, count: u32) -> WireResult<Vec<Address>> {
    let mut out = Vec::new();
    for _ in 0..count {
        let crc = cur.vlq32()?;
        let area = cur.vlq32()?;
        let ids = cur.vlq32()?;
        if ids == 0 || ids as usize > cur.remaining() {
            return Err(WireError(format!("{ids} IDs in an address")));
        }
        let sub_area = cur.vlq32()?;
        let lids = (1..ids).map(|_| cur.vlq32()).collect::<WireResult<_>>()?;
        out.push(Address {
            crc,
            area,
            sub_area,
            lids,
        });
    }
    Ok(out)
}

fn hit(f: &mut Faults) -> bool {
    if f.drop_replies > 0 {
        f.drop_replies -= 1;
        true
    } else {
        false
    }
}

impl Device {
    /// The ServerSessionVersion struct (attribute 306, struct 314).
    fn session_version(&self) -> Value {
        let c = &self.config;
        Value::Struct(
            314,
            vec![
                (315, Value::UDInt(897)),
                (316, Value::UDInt(897)),
                (317, Value::UDInt(8_405_696)),
                (318, Value::UDInt(8_405_696)),
                (
                    319,
                    Value::WString(format!(
                        "1;{};V{}.{}",
                        c.order_number, c.firmware[0], c.firmware[1]
                    )),
                ),
                (320, Value::WString(format!("2;{}", c.project_version))),
                (321, Value::UInt(3)),
            ],
        )
    }

    /// Handles one request PDU after the TLS handshake.
    pub(crate) fn handle(&mut self, conn: &mut Conn, pdu: &[u8]) -> Outcome {
        self.requests += 1;
        if self.recording {
            self.log.push(pdu.to_vec());
        }
        let mut cur = Cursor::new(pdu);
        let Ok(h) = header(&mut cur) else {
            return Outcome::close();
        };
        // sequence, version and session ID are checked before anything else
        let expected_session = if conn.created {
            self.config.session_id
        } else {
            NULL_SESSION
        };
        let version = if h.function == CREATE_OBJECT && !conn.created {
            1
        } else {
            2
        };
        if h.sequence != conn.next_sequence || h.session != expected_session || h.version != version
        {
            return Outcome::close();
        }
        conn.next_sequence = if h.sequence == 0xFFFF {
            1
        } else {
            h.sequence + 1
        };
        let delay = self.faults.delay;
        let event = self.faults.system_event.take().map(system_event);
        // the request is handled (counters advance) even when an Error PDU replaces its reply
        let reply = self.dispatch(conn, &h, &mut cur);
        let reply = match reply {
            Ok(Some(_)) if std::mem::take(&mut self.faults.error_pdu) => {
                let error = Header {
                    function: ERROR_PDU,
                    ..h
                };
                Ok(Some(response(&error, 0x34, RV_UNKNOWN, &[0; 4])))
            }
            other => other,
        };
        match reply {
            Ok(Some(reply)) => Outcome {
                reply: (!hit(&mut self.faults)).then_some(reply),
                event,
                delay,
                close: false,
            },
            Ok(None) | Err(_) => Outcome::close(),
        }
    }

    /// Ok(None) and Err close the connection.
    fn dispatch(
        &mut self,
        conn: &mut Conn,
        h: &Header,
        cur: &mut Cursor<'_>,
    ) -> WireResult<Option<Vec<u8>>> {
        match h.function {
            CREATE_OBJECT if !conn.created => Ok(Some(self.create_object(conn, h))),
            SET_MULTI if conn.created => self.set_multi(conn, h, cur),
            GET_MULTI if conn.setup => self.get_multi(conn, h, cur),
            GET_VAR_SUB if conn.setup => self.get_var_sub(conn, h, cur),
            EXPLORE if conn.setup => self.explore(conn, h, cur),
            DELETE_OBJECT if conn.created => self.delete_object(conn, h, cur),
            _ => Ok(None),
        }
    }

    fn integrity(counter: &mut u32, cur: &mut Cursor<'_>) -> WireResult<Option<u32>> {
        let got = cur.vlq32()?;
        if got != *counter {
            return Ok(None);
        }
        *counter = counter.wrapping_add(1);
        Ok(Some(got))
    }

    fn create_object(&mut self, conn: &mut Conn, h: &Header) -> Vec<u8> {
        conn.created = true;
        let version = self.session_version();
        conn.version = version.to_bytes();
        let c = &self.config;
        let mut body = vec![2];
        wire::put_vlq32(&mut body, c.session_id);
        wire::put_vlq32(&mut body, c.session_id.wrapping_add(1));
        body.push(0xA1);
        body.extend_from_slice(&NULL_SESSION.to_be_bytes());
        wire::put_vlq32(&mut body, 287);
        wire::put_vlq32(&mut body, 1);
        wire::put_vlq32(&mut body, 0);
        let challenge: Vec<Value> = (0..20)
            .map(|i| Value::USInt(rand_byte(self.requests, i)))
            .collect();
        let attrs = [
            (233, Value::WString(c.session_name.clone())),
            (299, Value::UDInt(2)),
            (301, Value::WString(c.server_version.clone())),
            (303, Value::array(dt::USINT, challenge)),
            (306, version),
        ];
        model::put_attributes(&mut body, &attrs, &[]);
        body.push(0xA2);
        body.extend_from_slice(&[0; 4]);
        response(h, 0x36, RV_CREATED, &body)
    }

    fn set_multi(
        &mut self,
        conn: &mut Conn,
        h: &Header,
        cur: &mut Cursor<'_>,
    ) -> WireResult<Option<Vec<u8>>> {
        let object = cur.u32()?;
        let count = cur.vlq32()?;
        if object != 0 {
            // session setup: write struct 306 back unchanged (spec 10.4)
            let fields = cur.vlq32()?;
            for _ in 0..fields {
                cur.vlq32()?;
            }
            let mut values = Vec::new();
            for _ in 0..count {
                cur.vlq32()?;
                values.push(Value::decode(cur)?);
            }
            cur.u8()?;
            skip_qualifier(cur)?;
            end(cur, 4)?;
            let ok = object == self.config.session_id
                && !conn.setup
                && values.len() == 1
                && values[0].to_bytes() == conn.version;
            if !ok {
                return Ok(None);
            }
            conn.setup = true;
            return Ok(Some(response(h, 0x34, 0, &[0, 0, 0, 0, 0, 0])));
        }
        if !conn.setup {
            return Ok(None);
        }
        cur.vlq32()?; // field count
        let addresses = addresses(cur, count)?;
        let mut values = Vec::with_capacity(addresses.len());
        for _ in 0..count {
            let item = cur.vlq32()?;
            values.push((item, Value::decode(cur)?));
        }
        cur.u8()?;
        skip_qualifier(cur)?;
        let Some(integrity) = Self::integrity(&mut conn.set_integrity, cur)? else {
            return Ok(None);
        };
        end(cur, 4)?;
        let mut errors = Vec::new();
        if count > self.config.max_write {
            return Ok(Some(write_reply(h, integrity, RV_TOO_MANY, &[])));
        }
        for (item, value) in &values {
            let Some(address) = (*item as usize)
                .checked_sub(1)
                .and_then(|i| addresses.get(i))
            else {
                return Ok(None);
            };
            let result = match self.item_fault(address) {
                Some(code) => Err(code),
                None => self.model.write(address, value),
            };
            if let Err(code) = result {
                errors.push((*item, code));
            }
        }
        let rv = self.items_failed(&errors);
        Ok(Some(write_reply(h, integrity, rv, &errors)))
    }

    /// The return value of a read or write: 0, or "items failed" (negative with that fault).
    fn items_failed(&self, errors: &[(u32, u64)]) -> u64 {
        match (errors.is_empty(), self.faults.negative_item_errors) {
            (true, _) => 0,
            (false, true) => RV_ITEM_FAILED_NEGATIVE,
            (false, false) => RV_ITEM_FAILED,
        }
    }

    /// An `item_error` fault on this address.
    fn item_fault(&self, address: &Address) -> Option<u64> {
        self.faults.items.iter().find_map(|(tag, code)| {
            let a = self.model.address(tag).ok()?;
            (a.area == address.area && a.sub_area == address.sub_area && a.lids == address.lids)
                .then_some(*code)
        })
    }

    fn items_reply(
        &self,
        h: &Header,
        integrity: u32,
        rv: u64,
        values: &[(u32, Value)],
        errors: &[(u32, u64)],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for (item, value) in values {
            wire::put_vlq32(&mut body, *item);
            value.encode(&mut body);
        }
        body.push(0);
        for (item, code) in errors {
            wire::put_vlq32(&mut body, *item);
            wire::put_vlq64(&mut body, *code);
        }
        body.push(0);
        wire::put_vlq32(&mut body, u32::from(h.sequence).wrapping_add(integrity));
        body.extend_from_slice(&[0; 4]);
        response(h, 0x34, rv, &body)
    }

    fn get_multi(
        &mut self,
        conn: &mut Conn,
        h: &Header,
        cur: &mut Cursor<'_>,
    ) -> WireResult<Option<Vec<u8>>> {
        cur.u32()?; // link ID
        let count = cur.vlq32()?;
        cur.vlq32()?; // field count
        let addresses = addresses(cur, count)?;
        skip_qualifier(cur)?;
        let Some(integrity) = Self::integrity(&mut conn.get_integrity, cur)? else {
            return Ok(None);
        };
        end(cur, 4)?;
        if count > self.config.max_read {
            return Ok(Some(self.items_reply(h, integrity, RV_TOO_MANY, &[], &[])));
        }
        let mut values = Vec::new();
        let mut errors = Vec::new();
        for (i, address) in addresses.iter().enumerate() {
            let item = i as u32 + 1;
            let result = match self.item_fault(address) {
                Some(code) => Err(code),
                None => self.read_item(address),
            };
            match result {
                Ok(value) => values.push((item, value)),
                Err(code) => errors.push((item, code)),
            }
        }
        let rv = self.items_failed(&errors);
        Ok(Some(self.items_reply(h, integrity, rv, &values, &errors)))
    }

    fn read_item(&self, address: &Address) -> Result<Value, u64> {
        if address.area == 201 {
            let c = &self.config;
            let value = match (address.sub_area, address.lids.as_slice()) {
                (1037, [1000]) => c.max_read,
                (1037, [1001]) => c.max_write,
                (1037 | 1081, [0]) => 250,
                (1037 | 1081, [1]) => 2000,
                (1037 | 1081, [2]) => 524_288,
                _ => return Err(model::ERR_NO_LID),
            };
            return Ok(Value::DInt(value as i32));
        }
        self.model.read(address)
    }

    fn get_var_sub(
        &mut self,
        conn: &mut Conn,
        h: &Header,
        cur: &mut Cursor<'_>,
    ) -> WireResult<Option<Vec<u8>>> {
        let object = cur.u32()?;
        let attribute = match Value::decode(cur)? {
            Value::Array { items, .. } => match items.first() {
                Some(Value::UDInt(a)) => *a,
                _ => return Ok(None),
            },
            _ => return Ok(None),
        };
        skip_qualifier(cur)?;
        cur.u16()?;
        let Some(integrity) = Self::integrity(&mut conn.get_integrity, cur)? else {
            return Ok(None);
        };
        end(cur, 4)?;
        let c = &self.config;
        let value = match (object, attribute) {
            (o, 1842) if o == c.session_id => Some(Value::UDInt(c.protection_level)),
            (50, 233) => Some(Value::WString(c.name.clone())),
            (49, 3753) => Some(Value::Blob(identification(c))),
            (1, 2459) => {
                let v = c.engineering_version;
                Some(Value::array(
                    dt::USINT,
                    v.iter().chain(v.iter()).map(|&b| Value::USInt(b)).collect(),
                ))
            }
            (0x894A_0000, 8342) => {
                let v = c.engineering_version;
                let short = format!("{}.{}", v[0], v[1]);
                Some(Value::Array {
                    flags: 0x20,
                    datatype: dt::WSTRING,
                    items: vec![
                        Value::WString(format!("V{short}")),
                        Value::WString(short),
                        Value::WString(c.project.clone()),
                    ],
                })
            }
            _ => None,
        };
        let mut body = vec![0];
        let rv = match value {
            Some(value) => {
                value.encode(&mut body);
                0
            }
            None => RV_UNKNOWN,
        };
        wire::put_vlq32(&mut body, u32::from(h.sequence).wrapping_add(integrity));
        body.extend_from_slice(&[0; 4]);
        Ok(Some(response(h, 0x34, rv, &body)))
    }

    fn explore(
        &mut self,
        conn: &mut Conn,
        h: &Header,
        cur: &mut Cursor<'_>,
    ) -> WireResult<Option<Vec<u8>>> {
        let rid = cur.u32()?;
        cur.vlq32()?;
        let children = cur.u8()? != 0;
        cur.u8()?;
        let parents = cur.u8()? != 0;
        let filtered = match cur.u8()? {
            0 => false,
            _ => {
                Value::decode(cur)?;
                cur.u8()?;
                true
            }
        };
        let count = cur.vlq32()?;
        let wanted = (0..count)
            .map(|_| cur.vlq32())
            .collect::<WireResult<Vec<u32>>>()?;
        let Some(integrity) = Self::integrity(&mut conn.get_integrity, cur)? else {
            return Ok(None);
        };
        end(cur, 5)?;
        let m = &self.model;
        let mut objects = Vec::new();
        let parent = match rid {
            3 => {
                if filtered {
                    for db in &m.dbs {
                        db_object(db, &[233], &mut objects);
                    }
                } else {
                    open_object(&mut objects, 3, 2520, 0x30);
                    if children {
                        for db in &m.dbs {
                            db_object(db, &wanted, &mut objects);
                        }
                        for (area, class) in m.areas.iter().zip(AREA_CLASSES) {
                            open_object(&mut objects, area.rid, class, 0);
                            model::put_attributes(
                                &mut objects,
                                &[(233, Value::WString(area.name.clone()))],
                                &wanted,
                            );
                            objects.push(0xA2);
                        }
                    }
                    objects.push(0xA2);
                }
                1
            }
            537 => {
                open_object(&mut objects, 537, 534, 0);
                if children {
                    for t in m.types.values() {
                        m.type_object(t, &[], &mut objects);
                    }
                }
                objects.push(0xA2);
                201
            }
            114 => {
                open_object(&mut objects, 114, 4672, 0);
                let languages = Value::Array {
                    flags: 0x20,
                    datatype: dt::UINT,
                    items: vec![Value::UInt(1033)],
                };
                model::put_attributes(&mut objects, &[(2717, languages)], &wanted);
                objects.push(0xA2);
                1
            }
            _ => {
                if let Some(t) = m.types.get(&rid) {
                    m.type_object(t, &wanted, &mut objects);
                    537
                } else if let Some(db) = m.dbs.iter().find(|b| b.rid == rid) {
                    db_object(db, &wanted, &mut objects);
                    3
                } else {
                    open_object(&mut objects, rid, 0, 0);
                    objects.push(0xA2);
                    0
                }
            }
        };
        let mut body = Vec::with_capacity(objects.len() + 20);
        body.extend_from_slice(&(parent as u32).to_be_bytes());
        wire::put_vlq32(&mut body, u32::from(h.sequence).wrapping_add(integrity));
        if parents && !filtered {
            open_object(&mut body, 1, 2478, 0);
            body.extend_from_slice(&objects);
            body.push(0xA2);
        } else {
            body.extend_from_slice(&objects);
        }
        body.extend_from_slice(&[0; 4]);
        Ok(Some(response(h, 0x34, 0, &body)))
    }

    fn delete_object(
        &mut self,
        conn: &mut Conn,
        h: &Header,
        cur: &mut Cursor<'_>,
    ) -> WireResult<Option<Vec<u8>>> {
        let object = cur.u32()?;
        cur.u8()?;
        skip_qualifier(cur)?;
        if Self::integrity(&mut conn.set_integrity, cur)?.is_none() {
            return Ok(None);
        }
        end(cur, 4)?;
        if object != self.config.session_id {
            return Ok(None);
        }
        let mut body = object.to_be_bytes().to_vec();
        body.extend_from_slice(&[0; 4]);
        Ok(Some(response(h, 0x34, RV_DELETED, &body)))
    }
}

/// A SetMultiVariables (tag write) reply (spec 17.2): error list, integrity ID, end; no value list.
fn write_reply(h: &Header, integrity: u32, rv: u64, errors: &[(u32, u64)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (item, code) in errors {
        wire::put_vlq32(&mut body, *item);
        wire::put_vlq64(&mut body, *code);
    }
    body.push(0);
    wire::put_vlq32(&mut body, u32::from(h.sequence).wrapping_add(integrity));
    body.extend_from_slice(&[0; 4]);
    response(h, 0x34, rv, &body)
}

fn open_object(out: &mut Vec<u8>, rid: u32, class: u32, flags: u32) {
    out.push(0xA1);
    out.extend_from_slice(&rid.to_be_bytes());
    wire::put_vlq32(out, class);
    wire::put_vlq32(out, flags);
    wire::put_vlq32(out, 0);
}

fn db_object(db: &model::Block, wanted: &[u32], out: &mut Vec<u8>) {
    open_object(out, db.rid, 2574, 0x20);
    let attrs = [
        (233, Value::WString(db.name.clone())),
        (2521, Value::UInt((db.rid - DB_AREA) as u16)),
        (
            4288,
            Value::Sparse {
                datatype: dt::WSTRING,
                items: Vec::new(),
            },
        ),
    ];
    model::put_attributes(out, &attrs, wanted);
    out.push(0xA2);
}

/// The 60-byte identification blob (spec 13.7).
fn identification(c: &S7PlusConfig) -> Vec<u8> {
    let mut out = vec![0x00, 0x20, 0x00, 0x38, 0x01, 0x00, 0x00, 0x2A];
    let field = |text: &str, n: usize| {
        let mut bytes: Vec<u8> = text.bytes().take(n).collect();
        bytes.resize(n, b' ');
        bytes
    };
    out.extend(field(&c.order_number, 19));
    out.push(b' ');
    out.extend(field(&c.serial_number, 16));
    out.push(0);
    out.push(c.hardware_version);
    out.push(b'V');
    out.extend_from_slice(&c.firmware);
    out.resize(60, 0);
    out
}

/// A system-event frame (spec 5, open questions): four 4-byte integers, then a struct with element 40305
/// holding the return value as a fixed-width LInt.
fn system_event(return_value: i64) -> Vec<u8> {
    let mut data = vec![0u8; 16];
    data.extend_from_slice(&[0x00, dt::STRUCT]);
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&40305u32.to_be_bytes());
    data.extend_from_slice(&[0x00, dt::LINT]);
    data.extend_from_slice(&return_value.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    let mut frame = vec![0x72, 0xFE];
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(&data);
    frame
}

/// A cheap varying byte (the session challenge has no meaning here).
fn rand_byte(seed: u64, i: u64) -> u8 {
    let x = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(i.wrapping_mul(0xBF58_476D_1CE4_E5B9))
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
    (x >> 29) as u8
}

impl S7PlusFault {
    pub(crate) fn apply(self, faults: &mut Faults) {
        match self {
            S7PlusFault::Delay(delay) => faults.delay = delay,
            S7PlusFault::DropReplies(n) => {
                faults.drop_replies = faults.drop_replies.saturating_add(n)
            }
            S7PlusFault::RefuseConnections => faults.refuse_connections = true,
            S7PlusFault::ItemError { tag, code } => faults.items.push((tag, code)),
            S7PlusFault::ErrorPdu => faults.error_pdu = true,
            S7PlusFault::NegativeItemErrors => faults.negative_item_errors = true,
            S7PlusFault::SystemEvent { return_value } => faults.system_event = Some(return_value),
            // handled by the simulator (it owns the sockets)
            S7PlusFault::CloseConnections => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> Device {
        let config = S7PlusConfig::default();
        Device {
            model: Model::new(&config).expect("model"),
            config,
            faults: Faults::default(),
            requests: 0,
            recording: false,
            log: Vec::new(),
        }
    }

    /// The protection-level read (spec 10.6) with any sequence and integrity.
    fn keep_alive(sequence: u16, integrity: u32) -> Vec<u8> {
        let mut pdu = wire::hex(
            "0231000005860000000570000a103470000a102004018e32000004e88969001200000000896a001300896b000400000001",
        );
        pdu[8..10].copy_from_slice(&sequence.to_be_bytes());
        wire::put_vlq32(&mut pdu, integrity);
        pdu.extend([0; 4]);
        pdu
    }

    fn ready() -> Conn {
        let mut conn = Conn::new();
        conn.created = true;
        conn.setup = true;
        conn
    }

    #[test]
    fn sequence_and_integrity_wrap() {
        let mut device = device();
        let mut conn = ready();
        conn.next_sequence = 0xFFF0;
        conn.get_integrity = u32::MAX - 5;
        let (mut sequence, mut integrity) = (0xFFF0u16, u32::MAX - 5);
        for _ in 0..40 {
            let outcome = device.handle(&mut conn, &keep_alive(sequence, integrity));
            let reply = outcome.reply.expect("reply");
            let mut tail = Vec::new();
            wire::put_vlq32(&mut tail, u32::from(sequence).wrapping_add(integrity));
            tail.extend([0; 4]);
            assert!(reply.ends_with(&tail));
            sequence = if sequence == 0xFFFF { 1 } else { sequence + 1 };
            integrity = integrity.wrapping_add(1);
        }
        assert_eq!(conn.next_sequence, 25);
        assert_eq!(conn.get_integrity, 34);
        // sequence 0 is skipped: sending it closes
        assert!(device.handle(&mut conn, &keep_alive(0, 34)).close);
    }

    #[test]
    fn seventy_thousand_requests_keep_counting() {
        let mut device = device();
        let mut conn = ready();
        conn.next_sequence = 4;
        let mut sequence = 4u16;
        for integrity in 1..=70_000u32 {
            let outcome = device.handle(&mut conn, &keep_alive(sequence, integrity));
            assert!(!outcome.close && outcome.reply.is_some());
            sequence = if sequence == 0xFFFF { 1 } else { sequence + 1 };
        }
    }

    #[test]
    fn the_init_ssl_response_is_the_spec_example() {
        let request = wire::hex("0131000005b30000000100000120300000 0000");
        let mut conn = Conn::new();
        assert_eq!(
            init_ssl(&request, &mut conn).expect("response"),
            wire::hex("0132000005b3000000017000 0000000000")
        );
        let mut wrong = request;
        wrong[9] = 2;
        assert!(init_ssl(&wrong, &mut Conn::new()).is_none());
    }
}
