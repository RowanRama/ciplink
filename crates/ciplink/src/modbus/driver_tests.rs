//! The driver against a small in-memory Modbus device (both framings). The full simulator tests live in
//! `crates/ciplink-sim/tests/modbus.rs`.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use super::*;
use crate::modbus::frame::{crc16, mbap_frame, rtu_frame};

const SIZE: usize = 1000;

/// A device with one set of tables (every live unit shares them).
struct Device {
    rtu: bool,
    holding: Vec<u16>,
    input: Vec<u16>,
    coils: Vec<bool>,
    discrete: Vec<bool>,
    /// Ranges of holding registers that answer exception 02.
    holes: Vec<(u16, u16)>,
    dead_units: Vec<u8>,
    /// (function, code): answer every request of `function` with exception `code`.
    exception: Option<(u8, u8)>,
    unsupported: Vec<u8>,
    max_registers: u16,
    /// (unit, PDU) of every request received.
    requests: Vec<(u8, Vec<u8>)>,
    /// The next n replies are lost.
    drop_next: u32,
    /// RTU: the next reply has a bad CRC.
    bad_crc_next: bool,
    /// MBAP: a reply with an older transaction id goes out before the next reply.
    stale_next: bool,
    /// RTU: a late reply to an earlier request sits in the input.
    garbage_next: bool,
    /// RTU: this late reply PDU arrives just after the next request is sent, before that request's reply.
    late_next: Option<Vec<u8>>,
    identity: Vec<(u8, &'static str)>,
    identity_conformity: u8,
    identity_page: usize,
    input_buf: Vec<u8>,
    output: VecDeque<u8>,
}

impl Device {
    fn new(rtu: bool) -> Self {
        Device {
            rtu,
            holding: vec![0; SIZE],
            input: vec![0; SIZE],
            coils: vec![false; SIZE],
            discrete: vec![false; SIZE],
            holes: Vec::new(),
            dead_units: vec![9],
            exception: None,
            unsupported: Vec::new(),
            max_registers: 125,
            requests: Vec::new(),
            drop_next: 0,
            bad_crc_next: false,
            stale_next: false,
            garbage_next: false,
            late_next: None,
            identity: vec![(0, "ciplink"), (1, "FAKE"), (2, "1.0"), (4, "Fake device")],
            identity_conformity: 0x82,
            identity_page: 2,
            input_buf: Vec::new(),
            output: VecDeque::new(),
        }
    }

    /// The length of the request at the head of the input, once enough of it is there.
    fn request_len(&self) -> Option<usize> {
        let b = &self.input_buf;
        if !self.rtu {
            let len = usize::from(u16::from_be_bytes([*b.get(4)?, *b.get(5)?]));
            return Some(6 + len);
        }
        Some(match *b.get(1)? {
            1..=6 | 8 => 8,
            15 | 16 => 9 + usize::from(*b.get(6)?),
            22 => 10,
            43 => 7,
            _ => b.len(),
        })
    }

    fn take_requests(&mut self) {
        while let Some(len) = self.request_len() {
            if self.input_buf.len() < len {
                return;
            }
            let frame: Vec<u8> = self.input_buf.drain(..len).collect();
            let (tid, unit, pdu) = if self.rtu {
                (0, frame[0], frame[1..len - 2].to_vec())
            } else {
                (
                    u16::from_be_bytes([frame[0], frame[1]]),
                    frame[6],
                    frame[7..].to_vec(),
                )
            };
            self.requests.push((unit, pdu.clone()));
            let Some(reply) = self.handle(unit, &pdu) else {
                continue;
            };
            if self.rtu {
                if std::mem::take(&mut self.garbage_next) {
                    self.output.extend(rtu_frame(unit, &[3, 2, 0xAA, 0xBB]));
                }
                if let Some(late) = self.late_next.take() {
                    self.output.extend(rtu_frame(unit, &late));
                }
                let mut out = rtu_frame(unit, &reply);
                if std::mem::take(&mut self.bad_crc_next) {
                    let n = out.len();
                    out[n - 1] ^= 0xFF;
                }
                self.output.extend(out);
            } else {
                if std::mem::take(&mut self.stale_next) {
                    self.output
                        .extend(mbap_frame(tid.wrapping_sub(1), unit, &[3, 2, 0xAA, 0xBB]));
                }
                self.output.extend(mbap_frame(tid, unit, &reply));
            }
        }
    }

    fn in_hole(&self, start: u16, count: u16) -> bool {
        self.holes
            .iter()
            .any(|&(s, n)| start < s + n && s < start.saturating_add(count))
    }

    fn handle(&mut self, unit: u8, pdu: &[u8]) -> Option<Vec<u8>> {
        if self.dead_units.contains(&unit) {
            return None;
        }
        if self.drop_next > 0 {
            self.drop_next -= 1;
            return None;
        }
        let fc = pdu[0];
        let exception = |code: u8| Some(vec![fc | 0x80, code]);
        if let Some((function, code)) = self.exception {
            if function == fc {
                return exception(code);
            }
        }
        if self.unsupported.contains(&fc) {
            return exception(1);
        }
        let word = |at: usize| {
            pdu.get(at..at + 2)
                .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]))
        };
        let (address, value) = (word(1), word(3));
        let a = usize::from(address);
        let reply = match fc {
            1..=4 => {
                let max = if fc <= 2 { 2000 } else { self.max_registers };
                if value == 0 || value > max {
                    return exception(3);
                }
                let n = usize::from(value);
                if a + n > SIZE || (fc == 3 && self.in_hole(address, value)) {
                    return exception(2);
                }
                let mut out = vec![fc];
                if fc <= 2 {
                    let bits = if fc == 1 { &self.coils } else { &self.discrete };
                    let mut bytes = vec![0u8; n.div_ceil(8)];
                    for i in 0..n {
                        if bits[a + i] {
                            bytes[i / 8] |= 1 << (i % 8);
                        }
                    }
                    out.push(bytes.len() as u8);
                    out.extend(bytes);
                } else {
                    let regs = if fc == 3 { &self.holding } else { &self.input };
                    out.push((n * 2) as u8);
                    for r in &regs[a..a + n] {
                        out.extend_from_slice(&r.to_be_bytes());
                    }
                }
                out
            }
            5 => {
                self.coils[a] = value == 0xFF00;
                pdu.to_vec()
            }
            6 => {
                self.holding[a] = value;
                pdu.to_vec()
            }
            15 => {
                for i in 0..usize::from(value) {
                    self.coils[a + i] = pdu[6 + i / 8] >> (i % 8) & 1 == 1;
                }
                pdu[..5].to_vec()
            }
            16 => {
                for i in 0..usize::from(value) {
                    self.holding[a + i] = word(6 + 2 * i);
                }
                pdu[..5].to_vec()
            }
            22 => {
                let (and, or) = (value, word(5));
                self.holding[a] = (self.holding[a] & and) | (or & !and);
                pdu.to_vec()
            }
            8 => pdu.to_vec(),
            0x2B => {
                let first = pdu[3];
                let objects: Vec<_> = self
                    .identity
                    .iter()
                    .filter(|(id, _)| *id >= first)
                    .collect();
                let page: Vec<_> = objects.iter().take(self.identity_page).collect();
                let more = objects.len() > page.len();
                let next = if more { objects[page.len()].0 } else { 0 };
                let mut out = vec![0x2B, 0x0E, pdu[2], self.identity_conformity];
                out.extend([if more { 0xFF } else { 0 }, next, page.len() as u8]);
                for (id, text) in page {
                    out.extend([*id, text.len() as u8]);
                    out.extend(text.as_bytes());
                }
                out
            }
            _ => return exception(1),
        };
        // RTU broadcast: applied, no reply
        (unit != 0 || !self.rtu).then_some(reply)
    }
}

#[derive(Clone)]
struct Fake(Arc<Mutex<Device>>);

impl Fake {
    fn new(rtu: bool) -> Self {
        Fake(Arc::new(Mutex::new(Device::new(rtu))))
    }

    fn dev(&self) -> MutexGuard<'_, Device> {
        self.0.lock().expect("device")
    }

    fn functions(&self) -> Vec<u8> {
        self.dev().requests.iter().map(|(_, pdu)| pdu[0]).collect()
    }

    fn clear(&self) {
        self.dev().requests.clear();
    }

    fn connector(&self) -> ModbusConnector {
        let fake = self.clone();
        Box::new(move |_, _| Ok(Box::new(fake.clone()) as Box<dyn Link>))
    }
}

impl io::Read for Fake {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut dev = self.dev();
        if dev.output.is_empty() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let n = buf.len().min(dev.output.len());
        for (slot, byte) in buf.iter_mut().zip(dev.output.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

impl io::Write for Fake {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut dev = self.dev();
        dev.input_buf.extend_from_slice(buf);
        dev.take_requests();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Link for Fake {
    fn set_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

const PATHS: [&str; 2] = ["tcp://127.0.0.1", "rtu+tcp://127.0.0.1"];

fn example_map() -> TagMap {
    TagMap::from_csv(include_str!("../../../../tools/sim/example_modbus_map.csv")).expect("map")
}

fn driver_with(path: &str, options: ModbusOptions) -> (ModbusDriver, Fake) {
    let fake = Fake::new(path.starts_with("rtu"));
    let driver = ModbusDriver::with_connector(path, options, fake.connector()).expect("driver");
    assert!(driver.open().expect("open"));
    (driver, fake)
}

fn driver(path: &str) -> (ModbusDriver, Fake) {
    driver_with(
        path,
        ModbusOptions {
            map: Some(example_map()),
            ..ModbusOptions::default()
        },
    )
}

fn value(results: &[TagResult], i: usize) -> Value {
    results[i]
        .value
        .clone()
        .unwrap_or_else(|| panic!("{:?}", results[i]))
}

fn kind(result: &TagResult) -> Option<ErrorKind> {
    result.error.as_ref().map(|e| e.kind)
}

#[test]
fn reads_every_type_from_the_map() {
    for path in PATHS {
        let (d, fake) = driver(path);
        {
            let mut dev = fake.dev();
            dev.holding[0..2].copy_from_slice(&[0xE979, 0x42F6]); // 123.456, CDAB
            dev.coils[0] = true;
            dev.discrete[3] = true;
            dev.input[10] = 655; // 65.5 %
            dev.input[11] = 650; // 25 degC
            dev.holding[100..108].copy_from_slice(&[0, 1, 0, 2, 0, 3, 1, 0]);
            dev.holding[200..203].copy_from_slice(&[0x5265, 0x6369, 0x7065]);
            dev.holding[300] = 0x0021;
            dev.holding[301] = 0x0010;
        }
        let names = [
            "Pump1_Speed",
            "Pump1_Run",
            "Pump1_Fault",
            "Tank_Level",
            "Tank_Temp",
            "Totals",
            "Recipe",
            "Drive_Status",
            "Horn",
            "Totals[3]",
            "Drive_Status.5",
            "drive_status.1",
        ];
        let r = d.read(&names).expect("read");
        assert_eq!(value(&r, 0), Value::Real(123.456), "{path}");
        assert_eq!(value(&r, 1), Value::Bool(true));
        assert_eq!(value(&r, 2), Value::Bool(true));
        assert_eq!(value(&r, 3), Value::LReal(655.0 * 0.1));
        assert_eq!(value(&r, 4), Value::LReal(650.0 * 0.1 - 40.0));
        assert_eq!(
            value(&r, 5),
            Value::Array(vec![
                Value::UDInt(1),
                Value::UDInt(2),
                Value::UDInt(3),
                Value::UDInt(0x10000)
            ])
        );
        assert_eq!(value(&r, 6), Value::String("Recipe".into()));
        assert_eq!(value(&r, 7), Value::UInt(0x21));
        assert_eq!(value(&r, 8), Value::Bool(true));
        assert_eq!(value(&r, 9), Value::UDInt(0x10000));
        assert_eq!(value(&r, 10), Value::Bool(true));
        assert_eq!(value(&r, 11), Value::Bool(false));
        let types: Vec<_> = r
            .iter()
            .map(|t| t.data_type.clone().unwrap_or_default())
            .collect();
        assert_eq!(
            types,
            [
                "REAL", "BOOL", "BOOL", "LREAL", "LREAL", "UDINT", "STRING", "UINT", "BOOL",
                "UDINT", "BOOL", "BOOL"
            ]
        );
        assert_eq!(r[11].tag, "drive_status.1", "the caller's name");
        // coil, discrete, input, and four holding blocks (the gaps between them are more than 8)
        let functions = fake.functions();
        assert_eq!(functions, [1, 2, 3, 3, 3, 3, 4], "{path}");
    }
}

#[test]
fn plain_addresses_without_a_map() {
    for path in PATHS {
        let (d, fake) = driver_with(path, ModbusOptions::default());
        {
            let mut dev = fake.dev();
            dev.holding[5..7].copy_from_slice(&[0x42F6, 0xE979]);
            dev.input[1] = 0xFFFF;
            dev.coils[2] = true;
        }
        let r = d
            .read(&[
                "hr5:float32",
                "ir1:int16",
                "co0{4}",
                "hr5",
                "di0",
                "Nope",
                "hr1.16",
            ])
            .expect("read");
        assert_eq!(value(&r, 0), Value::Real(123.456));
        assert_eq!(value(&r, 1), Value::Int(-1));
        assert_eq!(
            value(&r, 2),
            Value::Array(vec![
                Value::Bool(false),
                Value::Bool(false),
                Value::Bool(true),
                Value::Bool(false)
            ])
        );
        assert_eq!(value(&r, 3), Value::UInt(0x42F6));
        assert_eq!(value(&r, 4), Value::Bool(false));
        assert_eq!(kind(&r[5]), Some(ErrorKind::NotFound));
        assert_eq!(kind(&r[6]), Some(ErrorKind::BadRequest));
        assert!(d.map().is_empty());
    }
}

#[test]
fn neighbouring_tags_are_one_request_and_gaps_split() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    d.read(&["hr0", "hr2:int32", "hr12", "hr30", "ir0", "hr0@2"])
        .expect("read");
    let requests = fake.dev().requests.clone();
    assert_eq!(
        requests,
        [
            (1, pdu::read_request(Area::Holding, 0, 13)),
            (1, pdu::read_request(Area::Holding, 30, 1)),
            (1, pdu::read_request(Area::Input, 0, 1)),
            (2, pdu::read_request(Area::Holding, 0, 1)),
        ]
    );
}

#[test]
fn picky_device_max_registers() {
    let (d, fake) = driver_with(
        "tcp://h",
        ModbusOptions {
            max_registers: 10,
            ..ModbusOptions::default()
        },
    );
    fake.dev().max_registers = 10;
    fake.dev().holding[0..30].copy_from_slice(&[7; 30]);
    let r = d.read(&["hr0:uint16{30}", "hr0"]).expect("read");
    assert_eq!(value(&r, 0), Value::Array(vec![Value::UInt(7); 30]));
    assert_eq!(value(&r, 1), Value::UInt(7));
    let counts: Vec<u8> = fake.dev().requests.iter().map(|(_, p)| p[4]).collect();
    assert_eq!(counts, [10, 10, 10, 1]);
}

#[test]
fn hole_in_a_merged_block_falls_back_per_tag() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    fake.dev().holes.push((5, 1));
    fake.dev().holding[0] = 1;
    fake.dev().holding[8] = 8;
    let r = d.read(&["hr0", "hr5", "hr8"]).expect("read");
    assert_eq!(value(&r, 0), Value::UInt(1));
    assert_eq!(kind(&r[1]), Some(ErrorKind::NotFound));
    assert_eq!(r[1].error.as_ref().and_then(|e| e.status), Some(2));
    assert_eq!(value(&r, 2), Value::UInt(8));
    assert_eq!(fake.dev().requests.len(), 4, "one merged, then each alone");
    // max_gap 0 never reads an unrequested register
    let (d, fake) = driver_with(
        "tcp://h",
        ModbusOptions {
            max_gap: 0,
            ..ModbusOptions::default()
        },
    );
    fake.dev().holes.push((5, 1));
    let r = d.read(&["hr4", "hr6"]).expect("read");
    assert!(r.iter().all(TagResult::is_ok));
    assert_eq!(fake.dev().requests.len(), 2);
    // one target alone gets its exception with no retry
    fake.clear();
    let r = d.read(&["hr5"]).expect("read");
    assert_eq!(kind(&r[0]), Some(ErrorKind::NotFound));
    assert_eq!(fake.dev().requests.len(), 1);
}

#[test]
fn writes_use_fc05_06_15_16_22() {
    for path in PATHS {
        let (d, fake) = driver(path);
        fake.dev().holding[301] = 0x0101;
        let r = d
            .write(&[
                ("Pump1_Run", Value::Bool(true)),
                ("co0{3}", Value::Array(vec![Value::Bool(true); 3])),
                ("hr400", Value::UInt(9)),
                ("Pump1_Speed", Value::Real(123.456)),
                ("Horn", Value::Bool(true)),
                ("Recipe", Value::String("Mix".into())),
                ("hr10.1", Value::Int(0)),
            ])
            .expect("write");
        assert!(r.iter().all(TagResult::is_ok), "{r:?}");
        assert_eq!(fake.functions(), [5, 15, 6, 16, 22, 16, 22], "{path}");
        let dev = fake.dev();
        assert_eq!(&dev.holding[0..2], &[0xE979, 0x42F6]);
        assert_eq!(dev.holding[301], 0x0111);
        assert_eq!(dev.holding[400], 9);
        assert_eq!(&dev.holding[200..202], &[0x4D69, 0x7800]);
        assert!(dev.coils[0] && dev.coils[2]);
        assert_eq!(r[3].data_type.as_deref(), Some("REAL"));
        assert_eq!(r[3].value, Some(Value::Real(123.456)));
    }
}

#[test]
fn write_multiple_forces_fc15_16() {
    let (d, fake) = driver_with(
        "tcp://h",
        ModbusOptions {
            write_multiple: true,
            ..ModbusOptions::default()
        },
    );
    let r = d
        .write(&[("co1", Value::Bool(true)), ("hr1", Value::UInt(5))])
        .expect("write");
    assert!(r.iter().all(TagResult::is_ok));
    assert_eq!(fake.functions(), [15, 16]);
    assert!(fake.dev().coils[1]);
    assert_eq!(fake.dev().holding[1], 5);
}

#[test]
fn bit_write_without_fc22_is_bad_request_and_sends_nothing_else() {
    let (d, fake) = driver("tcp://h");
    fake.dev().unsupported.push(22);
    let r = d.write(&[("Horn", Value::Bool(true))]).expect("write");
    let error = r[0].error.clone().expect("error");
    assert_eq!((error.kind, error.status), (ErrorKind::BadRequest, Some(1)));
    assert!(error.message.contains("FC22"), "{}", error.message);
    assert_eq!(fake.functions(), [22], "no read-modify-write");
}

#[test]
fn read_only_rows_and_bad_values_are_refused_locally() {
    let (d, fake) = driver("tcp://h");
    let r = d
        .write(&[
            ("Drive_Status", Value::UInt(1)),
            ("Drive_Status.3", Value::Bool(true)),
            ("Tank_Level", Value::LReal(1.0)),
            ("Pump1_Fault", Value::Bool(true)),
            ("ir0", Value::UInt(1)),
            ("hr0:int16", Value::DInt(70000)),
            ("Totals", Value::UDInt(1)),
            ("hr0:uint16{124}", Value::Array(vec![Value::UInt(0); 124])),
            ("Nope", Value::Int(1)),
        ])
        .expect("write");
    let kinds: Vec<_> = r.iter().map(kind).collect();
    use ErrorKind::*;
    assert_eq!(
        kinds,
        [
            Some(Access),
            Some(Access),
            Some(Access),
            Some(Access),
            Some(Access),
            Some(BadValue),
            Some(BadValue),
            Some(BadRequest),
            Some(NotFound)
        ]
    );
    assert_eq!(
        r[0].error.as_ref().map(|e| e.message.as_str()),
        Some("'Drive_Status' is read-only")
    );
    assert!(fake.dev().requests.is_empty());
}

#[test]
fn exceptions_map_to_kinds() {
    use ErrorKind::*;
    for (code, read_kind, write_kind) in [
        (1, BadRequest, BadRequest),
        (2, NotFound, NotFound),
        (3, BadRequest, BadValue),
        (4, Device, Device),
        (5, Refused, Refused),
        (6, Refused, Refused),
        (8, Device, Device),
        (0x0A, Comm, Comm),
        (0x0B, Comm, Comm),
        (0x33, Device, Device),
    ] {
        let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
        fake.dev().exception = Some((3, code));
        let r = d.read(&["hr0"]).expect("read");
        let error = r[0].error.clone().expect("error");
        assert_eq!((error.kind, error.status), (read_kind, Some(code)));
        fake.dev().exception = Some((6, code));
        let r = d.write(&[("hr0", Value::UInt(1))]).expect("write");
        assert_eq!(kind(&r[0]), Some(write_kind));
        assert!(d.connected(), "an exception keeps the link");
    }
}

#[test]
fn rtu_timeout_fails_only_that_units_tags() {
    let (d, fake) = driver_with("rtu+tcp://h", ModbusOptions::default());
    fake.dev().holding[0] = 3;
    let r = d.read(&["hr0", "hr0@9", "hr1"]).expect("read");
    assert_eq!(value(&r, 0), Value::UInt(3));
    let error = r[1].error.clone().expect("dead unit");
    assert_eq!(error.kind, ErrorKind::Comm);
    assert_eq!(error.message, "no reply from unit 9 within 1 s");
    assert_eq!(value(&r, 2), Value::UInt(0));
    assert!(d.connected());
    let r = d.write(&[("hr0@9", Value::UInt(1))]).expect("write");
    assert!(
        r[0].error
            .as_ref()
            .is_some_and(|e| e.message.ends_with("(the write may have been applied)")),
        "{r:?}"
    );
}

#[test]
fn rtu_bad_crc_is_a_comm_result_and_the_next_read_is_good() {
    let (d, fake) = driver_with("rtu+tcp://h", ModbusOptions::default());
    fake.dev().bad_crc_next = true;
    let r = d.read(&["hr0"]).expect("read");
    let error = r[0].error.clone().expect("bad crc");
    assert_eq!(
        (error.kind, error.message.as_str()),
        (ErrorKind::Comm, "bad CRC from unit 1")
    );
    assert!(d.connected());
    assert!(d.read(&["hr0"]).expect("read")[0].is_ok());
}

#[test]
fn rtu_late_reply_is_drained() {
    let (d, fake) = driver_with("rtu+tcp://h", ModbusOptions::default());
    fake.dev().holding[0] = 42;
    // a lost reply, then a reply preceded by stale bytes: the first read times out and sets the drain
    fake.dev().drop_next = 1;
    assert_eq!(
        kind(&d.read(&["hr0"]).expect("read")[0]),
        Some(ErrorKind::Comm)
    );
    fake.dev().output.extend([0x01, 0x03, 0x02, 0x00]);
    let r = d.read(&["hr0"]).expect("read");
    assert_eq!(value(&r, 0), Value::UInt(42));
    // a reply from the wrong unit or function is a bad frame
    fake.dev().garbage_next = true;
    let r = d.read(&["co0"]).expect("read");
    assert_eq!(kind(&r[0]), Some(ErrorKind::Comm));
    assert!(d.read(&["co0"]).expect("read")[0].is_ok());
}

#[test]
fn rtu_late_reply_in_the_input_does_not_shift_later_replies() {
    let (d, fake) = driver_with("rtu+tcp://h", ModbusOptions::default());
    fake.dev().holding[0] = 1;
    fake.dev().holding[200] = 2;
    fake.dev().drop_next = 1;
    assert_eq!(
        kind(&d.read(&["hr0"]).expect("read")[0]),
        Some(ErrorKind::Comm)
    );
    assert_eq!(value(&d.read(&["hr200"]).expect("read"), 0), Value::UInt(2));
    // the lost reply to hr0 turns up after the drain, with the same unit, function and byte count as hr200's
    fake.dev().output.extend(rtu_frame(1, &[3, 2, 0, 1]));
    for _ in 0..3 {
        assert_eq!(value(&d.read(&["hr200"]).expect("read"), 0), Value::UInt(2));
        assert_eq!(value(&d.read(&["hr0"]).expect("read"), 0), Value::UInt(1));
    }
}

#[test]
fn rtu_rejected_reply_drains_and_later_replies_are_good() {
    let (d, fake) = driver_with("rtu+tcp://h", ModbusOptions::default());
    fake.dev().holding[0..2].copy_from_slice(&[3, 4]);
    fake.dev().holding[200] = 2;
    // a late reply with a byte count that does not fit hr0{2}: rejected, its real reply still queued
    fake.dev().late_next = Some(vec![3, 2, 0, 1]);
    let r = d.read(&["hr0{2}"]).expect("read");
    assert_eq!(
        r[0].error.as_ref().map(|e| e.message.as_str()),
        Some("bad reply from unit 1")
    );
    for _ in 0..3 {
        assert_eq!(value(&d.read(&["hr200"]).expect("read"), 0), Value::UInt(2));
        let r = d.read(&["hr0{2}"]).expect("read");
        assert_eq!(
            value(&r, 0),
            Value::Array(vec![Value::UInt(3), Value::UInt(4)])
        );
    }
    // a late FC06 echo for hr5 taken for the write to hr6: the write was applied all the same
    fake.dev().late_next = Some(vec![6, 0, 5, 0, 1]);
    let r = d.write(&[("hr6", Value::UInt(9))]).expect("write");
    let error = r[0].error.clone().expect("bad echo");
    assert_eq!(
        (error.kind, error.message.as_str()),
        (
            ErrorKind::Comm,
            "bad reply from unit 1 (the write may have been applied)"
        )
    );
    assert_eq!(fake.dev().holding[6], 9);
    assert!(d.write(&[("hr7", Value::UInt(1))]).expect("write")[0].is_ok());
}

#[test]
fn bit_of_a_byte_swapped_map_word_reads_and_writes_the_value_bit() {
    let map = TagMap::from_csv(
        "name,area,address,type,order
W,holding,5,uint16,BADC
",
    )
    .expect("map");
    for path in PATHS {
        let (d, fake) = driver_with(
            path,
            ModbusOptions {
                map: Some(map.clone()),
                ..ModbusOptions::default()
            },
        );
        fake.dev().holding[5] = 0x0001; // W = 256: value bit 8
        let r = d.read(&["W", "W.0", "W.8"]).expect("read");
        assert_eq!(value(&r, 0), Value::UInt(256));
        assert_eq!(value(&r, 1), Value::Bool(false));
        assert_eq!(value(&r, 2), Value::Bool(true));
        fake.dev().holding[5] = 0;
        assert!(d.write(&[("W.0", Value::Bool(true))]).expect("write")[0].is_ok());
        assert_eq!(value(&d.read(&["W"]).expect("read"), 0), Value::UInt(1));
        assert_eq!(fake.dev().holding[5], 0x0100);
    }
}

#[test]
fn long_float_array_is_never_split_inside_a_value() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    fake.dev().holding[124..126].copy_from_slice(&[0x42F6, 0xE979]);
    let r = d.read(&["hr0:float32{100}"]).expect("read");
    let Value::Array(items) = value(&r, 0) else {
        panic!("{r:?}")
    };
    assert_eq!(items[62], Value::Real(123.456));
    let starts: Vec<u16> = fake
        .dev()
        .requests
        .iter()
        .map(|(_, pdu)| u16::from_be_bytes([pdu[1], pdu[2]]))
        .collect();
    assert_eq!(starts, [0, 124]);
}

#[test]
fn tcp_link_lost_mid_batch_reports_the_items_already_written() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    let r = d
        .write(&[
            ("hr0", Value::UInt(7)),
            ("hr1@9", Value::UInt(8)),
            ("hr2", Value::UInt(1)),
        ])
        .expect("Ok: hr0 was written");
    assert!(r[0].is_ok(), "{r:?}");
    let failed = r[1].error.clone().expect("dead unit");
    assert_eq!(
        (failed.kind, failed.message.as_str()),
        (
            ErrorKind::Comm,
            "no reply from unit 9 within 1 s (the write may have been applied)"
        )
    );
    assert_eq!(kind(&r[2]), Some(ErrorKind::Comm));
    assert!(
        r[2].error
            .as_ref()
            .is_some_and(|e| e.message.contains("not sent"))
    );
    assert_eq!(&fake.dev().holding[0..3], &[7, 0, 0]);
    assert!(!d.connected());
}

#[test]
fn plain_address_cannot_write_a_read_only_row() {
    let (d, fake) = driver("tcp://h");
    let r = d
        .write(&[("hr300", Value::UInt(1)), ("hr300.2", Value::Bool(true))])
        .expect("write");
    assert_eq!(kind(&r[0]), Some(ErrorKind::Access));
    assert_eq!(kind(&r[1]), Some(ErrorKind::Access));
    assert!(fake.dev().requests.is_empty());
}

#[test]
fn tcp_timeout_drops_the_link() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    fake.dev().drop_next = 1;
    match d.read(&["hr0"]) {
        Err(Error::Comm(message)) => assert_eq!(message, "no reply from unit 1 within 1 s"),
        other => panic!("{other:?}"),
    }
    assert!(!d.connected());
    assert!(d.read(&["hr0"]).is_err(), "not connected");
    assert!(d.open().expect("reopen"));
    assert!(d.read(&["hr0"]).expect("read")[0].is_ok());
}

#[test]
fn tcp_late_reply_with_old_transaction_id_is_skipped() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    fake.dev().holding[0] = 5;
    fake.dev().stale_next = true;
    let r = d.read(&["hr0"]).expect("read");
    assert_eq!(value(&r, 0), Value::UInt(5));
}

#[test]
fn bad_mbap_header_drops_the_link() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    fake.dev().drop_next = 1;
    fake.dev().output.extend([0, 1, 0, 7, 0, 3, 1, 3, 0]);
    assert!(matches!(d.read(&["hr0"]), Err(Error::Comm(_))));
    assert!(!d.connected());
}

#[test]
fn device_info_basic_and_regular_with_paging() {
    for path in PATHS {
        let (d, fake) = driver_with(path, ModbusOptions::default());
        let info = d.device_info(None).expect("info");
        assert_eq!(
            info,
            DeviceInfo {
                vendor_name: "ciplink".into(),
                product_code: "FAKE".into(),
                revision: "1.0".into(),
                product_name: Some("Fake device".into()),
                ..DeviceInfo::default()
            }
        );
        let requests: Vec<Vec<u8>> = fake.dev().requests.iter().map(|(_, p)| p.clone()).collect();
        assert_eq!(
            requests,
            [
                pdu::read_device_id(1, 0),
                pdu::read_device_id(1, 2),
                pdu::read_device_id(2, 0),
                pdu::read_device_id(2, 2),
            ]
        );
        fake.dev().unsupported.push(0x2B);
        match d.device_info(Some(3)) {
            Err(Error::Response {
                kind,
                status,
                message,
                ..
            }) => {
                assert_eq!((kind, status), (Some(ErrorKind::BadRequest), Some(1)));
                assert!(message.ends_with("from unit 3"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn send_pdu_round_trip_and_exception() {
    for path in PATHS {
        let (d, fake) = driver_with(path, ModbusOptions::default());
        fake.dev().holding[1] = 0x1234;
        assert_eq!(
            d.send_pdu(None, &[3, 0, 1, 0, 1]).expect("pdu"),
            [3, 2, 0x12, 0x34]
        );
        match d.send_pdu(Some(4), &[3, 0x03, 0xE8, 0, 1]) {
            Err(Error::Response { status, .. }) => assert_eq!(status, Some(2)),
            other => panic!("{other:?}"),
        }
        assert!(matches!(d.send_pdu(None, &[]), Err(Error::Request { .. })));
        assert_eq!(fake.dev().requests[1].0, 4);
    }
}

#[test]
fn rtu_broadcast_write_gets_no_reply_and_succeeds() {
    let (d, fake) = driver_with("rtu+tcp://h?unit=0", ModbusOptions::default());
    let r = d.write(&[("hr3", Value::UInt(7))]).expect("write");
    assert!(r[0].is_ok(), "{r:?}");
    assert_eq!(fake.dev().holding[3], 7);
    let r = d.read(&["hr3"]).expect("read");
    assert_eq!(kind(&r[0]), Some(ErrorKind::BadRequest));
    assert_eq!(fake.dev().requests.len(), 1);
    // over TCP unit 0 is an ordinary unit
    let (d, _) = driver_with("tcp://h?unit=0", ModbusOptions::default());
    assert!(d.read(&["hr3"]).expect("read")[0].is_ok());
}

#[test]
fn keep_alive_sends_fc08_and_any_reply_counts() {
    let (d, fake) = driver_with("tcp://h", ModbusOptions::default());
    let mut state = d.session.lock();
    state.keep_alive().expect("echo");
    fake.dev().unsupported.push(8);
    state.keep_alive().expect("exception 01 counts");
    assert_eq!(fake.functions(), [8, 8]);
    fake.dev().drop_next = 1;
    assert!(state.keep_alive().is_err());
    assert!(!state.connected(), "a lost keep-alive drops the link");
    drop(state);

    let (d, fake) = driver_with(
        "rtu+tcp://h",
        ModbusOptions {
            keep_alive_address: Some("hr7".into()),
            ..ModbusOptions::default()
        },
    );
    let mut state = d.session.lock();
    state.keep_alive().expect("read");
    assert_eq!(
        fake.dev().requests[0].1,
        pdu::read_request(Area::Holding, 7, 1)
    );
    fake.dev().drop_next = 1;
    assert!(state.keep_alive().is_err());
    assert!(!state.connected(), "on RTU too");
}

#[test]
fn options_and_session_defaults() {
    let fake = Fake::new(false);
    let bad = |options: ModbusOptions| {
        ModbusDriver::with_connector("tcp://h", options, fake.connector()).is_err()
    };
    assert!(bad(ModbusOptions {
        max_registers: 126,
        ..ModbusOptions::default()
    }));
    assert!(bad(ModbusOptions {
        max_registers: 0,
        ..ModbusOptions::default()
    }));
    assert!(bad(ModbusOptions {
        max_bits: 2001,
        ..ModbusOptions::default()
    }));
    assert!(bad(ModbusOptions {
        keep_alive_address: Some("nope".into()),
        ..ModbusOptions::default()
    }));
    assert!(
        ModbusDriver::with_connector("10.0.0.9", ModbusOptions::default(), fake.connector())
            .is_err()
    );
    let tcp = ModbusDriver::default_session("tcp://h").expect("tcp");
    assert_eq!(tcp.keep_alive, Some(Duration::from_secs(30)));
    assert!(tcp.reconnect);
    let rtu = ModbusDriver::default_session("rtu://COM3").expect("rtu");
    assert_eq!(rtu.keep_alive, None);
    assert_eq!(
        ModbusDriver::default_session("rtu+tcp://h")
            .expect("gw")
            .keep_alive,
        Some(Duration::from_secs(30))
    );
    let d =
        ModbusDriver::with_connector("tcp://10.0.0.9", ModbusOptions::default(), fake.connector())
            .expect("driver");
    assert_eq!(d.to_string(), "ModbusDriver(tcp://10.0.0.9:502?unit=1)");
    assert_eq!(d.socket_timeout(), Duration::from_secs(1));
    d.set_socket_timeout(Duration::from_millis(250))
        .expect("set");
    assert_eq!(d.socket_timeout(), Duration::from_millis(250));
    assert!(d.set_socket_timeout(Duration::ZERO).is_err());
    assert!(!d.connected());
    let d = ModbusDriver::with_connector(
        "rtu://COM3?unit=2",
        ModbusOptions::default(),
        fake.connector(),
    )
    .expect("driver");
    assert_eq!(
        d.to_string(),
        "ModbusDriver(rtu://COM3?baud=19200&parity=E&data=8&stop=1&unit=2)"
    );
}

#[test]
fn rtu_frames_on_the_wire() {
    let (d, fake) = driver_with("rtu+tcp://h", ModbusOptions::default());
    d.read(&["hr0:int32"]).expect("read");
    // what the device received, reframed: the CRC the driver sent was checked by the framing
    let (unit, pdu) = fake.dev().requests[0].clone();
    let mut frame = vec![unit];
    frame.extend(&pdu);
    assert_eq!(crc16(&frame).to_le_bytes(), [0xC4, 0x0B]);
}

#[test]
fn tcp_connector_on_localhost() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut request = [0u8; 12];
        s.read_exact(&mut request).expect("request");
        assert_eq!(&request[2..], &[0, 0, 0, 6, 1, 3, 0, 0, 0, 1]);
        let mut reply = request[..2].to_vec();
        reply.extend([0, 0, 0, 5, 1, 3, 2, 0x12, 0x34]);
        s.write_all(&reply).expect("reply");
        // the second request gets no reply: the driver times out and drops the link
        s.read_exact(&mut request).expect("request");
        std::thread::sleep(Duration::from_millis(300));
    });
    let d = ModbusDriver::with_session(
        &format!("tcp://127.0.0.1:{port}"),
        ModbusOptions {
            socket_timeout: Duration::from_millis(100),
            ..ModbusOptions::default()
        },
        SessionOptions::off(),
        modbus_connector(),
    )
    .expect("driver");
    assert!(d.open().expect("open"));
    assert_eq!(
        value(&d.read(&["hr0"]).expect("read"), 0),
        Value::UInt(0x1234)
    );
    match d.read(&["hr0"]) {
        Err(Error::Comm(message)) => assert_eq!(message, "no reply from unit 1 within 0.1 s"),
        other => panic!("{other:?}"),
    }
    assert!(!d.connected());
    server.join().expect("server");
    let refused = ModbusDriver::new(&format!("tcp://127.0.0.1:{port}"), ModbusOptions::default())
        .expect("driver");
    match refused.open() {
        Err(Error::Comm(message)) => {
            assert_eq!(
                message,
                format!("Failed to open socket to 127.0.0.1:{port}")
            );
        }
        other => panic!("{other:?}"),
    }
}
