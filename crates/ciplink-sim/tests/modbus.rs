//! `ModbusDriver` end to end against the Modbus simulator over real sockets on 127.0.0.1, in both framings
//! (Modbus TCP and RTU over TCP): map tags of every type and word order, merged reads counted on the wire,
//! splits at the device's limits, writes, exceptions, unit ids, keep-alive, reconnect, async handles and
//! subscriptions.
#![allow(clippy::unwrap_used)]

use ciplink::cip::TagResult;
use ciplink::modbus::{ModbusDriver, ModbusOptions, TagMap, modbus_connector};
use ciplink::session::{ConnectionEvent, ConnectionState, SessionOptions, SubscribeOptions};
use ciplink::{Error, ErrorKind, Value};
use ciplink_sim::{Framing, ModbusFault, ModbusServer, ModbusSim};
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_millis(300);

const CONFIG: &str = r#"{
  "kind": "modbus",
  "units": [
    {"unit": 1, "holding": 1000, "input": 1000, "coils": 2000, "discrete": 2000,
     "holes": [{"area": "holding", "start": 500, "count": 10}],
     "identity": {"vendor_name": "ciplink", "product_code": "SIM-MB", "revision": "1.0",
                  "product_name": "ciplink-sim Modbus", "model_name": "MB-1"},
     "identity_page": 2},
    {"unit": 2, "holding": 100, "coils": 100, "unsupported": [22, 43]}
  ]
}"#;

/// Every type and word order. Holding rows 10..=86 of unit 1 are one FC03 with the default gap of 8.
const MAP: &str = "\
name,area,address,type,count,order,unit,scale,offset,units,description,writable
Coil,coil,0,bool,,,,,,,Run,
Coils,coil,1,bool,10,,,,,,,
Disc,discrete,3,bool,,,,,,,Fault,
I16,holding,10,int16,,,,,,,,
U16,holding,11,uint16,,,,,,,,
I16_BADC,holding,12,int16,,BADC,,,,,,
I32_ABCD,holding,14,int32,,ABCD,,,,,,
I32_CDAB,holding,16,int32,,CDAB,,,,,,
U32_BADC,holding,18,uint32,,BADC,,,,,,
U32_DCBA,holding,20,uint32,,DCBA,,,,,,
I64_ABCD,holding,22,int64,,ABCD,,,,,,
I64_CDAB,holding,26,int64,,CDAB,,,,,,
U64_BADC,holding,30,uint64,,BADC,,,,,,
U64_DCBA,holding,34,uint64,,DCBA,,,,,,
F32_ABCD,holding,40,float32,,ABCD,,,,,,
F32_CDAB,holding,42,float32,,CDAB,,,,,,
F32_BADC,holding,44,float32,,BADC,,,,,,
F32_DCBA,holding,46,float32,,DCBA,,,,,,
F64_ABCD,holding,50,float64,,ABCD,,,,,,
F64_CDAB,holding,54,float64,,CDAB,,,,,,
F64_BADC,holding,58,float64,,BADC,,,,,,
F64_DCBA,holding,62,float64,,DCBA,,,,,,
Str,holding,70,string,10,,,,,,,
Str_BADC,holding,76,string,5,BADC,,,,,,
Arr,holding,80,int16,4,,,,,,,
Bit,holding,84.4,bool,,,,,,,Horn,
RO,holding,85,uint16,,,,,,,Status,false
Scaled,holding,86,int16,,,,0.5,10,rpm,,
Level,input,10,int16,,,,0.1,-40,degC,,
IR_F32,input,12,float32,,CDAB,,,,,,
U2,holding,5,uint16,,,2,,,,On unit 2,
";

/// Holding-register rows of unit 1: name, value, address, registers on the wire (written by hand from the
/// word-order table: 0x12345678, 0xDEADBEEF, 0x0102030405060708, 0xF102030405060708, 123.456).
fn holding_rows() -> Vec<(&'static str, Value, u16, Vec<u16>)> {
    let f32_ = Value::Real(123.456);
    let f64_ = Value::LReal(123.456);
    vec![
        ("I16", Value::Int(-2), 10, vec![0xFFFE]),
        ("U16", Value::UInt(65000), 11, vec![0xFDE8]),
        ("I16_BADC", Value::Int(0x1234), 12, vec![0x3412]),
        (
            "I32_ABCD",
            Value::DInt(0x1234_5678),
            14,
            vec![0x1234, 0x5678],
        ),
        (
            "I32_CDAB",
            Value::DInt(0x1234_5678),
            16,
            vec![0x5678, 0x1234],
        ),
        (
            "U32_BADC",
            Value::UDInt(0xDEAD_BEEF),
            18,
            vec![0xADDE, 0xEFBE],
        ),
        (
            "U32_DCBA",
            Value::UDInt(0xDEAD_BEEF),
            20,
            vec![0xEFBE, 0xADDE],
        ),
        (
            "I64_ABCD",
            Value::LInt(0x0102_0304_0506_0708),
            22,
            vec![0x0102, 0x0304, 0x0506, 0x0708],
        ),
        (
            "I64_CDAB",
            Value::LInt(0x0102_0304_0506_0708),
            26,
            vec![0x0708, 0x0506, 0x0304, 0x0102],
        ),
        (
            "U64_BADC",
            Value::ULInt(0xF102_0304_0506_0708),
            30,
            vec![0x02F1, 0x0403, 0x0605, 0x0807],
        ),
        (
            "U64_DCBA",
            Value::ULInt(0xF102_0304_0506_0708),
            34,
            vec![0x0807, 0x0605, 0x0403, 0x02F1],
        ),
        ("F32_ABCD", f32_.clone(), 40, vec![0x42F6, 0xE979]),
        ("F32_CDAB", f32_.clone(), 42, vec![0xE979, 0x42F6]),
        ("F32_BADC", f32_.clone(), 44, vec![0xF642, 0x79E9]),
        ("F32_DCBA", f32_, 46, vec![0x79E9, 0xF642]),
        (
            "F64_ABCD",
            f64_.clone(),
            50,
            vec![0x405E, 0xDD2F, 0x1A9F, 0xBE77],
        ),
        (
            "F64_CDAB",
            f64_.clone(),
            54,
            vec![0xBE77, 0x1A9F, 0xDD2F, 0x405E],
        ),
        (
            "F64_BADC",
            f64_.clone(),
            58,
            vec![0x5E40, 0x2FDD, 0x9F1A, 0x77BE],
        ),
        ("F64_DCBA", f64_, 62, vec![0x77BE, 0x9F1A, 0x2FDD, 0x5E40]),
        (
            "Str",
            Value::String("HELLO".into()),
            70,
            vec![0x4845, 0x4C4C, 0x4F00, 0, 0],
        ),
        (
            "Str_BADC",
            Value::String("Hi!".into()),
            76,
            vec![0x6948, 0x0021, 0],
        ),
        (
            "Arr",
            Value::Array(vec![
                Value::Int(1),
                Value::Int(-1),
                Value::Int(300),
                Value::Int(-300),
            ]),
            80,
            vec![1, 0xFFFF, 300, 0xFED4],
        ),
        ("Scaled", Value::LReal(20.0), 86, vec![20]),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Tcp,
    RtuTcp,
}

const MODES: [Mode; 2] = [Mode::Tcp, Mode::RtuTcp];

/// A simulator served on 127.0.0.1 in one framing.
struct Rig {
    sim: ModbusSim,
    mode: Mode,
    path: String,
    _server: ModbusServer,
}

fn rig_with(config: &str, mode: Mode) -> Rig {
    let sim = ModbusSim::from_json(config).unwrap();
    let (framing, scheme) = match mode {
        Mode::Tcp => (Framing::Mbap, "tcp"),
        Mode::RtuTcp => (Framing::Rtu, "rtu+tcp"),
    };
    let server = sim.serve("127.0.0.1:0", framing).unwrap();
    Rig {
        path: format!("{scheme}://127.0.0.1:{}", server.port()),
        sim,
        mode,
        _server: server,
    }
}

fn rig(mode: Mode) -> Rig {
    rig_with(CONFIG, mode)
}

fn options() -> ModbusOptions {
    ModbusOptions {
        map: Some(TagMap::from_csv(MAP).unwrap()),
        socket_timeout: TIMEOUT,
        ..ModbusOptions::default()
    }
}

fn off() -> SessionOptions {
    SessionOptions::off()
}

fn reconnecting(min_ms: u64, max_ms: u64) -> SessionOptions {
    SessionOptions {
        reconnect: true,
        reconnect_min: Duration::from_millis(min_ms),
        reconnect_max: Duration::from_millis(max_ms),
        keep_alive: None,
    }
}

/// One request as the simulator received it.
#[derive(Clone, Debug, PartialEq)]
struct Request {
    unit: u8,
    pdu: Vec<u8>,
}

impl Request {
    fn function(&self) -> u8 {
        self.pdu[0]
    }

    /// Function, start and quantity of a read (or address and value of FC05/06).
    fn span(&self) -> (u8, u16, u16) {
        let word = |at: usize| u16::from_be_bytes([self.pdu[at], self.pdu[at + 1]]);
        (self.pdu[0], word(1), word(3))
    }
}

impl Rig {
    fn driver_on(
        &self,
        path: &str,
        options: ModbusOptions,
        session: SessionOptions,
    ) -> ModbusDriver {
        let plc = ModbusDriver::with_session(path, options, session, modbus_connector()).unwrap();
        assert!(plc.open().unwrap());
        plc
    }

    fn driver(&self, options: ModbusOptions, session: SessionOptions) -> ModbusDriver {
        self.driver_on(&self.path, options, session)
    }

    /// The requests received since recording started or the last call.
    fn requests(&self) -> Vec<Request> {
        self.sim
            .take_received()
            .into_iter()
            .map(|f| match self.mode {
                Mode::Tcp => Request {
                    unit: f[6],
                    pdu: f[7..].to_vec(),
                },
                Mode::RtuTcp => Request {
                    unit: f[0],
                    pdu: f[1..f.len() - 2].to_vec(),
                },
            })
            .collect()
    }

    fn spans(&self) -> Vec<(u8, u16, u16)> {
        self.requests().iter().map(Request::span).collect()
    }

    fn holding(&self, unit: u8, address: u16, count: u16) -> Vec<u16> {
        self.sim.registers(unit, "holding", address, count).unwrap()
    }

    fn set_holding(&self, unit: u8, address: u16, values: &[u16]) {
        self.sim
            .set_registers(unit, "holding", address, values)
            .unwrap();
    }
}

fn value(results: &[TagResult], i: usize) -> Value {
    assert!(results[i].error.is_none(), "{:?}", results[i]);
    results[i].value.clone().unwrap()
}

fn kind(result: &TagResult) -> Option<ErrorKind> {
    result.error.as_ref().map(|e| e.kind)
}

fn status(result: &TagResult) -> Option<u8> {
    result.error.as_ref().and_then(|e| e.status)
}

fn events(plc: &ModbusDriver) -> Receiver<ConnectionEvent> {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    plc.set_connection_callback(Some(Box::new(move |e| {
        let _ = tx.lock().unwrap().send(e.clone());
    })));
    rx
}

/// Waits for the Connected event, skipping the others.
fn reconnected(rx: &Receiver<ConnectionEvent>) -> bool {
    let deadline = Instant::now() + WAIT;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ConnectionEvent::Connected) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// Holds the next request inside the simulator until the sender sends; the receiver says it is held.
fn hold_next(sim: &ModbusSim) -> (Sender<()>, Receiver<()>) {
    let (release, gate) = channel::<()>();
    let (started_tx, started) = channel();
    let mut armed = true;
    sim.on_request(move |_, _| {
        if std::mem::take(&mut armed) {
            let _ = started_tx.send(());
            let _ = gate.recv();
        }
    });
    (release, started)
}

// ------------------------------------------------------------------------------------------------ types

#[test]
fn reads_every_type_and_word_order_from_the_map_in_five_requests() {
    for mode in MODES {
        let rig = rig(mode);
        let rows = holding_rows();
        for (_, _, address, regs) in &rows {
            rig.set_holding(1, *address, regs);
        }
        rig.set_holding(1, 84, &[0x8011]);
        rig.set_holding(1, 85, &[7]);
        rig.set_holding(2, 5, &[42]);
        rig.sim
            .set_registers(1, "input", 10, &[250, 0, 0xE979, 0x42F6])
            .unwrap();
        rig.sim
            .set_bits(1, "coil", 0, &[true, false, true, true])
            .unwrap();
        rig.sim.set_bits(1, "discrete", 3, &[true]).unwrap();
        let plc = rig.driver(options(), off());

        let mut names: Vec<&str> = rows.iter().map(|r| r.0).collect();
        names.extend([
            "Bit", "RO", "Level", "IR_F32", "Coil", "Coils", "Disc", "U2",
        ]);
        rig.sim.record(true);
        let results = plc.read(&names).unwrap();
        for (i, (name, expected, _, _)) in rows.iter().enumerate() {
            assert_eq!(results[i].tag, *name);
            assert_eq!(&value(&results, i), expected, "{mode:?} {name}");
        }
        let n = rows.len();
        assert_eq!(value(&results, n), Value::Bool(true));
        assert_eq!(value(&results, n + 1), Value::UInt(7));
        match value(&results, n + 2) {
            Value::LReal(v) => assert!((v - -15.0).abs() < 1e-9, "{v}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(value(&results, n + 3), Value::Real(123.456));
        assert_eq!(value(&results, n + 4), Value::Bool(true));
        let mut coils = vec![Value::Bool(false); 10];
        coils[1] = Value::Bool(true);
        coils[2] = Value::Bool(true);
        assert_eq!(value(&results, n + 5), Value::Array(coils));
        assert_eq!(value(&results, n + 6), Value::Bool(true));
        assert_eq!(value(&results, n + 7), Value::UInt(42));

        let types: Vec<&str> = results
            .iter()
            .map(|r| r.data_type.as_deref().unwrap())
            .collect();
        assert_eq!(
            types,
            [
                "INT", "UINT", "INT", "DINT", "DINT", "UDINT", "UDINT", "LINT", "LINT", "ULINT",
                "ULINT", "REAL", "REAL", "REAL", "REAL", "LREAL", "LREAL", "LREAL", "LREAL",
                "STRING", "STRING", "INT", "LREAL", "BOOL", "UINT", "LREAL", "REAL", "BOOL",
                "BOOL", "BOOL", "UINT"
            ]
        );
        // unit, then area (coil, discrete, holding, input); unit 2 last
        let requests = rig.requests();
        let units: Vec<u8> = requests.iter().map(|r| r.unit).collect();
        assert_eq!(units, [1, 1, 1, 1, 2], "{mode:?}");
        assert_eq!(
            requests.iter().map(Request::span).collect::<Vec<_>>(),
            [(1, 0, 11), (2, 3, 1), (3, 10, 77), (4, 10, 4), (3, 5, 1)],
            "{mode:?}"
        );
    }
}

#[test]
fn writes_every_type_and_word_order_with_the_right_functions() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 84, &[0x8001]);
        let plc = rig.driver(options(), off());
        let rows = holding_rows();
        let mut items: Vec<(&str, Value)> = rows.iter().map(|r| (r.0, r.1.clone())).collect();
        items.extend([
            ("Bit", Value::Bool(true)),
            ("Coil", Value::Bool(true)),
            ("Coils", Value::Array(vec![Value::Bool(true); 10])),
            ("U2", Value::UInt(9)),
        ]);
        rig.sim.record(true);
        let results = plc.write(&items).unwrap();
        for (i, r) in results.iter().enumerate() {
            assert!(r.error.is_none(), "{mode:?} {r:?}");
            assert_eq!(r.value.as_ref(), Some(&items[i].1));
        }
        for (name, _, address, regs) in &rows {
            let len = u16::try_from(regs.len()).unwrap();
            assert_eq!(&rig.holding(1, *address, len), regs, "{mode:?} {name}");
        }
        assert_eq!(rig.holding(1, 84, 1), [0x8011], "FC22 keeps the other bits");
        assert_eq!(rig.sim.bits(1, "coil", 0, 11).unwrap(), [true; 11]);
        assert_eq!(rig.holding(2, 5, 1), [9]);

        let functions: Vec<u8> = rig.requests().iter().map(Request::function).collect();
        let mut expected = vec![6, 6, 6];
        expected.extend([16; 19]);
        expected.extend([6, 22, 5, 15, 6]);
        assert_eq!(functions, expected, "{mode:?}");

        // every value read back as written
        let names: Vec<&str> = items.iter().map(|i| i.0).collect();
        let back = plc.read(&names).unwrap();
        for (i, item) in items.iter().enumerate() {
            assert_eq!(value(&back, i), item.1, "{mode:?} {}", item.0);
        }
    }
}

// ------------------------------------------------------------------------------------------------ merging

#[test]
fn neighbours_merge_and_gaps_units_and_areas_split() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 0, &[10, 11, 12, 13, 14, 0, 7]);
        let plc = rig.driver(options(), off());
        rig.sim.record(true);
        let results = plc
            .read(&[
                "hr29",
                "hr0",
                "hr1",
                "hr5:int32",
                "hr20",
                "hr40",
                "hr0@2",
                "ir0",
                "co0",
                "di0",
            ])
            .unwrap();
        assert!(results.iter().all(|r| r.error.is_none()), "{results:?}");
        assert_eq!(value(&results, 3), Value::DInt(7));
        // hr0..6 is one; hr20 is 13 past it (more than 8); hr29 is 8 past hr20; hr40 is 10 past hr29
        assert_eq!(
            rig.spans(),
            [
                (1, 0, 1),
                (2, 0, 1),
                (3, 0, 7),
                (3, 20, 10),
                (3, 40, 1),
                (4, 0, 1),
                (3, 0, 1)
            ],
            "{mode:?}"
        );

        let gapless = rig.driver(
            ModbusOptions {
                max_gap: 0,
                ..options()
            },
            off(),
        );
        gapless.read(&["hr0", "hr2", "hr1:int32"]).unwrap();
        assert_eq!(rig.spans(), [(3, 0, 3)], "touching tags still join");
        gapless.read(&["hr0", "hr2"]).unwrap();
        assert_eq!(rig.spans(), [(3, 0, 1), (3, 2, 1)]);
    }
}

#[test]
fn reads_beyond_the_device_limits_split() {
    let picky = CONFIG.replace(
        "\"kind\": \"modbus\",",
        "\"max_registers\": 10, \"max_bits\": 16,",
    );
    for mode in MODES {
        let rig = rig_with(&picky, mode);
        let counting: Vec<u16> = (0..25).collect();
        rig.set_holding(1, 0, &counting);
        let bits: Vec<bool> = (0..40).map(|i| i % 3 == 0).collect();
        rig.sim.set_bits(1, "coil", 0, &bits).unwrap();
        let plc = rig.driver(
            ModbusOptions {
                max_registers: 10,
                max_bits: 16,
                ..options()
            },
            off(),
        );
        rig.sim.record(true);
        let results = plc.read(&["hr0:uint16{25}", "co0{40}"]).unwrap();
        assert_eq!(
            value(&results, 0),
            Value::Array(counting.iter().map(|&v| Value::UInt(v)).collect())
        );
        assert_eq!(
            value(&results, 1),
            Value::Array(bits.iter().map(|&b| Value::Bool(b)).collect())
        );
        assert_eq!(
            rig.spans(),
            [
                (1, 0, 16),
                (1, 16, 16),
                (1, 32, 8),
                (3, 0, 10),
                (3, 10, 10),
                (3, 20, 5)
            ],
            "{mode:?}"
        );
        // neighbours fill a request up to the limit, then start the next
        plc.read(&["hr0", "hr5", "hr9", "hr12"]).unwrap();
        assert_eq!(rig.spans(), [(3, 0, 10), (3, 12, 1)]);
        // a string past the limit is put together from two requests
        rig.set_holding(1, 0, &[0x4142; 12]);
        let s = plc.read(&["hr0:string{24}"]).unwrap();
        assert_eq!(value(&s, 0), Value::String("AB".repeat(12)));
        assert_eq!(rig.spans(), [(3, 0, 10), (3, 10, 2)]);

        // a driver left at 125 gets the device's exception 03 for a read it refuses
        let eager = rig.driver(options(), off());
        let r = eager.read(&["hr0:uint16{20}"]).unwrap();
        assert_eq!(
            (kind(&r[0]), status(&r[0])),
            (Some(ErrorKind::BadRequest), Some(3))
        );
        assert_eq!(rig.spans(), [(3, 0, 20)]);
        // ... and merged neighbours that the device refuses fall back to one read each
        let r = eager.read(&["hr0", "hr8", "hr16"]).unwrap();
        assert!(r.iter().all(|r| r.error.is_none()), "{r:?}");
        assert_eq!(rig.spans(), [(3, 0, 17), (3, 0, 1), (3, 8, 1), (3, 16, 1)]);
    }
    // the protocol limit: 300 registers in three requests on a default device
    let rig = rig(Mode::Tcp);
    let plc = rig.driver(options(), off());
    rig.sim.record(true);
    let r = plc.read(&["hr0{300}"]).unwrap();
    assert!(r[0].error.is_none(), "{r:?}");
    assert_eq!(rig.spans(), [(3, 0, 125), (3, 125, 125), (3, 250, 50)]);
}

#[test]
fn hole_in_a_merged_read_falls_back_per_tag() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 497, &[1]);
        rig.set_holding(1, 512, &[2]);
        let plc = rig.driver(options(), off());
        rig.sim.record(true);
        let r = plc.read(&["hr497", "hr505", "hr512"]).unwrap();
        assert_eq!(value(&r, 0), Value::UInt(1));
        assert_eq!(
            (kind(&r[1]), status(&r[1])),
            (Some(ErrorKind::NotFound), Some(2))
        );
        assert_eq!(r[1].data_type.as_deref(), Some("UINT"));
        assert_eq!(value(&r, 2), Value::UInt(2));
        assert_eq!(
            rig.spans(),
            [(3, 497, 16), (3, 497, 1), (3, 505, 1), (3, 512, 1)]
        );
    }
}

// ------------------------------------------------------------------------------------------------ writes

#[test]
fn bit_writes_use_mask_write_only() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 11, &[0x00F0]);
        rig.set_holding(1, 200, &[0x0001]);
        let plc = rig.driver(options(), off());
        rig.sim.record(true);
        let r = plc
            .write(&[
                ("U16.0", Value::Bool(true)),
                ("U16.4", Value::Bool(false)),
                ("hr200.15", Value::Int(1)),
            ])
            .unwrap();
        assert!(r.iter().all(|r| r.error.is_none()), "{r:?}");
        assert_eq!(rig.holding(1, 11, 1), [0x00E1]);
        assert_eq!(rig.holding(1, 200, 1), [0x8001]);
        let requests = rig.requests();
        assert!(requests.iter().all(|r| r.function() == 22), "{requests:?}");
        assert_eq!(requests[0].pdu, [22, 0, 11, 0xFF, 0xFE, 0, 1]);

        // unit 2 lacks FC22: the exception is the result and nothing else is sent (no read-modify-write)
        let r = plc.write(&[("hr3.1@2", Value::Bool(true))]).unwrap();
        let error = r[0].error.as_ref().unwrap();
        assert_eq!((error.kind, error.status), (ErrorKind::BadRequest, Some(1)));
        assert!(error.message.contains("FC22"), "{}", error.message);
        assert_eq!(rig.requests().len(), 1);
        assert_eq!(rig.holding(2, 3, 1), [0]);
    }
}

#[test]
fn write_multiple_forces_fc15_and_fc16() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(
            ModbusOptions {
                write_multiple: true,
                ..options()
            },
            off(),
        );
        rig.sim.record(true);
        let r = plc
            .write(&[("U16", Value::UInt(5)), ("Coil", Value::Bool(true))])
            .unwrap();
        assert!(r.iter().all(|r| r.error.is_none()), "{r:?}");
        let requests = rig.requests();
        assert_eq!(requests[0].pdu, [16, 0, 11, 0, 1, 2, 0, 5]);
        assert_eq!(requests[1].pdu, [15, 0, 0, 0, 1, 1, 1]);
        assert_eq!(rig.holding(1, 11, 1), [5]);
    }
}

#[test]
fn read_only_and_bad_values_are_refused_without_a_request() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        rig.sim.record(true);
        let r = plc
            .write(&[
                ("RO", Value::UInt(1)),
                ("RO.3", Value::Bool(true)),
                ("Disc", Value::Bool(true)),
                ("Level", Value::LReal(1.0)),
                ("ir3", Value::UInt(1)),
                ("hr85", Value::UInt(1)), // RO by its plain address
                ("I16", Value::DInt(70000)),
                ("Str", Value::String("x".repeat(11))),
                ("nope", Value::Int(1)),
            ])
            .unwrap();
        let kinds: Vec<_> = r.iter().map(kind).collect();
        assert_eq!(
            kinds,
            [
                Some(ErrorKind::Access),
                Some(ErrorKind::Access),
                Some(ErrorKind::Access),
                Some(ErrorKind::Access),
                Some(ErrorKind::Access),
                Some(ErrorKind::Access),
                Some(ErrorKind::BadValue),
                Some(ErrorKind::BadValue),
                Some(ErrorKind::NotFound)
            ],
            "{mode:?} {r:?}"
        );
        assert!(rig.requests().is_empty());
        // a write longer than one request is refused, not split
        let r = plc
            .write(&[("hr200{124}", Value::Array(vec![Value::UInt(0); 124]))])
            .unwrap();
        assert_eq!(kind(&r[0]), Some(ErrorKind::BadRequest));
        assert!(rig.requests().is_empty());
    }
}

// ------------------------------------------------------------------------------------------------ errors

#[test]
fn exceptions_map_to_error_kinds() {
    let table = [
        (1, ErrorKind::BadRequest),
        (2, ErrorKind::NotFound),
        (3, ErrorKind::BadRequest),
        (4, ErrorKind::Device),
        (5, ErrorKind::Refused),
        (6, ErrorKind::Refused),
        (8, ErrorKind::Device),
        (0x0A, ErrorKind::Comm),
        (0x0B, ErrorKind::Comm),
        (0x42, ErrorKind::Device),
    ];
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        for (code, expected) in table {
            rig.sim.inject(ModbusFault::Exception {
                unit: 1,
                function: None,
                code,
            });
            let r = plc.read(&["I16", "Coil"]).unwrap();
            for r in &r {
                let e = r.error.as_ref().unwrap();
                assert_eq!((e.kind, e.status), (expected, Some(code)), "{mode:?} {r:?}");
                assert!(e.message.ends_with("from unit 1"), "{}", e.message);
            }
            let w = plc.write(&[("I16", Value::Int(1))]).unwrap();
            let write_kind = if code == 3 {
                ErrorKind::BadValue
            } else {
                expected
            };
            assert_eq!(kind(&w[0]), Some(write_kind));
            rig.sim.clear_faults();
        }
        assert!(plc.connected(), "exceptions keep the link");
        assert_eq!(value(&plc.read(&["I16"]).unwrap(), 0), Value::Int(0));
    }
}

#[test]
fn unit_ids_from_the_path_the_map_and_the_address() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 5, &[1]);
        rig.set_holding(2, 5, &[2]);
        let on2 = rig.driver_on(&format!("{}?unit=2", rig.path), options(), off());
        rig.sim.record(true);
        let r = on2.read(&["hr5", "hr5@1", "U2", "I16"]).unwrap();
        assert_eq!(value(&r, 0), Value::UInt(2));
        assert_eq!(value(&r, 1), Value::UInt(1));
        assert_eq!(value(&r, 2), Value::UInt(2));
        // a map row without a unit takes the path's
        assert_eq!(value(&r, 3), Value::Int(0));
        let units: Vec<u8> = rig.requests().iter().map(|r| r.unit).collect();
        assert_eq!(units, [1, 2], "{mode:?}");
        on2.write(&[("hr6", Value::UInt(66))]).unwrap();
        assert_eq!(rig.holding(2, 6, 1), [66]);
    }
}

#[test]
fn unknown_unit_is_a_tag_error_and_the_link_stays() {
    // a gateway answers 0B over Modbus TCP; on an RTU bus nobody answers and the request times out
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        let started = Instant::now();
        let r = plc.read(&["hr0@9", "hr0"]).unwrap();
        let e = r[0].error.as_ref().unwrap();
        assert_eq!(e.kind, ErrorKind::Comm, "{mode:?} {e:?}");
        match mode {
            Mode::Tcp => assert_eq!(e.status, Some(0x0B)),
            Mode::RtuTcp => {
                assert_eq!(e.status, None);
                assert!(e.message.contains("no reply from unit 9"), "{}", e.message);
                // Windows socket timeouts can fire a few milliseconds early
                assert!(started.elapsed() >= TIMEOUT - Duration::from_millis(50));
            }
        }
        assert_eq!(value(&r, 1), Value::UInt(0));
        assert!(plc.connected());
    }
}

#[test]
fn rtu_timeout_and_bad_crc_fail_only_their_request() {
    let rig = rig(Mode::RtuTcp);
    rig.set_holding(1, 0, &[5]);
    let plc = rig.driver(options(), off());
    rig.sim.inject(ModbusFault::BadCrc(1));
    let r = plc.read(&["hr0"]).unwrap();
    let e = r[0].error.as_ref().unwrap();
    assert_eq!(e.kind, ErrorKind::Comm);
    assert!(e.message.contains("bad CRC"), "{}", e.message);
    assert_eq!(value(&plc.read(&["hr0"]).unwrap(), 0), Value::UInt(5));

    // a late reply is drained before the next request, not taken for its reply
    rig.sim
        .inject(ModbusFault::Delay(TIMEOUT + Duration::from_millis(100)));
    let r = plc.read(&["hr0"]).unwrap();
    assert_eq!(kind(&r[0]), Some(ErrorKind::Comm));
    rig.sim.clear_faults();
    rig.set_holding(1, 1, &[6]);
    std::thread::sleep(Duration::from_millis(150));
    let r = plc.read(&["hr1"]).unwrap();
    assert_eq!(value(&r, 0), Value::UInt(6));

    // a write that times out may have been applied
    rig.sim.inject(ModbusFault::DropReplies(1));
    let w = plc.write(&[("hr2", Value::UInt(1))]).unwrap();
    let e = w[0].error.as_ref().unwrap();
    assert!(e.message.contains("may have been applied"), "{}", e.message);
    assert_eq!(rig.holding(1, 2, 1), [1]);
    assert!(plc.connected());
}

#[test]
fn tcp_timeout_fails_the_call_and_reconnects() {
    let rig = rig(Mode::Tcp);
    let plc = rig.driver(options(), reconnecting(10, 80));
    let rx = events(&plc);
    rig.sim.inject(ModbusFault::DropReplies(1));
    let err = plc.read(&["hr0"]).unwrap_err();
    assert!(
        matches!(err, Error::Comm(ref m) if m.contains("no reply")),
        "{err:?}"
    );
    assert!(reconnected(&rx));
    assert_eq!(value(&plc.read(&["hr0"]).unwrap(), 0), Value::UInt(0));
}

// ------------------------------------------------------------------------------------------------ session

#[test]
fn reconnects_after_the_sim_closes_connections() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 0, &[3]);
        let plc = rig.driver(options(), reconnecting(10, 80));
        let rx = events(&plc);
        assert_eq!(value(&plc.read(&["hr0"]).unwrap(), 0), Value::UInt(3));
        rig.sim.inject(ModbusFault::CloseConnections);
        let err = plc.read(&["hr0"]).unwrap_err();
        assert!(matches!(err, Error::Comm(_)), "{mode:?} {err:?}");
        assert!(reconnected(&rx), "{mode:?}");
        assert_eq!(plc.connection_state(), ConnectionState::Connected);
        assert_eq!(value(&plc.read(&["hr0"]).unwrap(), 0), Value::UInt(3));
    }
}

#[test]
fn keep_alive_sends_fc08_when_idle_and_any_reply_counts() {
    for mode in MODES {
        // unit 1 answers FC08 with exception 01, which still proves the link
        for config in [
            CONFIG.to_owned(),
            CONFIG.replace(
                "\"identity_page\": 2",
                "\"identity_page\": 2, \"unsupported\": [8]",
            ),
        ] {
            let rig = rig_with(&config, mode);
            let plc = rig.driver(
                options(),
                SessionOptions {
                    keep_alive: Some(Duration::from_millis(40)),
                    ..off()
                },
            );
            rig.sim.record(true);
            std::thread::sleep(Duration::from_millis(300));
            let requests = rig.requests();
            assert!(requests.len() >= 3, "{mode:?} {requests:?}");
            assert!(
                requests
                    .iter()
                    .all(|r| r.unit == 1 && r.pdu == [8, 0, 0, 0, 0]),
                "{requests:?}"
            );
            assert_eq!(plc.connection_state(), ConnectionState::Connected);
        }
    }
}

#[test]
fn keep_alive_address_reads_instead() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(
            ModbusOptions {
                keep_alive_address: Some("hr3@2".into()),
                ..options()
            },
            SessionOptions {
                keep_alive: Some(Duration::from_millis(40)),
                ..off()
            },
        );
        rig.sim.record(true);
        std::thread::sleep(Duration::from_millis(200));
        let requests = rig.requests();
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|r| r.unit == 2 && r.pdu == [3, 0, 3, 0, 1]),
            "{requests:?}"
        );
        drop(plc);
    }
}

#[test]
fn keep_alive_finds_a_link_lost_while_idle_and_reconnects() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(
            options(),
            SessionOptions {
                keep_alive: Some(Duration::from_millis(30)),
                ..reconnecting(10, 80)
            },
        );
        // one request first: the server takes the connection's epoch when its thread starts serving it
        assert!(plc.read(&["hr0"]).unwrap()[0].error.is_none());
        let rx = events(&plc);
        rig.sim.inject(ModbusFault::CloseConnections);
        assert!(matches!(
            rx.recv_timeout(WAIT).unwrap(),
            ConnectionEvent::Disconnected { .. }
        ));
        assert!(reconnected(&rx), "{mode:?}");
        assert!(plc.read(&["hr0"]).unwrap()[0].error.is_none());
    }
}

#[test]
fn reads_from_three_callers_are_one_request() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 0, &[1, 2, 0, 3, 4, 5]);
        let plc = rig.driver(options(), off());
        let names = ["hr1", "hr3:int32", "hr5"];
        let solo: Vec<Value> = names
            .iter()
            .map(|t| value(&plc.read(&[t]).unwrap(), 0))
            .collect();
        rig.sim.record(true);
        let (release, held) = hold_next(&rig.sim);
        let first = plc.read_async(&["hr0"]);
        held.recv_timeout(WAIT).unwrap();
        let handles: Vec<_> = names.iter().map(|t| plc.read_async(&[t])).collect();
        release.send(()).unwrap();
        assert_eq!(value(&first.wait().unwrap(), 0), Value::UInt(1));
        for (i, h) in handles.into_iter().enumerate() {
            let r = h.wait().unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].tag, names[i]);
            assert_eq!(value(&r, 0), solo[i]);
        }
        rig.sim.clear_hook();
        assert_eq!(rig.spans(), [(3, 0, 1), (3, 1, 5)], "{mode:?}");
    }
}

#[test]
fn async_write_then_read_from_two_callers_reads_the_write() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        let (release, held) = hold_next(&rig.sim);
        let first = plc.read_async(&["hr0"]);
        held.recv_timeout(WAIT).unwrap();
        let write = plc.write_async(&[("F32_CDAB", Value::Real(2.5))]);
        let read = plc.read_async(&["F32_CDAB"]);
        assert!(!read.is_done());
        release.send(()).unwrap();
        first.wait().unwrap();
        assert!(write.wait().unwrap()[0].error.is_none());
        assert_eq!(value(&read.wait().unwrap(), 0), Value::Real(2.5));
        rig.sim.clear_hook();

        let (tx, rx) = channel();
        plc.read_async(&["F32_CDAB"]).on_complete(move |r| {
            let _ = tx.send(r);
        });
        let r = rx.recv_timeout(WAIT).unwrap().unwrap();
        assert_eq!(value(&r, 0), Value::Real(2.5));
    }
}

#[test]
fn subscription_with_deadband_delivers_only_big_changes() {
    for mode in MODES {
        let rig = rig(mode);
        rig.set_holding(1, 40, &[0x42F6, 0xE979]); // 123.456
        let plc = rig.driver(options(), off());
        let sub = plc
            .subscribe(
                &["F32_ABCD", "Coil"],
                SubscribeOptions {
                    interval: Duration::from_millis(20),
                    deadband: Some(1.0),
                },
            )
            .unwrap();
        let first = sub.recv_timeout(WAIT).unwrap();
        assert_eq!(first.results.len(), 2);
        let set = |v: f32| {
            let bits = v.to_bits();
            rig.set_holding(1, 40, &[(bits >> 16) as u16, bits as u16]);
        };
        set(123.956);
        assert!(
            sub.recv_timeout(Duration::from_millis(200)).is_none(),
            "{mode:?}"
        );
        set(125.0);
        let next = sub.recv_timeout(WAIT).unwrap();
        assert_eq!(next.results.len(), 1);
        assert_eq!(next.results[0].value, Some(Value::Real(125.0)));
        // the deadband counts from the last delivered value, not the last read
        set(125.6);
        assert!(sub.recv_timeout(Duration::from_millis(200)).is_none());
        set(126.2);
        let next = sub.recv_timeout(WAIT).unwrap();
        assert_eq!(next.results[0].value, Some(Value::Real(126.2)));
        // bools change whatever the deadband
        rig.sim.set_bits(1, "coil", 0, &[true]).unwrap();
        let next = sub.recv_timeout(WAIT).unwrap();
        assert_eq!(next.results[0].tag, "Coil");
        assert_eq!(next.results[0].value, Some(Value::Bool(true)));

        // each poll is one request per area
        rig.sim.record(true);
        std::thread::sleep(Duration::from_millis(150));
        sub.close();
        let spans = rig.spans();
        assert!(spans.len() >= 4, "{spans:?}");
        assert!(
            spans.iter().all(|s| [(1, 0, 1), (3, 40, 2)].contains(s)),
            "{mode:?} {spans:?}"
        );
        assert!(spans.windows(2).all(|w| w[0] != w[1]), "{spans:?}");
    }
}

#[test]
fn subscription_reports_an_exception_and_its_recovery() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        let sub = plc
            .subscribe(
                &["I16", "Coil"],
                SubscribeOptions {
                    interval: Duration::from_millis(20),
                    deadband: None,
                },
            )
            .unwrap();
        sub.recv_timeout(WAIT).unwrap();
        rig.sim.inject(ModbusFault::Exception {
            unit: 1,
            function: Some(3),
            code: 4,
        });
        let next = sub.recv_timeout(WAIT).unwrap();
        assert_eq!(next.results.len(), 1);
        assert_eq!(next.results[0].tag, "I16");
        assert_eq!(status(&next.results[0]), Some(4));
        rig.sim.clear_faults();
        let next = sub.recv_timeout(WAIT).unwrap();
        assert_eq!(next.results[0].value, Some(Value::Int(0)));
    }
}

// ------------------------------------------------------------------------------------------------ others

#[test]
fn device_info_with_paging_and_send_pdu() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        let info = plc.device_info(None).unwrap();
        assert_eq!(info.vendor_name, "ciplink");
        assert_eq!(info.product_code, "SIM-MB");
        assert_eq!(info.revision, "1.0");
        assert_eq!(info.product_name.as_deref(), Some("ciplink-sim Modbus"));
        assert_eq!(info.model_name.as_deref(), Some("MB-1"));
        assert_eq!(info.vendor_url, None);
        match plc.device_info(Some(2)) {
            Err(Error::Response { kind, status, .. }) => {
                assert_eq!((kind, status), (Some(ErrorKind::BadRequest), Some(1)));
            }
            other => panic!("{other:?}"),
        }
        // FC23 is not wrapped by the driver; its reply frames over RTU too
        let reply = plc
            .send_pdu(None, &[23, 0, 40, 0, 2, 0, 41, 0, 1, 2, 0xAB, 0xCD])
            .unwrap();
        assert_eq!(reply, [23, 4, 0, 0, 0xAB, 0xCD]);
        match plc.send_pdu(None, &[3, 0, 0, 0, 200]) {
            Err(Error::Response { kind, status, .. }) => {
                assert_eq!((kind, status), (Some(ErrorKind::BadRequest), Some(3)));
            }
            other => panic!("{other:?}"),
        }
        assert!(plc.connected());
    }
}

#[test]
fn in_memory_connector_runs_the_same_driver() {
    for framing in [Framing::Mbap, Framing::Rtu] {
        let sim = ModbusSim::from_json(CONFIG).unwrap();
        sim.set_registers(1, "holding", 40, &[0x42F6, 0xE979])
            .unwrap();
        let path = if framing == Framing::Mbap {
            "tcp://sim"
        } else {
            "rtu+tcp://sim"
        };
        let plc = ModbusDriver::with_connector(path, options(), sim.connector(framing)).unwrap();
        assert!(plc.open().unwrap());
        assert_eq!(
            value(&plc.read(&["F32_ABCD"]).unwrap(), 0),
            Value::Real(123.456)
        );
        sim.inject(ModbusFault::RefuseConnections);
        sim.inject(ModbusFault::CloseConnections);
        assert!(plc.read(&["F32_ABCD"]).is_err());
        assert!(!plc.connected());
        assert!(plc.open().is_err());
        sim.clear_faults();
        assert!(plc.open().unwrap());
        assert!(plc.read(&["F32_ABCD"]).unwrap()[0].error.is_none());
    }
}

#[test]
fn elements_bits_ranges_and_plain_orders() {
    for mode in MODES {
        let rig = rig(mode);
        let plc = rig.driver(options(), off());
        let r = plc
            .write(&[
                ("Arr[2]", Value::Int(-7)),
                ("Arr[1].15", Value::Bool(true)),
                ("Coils[3]", Value::Bool(true)),
                ("U64_DCBA", Value::ULInt(u64::MAX)),
                ("I64_CDAB", Value::LInt(i64::MIN)),
                ("F32_BADC", Value::LReal(2.5)),
                ("F64_CDAB", Value::Int(-3)),
                ("Str", Value::String("caf\u{e9}".into())),
                ("hr300:float32:cdab", Value::Real(-1.5)),
                (
                    "hr310:uint32:dcba{2}",
                    Value::Array(vec![Value::UDInt(1), Value::UDInt(0x0102_0304)]),
                ),
                ("Scaled", Value::DInt(11)),
            ])
            .unwrap();
        assert!(r.iter().all(|r| r.error.is_none()), "{mode:?} {r:?}");
        assert_eq!(rig.holding(1, 81, 2), [0x8000, 0xFFF9]);
        assert_eq!(rig.sim.bits(1, "coil", 4, 1).unwrap(), [true]);
        assert_eq!(rig.holding(1, 300, 2), [0x0000, 0xBFC0]);
        assert_eq!(rig.holding(1, 310, 4), [0x0100, 0, 0x0403, 0x0201]);
        assert_eq!(rig.holding(1, 70, 2), [0x6361, 0x66E9]);
        // 11 = 10 + raw * 0.5: raw 2
        assert_eq!(rig.holding(1, 86, 1), [2]);
        let r = plc
            .read(&[
                "Arr[2]",
                "Arr[1].15",
                "Arr",
                "Coils[3]",
                "U64_DCBA",
                "I64_CDAB",
                "F32_BADC",
                "F64_CDAB",
                "Str",
                "hr300:float32:cdab",
                "hr311:uint32:dcba",
                "Scaled",
            ])
            .unwrap();
        let values: Vec<Value> = (0..r.len()).map(|i| value(&r, i)).collect();
        assert_eq!(
            values,
            [
                Value::Int(-7),
                Value::Bool(true),
                Value::Array(vec![
                    Value::Int(0),
                    Value::Int(i16::MIN),
                    Value::Int(-7),
                    Value::Int(0)
                ]),
                Value::Bool(true),
                Value::ULInt(u64::MAX),
                Value::LInt(i64::MIN),
                Value::Real(2.5),
                Value::LReal(-3.0),
                Value::String("caf\u{e9}".into()),
                Value::Real(-1.5),
                // one register in: registers 311-312 are 0x0000 0x0403
                Value::UDInt(0x0304_0000),
                Value::LReal(11.0),
            ],
            "{mode:?}"
        );
        // out of range elements and bits, values that do not fit
        let r = plc
            .read(&["Arr[4]", "F32_ABCD.3", "Coil.1", "hr65535:int32"])
            .unwrap();
        let kinds: Vec<_> = r.iter().map(kind).collect();
        assert_eq!(
            kinds,
            [
                Some(ErrorKind::NotFound),
                Some(ErrorKind::BadRequest),
                Some(ErrorKind::BadRequest),
                Some(ErrorKind::BadRequest)
            ],
            "{mode:?} {r:?}"
        );
        let r = plc
            .write(&[
                ("F32_ABCD", Value::LReal(1e300)),
                ("U16", Value::Int(-1)),
                ("I16", Value::Real(1.5)),
                ("Str", Value::String("\u{263A}".into())),
                ("Arr", Value::Array(vec![Value::Int(1); 3])),
                ("Scaled", Value::LReal(1e9)),
            ])
            .unwrap();
        assert!(
            r.iter().all(|r| kind(r) == Some(ErrorKind::BadValue)),
            "{mode:?} {r:?}"
        );
    }
}

#[test]
fn malformed_names_are_tag_errors_and_send_nothing() {
    let rig = rig(Mode::RtuTcp);
    let plc = rig.driver(options(), off());
    rig.sim.record(true);
    let names = [
        "",
        "hr",
        "hr-1",
        "hr65536",
        "hr0{0}",
        "co0{0}",
        "hr0:string",
        "hr0:string{0}",
        "hr0.16",
        "hr0.1:int32",
        "co0.1",
        "hr0{65536}",
        "hr65000{1000}",
        "hr0@256",
        "hr0@",
        "hr0:float32:xyz",
        "hr0:bogus",
        "Arr[99999999999]",
        "Arr[-1]",
        "Arr[",
        "Arr[1].16",
        "Arr.1",
        "Str.1",
        "I16..1",
        "co65535{2}",
        "ir65500:string{300}",
        "hr0{1}{2}",
        "hr0@1@2",
        "\u{e9}",
    ];
    let r = plc.read(&names).unwrap();
    assert_eq!(r.len(), names.len());
    for (i, r) in r.iter().enumerate() {
        assert_eq!(r.tag, names[i]);
        assert!(r.error.is_some(), "{r:?}");
        assert!(r.value.is_none());
    }
    let items: Vec<(&str, Value)> = names.iter().map(|n| (*n, Value::UInt(1))).collect();
    let w = plc.write(&items).unwrap();
    assert!(w.iter().all(|r| r.error.is_some()), "{w:?}");
    assert!(rig.requests().is_empty());
}

#[test]
fn example_map_on_the_example_device() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/sim/");
    let config = std::fs::read_to_string(format!("{dir}example_modbus.json")).unwrap();
    for mode in MODES {
        let rig = rig_with(&config, mode);
        let plc = rig.driver(
            ModbusOptions {
                map: Some(TagMap::load(format!("{dir}example_modbus_map.csv")).unwrap()),
                socket_timeout: TIMEOUT,
                ..ModbusOptions::default()
            },
            off(),
        );
        let names: Vec<String> = plc.map().tags().map(|t| t.name.clone()).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        rig.sim.record(true);
        let r = plc.read(&names).unwrap();
        let level = match value(&r, 3) {
            Value::LReal(v) => v,
            other => panic!("{other:?}"),
        };
        assert!(
            (level - 52.3).abs() < 1e-9
                && matches!(value(&r, 4), Value::LReal(t) if (t - 25.0).abs() < 1e-9)
        );
        assert_eq!(
            [0, 1, 2, 5, 6, 7, 8, 9].map(|i| value(&r, i)),
            [
                Value::Real(123.456),
                Value::Bool(true),
                Value::Bool(true),
                Value::Array([120, 135, 99, 140].map(Value::UDInt).to_vec()),
                Value::String("MIX-A".into()),
                Value::UInt(5),
                Value::Bool(false),
                Value::Bool(false),
            ],
            "{mode:?}"
        );
        // coil, discrete, holding 0..301 is too far apart for one request, input, then unit 2
        assert_eq!(
            rig.spans(),
            [
                (1, 0, 1),
                (2, 3, 1),
                (3, 0, 2),
                (3, 100, 8),
                (3, 200, 8),
                (3, 300, 2),
                (4, 10, 2),
                (1, 10, 1)
            ],
            "{mode:?}"
        );
        let w = plc
            .write(&[
                ("Horn", Value::Bool(true)),
                ("Valve2_Open", Value::Bool(true)),
                ("Drive_Status", Value::UInt(1)),
            ])
            .unwrap();
        assert!(w[0].error.is_none() && w[1].error.is_none(), "{w:?}");
        assert_eq!(kind(&w[2]), Some(ErrorKind::Access));
        assert_eq!(rig.holding(1, 301, 1), [0x10]);
        assert_eq!(rig.sim.bits(2, "coil", 10, 1).unwrap(), [true]);
        let requests = rig.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!((requests[0].unit, requests[0].function()), (1, 22));
        assert_eq!((requests[1].unit, requests[1].function()), (2, 5));
    }
}
