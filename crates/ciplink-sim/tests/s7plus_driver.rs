//! The S7comm-plus driver (`ciplink::s7plus::S7PlusDriver`) against the S7comm-plus simulator on 127.0.0.1, end
//! to end over TLS: browse, every type, arrays and structures, batching by the PLC's limits, writes, item
//! errors, keep-alive, reconnect, async handles, subscriptions and certificate pinning.

use ciplink::s7plus::wire::function;
use ciplink::s7plus::{S7PlusDriver, S7PlusOptions};
use ciplink::session::{ConnectionEvent, ConnectionState, SessionOptions, SubscribeOptions};
use ciplink::{Error, ErrorKind, Value};
use ciplink_sim::s7plus::{S7PlusFault, S7PlusServer, S7PlusSimulator};
use serde_json::json;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A program with every simulated type (all names invented).
const CONFIG: &str = r#"{"s7plus": {
  "name": "PLC_Line1",
  "types": {"Recipe": {"members": {
    "Speed": "REAL", "Count": "DINT", "Name": "STRING[10]", "Flag": "BOOL"}}},
  "dbs": [
    {"name": "Line1", "number": 5, "members": {
      "Conveyor": {"type": "STRUCT", "members": {
        "Speed": {"type": "REAL", "value": 1.5}, "Running": {"type": "BOOL", "value": true}}},
      "Count": {"type": "DINT", "value": -300},
      "Items": "ARRAY[1..300] OF UINT",
      "Flags": "ARRAY[0..15] OF BOOL",
      "Grid": "ARRAY[0..3, 0..2] OF DINT",
      "Recipe": {"type": "Recipe", "members": {"Speed": {"type": "REAL", "value": 2.5}}},
      "Recipes": "ARRAY[1..3] OF Recipe",
      "Stamp": {"type": "DTL", "value": "2026-11-18T16:34:46.1"},
      "Delay": "IEC_TIMER",
      "Hidden": {"type": "INT", "hmi_accessible": false}}},
    {"name": "Types", "number": 7, "members": {
      "Bool": {"type": "BOOL", "value": true},
      "Byte": {"type": "BYTE", "value": 171},
      "Word": {"type": "WORD", "value": 4660},
      "DWord": {"type": "DWORD", "value": 3735928559},
      "LWord": {"type": "LWORD", "value": 81985529216486895},
      "SInt": {"type": "SINT", "value": -5},
      "Int": {"type": "INT", "value": -1234},
      "DInt": {"type": "DINT", "value": -123456},
      "LInt": {"type": "LINT", "value": -1234567890123},
      "USInt": {"type": "USINT", "value": 200},
      "UInt": {"type": "UINT", "value": 60000},
      "UDInt": {"type": "UDINT", "value": 4000000000},
      "ULInt": {"type": "ULINT", "value": 18000000000000000000},
      "Real": {"type": "REAL", "value": 1.5},
      "LReal": {"type": "LREAL", "value": -2.25},
      "Char": {"type": "CHAR", "value": "A"},
      "WChar": {"type": "WCHAR", "value": "Ω"},
      "Time": {"type": "TIME", "value": -5000},
      "LTime": {"type": "LTIME", "value": 1500000000},
      "S5Time": {"type": "S5TIME", "value": 2500},
      "Date": {"type": "DATE", "value": "2026-11-18"},
      "Tod": {"type": "TIME_OF_DAY", "value": "16:34:46.100"},
      "LTod": {"type": "LTOD", "value": "16:34:46.123456789"},
      "Dt": {"type": "DATE_AND_TIME", "value": "2026-11-18T16:34:46.120"},
      "Ldt": {"type": "LDT", "value": "2026-11-18T16:34:46.123456789"},
      "DbAny": {"type": "DB_ANY", "value": 5},
      "String": {"type": "STRING[10]", "value": "Mix1"},
      "WString": {"type": "WSTRING[4]", "value": "OK"},
      "Dtl": {"type": "DTL", "value": "2026-11-18T16:34:46.1"}}},
    {"name": "Classic", "number": 8, "optimized": false, "members": {
      "A": {"type": "BOOL", "value": true}, "B": "BOOL", "C": {"type": "BOOL", "value": true},
      "Level": {"type": "INT", "value": 77},
      "Pair": {"type": "STRUCT", "members": {"X": {"type": "BOOL", "value": true}, "Y": {"type": "INT", "value": 9}}}}}
  ],
  "areas": {"I": {"StartButton": {"type": "BOOL", "value": true}}, "Q": {"Motor": "BOOL"},
            "M": {"Mode": {"type": "INT", "value": 3}}}
}}"#;

fn start(config: &str) -> (S7PlusSimulator, S7PlusServer) {
    let sim = S7PlusSimulator::from_json(config).expect("config");
    let server = sim.serve("127.0.0.1:0").expect("serve");
    (sim, server)
}

fn options(pin: Option<String>) -> S7PlusOptions {
    S7PlusOptions {
        socket_timeout: Some(Duration::from_secs(5)),
        init_tags: true,
        tls_fingerprint: pin,
    }
}

fn driver(server: &S7PlusServer, session: SessionOptions) -> S7PlusDriver {
    S7PlusDriver::with_session(
        &format!("127.0.0.1:{}", server.port()),
        options(None),
        session,
    )
    .expect("driver")
}

fn open(server: &S7PlusServer) -> S7PlusDriver {
    let d = driver(server, SessionOptions::off());
    assert!(d.open().expect("open"));
    d
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// The function code of a recorded request PDU.
fn function_of(pdu: &[u8]) -> u16 {
    u16::from_be_bytes([pdu[4], pdu[5]])
}

/// The item count of a recorded Get/SetMultiVariables request (a VLQ32 after the 4-byte link / object ID).
fn item_count(pdu: &[u8]) -> u32 {
    let mut n = 0u32;
    for &b in &pdu[19..] {
        n = n << 7 | u32::from(b & 0x7F);
        if b & 0x80 == 0 {
            break;
        }
    }
    n
}

fn requests(sim: &S7PlusSimulator, f: u16) -> Vec<Vec<u8>> {
    sim.take_received()
        .into_iter()
        .filter(|p| function_of(p) == f)
        .collect()
}

fn value(d: &S7PlusDriver, tag: &str) -> Value {
    let r = d.read(&[tag]).expect("read").remove(0);
    r.value
        .unwrap_or_else(|| panic!("{tag}: {:?}", r.error.map(|e| e.message)))
}

fn s(text: &str) -> Value {
    Value::String(text.into())
}

/// Every elementary, string, date and time type, read, written and read again.
const TYPES: &[(&str, &str)] = &[
    ("Bool", "BOOL"),
    ("Byte", "BYTE"),
    ("Word", "WORD"),
    ("DWord", "DWORD"),
    ("LWord", "LWORD"),
    ("SInt", "SINT"),
    ("Int", "INT"),
    ("DInt", "DINT"),
    ("LInt", "LINT"),
    ("USInt", "USINT"),
    ("UInt", "UINT"),
    ("UDInt", "UDINT"),
    ("ULInt", "ULINT"),
    ("Real", "REAL"),
    ("LReal", "LREAL"),
    ("Char", "CHAR"),
    ("WChar", "WCHAR"),
    ("Time", "TIME"),
    ("LTime", "LTIME"),
    ("S5Time", "S5TIME"),
    ("Date", "DATE"),
    ("Tod", "TIME_OF_DAY"),
    ("LTod", "LTOD"),
    ("Dt", "DATE_AND_TIME"),
    ("Ldt", "LDT"),
    ("DbAny", "DB_ANY"),
    ("String", "STRING"),
    ("WString", "WSTRING"),
    ("Dtl", "DTL"),
];

#[test]
fn every_type_reads_and_writes() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    let names: Vec<String> = TYPES.iter().map(|(n, _)| format!("Types.{n}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let read = d.read(&refs).expect("read");
    let expected = [
        Value::Bool(true),
        Value::USInt(171),
        Value::UInt(4660),
        Value::UDInt(3_735_928_559),
        Value::ULInt(81_985_529_216_486_895),
        Value::SInt(-5),
        Value::Int(-1234),
        Value::DInt(-123_456),
        Value::LInt(-1_234_567_890_123),
        Value::USInt(200),
        Value::UInt(60000),
        Value::UDInt(4_000_000_000),
        Value::ULInt(18_000_000_000_000_000_000),
        Value::Real(1.5),
        Value::LReal(-2.25),
        s("A"),
        s("Ω"),
        Value::DInt(-5000),
        Value::LInt(1_500_000_000),
        Value::DInt(2500),
        s("2026-11-18"),
        s("16:34:46.100"),
        s("16:34:46.123456789"),
        s("2026-11-18T16:34:46.120"),
        s("2026-11-18T16:34:46.123456789"),
        Value::UInt(5),
        s("Mix1"),
        s("OK"),
        s("2026-11-18T16:34:46.100000000"),
    ];
    for ((r, want), (_, type_name)) in read.iter().zip(&expected).zip(TYPES) {
        assert_eq!(r.value.as_ref(), Some(want), "{}: {:?}", r.tag, r.error);
        let data_type = r.data_type.as_deref().unwrap_or("");
        assert!(
            data_type.starts_with(type_name),
            "{}: data type {data_type}",
            r.tag
        );
    }

    let new = [
        Value::Bool(false),
        Value::USInt(0x5A),
        Value::UInt(0xBEEF),
        Value::UDInt(0x0102_0304),
        Value::ULInt(u64::MAX),
        Value::SInt(i8::MIN),
        Value::Int(i16::MAX),
        Value::DInt(i32::MIN),
        Value::LInt(i64::MIN),
        Value::USInt(1),
        Value::UInt(2),
        Value::UDInt(3),
        Value::ULInt(4),
        Value::Real(-0.5),
        Value::LReal(1e300),
        s("z"),
        s("€"),
        Value::DInt(86_400_000),
        Value::LInt(-7),
        Value::DInt(9_990_000),
        s("1999-12-31"),
        s("23:59:59.999"),
        s("00:00:00.000000001"),
        s("1999-12-31T23:59:59.990"),
        s("1970-01-01T00:00:00.000000000"),
        Value::UInt(65535),
        s("0123456789"),
        s("Größ"),
        s("2027-01-02T03:04:05.123456789"),
    ];
    let items: Vec<(&str, Value)> = refs.iter().copied().zip(new.iter().cloned()).collect();
    let written = d.write(&items).expect("write");
    for w in &written {
        assert!(w.is_ok(), "{}: {:?}", w.tag, w.error);
    }
    let read = d.read(&refs).expect("read back");
    for (r, want) in read.iter().zip(&new) {
        assert_eq!(r.value.as_ref(), Some(want), "{}: {:?}", r.tag, r.error);
    }
    // the simulator holds what the driver wrote
    assert_eq!(sim.value("Types.WString").expect("value"), json!("Größ"));
    assert_eq!(
        sim.value("Types.Dt").expect("value"),
        json!("1999-12-31T23:59:59.990")
    );
    assert_eq!(sim.value("Types.LWord").expect("value"), json!(u64::MAX));
}

#[test]
fn arrays_structures_areas_and_classic_blocks_read() {
    let (sim, server) = start(CONFIG);
    sim.set_value("Line1.Items[300]", &json!(42)).expect("set");
    sim.set_value("Line1.Flags[4]", &json!(true)).expect("set");
    sim.set_value("Line1.Grid[2,1]", &json!(-9)).expect("set");
    sim.set_value("Line1.Recipes[2].Name", &json!("Two"))
        .expect("set");
    sim.set_value("Line1.Delay", &json!({"PT": 5000, "IN": true, "Q": true}))
        .expect("set");
    let d = open(&server);

    // whole arrays and elements (index by the declared lower bound)
    let Value::Array(items) = value(&d, "Line1.Items") else {
        panic!("Items is an array")
    };
    assert_eq!(items.len(), 300);
    assert_eq!(items[299], Value::UInt(42));
    assert_eq!(value(&d, "Line1.Items[300]"), Value::UInt(42));
    assert_eq!(
        d.read(&["Line1.Items"]).expect("read")[0]
            .data_type
            .as_deref(),
        Some("UINT[300]")
    );
    let Value::Array(flags) = value(&d, "Line1.Flags") else {
        panic!("Flags is an array")
    };
    assert_eq!(flags.len(), 16);
    assert_eq!(flags[4], Value::Bool(true));
    assert_eq!(flags.iter().filter(|f| **f == Value::Bool(true)).count(), 1);
    assert_eq!(value(&d, "Line1.Flags[4]"), Value::Bool(true));
    // elements of multi-dimensional arrays are refused until their flat order is verified on a CPU
    assert_eq!(
        d.read(&["Line1.Grid[2,1]"]).expect("read")[0].error_kind(),
        Some(ErrorKind::BadRequest)
    );
    let Value::Array(grid) = value(&d, "Line1.Grid") else {
        panic!("Grid is an array")
    };
    assert_eq!(grid[2 * 3 + 1], Value::DInt(-9), "last dimension fastest");

    // structures: members, whole structs, arrays of structs, system types
    assert_eq!(value(&d, "Line1.Conveyor.Speed"), Value::Real(1.5));
    assert_eq!(value(&d, "\"Line1\".Conveyor.Running"), Value::Bool(true));
    let Value::Struct(conveyor) = value(&d, "Line1.Conveyor") else {
        panic!("Conveyor is a struct")
    };
    assert_eq!(conveyor["Speed"], Value::Real(1.5));
    assert_eq!(conveyor["Running"], Value::Bool(true));
    assert_eq!(value(&d, "Line1.Recipe.Speed"), Value::Real(2.5));
    assert_eq!(value(&d, "Line1.Recipes[2].Name"), s("Two"));
    let Value::Struct(recipe) = value(&d, "Line1.Recipes[2]") else {
        panic!("an element of a struct array is a struct")
    };
    assert_eq!(recipe["Name"], s("Two"));
    // a whole array of structures: one value per element
    let Value::Array(recipes) = value(&d, "Line1.Recipes") else {
        panic!("Recipes is an array")
    };
    assert_eq!(recipes.len(), 3);
    assert_eq!(recipes[1], Value::Struct(recipe));
    let Value::Struct(timer) = value(&d, "Line1.Delay") else {
        panic!("IEC_TIMER is a struct")
    };
    assert_eq!(timer["PT"], Value::DInt(5000));
    assert_eq!(timer["IN"], Value::Bool(true));
    assert_eq!(timer["Q"], Value::Bool(true));
    assert_eq!(timer["RU"], Value::Bool(false));
    assert_eq!(value(&d, "Line1.Delay.PT"), Value::DInt(5000));
    assert_eq!(value(&d, "Line1.Stamp.MONTH"), Value::USInt(11));
    assert_eq!(
        value(&d, "line1.stamp.year"),
        Value::UInt(2026),
        "case-insensitive"
    );

    // the I, Q and M areas and a standard-access (classic) block
    assert_eq!(value(&d, "StartButton"), Value::Bool(true));
    assert_eq!(value(&d, "Motor"), Value::Bool(false));
    assert_eq!(value(&d, "Mode"), Value::Int(3));
    assert_eq!(value(&d, "Classic.C"), Value::Bool(true));
    assert_eq!(value(&d, "Classic.B"), Value::Bool(false));
    assert_eq!(value(&d, "Classic.Level"), Value::Int(77));
    let Value::Struct(pair) = value(&d, "Classic.Pair") else {
        panic!("Pair is a struct")
    };
    assert_eq!(pair["X"], Value::Bool(true));
    assert_eq!(pair["Y"], Value::Int(9));
    let classic_bool = d
        .data_types()
        .values()
        .find_map(|t| t.members.get("X").map(|m| m.softdatatype));
    assert_eq!(
        classic_bool,
        Some(1),
        "a STRUCT in a standard block has BOOL bits"
    );
    assert_eq!(
        value(&d, "Line1.Hidden"),
        Value::Int(0),
        "not HMI accessible but readable"
    );

    // browse results
    let tags = d.tags();
    assert_eq!(
        tags.keys().map(String::as_str).collect::<Vec<_>>(),
        ["Line1", "Types", "Classic", "StartButton", "Motor", "Mode"]
    );
    assert!(d.data_types().contains_key("DTL"));
    let list = d.tag_list().expect("tag list");
    let hidden = list
        .iter()
        .find(|s| s.name == "Line1.Hidden")
        .expect("Hidden");
    assert!(!hidden.hmi_accessible);
    assert!(list.iter().any(|s| s.name == "Line1.Recipes[3].Flag"));
    assert!(list.iter().any(|s| s.name == "Types.Dtl"));
    let info = d.get_tag_info("Line1.Conveyor.Speed").expect("info");
    assert_eq!(info.type_name, "REAL");
    assert_ne!(info.crc, 0);
    assert_eq!(d.name().as_deref(), Some("PLC_Line1"));
    let cpu = d.get_plc_info().expect("plc info");
    assert_eq!(cpu.firmware.as_deref(), Some("V3.1.3"));
    assert_eq!(cpu.project.as_deref(), Some("Demo_Line"));
    assert_eq!(cpu.protection_level, Some(0));
    d.close().expect("close");
}

#[test]
fn arrays_and_structure_members_are_written() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    let grid: Vec<Value> = (0..12).map(Value::DInt).collect();
    let w = d
        .write(&[
            ("Line1.Items[1]", Value::UInt(11)),
            ("Line1.Flags[15]", Value::Bool(true)),
            ("Line1.Grid", Value::Array(grid.clone())),
            ("Line1.Recipes[3].Name", s("Three")),
            ("Line1.Recipes[3].Flag", Value::Bool(true)),
            ("Line1.Conveyor.Running", Value::Bool(false)),
            ("Line1.Stamp", s("2030-01-02T03:04:05")),
            ("Line1.Delay.PT", Value::DInt(1234)),
            ("Classic.B", Value::Bool(true)),
            ("Classic.Pair.Y", Value::Int(-1)),
            ("Motor", Value::Bool(true)),
            ("Mode", Value::Int(-3)),
        ])
        .expect("write");
    for r in &w {
        assert!(r.is_ok(), "{}: {:?}", r.tag, r.error);
    }
    assert_eq!(sim.value("Line1.Items[1]").expect("v"), json!(11));
    assert_eq!(sim.value("Line1.Flags[15]").expect("v"), json!(true));
    assert_eq!(sim.value("Line1.Grid[3,2]").expect("v"), json!(11));
    assert_eq!(
        sim.value("Line1.Recipes[3].Name").expect("v"),
        json!("Three")
    );
    assert_eq!(sim.value("Line1.Recipes[3].Flag").expect("v"), json!(true));
    assert_eq!(
        sim.value("Line1.Conveyor.Running").expect("v"),
        json!(false)
    );
    assert_eq!(sim.value("Line1.Stamp.YEAR").expect("v"), json!(2030));
    assert_eq!(
        sim.value("Line1.Stamp.WEEKDAY").expect("v"),
        json!(4),
        "Wednesday"
    );
    assert_eq!(sim.value("Line1.Delay.PT").expect("v"), json!(1234));
    assert_eq!(sim.value("Classic.B").expect("v"), json!(true));
    assert_eq!(
        sim.value("Classic.A").expect("v"),
        json!(true),
        "neighbour bit kept"
    );
    assert_eq!(sim.value("Classic.Pair.Y").expect("v"), json!(-1));
    assert_eq!(sim.value("Motor").expect("v"), json!(true));
    assert_eq!(sim.value("Mode").expect("v"), json!(-3));
    assert_eq!(value(&d, "Line1.Grid"), Value::Array(grid));
}

#[test]
fn per_item_errors_leave_the_other_items_alone() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    sim.inject(S7PlusFault::ItemError {
        tag: "Line1.Count".into(),
        code: 0x8104_8800_0000_FF80,
    });
    sim.record(true);
    let r = d
        .read(&[
            "Line1.Conveyor.Speed",
            "Line1.Count",
            "Line1.Nope",
            "Line1.Items[301]",
            "Line1.Items[0]",
            "Line1.Recipes[4].Speed",
            "Line1.Items[x]",
            "Mode",
        ])
        .expect("read");
    assert_eq!(r[0].value, Some(Value::Real(1.5)));
    assert_eq!(r[1].error_kind(), Some(ErrorKind::Device));
    let message = &r[1].error.as_ref().expect("error").message;
    assert!(message.contains("0x810488000000FF80"), "{message}");
    for r in &r[2..6] {
        assert_eq!(r.error_kind(), Some(ErrorKind::NotFound), "{}", r.tag);
    }
    assert!(r[6].error.is_some());
    assert_eq!(r[7].value, Some(Value::Int(3)));
    let reads = requests(&sim, function::GET_MULTI_VARIABLES);
    assert_eq!(reads.len(), 1);
    assert_eq!(item_count(&reads[0]), 3, "bad names are not sent");

    let w = d
        .write(&[
            ("Line1.Count", Value::DInt(1)),
            ("Line1.Conveyor.Speed", Value::Real(3.0)),
            ("Types.Int", Value::DInt(70_000)),
            ("Types.String", s("much too long")),
            ("Line1.Conveyor", Value::Struct(Default::default())),
            ("Line1.Flags", Value::Array(vec![Value::Bool(true); 16])),
            ("Types.Bool", s("yes")),
            ("Line1.Nope", Value::Int(1)),
        ])
        .expect("write");
    assert_eq!(w[0].error_kind(), Some(ErrorKind::Device));
    assert!(w[1].is_ok(), "{:?}", w[1].error);
    assert_eq!(w[2].error_kind(), Some(ErrorKind::BadValue));
    assert_eq!(w[3].error_kind(), Some(ErrorKind::BadValue));
    assert_eq!(w[4].error_kind(), Some(ErrorKind::BadRequest));
    assert_eq!(w[5].error_kind(), Some(ErrorKind::BadRequest));
    assert_eq!(w[6].error_kind(), Some(ErrorKind::BadValue));
    assert_eq!(w[7].error_kind(), Some(ErrorKind::NotFound));
    assert_eq!(sim.value("Line1.Conveyor.Speed").expect("v"), json!(3.0));
    let writes = requests(&sim, function::SET_MULTI_VARIABLES);
    assert_eq!(writes.len(), 1);
    assert_eq!(
        item_count(&writes[0]),
        2,
        "only the encodable items are sent"
    );
    assert!(d.connected());
}

#[test]
fn reads_and_writes_are_split_by_the_plc_limits() {
    let config = CONFIG.replace(
        r#""name": "PLC_Line1","#,
        r#""name": "PLC_Line1", "max_read": 30, "max_write": 20,"#,
    );
    let (sim, server) = start(&config);
    let d = open(&server);
    let cpu = d.get_plc_info().expect("info");
    assert_eq!((cpu.max_read, cpu.max_write), (30, 20));
    let names: Vec<String> = (1..=250)
        .map(|i| format!("Line1.Items[{}]", (i % 300) + 1))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let items: Vec<(&str, Value)> = refs
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, Value::UInt(i as u16)))
        .collect();
    sim.record(true);
    let w = d.write(&items).expect("write");
    assert!(w.iter().all(|r| r.is_ok()));
    let writes = requests(&sim, function::SET_MULTI_VARIABLES);
    let sizes: Vec<u32> = writes.iter().map(|p| item_count(p)).collect();
    assert_eq!(sizes.iter().sum::<u32>(), 250);
    assert!(sizes.iter().all(|&n| n <= 20), "{sizes:?}");
    let r = d.read(&refs).expect("read");
    assert_eq!(r.len(), 250);
    for (i, r) in r.iter().enumerate() {
        assert_eq!(r.value, Some(Value::UInt(i as u16)), "{}", r.tag);
    }
    let reads = requests(&sim, function::GET_MULTI_VARIABLES);
    let sizes: Vec<u32> = reads.iter().map(|p| item_count(p)).collect();
    assert_eq!(sizes, [30, 30, 30, 30, 30, 30, 30, 30, 10]);
}

#[test]
fn more_than_100_tags_with_the_default_limit() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    let names: Vec<String> = (1..=300).map(|i| format!("Line1.Items[{i}]")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    sim.record(true);
    let r = d.read(&refs).expect("read");
    assert!(r.iter().all(|r| r.value == Some(Value::UInt(0))));
    let sizes: Vec<u32> = requests(&sim, function::GET_MULTI_VARIABLES)
        .iter()
        .map(|p| item_count(p))
        .collect();
    assert_eq!(sizes, [100, 100, 100]);
}

#[test]
fn concurrent_async_reads_share_requests_and_writes_keep_their_order() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    sim.record(true);
    sim.inject(S7PlusFault::Delay(Duration::from_millis(200)));
    let first = d.read_async(&["Line1.Count"]);
    std::thread::sleep(Duration::from_millis(50));
    let handles: Vec<_> = ["Line1.Conveyor.Speed", "Mode", "Line1.Count"]
        .iter()
        .map(|t| d.read_async(&[t]))
        .collect();
    let write = d.write_async(&[("Line1.Count", Value::DInt(5))]);
    let after = d.read_async(&["Line1.Count"]);
    assert_eq!(
        first.wait().expect("first")[0].value,
        Some(Value::DInt(-300))
    );
    let values: Vec<Option<Value>> = handles
        .into_iter()
        .map(|h| h.wait().expect("read").remove(0).value)
        .collect();
    assert_eq!(
        values,
        [
            Some(Value::Real(1.5)),
            Some(Value::Int(3)),
            Some(Value::DInt(-300))
        ]
    );
    assert!(write.wait().expect("write")[0].is_ok());
    assert_eq!(after.wait().expect("after")[0].value, Some(Value::DInt(5)));
    let sizes: Vec<u32> = requests(&sim, function::GET_MULTI_VARIABLES)
        .iter()
        .map(|p| item_count(p))
        .collect();
    assert_eq!(sizes, [1, 3, 1], "the three queued reads are one request");
}

#[test]
fn subscriptions_deliver_changes() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    let sub = d
        .subscribe(
            &["Line1.Count", "Mode"],
            SubscribeOptions {
                interval: Duration::from_millis(30),
                deadband: None,
            },
        )
        .expect("subscribe");
    let first = sub.recv_timeout(Duration::from_secs(5)).expect("first");
    assert_eq!(first.results.len(), 2);
    sim.set_value("Line1.Count", &json!(17)).expect("set");
    let started = Instant::now();
    loop {
        let changes = sub.recv_timeout(Duration::from_secs(5)).expect("change");
        if let Some(r) = changes.results.iter().find(|r| r.tag == "Line1.Count") {
            assert_eq!(r.value, Some(Value::DInt(17)));
            assert_eq!(changes.results.len(), 1, "Mode did not change");
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    sub.close();
}

#[test]
fn keep_alive_requests_go_out_when_idle() {
    let (sim, server) = start(CONFIG);
    let session = SessionOptions {
        keep_alive: Some(Duration::from_millis(50)),
        ..SessionOptions::off()
    };
    let d = driver(&server, session);
    assert!(d.open().expect("open"));
    sim.record(true);
    std::thread::sleep(Duration::from_millis(400));
    let keep_alives = requests(&sim, function::GET_VAR_SUB_STREAMED).len();
    assert!(keep_alives >= 3, "{keep_alives}");
    assert!(d.connected());
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));
}

fn events(d: &S7PlusDriver) -> Arc<Mutex<Vec<ConnectionEvent>>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let e = Arc::clone(&events);
    d.set_connection_callback(Some(Box::new(move |ev: &ConnectionEvent| {
        e.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(ev.clone());
    })));
    events
}

#[test]
fn a_closed_connection_reconnects_without_browsing_again() {
    let (sim, server) = start(CONFIG);
    let session = SessionOptions {
        keep_alive: Some(Duration::from_millis(50)),
        ..S7PlusOptions::default_session()
    };
    let d = driver(&server, session);
    let events = events(&d);
    assert!(d.open().expect("open"));
    sim.record(true);
    sim.inject(S7PlusFault::CloseConnections);
    wait_for("the keep-alive to notice", || {
        events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|e| matches!(e, ConnectionEvent::Disconnected { .. }))
    });
    wait_for("reconnect", || {
        d.connection_state() == ConnectionState::Connected && d.connected()
    });
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));
    let received = sim.take_received();
    assert!(
        received
            .iter()
            .any(|p| function_of(p) == function::CREATE_OBJECT),
        "a new session"
    );
    assert!(
        !received.iter().any(|p| function_of(p) == function::EXPLORE),
        "the symbol table was kept"
    );
    // a program change (new session version) is browsed again on the next reconnect
    sim.change_program();
    sim.inject(S7PlusFault::CloseConnections);
    wait_for("reconnect after a download", || {
        sim.take_received()
            .iter()
            .any(|p| function_of(p) == function::EXPLORE)
    });
    wait_for("connected", || {
        d.connection_state() == ConnectionState::Connected
    });
    assert_eq!(value(&d, "Line1.Conveyor.Speed"), Value::Real(1.5));
    assert!(d.tags_version() >= 2, "the new table differs");
    d.close().expect("close");
    assert_eq!(d.connection_state(), ConnectionState::Closed);
}

#[test]
fn requests_fail_fast_while_the_plc_refuses_and_recover_after() {
    let (sim, server) = start(CONFIG);
    let session = SessionOptions {
        keep_alive: None,
        reconnect_max: Duration::from_millis(200),
        ..S7PlusOptions::default_session()
    };
    let d = driver(&server, session);
    assert!(d.open().expect("open"));
    sim.inject(S7PlusFault::RefuseConnections);
    sim.inject(S7PlusFault::CloseConnections);
    let err = d.read(&["Line1.Count"]).expect_err("lost");
    assert!(matches!(err, Error::Comm(_)), "{err}");
    wait_for("reconnecting", || {
        d.connection_state() == ConnectionState::Reconnecting
    });
    assert!(matches!(d.read(&["Line1.Count"]), Err(Error::Comm(_))));
    sim.clear_faults();
    wait_for("reconnect", || {
        d.connection_state() == ConnectionState::Connected
    });
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));
}

#[test]
fn error_pdus_and_negative_system_events_drop_the_link() {
    let (sim, server) = start(CONFIG);
    let session = SessionOptions {
        keep_alive: None,
        ..S7PlusOptions::default_session()
    };
    let d = driver(&server, session);
    let events = events(&d);
    assert!(d.open().expect("open"));

    // a system event with a non-negative return value is ignored
    sim.inject(S7PlusFault::SystemEvent { return_value: 0 });
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));

    sim.inject(S7PlusFault::ErrorPdu);
    assert!(matches!(d.read(&["Line1.Count"]), Err(Error::Comm(_))));
    wait_for("reconnect", || {
        d.connection_state() == ConnectionState::Connected
    });
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));

    sim.inject(S7PlusFault::SystemEvent { return_value: -1 });
    assert!(matches!(d.read(&["Line1.Count"]), Err(Error::Comm(_))));
    wait_for("reconnect", || {
        d.connection_state() == ConnectionState::Connected
    });
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));
    let disconnects = events
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|e| matches!(e, ConnectionEvent::Disconnected { .. }))
        .count();
    assert_eq!(disconnects, 2);
}

#[test]
fn a_lost_reply_times_out_and_reconnects() {
    let (sim, server) = start(CONFIG);
    let d = S7PlusDriver::with_session(
        &format!("127.0.0.1:{}", server.port()),
        S7PlusOptions {
            socket_timeout: Some(Duration::from_millis(300)),
            ..options(None)
        },
        SessionOptions {
            keep_alive: None,
            ..S7PlusOptions::default_session()
        },
    )
    .expect("driver");
    assert!(d.open().expect("open"));
    sim.inject(S7PlusFault::DropReplies(1));
    assert!(matches!(d.read(&["Line1.Count"]), Err(Error::Comm(_))));
    wait_for("reconnect", || {
        d.connection_state() == ConnectionState::Connected
    });
    assert_eq!(value(&d, "Line1.Count"), Value::DInt(-300));
}

#[test]
fn a_program_change_heals_reads_and_fails_one_write() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    let version = d.tags_version();
    sim.change_program();
    sim.record(true);
    // the first member of the first DB (Line1.Conveyor) got a new CRC
    let r = d.read(&["Line1.Conveyor.Speed", "Mode"]).expect("read");
    assert_eq!(r[0].value, Some(Value::Real(1.5)), "{:?}", r[0].error);
    assert_eq!(r[1].value, Some(Value::Int(3)));
    assert_eq!(d.tags_version(), version + 1);
    assert!(
        sim.take_received()
            .iter()
            .any(|p| function_of(p) == function::EXPLORE)
    );
    sim.change_program();
    let w = d
        .write(&[("Line1.Conveyor.Speed", Value::Real(4.0))])
        .expect("write");
    assert_eq!(w[0].error_kind(), Some(ErrorKind::TableChanged));
    let w = d
        .write(&[("Line1.Conveyor.Speed", Value::Real(4.0))])
        .expect("write");
    assert!(w[0].is_ok(), "{:?}", w[0].error);
    assert_eq!(sim.value("Line1.Conveyor.Speed").expect("v"), json!(4.0));
}

#[test]
fn the_certificate_can_be_pinned() {
    let (sim, server) = start(CONFIG);
    let path = format!("127.0.0.1:{}", server.port());
    let pin = sim.fingerprint().to_lowercase().replace(':', "");
    let d = S7PlusDriver::with_session(&path, options(Some(pin)), SessionOptions::off())
        .expect("driver");
    assert!(d.open().expect("pinned open"));
    assert_eq!(d.certificate_fingerprint(), Some(sim.fingerprint()));
    d.close().expect("close");

    let other = S7PlusSimulator::from_json(CONFIG)
        .expect("config")
        .fingerprint();
    let d = S7PlusDriver::with_session(&path, options(Some(other.clone())), SessionOptions::off())
        .expect("driver");
    let err = d.open().expect_err("wrong pin");
    assert!(
        matches!(&err, Error::Comm(m) if m.contains("does not match") && m.contains(&other)),
        "{err}"
    );
    assert!(!d.connected());
    assert_eq!(
        d.certificate_fingerprint(),
        Some(sim.fingerprint()),
        "the refused certificate is shown for trust on first use"
    );

    // no pin: anything is accepted and the fingerprint is exposed
    let d = open(&server);
    assert_eq!(d.certificate_fingerprint(), Some(sim.fingerprint()));
}

#[test]
fn a_refused_connection_opens_false() {
    let (sim, server) = start(CONFIG);
    sim.inject(S7PlusFault::RefuseConnections);
    let d = driver(&server, SessionOptions::off());
    assert!(!d.open().expect("open"));
    assert!(!d.connected());
}

#[test]
fn close_deletes_the_session() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    sim.record(true);
    d.close().expect("close");
    let received = sim.take_received();
    assert_eq!(
        received.iter().map(|p| function_of(p)).collect::<Vec<_>>(),
        [function::DELETE_OBJECT]
    );
    wait_for("the connection to end", || sim.connections() == 0);
    assert!(matches!(d.read(&["Line1.Count"]), Err(Error::Comm(_))));
}

#[test]
fn the_sequence_number_wraps_as_the_simulator_expects() {
    // the simulator closes the connection on any sequence or integrity mismatch; 65,535 requests take the
    // sequence number past 0xFFFF (to 1, skipping 0)
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    let start = sim.requests();
    while sim.requests() - start < 65_600 {
        assert_eq!(value(&d, "Mode"), Value::Int(3));
    }
    assert!(d.connected());
    assert_eq!(sim.connections(), 1, "no reconnect");
}

#[test]
fn failed_items_with_a_negative_return_value_keep_the_link() {
    let (sim, server) = start(CONFIG);
    let d = open(&server);
    sim.inject(S7PlusFault::NegativeItemErrors);
    sim.inject(S7PlusFault::ItemError {
        tag: "Line1.Count".into(),
        code: 0x8104_8800_0000_FF80,
    });
    let w = d
        .write(&[
            ("Line1.Count", Value::DInt(1)),
            ("Line1.Conveyor.Speed", Value::Real(4.0)),
        ])
        .expect("write keeps the item results");
    assert_eq!(w[0].error_kind(), Some(ErrorKind::Device));
    assert!(w[1].is_ok(), "{:?}", w[1].error);
    assert_eq!(sim.value("Line1.Conveyor.Speed").expect("v"), json!(4.0));
    let r = d
        .read(&["Line1.Count", "Line1.Conveyor.Speed"])
        .expect("read keeps the item results");
    assert_eq!(r[0].error_kind(), Some(ErrorKind::Device));
    assert_eq!(r[1].value, Some(Value::Real(4.0)));
    assert!(d.connected());
    d.close().expect("close");
}
