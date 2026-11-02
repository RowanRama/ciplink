//! The driver against the simulator's test hooks: which bytes a write changes (lent memory and
//! `Serviced::writes`), requests held until `service`, explicit type layouts, a fixed clock and the identity
//! status.
#![allow(clippy::unwrap_used)]

use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ciplink::cip::{CipDriver, CipOptions, TagResult};
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::{Error, Value};
use ciplink_sim::{LogixConfig, MemberConfig, Simulator, TagConfig, TypeConfig};
use indexmap::IndexMap;
use serde_json::json;

fn options(timeout: Duration, connection_size: u16) -> LogixOptions {
    LogixOptions {
        cip: CipOptions {
            socket_timeout: Some(timeout),
            connection_size,
        },
        ..LogixOptions::default()
    }
}

/// An open driver; the simulator must answer at once (not deferred) while it opens.
fn driver(sim: &Simulator, timeout: Duration, connection_size: u16) -> LogixDriver {
    let plc = LogixDriver::with_connector(
        "192.0.2.1",
        options(timeout, connection_size),
        sim.connector(),
    )
    .unwrap();
    plc.open().unwrap();
    plc
}

fn ok(result: &TagResult) -> &Value {
    assert!(result.error.is_none(), "{}: {:?}", result.tag, result.error);
    result.value.as_ref().unwrap()
}

fn read_one(plc: &LogixDriver, tag: &str) -> Value {
    ok(&plc.read(&[tag]).unwrap()[0]).clone()
}

fn strukt(members: &[(&str, Value)]) -> Value {
    Value::Struct(
        members
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect::<IndexMap<_, _>>(),
    )
}

/// Runs `f` with the driver on a thread of its own while this one services the deferred simulator with
/// `mem`, every waiting request at each call; gives back the driver, `f`'s result and every range written.
fn serviced<R: Send + 'static>(
    sim: &Simulator,
    plc: LogixDriver,
    mem: &mut Vec<u8>,
    f: impl FnOnce(&LogixDriver) -> R + Send + 'static,
) -> (LogixDriver, R, Vec<(u32, u32)>) {
    let client = std::thread::spawn(move || {
        let result = f(&plc);
        (plc, result)
    });
    let mut writes = Vec::new();
    while !client.is_finished() {
        writes.extend(sim.service(mem, usize::MAX).unwrap().writes);
        std::thread::sleep(Duration::from_millis(1));
    }
    let (plc, result) = client.join().unwrap();
    (plc, result, writes)
}

// ---- write isolation ----

/// 32 bytes of memory: `word` DINT at 0, `flag` bit 5 of byte 1 (a bit alias into `word`), `pt` a Point at
/// 8 (its BOOL `on` bit 0 of a hidden SINT at 8, `x` at 12, `r` at 16), `next` DINT at 24.
fn placed() -> LogixConfig {
    LogixConfig {
        memory_len: Some(32),
        ..LogixConfig::default()
    }
    .with_type(TypeConfig::udt(
        "Point",
        [
            MemberConfig::new("on", "BOOL"),
            MemberConfig::new("x", "DINT"),
            MemberConfig::array("r", "REAL", 2),
        ],
    ))
    .with_tag(TagConfig::new("word", "DINT").at(0))
    .with_tag(TagConfig::new("flag", "BOOL").at(1).bit(5))
    .with_tag(TagConfig::new("pt", "Point").at(8))
    .with_tag(TagConfig::new("next", "DINT").at(24))
}

/// 0xA5 in every byte: bits 0, 2, 5 and 7 set.
const PATTERN: u8 = 0xA5;

/// Writes `items` through a driver against a deferred `placed()` controller whose memory is all
/// [`PATTERN`]; the memory after and the ranges written.
fn write_placed(items: &'static [(&'static str, Value)]) -> (Vec<u8>, Vec<(u32, u32)>) {
    let sim = Simulator::new(placed()).unwrap();
    let plc = driver(&sim, Duration::from_secs(5), 4002);
    sim.set_deferred(true);
    let mut mem = vec![PATTERN; 32];
    let (_, results, writes) = serviced(&sim, plc, &mut mem, move |plc| plc.write(items));
    for result in results.unwrap() {
        assert!(result.error.is_none(), "{}: {:?}", result.tag, result.error);
    }
    (mem, writes)
}

/// The memory, all [`PATTERN`] but these bytes.
fn pattern_with(changes: &[(usize, u8)]) -> Vec<u8> {
    let mut mem = vec![PATTERN; 32];
    for &(at, byte) in changes {
        mem[at] = byte;
    }
    mem
}

#[test]
fn a_bit_of_a_dint_write_changes_only_that_bit() {
    let (mem, writes) = write_placed(&[("word.3", Value::Bool(true))]);
    // read-modify-write of the whole DINT, with masks that keep the other bits
    assert_eq!(writes, [(0, 4)]);
    assert_eq!(mem, pattern_with(&[(0, PATTERN | 0x08)]));
    let (mem, _) = write_placed(&[("word.7", Value::Bool(false))]);
    assert_eq!(mem, pattern_with(&[(0, PATTERN & !0x80)]));
}

#[test]
fn a_bool_member_write_changes_only_its_bit_of_the_host() {
    let (mem, writes) = write_placed(&[("pt.on", Value::Bool(false))]);
    assert_eq!(writes, [(8, 1)]);
    assert_eq!(mem, pattern_with(&[(8, PATTERN & !0x01)]));
}

#[test]
fn a_bit_alias_write_changes_only_its_bit() {
    let (mem, writes) = write_placed(&[("flag", Value::Bool(false))]);
    assert_eq!(writes, [(1, 1)]);
    assert_eq!(mem, pattern_with(&[(1, PATTERN & !0x20)]));
}

#[test]
fn a_udt_member_write_changes_only_its_bytes() {
    let (mem, writes) = write_placed(&[("pt.x", Value::DInt(0x1122_3344))]);
    assert_eq!(writes, [(12, 4)]);
    assert_eq!(
        mem,
        pattern_with(&[(12, 0x44), (13, 0x33), (14, 0x22), (15, 0x11)])
    );
}

#[test]
fn writes_packed_in_one_request_change_only_their_bytes_in_order() {
    let (mem, writes) = write_placed(&[
        ("word.3", Value::Bool(true)),
        ("flag", Value::Bool(false)),
        ("pt.on", Value::Bool(false)),
        ("pt.x", Value::DInt(-1)),
        ("next", Value::DInt(0)),
    ]);
    assert_eq!(writes, [(0, 4), (1, 1), (8, 1), (12, 4), (24, 4)]);
    assert_eq!(
        mem,
        pattern_with(&[
            (0, PATTERN | 0x08),
            (1, PATTERN & !0x20),
            (8, PATTERN & !0x01),
            (12, 0xFF),
            (13, 0xFF),
            (14, 0xFF),
            (15, 0xFF),
            (24, 0),
            (25, 0),
            (26, 0),
            (27, 0),
        ])
    );
}

// ---- deferred timing ----

fn spawn_read(plc: LogixDriver, tag: &'static str) -> JoinHandle<(LogixDriver, Value)> {
    std::thread::spawn(move || {
        let value = read_one(&plc, tag);
        (plc, value)
    })
}

#[test]
fn a_read_is_answered_only_when_serviced() {
    let sim = Simulator::new(placed()).unwrap();
    let plc = driver(&sim, Duration::from_secs(5), 4002);
    sim.set_deferred(true);
    let client = spawn_read(plc, "word");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!client.is_finished(), "answered before service");
    assert!(sim.pending());
    let mut mem = vec![0u8; 32];
    mem[..4].copy_from_slice(&77i32.to_le_bytes());
    assert_eq!(sim.service(&mut mem, 10).unwrap().requests, 1);
    assert_eq!(client.join().unwrap().1, Value::DInt(77));
    assert!(!sim.pending());
}

#[test]
fn a_request_never_serviced_times_out() {
    let sim = Simulator::new(placed()).unwrap();
    let plc = driver(&sim, Duration::from_millis(100), 4002);
    sim.set_deferred(true);
    let start = Instant::now();
    let read = plc.read(&["word"]);
    let took = start.elapsed();
    assert!(matches!(read, Err(Error::Comm(_))), "{read:?}");
    assert!(
        took >= Duration::from_millis(100) && took < Duration::from_secs(2),
        "{took:?}"
    );
    // the failed transport is dropped, so a late answer cannot reach the next request
    assert!(!plc.connected());
    assert!(sim.pending());
}

#[test]
fn the_driver_reconnects_after_a_timeout() {
    let sim = Simulator::new(placed()).unwrap();
    let plc = driver(&sim, Duration::from_millis(100), 4002);
    sim.set_deferred(true);
    assert!(plc.read(&["word"]).is_err());
    let mut mem = vec![0u8; 32];
    mem[..4].copy_from_slice(&5i32.to_le_bytes());
    let (plc, value, _) = serviced(&sim, plc, &mut mem, |plc| {
        assert!(plc.open().unwrap());
        read_one(plc, "word")
    });
    assert_eq!(value, Value::DInt(5));
    assert!(plc.connected());
}

/// 30 DINTs `t0`..`t29` at 0, `ary` DINT[200] at 128.
fn many() -> LogixConfig {
    let mut config = LogixConfig {
        memory_len: Some(928),
        ..LogixConfig::default()
    };
    for i in 0..30 {
        config = config.with_tag(TagConfig::new(&format!("t{i}"), "DINT").at(4 * i));
    }
    config.with_tag(TagConfig::new("ary", "DINT").dims(&[200]).at(128))
}

#[test]
fn packed_and_fragmented_requests_are_answered_in_order_one_per_service() {
    let sim = Simulator::new(many()).unwrap();
    // a 500-byte connection: 30 reads need more than one packet, the array more than one fragment
    let plc = driver(&sim, Duration::from_secs(5), 500);
    sim.set_deferred(true);
    let mut mem = vec![0u8; 928];
    for i in 0..30 {
        mem[4 * i..4 * i + 4].copy_from_slice(&(i as i32 * 11).to_le_bytes());
    }
    for j in 0..200 {
        let at = 128 + 4 * j;
        mem[at..at + 4].copy_from_slice(&(j as i32 * 3).to_le_bytes());
    }
    let client = std::thread::spawn(move || {
        let mut tags: Vec<String> = (0..30).map(|i| format!("t{i}")).collect();
        tags.push("ary{200}".into());
        let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
        plc.read(&tags).unwrap()
    });
    let mut frames = 0;
    while !client.is_finished() {
        let served = sim.service(&mut mem, 1).unwrap();
        assert!(served.requests <= 1);
        frames += served.requests;
        std::thread::sleep(Duration::from_millis(1));
    }
    let results = client.join().unwrap();
    for (i, result) in results[..30].iter().enumerate() {
        assert_eq!(ok(result), &Value::DInt(i as i32 * 11), "t{i}");
    }
    let ary: Vec<Value> = (0..200).map(|j| Value::DInt(j * 3)).collect();
    assert_eq!(ok(&results[30]), &Value::Array(ary));
    // two packets of reads and at least two fragments of the array
    assert!(frames >= 4, "{frames} frames");
}

// ---- explicit layouts ----

/// TIMER-like: PRE and ACC, the status bits EN, TT and DN in the hidden DINT `CTL`.
fn timer_like() -> TypeConfig {
    TypeConfig {
        template_id: Some(0xF40),
        ..TypeConfig::explicit(
            "TMRLIKE",
            12,
            [
                MemberConfig::new("CTL", "DINT").at(0).hidden(),
                MemberConfig::new("PRE", "DINT").at(4),
                MemberConfig::new("ACC", "DINT").at(8),
                MemberConfig::new("EN", "BOOL").at(3).bit(7),
                MemberConfig::new("TT", "BOOL").at(3).bit(6),
                MemberConfig::new("DN", "BOOL").at(3).bit(5),
            ],
        )
    }
}

/// MESSAGE-like: status bits in the hidden DINT `Control`, error codes, a hidden reserved block and a STRING.
fn message_like() -> TypeConfig {
    TypeConfig {
        template_id: Some(0xF41),
        ..TypeConfig::explicit(
            "MSGLIKE",
            120,
            [
                MemberConfig::new("Control", "DINT").at(0).hidden(),
                MemberConfig::new("EN", "BOOL").at(3).bit(7),
                MemberConfig::new("ST", "BOOL").at(3).bit(6),
                MemberConfig::new("DN", "BOOL").at(3).bit(5),
                MemberConfig::new("ER", "BOOL").at(3).bit(4),
                MemberConfig::new("ERR", "INT").at(4),
                MemberConfig::new("EXERR", "DINT").at(8),
                MemberConfig::new("REQ_LEN", "INT").at(12),
                MemberConfig::array("__Reserved", "SINT", 16)
                    .at(16)
                    .hidden(),
                MemberConfig::new("Path", "STRING").at(32),
            ],
        )
    }
}

fn layouts() -> LogixConfig {
    LogixConfig::default()
        .with_type(timer_like())
        .with_type(message_like())
        .with_tag(
            TagConfig::new("t", "TMRLIKE")
                .value(json!({"PRE": 1000, "ACC": 250, "EN": true, "DN": true})),
        )
        .with_tag(TagConfig::new("m", "MSGLIKE").value(json!({
            "DN": true, "ER": true, "ERR": 0x1F, "EXERR": -2, "REQ_LEN": 12, "Path": "1,0"
        })))
}

#[test]
fn a_timer_like_explicit_type_decodes_without_its_hidden_word() {
    let sim = Simulator::new(layouts()).unwrap();
    let plc = driver(&sim, Duration::from_secs(1), 4002);
    let result = &plc.read(&["t"]).unwrap()[0];
    assert_eq!(result.data_type.as_deref(), Some("TMRLIKE"));
    assert_eq!(
        ok(result),
        &strukt(&[
            ("PRE", Value::DInt(1000)),
            ("ACC", Value::DInt(250)),
            ("EN", Value::Bool(true)),
            ("TT", Value::Bool(false)),
            ("DN", Value::Bool(true)),
        ])
    );
    assert_eq!(read_one(&plc, "t.ACC"), Value::DInt(250));
    assert_eq!(read_one(&plc, "t.DN"), Value::Bool(true));
    for r in plc.write(&[("t.TT", Value::Bool(true))]).unwrap() {
        assert!(r.error.is_none(), "{:?}", r.error);
    }
    assert_eq!(
        sim.value("t").unwrap(),
        json!({"PRE": 1000, "ACC": 250, "EN": true, "TT": true, "DN": true})
    );
}

#[test]
fn a_message_like_explicit_type_decodes_its_members_and_string() {
    let sim = Simulator::new(layouts()).unwrap();
    let plc = driver(&sim, Duration::from_secs(1), 4002);
    assert_eq!(
        read_one(&plc, "m"),
        strukt(&[
            ("ERR", Value::Int(0x1F)),
            ("EXERR", Value::DInt(-2)),
            ("REQ_LEN", Value::Int(12)),
            ("Path", Value::String("1,0".into())),
            ("EN", Value::Bool(false)),
            ("ST", Value::Bool(false)),
            ("DN", Value::Bool(true)),
            ("ER", Value::Bool(true)),
        ])
    );
    assert_eq!(read_one(&plc, "m.Path"), Value::String("1,0".into()));
    assert_eq!(read_one(&plc, "m.ER"), Value::Bool(true));
}

#[test]
fn the_uploaded_templates_match_type_layout() {
    let sim = Simulator::new(layouts()).unwrap();
    let plc = driver(&sim, Duration::from_secs(1), 4002);
    let types = plc.data_types();
    for name in ["TMRLIKE", "MSGLIKE"] {
        let layout = sim.with_logix(|l| l.type_layout(name)).unwrap().unwrap();
        let uploaded = types.get(&Some(name.to_owned())).expect(name);
        assert_eq!(uploaded.template.structure_size, layout.size, "{name}");
        assert_eq!(
            usize::from(uploaded.template.member_count),
            layout.members.len()
        );
        for member in &layout.members {
            let info = &uploaded.internal_tags[&member.name];
            assert_eq!(info.offset, member.offset, "{name}.{}", member.name);
            assert_eq!(
                info.bit,
                member.bit.map(u16::from),
                "{name}.{}",
                member.name
            );
            if member.bit.is_none() {
                assert_eq!(info.array, u16::try_from(member.dim).ok());
            }
            // the driver hides exactly what the simulator hides
            assert_eq!(
                uploaded.private_members.contains(&member.name),
                member.hidden,
                "{name}.{}",
                member.name
            );
        }
    }
}

// ---- fixed clock and identity ----

fn plc_time(plc: &LogixDriver) -> u64 {
    match ok(&plc.get_plc_time().unwrap()) {
        Value::Struct(map) => match map["microseconds"] {
            Value::ULInt(us) => us,
            ref other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_fixed_clock_makes_clock_reads_and_sets_exact() {
    let sim = Simulator::new(placed()).unwrap();
    sim.with_logix(|l| l.set_clock_us(Some(1_700_000_000_123_456)))
        .unwrap();
    let plc = driver(&sim, Duration::from_secs(5), 4002);
    assert_eq!(plc_time(&plc), 1_700_000_000_123_456);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(plc_time(&plc), 1_700_000_000_123_456);
    let set = plc.set_plc_time(Some(1_800_000_000_000_001)).unwrap();
    assert!(set.error.is_none(), "{:?}", set.error);
    assert_eq!(plc_time(&plc), 1_800_000_000_000_001);
    assert_eq!(
        sim.with_logix(|l| l.clock_us()),
        Some(1_800_000_000_000_001)
    );

    // a set while serviced is reported
    sim.set_deferred(true);
    let mut mem = vec![0u8; 32];
    let client = std::thread::spawn(move || plc.set_plc_time(Some(42)).unwrap());
    let mut clock_set = None;
    while !client.is_finished() {
        clock_set = sim
            .service(&mut mem, 10)
            .unwrap()
            .clock_set_us
            .or(clock_set);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(client.join().unwrap().error.is_none());
    assert_eq!(clock_set, Some(42));
}

#[test]
fn the_identity_status_and_state_show_in_the_drivers_reads() {
    let sim = Simulator::new(placed()).unwrap();
    let plc = driver(&sim, Duration::from_secs(1), 4002);
    let cases = [
        ([0x60, 0x30], 3, "REMOTE RUN"),
        ([0x70, 0x20], 2, "PROG"),
        ([0x70, 0x30], 4, "REMOTE PROG"),
        // a minor recoverable fault (bit 8) with the key in RUN
        ([0x60, 0x11], 5, "RUN"),
    ];
    for (status, state, keyswitch) in cases {
        sim.set_identity_status(u16::from_le_bytes(status), state);
        let info = plc.get_plc_info().unwrap();
        assert_eq!(
            (info.identity.status, info.keyswitch.as_str()),
            (status, keyswitch)
        );
        let listed = CipDriver::list_identity_with(
            "192.0.2.1",
            CipOptions::default(),
            sim.connector(),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!((listed.identity.status, listed.state), (status, state));
    }
}
