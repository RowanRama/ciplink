//! Bit strings (BYTE, WORD, DWORD, LWORD) and BOOL arrays through the driver, against the example controller:
//! a scalar bit string is a value of its own, a DWORD with dimensions (or a member array of DWORDs) a BOOL array.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use ciplink::Value;
use ciplink::cip::{CipOptions, TagResult};
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::trend::TrendOptions;
use ciplink::{ErrorKind, TagError};
use ciplink_sim::Simulator;
use serde_json::Value as Json;

fn sim() -> Simulator {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/sim/");
    Simulator::from_file(format!("{dir}example_controller.json")).unwrap()
}

fn driver(sim: &Simulator) -> LogixDriver {
    let options = LogixOptions {
        cip: CipOptions {
            socket_timeout: Some(Duration::from_millis(300)),
            ..CipOptions::default()
        },
        ..LogixOptions::default()
    };
    let plc = LogixDriver::with_connector("192.0.2.1", options, sim.connector()).unwrap();
    plc.open().unwrap();
    plc
}

/// The bits of a value, least significant first.
fn bools(bits: usize, word: u64) -> Value {
    Value::Array((0..bits).map(|i| Value::Bool(word >> i & 1 == 1)).collect())
}

/// The integer of a list of bools from the simulator.
fn word_of(json: &Json) -> u64 {
    json.as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, b)| u64::from(b.as_bool().unwrap()) << i)
        .sum()
}

fn ok(result: &TagResult) -> (&Value, &str) {
    assert!(result.error.is_none(), "{}: {:?}", result.tag, result.error);
    (
        result.value.as_ref().unwrap(),
        result.data_type.as_deref().unwrap(),
    )
}

fn read_one(plc: &LogixDriver, tag: &str) -> TagResult {
    plc.read(&[tag]).unwrap().remove(0)
}

fn write_ok(plc: &LogixDriver, items: &[(&str, Value)]) {
    for r in plc.write(items).unwrap() {
        assert!(r.error.is_none(), "{}: {:?}", r.tag, r.error);
    }
}

#[test]
fn scalar_bit_strings_read_whole() {
    let sim = sim();
    let plc = driver(&sim);
    let cases = [
        ("byte1", "BYTE", 8, 0xA5),
        ("word1", "WORD", 16, 0x8001),
        ("dword1", "DWORD", 32, 0x8000_0005),
        ("lword1", "LWORD", 64, 0x8000_0000_0000_0003),
        ("bits_udt.b", "BYTE", 8, 0x81),
        ("bits_udt.w", "WORD", 16, 2),
        ("bits_udt.dw", "DWORD", 32, 4),
        ("bits_udt.lw", "LWORD", 64, 0x8000_0000_0000_0008),
    ];
    let tags: Vec<&str> = cases.iter().map(|c| c.0).collect();
    let results = plc.read(&tags).unwrap();
    for ((tag, type_name, bits, word), result) in cases.iter().zip(&results) {
        assert_eq!(ok(result), (&bools(*bits, *word), *type_name), "{tag}");
    }
}

#[test]
fn scalar_bit_string_bits_read_as_bool() {
    let sim = sim();
    let plc = driver(&sim);
    let cases = [
        ("byte1.0", true),
        ("byte1.1", false),
        ("byte1.7", true),
        ("word1.15", true),
        ("word1.14", false),
        ("dword1.0", true),
        ("dword1.1", false),
        ("dword1.2", true),
        ("dword1.31", true),
        ("lword1.1", true),
        ("lword1.62", false),
        ("lword1.63", true),
        ("bits_udt.b.7", true),
        ("bits_udt.w.1", true),
        ("bits_udt.dw.2", true),
        ("bits_udt.dw.0", false),
        ("bits_udt.lw.3", true),
        ("bits_udt.lw.63", true),
    ];
    let tags: Vec<&str> = cases.iter().map(|c| c.0).collect();
    let results = plc.read(&tags).unwrap();
    for ((tag, set), result) in cases.iter().zip(&results) {
        assert_eq!(ok(result), (&Value::Bool(*set), "BOOL"), "{tag}");
        assert_eq!(result.tag, *tag);
    }
}

#[test]
fn bits_outside_a_bit_string_are_refused() {
    let sim = sim();
    let plc = driver(&sim);
    let tags = [
        "byte1.8",
        "word1.16",
        "dword1.32",
        "lword1.64",
        "bits_udt.dw.32",
    ];
    for result in plc.read(&tags).unwrap() {
        let error: &TagError = result.error.as_ref().unwrap();
        assert_eq!(error.kind, ErrorKind::BadRequest, "{}", result.tag);
        assert!(
            error
                .message
                .contains("Bit index is outside the tag's data type"),
            "{}: {}",
            result.tag,
            error.message
        );
    }
    let written = plc
        .write(&[("dword1.32", Value::Bool(true))])
        .unwrap()
        .remove(0);
    assert!(written.error.is_some());
    assert_eq!(word_of(&sim.value("dword1").unwrap()), 0x8000_0005);
}

#[test]
fn scalar_bit_string_bit_writes_change_only_that_bit() {
    let sim = sim();
    let plc = driver(&sim);
    // several bits of one word in one call, and bits of other words
    write_ok(
        &plc,
        &[
            ("dword1.4", Value::Bool(true)),
            ("dword1.0", Value::Bool(false)),
            ("dword1.31", Value::Bool(false)),
            ("byte1.1", Value::Bool(true)),
            ("byte1.7", Value::Bool(false)),
            ("word1.8", Value::Bool(true)),
            ("lword1.63", Value::Bool(false)),
            ("lword1.40", Value::Bool(true)),
            ("bits_udt.dw.9", Value::Bool(true)),
            ("bits_udt.lw.62", Value::Bool(true)),
        ],
    );
    let expected = [
        ("dword1", 0x0000_0014),
        ("byte1", 0x27),
        ("word1", 0x8101),
        ("lword1", 0x0000_0100_0000_0003),
        ("bits_udt.dw", 0x204),
        ("bits_udt.lw", 0xC000_0000_0000_0008),
        ("bits_udt.b", 0x81),
        ("bits_udt.w", 2),
    ];
    for (tag, word) in expected {
        assert_eq!(word_of(&sim.value(tag).unwrap()), word, "{tag}");
    }
    // and read back through the driver
    assert_eq!(
        ok(&read_one(&plc, "dword1.4")),
        (&Value::Bool(true), "BOOL")
    );
    assert_eq!(
        ok(&read_one(&plc, "dword1.0")),
        (&Value::Bool(false), "BOOL")
    );
}

#[test]
fn scalar_bit_strings_write_whole() {
    let sim = sim();
    let plc = driver(&sim);
    write_ok(
        &plc,
        &[
            ("word1", bools(16, 0x1234)),
            ("dword1", bools(32, 0xDEAD_BEEF)),
            ("bits_udt.b", bools(8, 0x5A)),
        ],
    );
    assert_eq!(word_of(&sim.value("word1").unwrap()), 0x1234);
    assert_eq!(word_of(&sim.value("dword1").unwrap()), 0xDEAD_BEEF);
    assert_eq!(word_of(&sim.value("bits_udt.b").unwrap()), 0x5A);
    assert_eq!(
        ok(&read_one(&plc, "dword1")),
        (&bools(32, 0xDEAD_BEEF), "DWORD")
    );
}

#[test]
fn bit_string_array_elements_behave_like_integer_elements() {
    let sim = sim();
    let plc = driver(&sim);
    assert_eq!(
        ok(&read_one(&plc, "word_ary[2]")),
        (&bools(16, 0x8000), "WORD")
    );
    assert_eq!(
        ok(&read_one(&plc, "word_ary[2].15")),
        (&Value::Bool(true), "BOOL")
    );
    assert_eq!(
        ok(&read_one(&plc, "word_ary[0].1")),
        (&Value::Bool(false), "BOOL")
    );
    write_ok(&plc, &[("word_ary[1].4", Value::Bool(true))]);
    assert_eq!(
        sim.value("word_ary").unwrap().as_array().unwrap().len(),
        48 // the simulator flattens bit string elements
    );
    assert_eq!(
        ok(&read_one(&plc, "word_ary[1]")),
        (&bools(16, 0x12), "WORD")
    );
    assert_eq!(ok(&read_one(&plc, "word_ary[0]")), (&bools(16, 1), "WORD"));
}

#[test]
fn bool_arrays_are_unchanged() {
    let sim = sim();
    let plc = driver(&sim);
    // bool_ary: bits 0, 5, 31, 32, 45, 60, 95 set
    let reads = plc
        .read(&[
            "bool_ary[5]",
            "bool_ary[6]",
            "bool_ary[45]",
            "bool_ary[31]{3}",
            "udt2.bools[5]",
        ])
        .unwrap();
    assert_eq!(ok(&reads[0]), (&Value::Bool(true), "BOOL"));
    assert_eq!(ok(&reads[1]), (&Value::Bool(false), "BOOL"));
    assert_eq!(ok(&reads[2]), (&Value::Bool(true), "BOOL"));
    assert_eq!(
        ok(&reads[3]),
        (
            &Value::Array(vec![
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(false)
            ]),
            "BOOL[3]"
        )
    );
    assert_eq!(ok(&reads[4]), (&Value::Bool(true), "BOOL"));

    write_ok(
        &plc,
        &[
            ("bool_ary[40]", Value::Bool(true)),
            ("bool_ary[45]", Value::Bool(false)),
            ("udt2.bools[33]", Value::Bool(true)),
        ],
    );
    let bits = sim.value("bool_ary").unwrap();
    let bits = bits.as_array().unwrap();
    assert_eq!(bits[40], Json::Bool(true));
    assert_eq!(bits[45], Json::Bool(false));
    assert_eq!(bits[32], Json::Bool(true));
    assert_eq!(
        sim.value("udt2.bools").unwrap().as_array().unwrap()[33],
        Json::Bool(true)
    );
    assert_eq!(
        ok(&read_one(&plc, "bool_ary[40]")),
        (&Value::Bool(true), "BOOL")
    );
}

#[test]
fn trend_pens_sample_bits_of_a_scalar_dword() {
    let sim = sim();
    let plc = driver(&sim);
    let options = TrendOptions {
        period: Duration::from_millis(5),
        ..TrendOptions::default()
    };
    let trend = plc
        .trend(&["dword1.2", "dword1.1", "bool_ary[45]"], options)
        .unwrap();
    let types: Vec<&str> = trend.pens().iter().map(|p| p.data_type).collect();
    assert_eq!(types, ["BOOL", "BOOL", "BOOL"]);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut samples = Vec::new();
    while samples.is_empty() && std::time::Instant::now() < deadline {
        samples.extend(trend.read().unwrap());
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        samples[0].values,
        [Value::Bool(true), Value::Bool(false), Value::Bool(true)]
    );
    trend.close().unwrap();
}
