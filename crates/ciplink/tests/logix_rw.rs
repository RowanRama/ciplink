//! LogixDriver read/write parity with the Python LogixDriver (fixtures from tools/fixtures/gen_logix_rw.py): the
//! scenarios of tools/reference/tests/offline/test_logix_read_write.py, test_logix_transfers.py, test_logix_request_paths.py,
//! test_strict_writes.py, test_error_kinds.py and the read/write parts of test_logix_tag_table_version.py and
//! test_logix_aoi.py, replayed against the scripted fake transport: the same frames in the same order, the same
//! values, type names, error messages, kinds and statuses.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use ciplink::cip::TagResult;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::{Error, ErrorKind, Value};
use common::fake::Fake;
use common::{class, hex, to_hex};
use serde_json::{Value as Json, json};

// ---- values ----

/// a fixture value (tagged, with the compact {"ints": [..]} and {"bools": "01.."} lists) as a write value
fn input(json: &Json) -> Value {
    if let Some(ints) = json.get("ints") {
        return Value::Array(
            ints.as_array()
                .unwrap()
                .iter()
                .map(|n| Value::LInt(n.as_i64().unwrap()))
                .collect(),
        );
    }
    if let Some(bits) = json.get("bools") {
        return Value::Array(
            bits.as_str()
                .unwrap()
                .chars()
                .map(|c| Value::Bool(c == '1'))
                .collect(),
        );
    }
    if let Some(items) = json.get("list") {
        return Value::Array(items.as_array().unwrap().iter().map(input).collect());
    }
    if let Some(runs) = json.get("runs") {
        return Value::Array(runs_of(runs).iter().map(input).collect());
    }
    if let Some(items) = json.get("dict") {
        return Value::Struct(
            items
                .as_array()
                .unwrap()
                .iter()
                .map(|kv| (kv[0].as_str().unwrap().to_owned(), input(&kv[1])))
                .collect(),
        );
    }
    common::input(json).unwrap()
}

/// the items of a {"runs": [[value, count], ...]} list
fn runs_of(runs: &Json) -> Vec<Json> {
    runs.as_array()
        .unwrap()
        .iter()
        .flat_map(|run| std::iter::repeat_n(run[0].clone(), run[1].as_u64().unwrap() as usize))
        .collect()
}

/// asserts a result value equals the fixture's
fn assert_value(actual: &Option<Value>, expected: &Json, ctx: &str) {
    let Some(actual) = actual else {
        assert!(expected.is_null(), "{ctx}: got None, expected {expected}");
        return;
    };
    assert!(!expected.is_null(), "{ctx}: got {actual:?}, expected None");
    let items = |v: &Value| match v {
        Value::Array(items) => items.clone(),
        other => panic!("{ctx}: expected a list, got {other:?}"),
    };
    if let Some(ints) = expected.get("ints") {
        let got: Vec<Option<i128>> = items(actual).iter().map(Value::as_i128).collect();
        let want: Vec<Option<i128>> = ints
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_i64().map(i128::from))
            .collect();
        assert_eq!(got, want, "{ctx}");
    } else if let Some(bits) = expected.get("bools") {
        let got: String = items(actual)
            .iter()
            .map(|b| match b {
                Value::Bool(true) => '1',
                Value::Bool(false) => '0',
                other => panic!("{ctx}: not a bool {other:?}"),
            })
            .collect();
        assert_eq!(got, bits.as_str().unwrap(), "{ctx}");
    } else if let Some(want) = expected
        .get("list")
        .cloned()
        .or_else(|| expected.get("runs").map(|r| Json::Array(runs_of(r))))
    {
        let got = items(actual);
        let want = want.as_array().unwrap();
        assert_eq!(got.len(), want.len(), "{ctx}: length");
        for (i, (g, w)) in got.iter().zip(want).enumerate() {
            assert_value(&Some(g.clone()), w, &format!("{ctx}[{i}]"));
        }
    } else if let Some(want) = expected.get("dict") {
        let Value::Struct(map) = actual else {
            panic!("{ctx}: expected a dict, got {actual:?}")
        };
        let want = want.as_array().unwrap();
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        let want_keys: Vec<&str> = want.iter().map(|kv| kv[0].as_str().unwrap()).collect();
        assert_eq!(keys, want_keys, "{ctx}: keys");
        for kv in want {
            let key = kv[0].as_str().unwrap();
            assert_value(&Some(map[key].clone()), &kv[1], &format!("{ctx}.{key}"));
        }
    } else {
        common::assert_value(actual, expected, ctx);
    }
}

fn check_results(got: &[TagResult], want: &Json, ctx: &str) {
    let want = want.as_array().unwrap();
    assert_eq!(got.len(), want.len(), "{ctx}: result count: {got:?}");
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        let ctx = format!("{ctx} #{i} {}", w["tag"]);
        assert_eq!(g.tag, w["tag"].as_str().unwrap(), "{ctx}: tag");
        assert_eq!(g.data_type.as_deref(), w["type"].as_str(), "{ctx}: type");
        let error = g.error.as_ref();
        // logix/types.rs words Python's TypeError of a structure reply to an atomic tag without its 3.12 suffix
        let want_error = w["error"]
            .as_str()
            .map(|e| e.replace("must be integers, not 'str'", "must be integers"));
        let got_error = error.map(|e| {
            e.message
                .replace("must be integers, not 'str'", "must be integers")
        });
        assert_eq!(got_error, want_error, "{ctx}: error");
        assert_eq!(
            error.map(|e| e.kind.as_str()),
            w["kind"].as_str(),
            "{ctx}: kind"
        );
        assert_eq!(
            error.and_then(|e| e.status).map(u64::from),
            w["status"].as_u64(),
            "{ctx}: status"
        );
        assert_eq!(
            error.and_then(|e| e.ext).map(u64::from),
            w["ext"].as_u64(),
            "{ctx}: ext"
        );
        assert_value(&g.value, &w["value"], &format!("{ctx}: value"));
    }
}

// ---- scenarios ----

fn options(json: &Json) -> LogixOptions {
    let mut o = LogixOptions::default();
    for (k, v) in json.as_object().unwrap() {
        match k.as_str() {
            "init_tags" => o.init_tags = v.as_bool().unwrap(),
            "init_program_tags" => o.init_program_tags = v.as_bool().unwrap(),
            "lazy_tags" => o.lazy_tags = v.as_bool().unwrap(),
            "connection_size" => o.cip.connection_size = v.as_u64().unwrap() as u16,
            other => panic!("option {other}"),
        }
    }
    o
}

enum Outcome {
    None,
    Results(ciplink::Result<Vec<TagResult>>),
    Json(ciplink::Result<Json>),
}

fn step(d: &mut LogixDriver, fake: &Fake, step: &Json) -> Outcome {
    match step["call"].as_str().unwrap() {
        "new" => {
            *d = LogixDriver::with_connector(
                step["path"].as_str().unwrap(),
                options(&step["options"]),
                fake.connector(),
            )
            .unwrap();
            Outcome::None
        }
        "edit" | "fail_receive" => Outcome::None, // in the recorded replies
        "advance" => {
            d.advance_clock(Duration::from_secs_f64(step["seconds"].as_f64().unwrap()));
            Outcome::None
        }
        "use_ids" => {
            d.set_use_instance_ids(step["on"].as_bool().unwrap());
            Outcome::None
        }
        "open" => Outcome::Json(d.open().map(|b| json!({ "bool": b }))),
        "close" => Outcome::Json(d.close().map(|_| Json::Null)),
        "check" => Outcome::Json(d.check_tag_table().map(|b| json!({ "bool": b }))),
        "list" => Outcome::Json(
            d.get_tag_list(None, true, "")
                .map(|t| json!({ "int": t.len() })),
        ),
        "version" => {
            let version = d.tag_table_version().map_or(Json::Null, |v| {
                let items: Vec<Json> = [i32::from(v.0), v.1.into(), v.2, v.3, v.4]
                    .iter()
                    .map(|n| json!({ "int": n }))
                    .collect();
                json!({ "list": items })
            });
            let ids: Vec<Json> = d
                .tags()
                .iter()
                .map(|(k, t)| json!([k, t.instance_id]))
                .collect();
            Outcome::Json(Ok(json!({ "version": version, "ids": ids })))
        }
        "read" => {
            let tags: Vec<&str> = step["tags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap())
                .collect();
            Outcome::Results(d.read(&tags))
        }
        "write" => {
            let items: Vec<(&str, Value)> = step["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|kv| (kv[0].as_str().unwrap(), input(&kv[1])))
                .collect();
            Outcome::Results(d.write(&items))
        }
        other => panic!("step {other}"),
    }
}

fn check_error(err: &Error, want: &Json, ctx: &str) {
    assert_eq!(class(err), want["err"].as_str().unwrap(), "{ctx}: {err:?}");
    assert_eq!(err.to_string(), want["msg"].as_str().unwrap(), "{ctx}");
    assert_eq!(
        err.carried_kind().map(ErrorKind::as_str),
        want["kind"].as_str(),
        "{ctx}: kind"
    );
}

/// zeroes the random connection triad of Forward Open / Forward Close requests
fn mask_triad(frame: &[u8]) -> Vec<u8> {
    let mut f = frame.to_vec();
    if f.first() == Some(&0x6F) && f.len() >= 56 {
        match f[40] {
            0x54 | 0x5B if f.len() >= 64 => {
                f[52..58].fill(0);
                f[60..64].fill(0);
            }
            0x4E => {
                f[48..50].fill(0);
                f[52..56].fill(0);
            }
            _ => {}
        }
    }
    f
}

fn queue_replies(fake: &Fake, case: &Json) {
    for reply in case["replies"].as_array().unwrap() {
        match reply.as_str() {
            Some(r) => fake.reply(hex(r)),
            None => fake.reply_err(Error::comm("connection lost")),
        };
    }
}

fn new_driver(case: &Json, fake: &Fake) -> LogixDriver {
    LogixDriver::with_connector(
        case["path"].as_str().unwrap(),
        options(&case["options"]),
        fake.connector(),
    )
    .unwrap()
}

fn run_scenario(case: &Json) {
    let name = case["name"].as_str().unwrap();
    let fake = Fake::new();
    queue_replies(&fake, case);
    let mut d = new_driver(case, &fake);
    let steps = case["steps"].as_array().unwrap();
    let results = case["results"].as_array().unwrap();
    for (i, (s, want)) in steps.iter().zip(results).enumerate() {
        let ctx = format!("{name}[{i}] {}", s["call"]);
        match (step(&mut d, &fake, s), want.get("ok")) {
            (Outcome::None, _) => assert!(want.is_null(), "{ctx}: expected {want}"),
            (Outcome::Results(Ok(got)), Some(ok)) => check_results(&got, ok, &ctx),
            (Outcome::Json(Ok(got)), Some(ok)) => assert_eq!(&got, ok, "{ctx}"),
            (Outcome::Results(Err(err)) | Outcome::Json(Err(err)), None) => {
                check_error(&err, want, &ctx)
            }
            (Outcome::Results(got), _) => panic!("{ctx}: got {got:?}, expected {want}"),
            (Outcome::Json(got), _) => panic!("{ctx}: got {got:?}, expected {want}"),
        }
    }
    let sent: Vec<String> = fake.sent().iter().map(|f| to_hex(&mask_triad(f))).collect();
    let want: Vec<String> = case["sent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| to_hex(&mask_triad(&hex(f.as_str().unwrap()))))
        .collect();
    for (i, (s, w)) in sent.iter().zip(&want).enumerate() {
        assert_eq!(s, w, "{name}: frame {i}");
    }
    assert_eq!(sent.len(), want.len(), "{name}: frame count");
    assert_eq!(fake.pending(), 0, "{name}: replies left");
}

fn fixture() -> Json {
    common::load("logix_rw.json")
}

fn scenarios(prefix: &str) {
    let fixture = fixture();
    let mut ran = 0;
    for case in common::cases(&fixture, "scenarios") {
        if case["name"].as_str().unwrap().starts_with(prefix) {
            run_scenario(case);
            ran += 1;
        }
    }
    assert!(ran > 0, "no scenario for {prefix}");
}

const PREFIXES: [&str; 7] = [
    "rw_", "xfer_", "paths_", "strict_", "kinds_", "ver_", "aoi_rw_",
];

#[test]
fn reads_and_writes_like_python() {
    // test_logix_read_write.py: bit write values, call order of masks and writes, fragmented and batched sizes,
    // error replies, bad requests per tag, failed fragments, case-insensitive names; by ID and by name
    scenarios("rw_");
}

#[test]
fn transfers_like_python() {
    // test_logix_transfers.py: packet budgets, BOOL slices, bits of integers, malformed replies, partial reads
    // read again fragmented, fragmented reads and writes, >65535 element reads and writes, lazy tags, mixed
    // masks and whole writes in the caller's order, Micro800
    scenarios("xfer_");
}

#[test]
fn request_paths_like_python() {
    // test_logix_request_paths.py: the base tag by symbol instance ID, program tags, members, BOOL array words,
    // fragmented requests and chunks, names without IDs, paths that follow a reloaded tag list
    scenarios("paths_");
}

#[test]
fn strict_writes_like_python() {
    // test_strict_writes.py: values that do not fit are refused before sending, the others written
    scenarios("strict_");
}

#[test]
fn error_kinds_like_python() {
    // test_error_kinds.py: controller statuses and extended statuses, lost and unparseable replies, bad requests
    scenarios("kinds_");
}

#[test]
fn tag_table_version_checks_reads_and_writes_like_python() {
    // test_logix_tag_table_version.py: checks in every read packet, around fragmented reads and writes, reloads,
    // retries, backoff, TABLE_CHANGED errors
    scenarios("ver_");
}

#[test]
fn aoi_reads_and_writes_like_python() {
    // test_logix_aoi.py: whole AOI reads as their readable members, refused locals never requested
    scenarios("aoi_rw_");
}

#[test]
fn every_scenario_is_covered_by_a_test() {
    let fixture = fixture();
    for case in common::cases(&fixture, "scenarios") {
        let name = case["name"].as_str().unwrap();
        assert!(
            PREFIXES.iter().any(|p| name.starts_with(p)),
            "{name} is not run"
        );
    }
}

// ---- behaviour without fixtures ----

#[test]
fn read_and_write_of_a_closed_driver_are_comm_errors() {
    let d = LogixDriver::with_connector(
        "127.0.0.1",
        LogixOptions::default(),
        Fake::new().connector(),
    )
    .unwrap();
    assert!(matches!(d.read(&["a"]), Err(Error::Comm(_))));
    assert!(matches!(
        d.write(&[("a", Value::DInt(1))]),
        Err(Error::Comm(_))
    ));
}

// ---- robustness: damaged replies never panic or hang ----

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn damage(frame: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut f = frame.to_vec();
    if f.is_empty() {
        return f;
    }
    match rng.below(3) {
        0 => f.truncate(rng.below(f.len())),
        1 => {
            let i = rng.below(f.len());
            f[i] = rng.next() as u8;
        }
        _ => {
            let start = f.len().min(46);
            let i = start + rng.below(f.len() - start);
            if i < f.len() {
                f[i] = 0xFF;
            }
        }
    }
    f
}

fn run_damaged(case: &Json, seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let fake = Fake::new();
    for reply in case["replies"].as_array().unwrap() {
        match reply.as_str() {
            Some(r) if rng.below(6) == 0 => fake.reply(damage(&hex(r), &mut rng)),
            Some(r) => fake.reply(hex(r)),
            None => fake.reply_err(Error::comm("connection lost")),
        };
    }
    let mut d = new_driver(case, &fake);
    for s in case["steps"].as_array().unwrap() {
        drop(step(&mut d, &fake, s));
    }
}

#[test]
fn damaged_replies_never_panic_or_hang() {
    let cases = common::cases(&fixture(), "scenarios").clone();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for case in &cases {
            for seed in 0..4 {
                let name = case["name"].as_str().unwrap().to_owned();
                if std::panic::catch_unwind(|| run_damaged(case, seed)).is_err() {
                    done.send(Err(format!("{name} seed {seed} panicked")))
                        .unwrap();
                    return;
                }
            }
        }
        done.send(Ok(())).unwrap();
    });
    match finished.recv_timeout(Duration::from_secs(300)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{e}"),
        Err(_) => panic!("damaged replies made the driver hang"),
    }
}

// ---- thread safety: one driver shared by several threads, against the simulator over TCP ----

/// The `ciplink-sim` binary that `cargo test --workspace` builds next to this test's `deps` folder.
fn sim_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin = exe
        .parent()?
        .parent()?
        .join(format!("ciplink-sim{}", std::env::consts::EXE_SUFFIX));
    bin.exists().then_some(bin)
}

/// The simulator process, killed on drop.
struct Sim(std::process::Child);

impl Drop for Sim {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

fn start_sim(bin: &std::path::Path) -> (Sim, String) {
    use std::io::BufRead;
    let config = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/sim/example_controller.json"
    );
    let mut child = std::process::Command::new(bin)
        .args(["--config", config, "--port", "0"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let sim = Sim(child);
    let mut lines = std::io::BufReader::new(stdout).lines();
    let address = lines
        .by_ref()
        .map_while(|l| l.ok())
        .find_map(|l| l.strip_prefix("listening on ").map(str::to_owned))
        .expect("the simulator prints its address");
    // keep draining stdout so the simulator never blocks on a full pipe
    std::thread::spawn(move || lines.for_each(drop));
    (sim, address)
}

fn ok_value(results: &[TagResult], i: usize) -> &Value {
    let r = &results[i];
    assert!(r.error.is_none(), "{}: {:?}", r.tag, r.error);
    r.value.as_ref().unwrap()
}

#[test]
fn one_driver_serves_concurrent_reads_and_writes_from_several_threads() {
    let Some(bin) = sim_binary() else {
        eprintln!("skipped: ciplink-sim is not built (run `cargo test --workspace`)");
        return;
    };
    let (_sim, address) = start_sim(&bin);
    let driver = std::sync::Arc::new(LogixDriver::new(&address, LogixOptions::default()).unwrap());
    assert!(driver.open().unwrap());
    // the sim starts big_ary as [1, 2, 3, 0, ...]: make it uniform first, or a read before thread 0's first
    // write looks torn
    let w = driver
        .write(&[("big_ary{2000}", Value::Array(vec![Value::DInt(-1); 2000]))])
        .unwrap();
    assert!(w[0].error.is_none(), "{:?}", w[0].error);
    const THREADS: i32 = 4;
    const ROUNDS: i32 = 15;
    let threads: Vec<_> = (0..THREADS)
        .map(|t| {
            let d = std::sync::Arc::clone(&driver);
            std::thread::spawn(move || {
                let (dint, bit) = (format!("dint_ary[{t}]"), format!("bool_ary[{t}]"));
                for round in 0..ROUNDS {
                    let (n, on) = (t * 1000 + round, round % 2 == 0);
                    if t == 0 {
                        // a fragmented write of the whole array, one value throughout
                        let all = Value::Array(vec![Value::DInt(round); 2000]);
                        let w = d.write(&[("big_ary{2000}", all)]).unwrap();
                        assert!(w[0].error.is_none(), "{:?}", w[0].error);
                    }
                    // bits of the same DINT word, written with masks by every thread
                    let w = d
                        .write(&[
                            (dint.as_str(), Value::DInt(n)),
                            (bit.as_str(), Value::Bool(on)),
                        ])
                        .unwrap();
                    assert!(w.iter().all(|r| r.error.is_none()), "{w:?}");
                    let r = d
                        .read(&[dint.as_str(), bit.as_str(), "big_ary{2000}"])
                        .unwrap();
                    assert_eq!(ok_value(&r, 0), &Value::DInt(n));
                    assert_eq!(ok_value(&r, 1), &Value::Bool(on));
                    // the fragments of one read are never interleaved with another thread's write
                    let Value::Array(big) = ok_value(&r, 2) else {
                        panic!("big_ary is an array")
                    };
                    assert_eq!(big.len(), 2000);
                    assert!(big.iter().all(|v| v == &big[0]), "a torn fragmented read");
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let last = (ROUNDS - 1) % 2 == 0;
    let r = driver.read(&["bool_ary{4}"]).unwrap();
    assert_eq!(ok_value(&r, 0), &Value::Array(vec![Value::Bool(last); 4]));
    driver.close().unwrap();
}

#[test]
fn odd_tag_names_and_values_never_panic() {
    let Some(bin) = sim_binary() else {
        eprintln!("skipped: ciplink-sim is not built (run `cargo test --workspace`)");
        return;
    };
    let (_sim, address) = start_sim(&bin);
    let d = LogixDriver::new(&address, LogixOptions::default()).unwrap();
    assert!(d.open().unwrap());
    let tags = [
        "",
        "{}",
        "{",
        "}",
        "a{",
        "}{",
        "{5}",
        "dint1{}",
        "dint1{0}",
        "dint1{-1}",
        "dint1{x}",
        "dint1{1}{2}",
        "[",
        "]",
        "[]",
        "dint_ary[",
        "dint_ary]",
        "dint_ary[]",
        "dint_ary[-1]",
        "dint_ary[1,2]",
        "dint_ary[99999999999999999999]",
        "dint_ary[9223372036854775807]{3}",
        "big_ary[9223372036854775000]{70000}",
        "big_ary[0]{999999999999}",
        "bool_ary[-1]",
        "bool_ary[-33]{40}",
        "bool_ary[9223372036854775807]",
        "bool_ary[0]{9223372036854775807}",
        "dint1.32",
        "dint1.-1",
        "dint1.99999999999999999999",
        "sint1.7",
        "real1.0",
        ".",
        "..",
        "a.",
        ".a",
        "udt1..dint",
        "Program:",
        "Program:.",
        "Program:MainProgram",
        "Program:X.y",
        "str1.LEN.0",
        "udt1.dint.31",
        "\u{e9}\u{1F600}[1]",
        "dint_2d[1]",
        "dint_2d[9,9]{2}",
    ];
    let r = d.read(&tags).unwrap();
    assert_eq!(r.len(), tags.len());
    let values = [
        Value::DInt(1),
        Value::Bool(true),
        Value::Real(f32::NAN),
        Value::String("x".repeat(600)),
        Value::Bytes(vec![1, 2, 3]),
        Value::Array(Vec::new()),
        Value::Array(vec![Value::Bool(true); 3]),
    ];
    for v in values {
        let items: Vec<(&str, Value)> = tags.iter().map(|t| (*t, v.clone())).collect();
        let w = d.write(&items).unwrap();
        assert_eq!(w.len(), tags.len());
    }
    // the driver still works afterwards
    let w = d.write(&[("dint1", Value::DInt(7))]).unwrap();
    assert!(w[0].error.is_none(), "{:?}", w[0].error);
    assert_eq!(ok_value(&d.read(&["dint1"]).unwrap(), 0), &Value::DInt(7));
}
