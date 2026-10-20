//! LogixDriver parity with the Python LogixDriver (fixtures from tools/fixtures/gen_logix_driver.py): the scenarios
//! of tools/reference/tests/offline/test_logix_driver.py, test_logix_tag_list.py, test_logix_tag_upload.py, test_logix_tag_cache.py,
//! the probe parts of test_logix_aoi.py and the upload/check parts of test_logix_tag_table_version.py, replayed
//! against the scripted fake transport: the same frames and the same results.  The tag cache files differ in format
//! (Python writes JSON, Rust its binary file): a file Python wrote in a scenario is written as the binary file with
//! the same contents (see `python_cache_file`), and the files Rust writes must hold what Python's hold.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::PathBuf;
use std::time::Duration;

use ciplink::logix::driver::{
    AoiProbe, LogixDriver, LogixOptions, TagDefinition, format_plc_time_utc,
};
use ciplink::logix::tag_cache::{TagCacheError, TagCacheFile};
use ciplink::logix::types::{PyObj, Symbol, TemplateMakeup};
use ciplink::{Error, Value};
use common::fake::Fake;
use common::{class, hex, to_hex};
use serde_json::{Value as Json, json};

/// a PyObj as the fixtures tag Python values
fn tagged(obj: &PyObj) -> Json {
    match obj {
        PyObj::None => Json::Null,
        PyObj::Bool(b) => json!({ "bool": b }),
        PyObj::Int(n) => match i64::try_from(*n) {
            Ok(n) => json!({ "int": n }),
            Err(_) => json!({ "int": u64::try_from(*n).unwrap() }),
        },
        PyObj::Str(s) => json!({ "str": s }),
        PyObj::List(items) => json!({ "list": items.iter().map(tagged).collect::<Vec<_>>() }),
        PyObj::Dict(items) => json!({
            "dict": items.iter().map(|(k, v)| json!([key(k), tagged(v)])).collect::<Vec<_>>()
        }),
    }
}

/// Python's str() of a dict key
fn key(k: &PyObj) -> String {
    match k {
        PyObj::Str(s) => s.clone(),
        PyObj::Int(n) => n.to_string(),
        PyObj::None => "None".into(),
        PyObj::Bool(b) => if *b { "True" } else { "False" }.into(),
        other => panic!("key {other:?}"),
    }
}

/// the info dict, its status word as bytes (PyObj has no bytes, it is a list of the two bytes)
fn info_json(obj: &PyObj) -> Json {
    let PyObj::Dict(items) = obj else {
        panic!("info is not a dict")
    };
    let entries: Vec<Json> = items
        .iter()
        .map(|(k, v)| match (k, v) {
            (PyObj::Str(s), PyObj::List(bytes)) if s == "status" => {
                let bytes: Vec<u8> = bytes
                    .iter()
                    .map(|b| match b {
                        PyObj::Int(n) => *n as u8,
                        other => panic!("status byte {other:?}"),
                    })
                    .collect();
                json!(["status", { "bytes": to_hex(&bytes) }])
            }
            _ => json!([key(k), tagged(v)]),
        })
        .collect();
    json!({ "dict": entries })
}

fn value_json(value: &Option<Value>) -> Json {
    match value {
        None => Json::Null,
        Some(Value::Bytes(b)) => json!({ "bytes": to_hex(b) }),
        Some(Value::String(s)) => json!({ "str": s }),
        Some(v) => json!({ "int": v.as_i128().unwrap() as i64 }),
    }
}

fn state(d: &LogixDriver) -> Json {
    let version = d.tag_table_version().map_or(Json::Null, |v| {
        let items: Vec<Json> = [i32::from(v.0), v.1.into(), v.2, v.3, v.4]
            .iter()
            .map(|n| json!({ "int": n }))
            .collect();
        json!({ "list": items })
    });
    let name = d.name().map_or(Json::Null, |n| json!({ "str": n }));
    json!({ "dict": [
        ["connected", { "bool": d.connected() }],
        ["tags", tagged(&d.tags_py())],
        ["data_types", tagged(&d.data_types_py())],
        ["info", info_json(&d.info_py())],
        ["version", version],
        ["use_ids", { "bool": d.use_instance_ids() }],
        ["micro800", { "bool": d.micro800() }],
        ["name", name],
        ["revision_major", { "int": d.revision_major() }],
        ["str", { "str": d.to_string() }],
    ]})
}

struct Run {
    fake: Fake,
    dir: PathBuf,
    driver: Option<LogixDriver>,
    /// the driver before the last `new`, whose tags a `share` step shares
    previous: Option<LogixDriver>,
}

impl Run {
    fn file(&self) -> PathBuf {
        self.dir.join("tags.json")
    }

    fn options(&self, json: &Json) -> LogixOptions {
        let mut o = LogixOptions::default();
        let obj = json.as_object().unwrap();
        for (k, v) in obj {
            match k.as_str() {
                "init_tags" => o.init_tags = v.as_bool().unwrap(),
                "init_program_tags" => o.init_program_tags = v.as_bool().unwrap(),
                "lazy_tags" => o.lazy_tags = v.as_bool().unwrap(),
                "tag_namespace_filter" => o.tag_namespace_filter = v.as_str().unwrap().into(),
                "connection_size" => o.cip.connection_size = v.as_u64().unwrap() as u16,
                "tag_cache_file" => {
                    o.tag_cache_file = Some(match v.as_str().unwrap() {
                        "<file>" => self.file(),
                        "<missing_dir_file>" => self.dir.join("missing_dir").join("tags.json"),
                        other => panic!("cache file {other}"),
                    })
                }
                other => panic!("option {other}"),
            }
        }
        o
    }

    fn new_driver(&mut self, path: &str, options: &Json) {
        let options = self.options(options);
        let driver = LogixDriver::with_connector(path, options, self.fake.connector()).unwrap();
        self.previous = self.driver.replace(driver);
    }

    fn d(&self) -> &LogixDriver {
        self.driver.as_ref().unwrap()
    }

    /// runs a step; None for steps without a result
    fn step(&mut self, step: &Json) -> Option<ciplink::Result<Json>> {
        let call = step["call"].as_str().unwrap();
        let ok = |v: Json| Some(Ok(v));
        match call {
            "new" => {
                self.new_driver(step["path"].as_str().unwrap(), &step["options"]);
                None
            }
            "edit" | "fail_receive" => None, // in the recorded replies
            "write_file" => {
                let bytes = match python_cache_file(step["text"].as_str().unwrap()) {
                    PythonCacheFile::Used(file) => file.encode(),
                    PythonCacheFile::OtherVersion => {
                        let mut bytes = TagCacheFile::default().encode();
                        bytes[8..10].copy_from_slice(&0u16.to_le_bytes());
                        bytes
                    }
                    PythonCacheFile::Unreadable => b"damaged tag cache file".to_vec(),
                };
                std::fs::write(self.file(), bytes).unwrap();
                None
            }
            "share" => {
                // Python's plc2._tags = plc1.tags
                self.d().share_tags_from(self.previous.as_ref().unwrap());
                None
            }
            "advance" => {
                let secs = step["seconds"].as_f64().unwrap();
                self.d().advance_clock(Duration::from_secs_f64(secs));
                None
            }
            "open" => Some(self.d().open().map(|b| json!({ "bool": b }))),
            "close" => Some(self.d().close().map(|_| Json::Null)),
            "check" => Some(self.d().check_tag_table().map(|b| json!({ "bool": b }))),
            "list" => {
                let program = step["program"].as_str();
                let cache = step["cache"].as_bool().unwrap();
                let filter = step["filter"].as_str().unwrap();
                Some(
                    self.d()
                        .get_tag_list(program, cache, filter)
                        .map(|tags| tagged(&self.d().tag_list_py(&tags))),
                )
            }
            "state" => ok(state(self.d())),
            "tag_info" => {
                let name = step["name"].as_str().unwrap();
                // one lookup sends what Python's one sends (a failed lazy load is tried again by the next
                // lookup), so the typed lookup only follows a successful one, which it finds loaded
                let py = self.d().get_tag_info_py(name);
                if let Ok(p) = &py {
                    // the typed and the rendered lookups agree
                    match self.d().get_tag_info(name) {
                        Ok(TagDefinition::Tag(t)) => assert_eq!(t.tag_name, key_str(p, "tag_name")),
                        Ok(TagDefinition::Member(m)) => {
                            assert_eq!(i128::from(m.offset), key_int(p, "offset"))
                        }
                        other => panic!("typed and rendered tag info differ: {other:?}"),
                    }
                }
                Some(py.map(|p| tagged(&p)))
            }
            "plc_time" => Some(self.d().get_plc_time().map(|t| {
                let us = match &t.value {
                    Some(Value::Struct(m)) => match m.get("microseconds") {
                        Some(Value::ULInt(us)) => json!({ "int": us }),
                        other => panic!("time {other:?}"),
                    },
                    None => Json::Null,
                    other => panic!("time {other:?}"),
                };
                let kind = error_kind_json(&t);
                let error = t.error.map_or(Json::Null, |e| json!({ "str": e.message }));
                json!({ "dict": [["value", us], ["error", error], ["kind", kind]] })
            })),
            "set_plc_time" => {
                let us = step["microseconds"].as_u64();
                Some(self.d().set_plc_time(us).map(|t| {
                    let kind = error_kind_json(&t);
                    let error = t.error.map_or(Json::Null, |e| json!({ "str": e.message }));
                    json!({ "dict": [
                        ["tag", { "str": t.tag }], ["value", value_json(&t.value)], ["error", error], ["kind", kind]
                    ] })
                }))
            }
            "plc_info" => Some(self.d().get_plc_info().map(|i| {
                json!({ "dict": [["keyswitch", { "str": i.keyswitch }], ["serial", { "str": i.identity.serial }]] })
            })),
            "plc_name" => Some(self.d().get_plc_name().map(|n| json!({ "str": n }))),
            "file" => ok(match std::fs::read(self.file()) {
                Err(_) => Json::Null,
                Ok(bytes) => match TagCacheFile::decode(&bytes) {
                    Ok(file) => json!({ "file": format!("{file:?}") }),
                    Err(err) => json!({ "unreadable": err.to_string() }),
                },
            }),
            other => panic!("step {other}"),
        }
    }
}

fn key_str(obj: &PyObj, k: &str) -> String {
    match dict_get(obj, k) {
        Some(PyObj::Str(s)) => s.clone(),
        other => panic!("{k}: {other:?}"),
    }
}

fn key_int(obj: &PyObj, k: &str) -> i128 {
    match dict_get(obj, k) {
        Some(PyObj::Int(n)) => *n,
        other => panic!("{k}: {other:?}"),
    }
}

fn dict_get<'a>(obj: &'a PyObj, k: &str) -> Option<&'a PyObj> {
    let PyObj::Dict(items) = obj else { return None };
    items
        .iter()
        .find(|(key, _)| matches!(key, PyObj::Str(s) if s == k))
        .map(|(_, v)| v)
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

/// the first difference of two JSON values, as a path and the two values
fn diff(a: &Json, b: &Json, path: &str) -> Option<String> {
    match (a, b) {
        (Json::Object(x), Json::Object(y)) => {
            for (k, v) in x {
                match y.get(k) {
                    Some(w) => {
                        if let Some(d) = diff(v, w, &format!("{path}.{k}")) {
                            return Some(d);
                        }
                    }
                    None => return Some(format!("{path}.{k}: missing on one side")),
                }
            }
            (x.len() != y.len()).then(|| format!("{path}: keys {:?} vs {:?}", x.keys(), y.keys()))
        }
        (Json::Array(x), Json::Array(y)) => {
            for (i, (v, w)) in x.iter().zip(y).enumerate() {
                if let Some(d) = diff(v, w, &format!("{path}[{i}]")) {
                    return Some(d);
                }
            }
            (x.len() != y.len()).then(|| format!("{path}: length {} vs {}", x.len(), y.len()))
        }
        _ => (a != b).then(|| format!("{path}: {a} vs {b}")),
    }
}

/// the ErrorKind value of a result's error (Python's `tag.error_kind.value`), null without one
fn error_kind_json(t: &ciplink::cip::TagResult) -> Json {
    t.error
        .as_ref()
        .map_or(Json::Null, |e| json!({ "str": e.kind.as_str() }))
}

fn check(result: ciplink::Result<Json>, want: &Json, ctx: &str) {
    match (result, want.get("ok"), want.get("err")) {
        (Ok(got), Some(ok), None) => {
            if let Some(d) = diff(&got, ok, "") {
                panic!("{ctx}: rust vs python differ at {d}");
            }
        }
        (Err(err), None, Some(class_name)) => {
            assert_eq!(class(&err), class_name.as_str().unwrap(), "{ctx}: {err:?}");
            assert_eq!(err.to_string(), want["msg"].as_str().unwrap(), "{ctx}");
            // the ErrorKind of the TagError a RequestError/ResponseError carries
            let kind = err.carried_kind().map(|k| k.as_str());
            assert_eq!(kind, want["kind"].as_str(), "{ctx}: error kind");
        }
        (got, _, _) => panic!("{ctx}: got {got:?}, expected {want}"),
    }
}

/// What the Rust driver makes of a tag cache file the Python driver wrote, as the Python driver reads it.
enum PythonCacheFile {
    /// A file Python uses, as the binary file with the same contents.
    Used(TagCacheFile),
    /// A file of another format version: not used.
    OtherVersion,
    /// A file Python cannot use at all (not JSON, a missing key, a bad number), or one whose symbol lists are
    /// damaged, which Python ignores as soon as it reads them: not a tag cache file.
    Unreadable,
}

/// Python's `int(x)` of a JSON value: integers, floats truncated, booleans and decimal strings.
fn py_int(value: &Json) -> Option<i128> {
    match value {
        Json::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite())
                    .map(|f| f.trunc() as i128)
            }),
        Json::Bool(b) => Some(i128::from(*b)),
        Json::String(s) => s.trim().replace('_', "").parse().ok(),
        _ => None,
    }
}

/// A value Python compares by `==` with an int (`2.0 == 2`, `True == 1`): whole numbers only.
fn py_whole<T: TryFrom<i128>>(value: &Json) -> Option<T> {
    let n = match value {
        Json::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() != 0.0 => return None,
            _ => py_int(value)?,
        },
        Json::Bool(b) => i128::from(*b),
        _ => return None,
    };
    T::try_from(n).ok()
}

fn opt_str(value: &Json) -> Option<Option<String>> {
    match value {
        Json::Null => Some(None),
        Json::String(s) => Some(Some(s.clone())),
        _ => None,
    }
}

fn python_cache_file(text: &str) -> PythonCacheFile {
    let Ok(file) = serde_json::from_str::<Json>(text) else {
        return PythonCacheFile::Unreadable;
    };
    match file.get("version").map(py_whole::<i64>) {
        Some(Some(2)) => {}
        Some(_) => return PythonCacheFile::OtherVersion,
        None => return PythonCacheFile::Unreadable,
    }
    python_contents(&file).map_or(PythonCacheFile::Unreadable, PythonCacheFile::Used)
}

fn python_contents(file: &Json) -> Option<TagCacheFile> {
    let makeup = |m: &Json| -> Option<TemplateMakeup> {
        Some(TemplateMakeup {
            object_definition_size: u32::try_from(py_int(m.get("object_definition_size")?)?)
                .ok()?,
            structure_size: u32::try_from(py_int(m.get("structure_size")?)?).ok()?,
            member_count: u16::try_from(py_int(m.get("member_count")?)?).ok()?,
            structure_handle: u16::try_from(py_int(m.get("structure_handle")?)?).ok()?,
        })
    };
    let entries = |key: &str| -> Option<Vec<(u16, TemplateMakeup, Json)>> {
        let Some(items) = file.get(key) else {
            return Some(Vec::new());
        };
        items
            .as_array()?
            .iter()
            .map(|e| match e.as_array()?.as_slice() {
                [id, m, v] => Some((u16::try_from(py_int(id)?).ok()?, makeup(m)?, v.clone())),
                _ => None,
            })
            .collect()
    };
    let symbol = |s: &Json| -> Option<Symbol> {
        let dims = s.get("dimensions")?.as_array()?;
        let dim = |i: usize| py_whole::<u32>(dims.get(i)?);
        Some(Symbol {
            instance_id: py_whole(s.get("instance_id")?)?,
            tag_name: s.get("tag_name")?.as_str()?.to_owned(),
            symbol_type: py_whole(s.get("symbol_type")?)?,
            symbol_address: py_whole(s.get("symbol_address")?)?,
            symbol_object_address: py_whole(s.get("symbol_object_address")?)?,
            software_control: py_whole(s.get("software_control")?)?,
            external_access: s.get("external_access")?.as_str()?.to_owned(),
            dimensions: [dim(0)?, dim(1)?, dim(2)?],
        })
    };
    let symbols = file
        .get("symbols")?
        .as_array()?
        .iter()
        .map(|scope| match scope.as_array()?.as_slice() {
            [name, list] => Some((
                opt_str(name)?,
                list.as_array()?
                    .iter()
                    .map(symbol)
                    .collect::<Option<Vec<_>>>()?,
            )),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let table_version = match file.get("table_version")? {
        Json::Null => None,
        Json::Array(v) => match v.as_slice() {
            [a, b, c, d, e] => Some((
                py_whole(a)?,
                py_whole(b)?,
                py_whole(c)?,
                py_whole(d)?,
                py_whole(e)?,
            )),
            _ => return None,
        },
        _ => return None,
    };
    file.get("templates")?; // required, "aoi" is not
    let templates = entries("templates")?
        .into_iter()
        .map(|(id, m, data)| Some((id, m, from_hex(data.as_str()?)?)))
        .collect::<Option<Vec<_>>>()?;
    let names = |p: &Json, key: &str| -> Option<Vec<String>> {
        p.get(key)?
            .as_array()?
            .iter()
            .map(|n| n.as_str().map(str::to_owned))
            .collect()
    };
    let probes = entries("aoi")?
        .into_iter()
        .map(|(id, m, p)| {
            let probe = AoiProbe {
                whole_read: p.get("whole_read")?.as_bool()?,
                readable: names(&p, "readable")?,
                refused: names(&p, "refused")?,
            };
            Some((id, m, probe))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(TagCacheFile {
        scope: opt_str(file.get("scope")?)?,
        serial: opt_str(file.get("serial")?)?,
        table_version,
        symbols,
        templates,
        probes,
    })
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 == 1 {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// A tag cache file after a step: Rust's exists when Python's does, and holds what Python's holds.
fn check_file(got: Option<ciplink::Result<Json>>, want: &Json, ctx: &str) {
    let got = got.unwrap().unwrap();
    match want["ok"].get("str").and_then(Json::as_str) {
        None => assert_eq!(got, Json::Null, "{ctx}: Python wrote no file"),
        Some(text) => {
            assert!(got.get("file").is_some(), "{ctx}: {got}");
            match python_cache_file(text) {
                PythonCacheFile::Used(file) => {
                    assert_eq!(got["file"], json!(format!("{file:?}")), "{ctx}: contents")
                }
                PythonCacheFile::OtherVersion => {
                    panic!("{ctx}: Python's file is of another version")
                }
                PythonCacheFile::Unreadable => panic!("{ctx}: Python's file is unreadable"),
            }
        }
    }
}

#[test]
fn python_cache_files_convert_as_python_reads_them() {
    let text = r#"{"version": 2.0, "scope": "*", "serial": "c0ffee01", "table_version": [316.0, 1, 10, 10, 20],
        "symbols": [[null, [{"instance_id": 1.0, "tag_name": "a", "symbol_type": 196, "symbol_address": 0,
        "symbol_object_address": 0, "software_control": 67108864, "external_access": "None",
        "dimensions": [0, 0, 0]}]]], "templates": [["291", {"object_definition_size": 3, "structure_size": 4,
        "member_count": 1, "structure_handle": 7}, "0a ff"]]}"#;
    let PythonCacheFile::Used(file) = python_cache_file(text) else {
        panic!("not used")
    };
    assert_eq!(file.table_version, Some((316, 1, 10, 10, 20)));
    assert_eq!(file.templates[0].0, 291);
    assert_eq!(file.templates[0].2, vec![0x0A, 0xFF]);
    assert!(file.probes.is_empty());
    assert_eq!(TagCacheFile::decode(&file.encode()), Ok(file));
    assert!(matches!(
        python_cache_file(r#"{"version": 1}"#),
        PythonCacheFile::OtherVersion
    ));
    assert!(matches!(
        python_cache_file("not json"),
        PythonCacheFile::Unreadable
    ));
    let mut bytes = TagCacheFile::default().encode();
    bytes[8..10].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        TagCacheFile::decode(&bytes),
        Err(TagCacheError::OtherVersion(0))
    );
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ciplink-logix-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_scenario(case: &Json) {
    let name = case["name"].as_str().unwrap();
    let fake = Fake::new();
    for reply in case["replies"].as_array().unwrap() {
        match reply.as_str() {
            Some(r) => fake.reply(hex(r)),
            None => fake.reply_err(Error::comm("connection lost")),
        };
    }
    let mut run = Run {
        fake: fake.clone(),
        dir: temp_dir(name),
        driver: None,
        previous: None,
    };
    run.new_driver(case["path"].as_str().unwrap(), &case["options"]);
    let steps = case["steps"].as_array().unwrap();
    let results = case["results"].as_array().unwrap();
    for (i, (step, want)) in steps.iter().zip(results).enumerate() {
        let ctx = format!("{name}[{i}] {}", step["call"]);
        if step["call"] == "file" {
            check_file(run.step(step), want, &ctx);
            continue;
        }
        match (run.step(step), want.is_null()) {
            (None, true) => {}
            (Some(result), false) => check(result, want, &ctx),
            (got, _) => panic!("{ctx}: step result {got:?}, expected {want}"),
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
    let _ = std::fs::remove_dir_all(&run.dir);
}

fn scenarios(prefixes: &[&str]) {
    let fixture = common::load("logix_driver.json");
    let mut ran = 0;
    for case in common::cases(&fixture, "scenarios") {
        let name = case["name"].as_str().unwrap();
        if prefixes.iter().any(|p| name.starts_with(p)) {
            run_scenario(case);
            ran += 1;
        }
    }
    assert!(ran > 0, "no scenario for {prefixes:?}");
}

#[test]
fn connect_initializes_like_python() {
    // test_logix_driver.py: identity, Micro800 detection and path strip, instance IDs by revision, program
    // name, clock, init failures closing the connection
    scenarios(&["init_", "open_fails_", "upload_fails_", "comm_errors_"]);
}

#[test]
fn tag_list_uploads_like_python() {
    // test_logix_tag_list.py: request bytes per program, pages, definitions, namespace filter, modules
    scenarios(&["tag_list_", "namespace_filter", "module_tags"]);
}

#[test]
fn uploads_batch_programs_makeups_and_keep_templates_like_python() {
    // test_logix_tag_upload.py
    scenarios(&[
        "connect_batches",
        "reload_",
        "reconnect_",
        "pages_continue",
        "page_without",
        "rejected_batches",
        "service_rejected",
        "download_reads",
        "micro800_upload",
        "small_connection_size",
    ]);
}

#[test]
fn tag_cache_file_is_read_and_written_like_python() {
    // test_logix_tag_cache.py, with files written by Python read by Rust and the files Rust writes compared
    // byte for byte with Python's
    scenarios(&["cache_"]);
}

#[test]
fn aoi_probes_like_python() {
    // test_logix_aoi.py, the probe parts
    scenarios(&["aoi_"]);
}

#[test]
fn tag_table_version_uploads_and_checks_like_python() {
    // test_logix_tag_table_version.py, the upload and check parts
    scenarios(&["version_"]);
}

#[test]
fn error_paths_and_lazy_lookups_like_python() {
    // branches of the Python driver the scenarios above leave out: a batched symbol page that does not advance
    // (test_batched_page_that_does_not_advance_continues_alone), calls before open and a refused session,
    // clock / program name / identity failures and keyswitch positions, Micro800 identity, damaged symbol
    // lists, template and makeup failures (alone and batched), lazy lookups (program scope, case, system tags,
    // filter, members) and lazy failures, uploads without cache, failed reloads (lazy and not)
    scenarios(&["review_"]);
}

#[test]
fn routes_names_instance_ids_shared_tags_and_cache_numbers_like_python() {
    // a Micro800 route stripped again on every connect, an empty program name, 8/16-bit symbol instance
    // segments in pages (alone and batched), latin-1 and damaged program names, tags shared between
    // connections with their AOI probes (before and after the second connected), a tag cache file compared
    // as Python compares (2.0 == 2), uploads without cache and init_tags=False through the file
    scenarios(&["parity_"]);
}

#[test]
fn every_scenario_is_covered_by_a_test() {
    let covered = [
        "init_",
        "open_fails_",
        "upload_fails_",
        "comm_errors_",
        "tag_list_",
        "namespace_filter",
        "module_tags",
        "connect_batches",
        "reload_",
        "reconnect_",
        "pages_continue",
        "page_without",
        "rejected_batches",
        "service_rejected",
        "download_reads",
        "micro800_upload",
        "small_connection_size",
        "cache_",
        "aoi_",
        "version_",
        "review_",
        "parity_",
    ];
    let fixture = common::load("logix_driver.json");
    for case in common::cases(&fixture, "scenarios") {
        let name = case["name"].as_str().unwrap();
        assert!(
            covered.iter().any(|p| name.starts_with(p)),
            "{name} is not run"
        );
    }
}

// ---- behaviour without fixtures ----

fn closed_driver(options: LogixOptions) -> LogixDriver {
    LogixDriver::with_connector("192.168.1.100/1", options, Fake::new().connector()).unwrap()
}

#[test]
fn new_driver_is_closed_with_no_tags() {
    // test_default_logix_tags_are_empty_dict, test_logix_connected_false_on_init_with_false_init_params,
    // test_str_shows_name_device_and_revision
    let d = closed_driver(LogixOptions::default());
    assert!(d.tags().is_empty());
    assert!(!d.connected());
    assert_eq!(
        d.to_string(),
        "Program Name: None, Device: None, Revision: -1.-1"
    );
    assert_eq!(d.revision_major(), 0);
    assert_eq!(d.name(), None);
    assert_eq!(d.tags_py(), PyObj::Dict(vec![]));
    assert_eq!(d.info_py(), PyObj::Dict(vec![]));
}

#[test]
fn connect_failure_is_a_comm_error() {
    let fake = Fake::new();
    fake.fail_connect(Error::comm("refused"));
    let d = LogixDriver::with_connector("10.0.0.1", LogixOptions::default(), fake.connector());
    let d = d.unwrap();
    assert_eq!(d.open(), Err(Error::comm("failed to open a connection")));
    assert!(fake.sent().is_empty());
}

#[test]
fn tag_info_of_a_closed_driver_without_lazy_tags_is_not_found() {
    let d = closed_driver(LogixOptions::default());
    let err = d.get_tag_info("missing.member").unwrap_err();
    assert_eq!(err.to_string(), "Tag doesn't exist - missing");
    assert_eq!(err.carried_kind(), Some(ciplink::ErrorKind::NotFound));
    assert!(matches!(
        d.get_tag_info("Program:Main"),
        Err(Error::Request { .. })
    ));
}

#[test]
fn plc_time_string_is_formatted_in_utc() {
    assert_eq!(
        format_plc_time_utc(1_700_000_000_123_456),
        "Tuesday, November 14, 2023 10:13:20PM"
    );
}

// ---- robustness: damaged replies never panic or hang ----

/// a small deterministic PRNG (xorshift64*)
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

/// `frame` truncated, with a byte changed, or with a length/count field blown up
fn damage(frame: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut f = frame.to_vec();
    if f.is_empty() {
        return f;
    }
    match rng.below(4) {
        0 => f.truncate(rng.below(f.len())),
        1 => {
            let i = rng.below(f.len());
            f[i] = rng.next() as u8;
        }
        2 => {
            let i = rng.below(f.len());
            f[i] = 0xFF;
            if i + 1 < f.len() {
                f[i + 1] = 0xFF;
            }
        }
        _ => {
            // damage the CIP part only (after the 24-byte encapsulation header and the CPF items)
            let start = f.len().min(40);
            let i = start + rng.below(f.len() - start);
            if i < f.len() {
                f[i] = rng.next() as u8;
            }
        }
    }
    f
}

/// runs a scenario's calls with some replies damaged, discarding the results: nothing may panic
fn run_damaged(case: &Json, seed: u64) {
    let name = case["name"].as_str().unwrap();
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let fake = Fake::new();
    let replies = case["replies"].as_array().unwrap();
    let damaged = rng.below(replies.len());
    for (i, reply) in replies.iter().enumerate() {
        match reply.as_str() {
            Some(r) if i == damaged || rng.below(8) == 0 => fake.reply(damage(&hex(r), &mut rng)),
            Some(r) => fake.reply(hex(r)),
            None => fake.reply_err(Error::comm("connection lost")),
        };
    }
    let mut run = Run {
        fake: fake.clone(),
        dir: temp_dir(&format!("{name}-damaged-{seed}")),
        driver: None,
        previous: None,
    };
    run.new_driver(case["path"].as_str().unwrap(), &case["options"]);
    for step in case["steps"].as_array().unwrap() {
        let d = run.d();
        match step["call"].as_str().unwrap() {
            "open" => drop(d.open()),
            "close" => drop(d.close()),
            "check" => drop(d.check_tag_table()),
            "list" => {
                let tags = d.get_tag_list(
                    step["program"].as_str(),
                    step["cache"].as_bool().unwrap(),
                    step["filter"].as_str().unwrap(),
                );
                if let Ok(tags) = tags {
                    drop(d.tag_list_py(&tags));
                }
            }
            "state" => {
                drop((d.tags_py(), d.data_types_py(), d.info_py(), d.to_string()));
            }
            "tag_info" => drop(d.get_tag_info_py(step["name"].as_str().unwrap())),
            "plc_time" => drop(d.get_plc_time()),
            "set_plc_time" => drop(d.set_plc_time(step["microseconds"].as_u64())),
            "plc_info" => drop(d.get_plc_info()),
            "plc_name" => drop(d.get_plc_name()),
            _ => drop(run.step(step)),
        }
    }
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn damaged_replies_never_panic_or_hang() {
    let fixture = common::load("logix_driver.json");
    let cases = common::cases(&fixture, "scenarios").clone();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for case in &cases {
            for seed in 0..8 {
                let name = case["name"].as_str().unwrap().to_owned();
                let result = std::panic::catch_unwind(|| run_damaged(case, seed));
                if result.is_err() {
                    done.send(Err(format!("{name} seed {seed} panicked")))
                        .unwrap();
                    return;
                }
            }
        }
        done.send(Ok(())).unwrap();
    });
    match finished.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{e}"),
        Err(_) => panic!("damaged replies made the driver hang"),
    }
}

// ---- thread safety ----

#[test]
fn driver_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LogixDriver>();
}

/// A v20 controller (no instance IDs, so no tag table version) answering identity, program name and clock
/// (the clock reply's time is the request's sequence count).
fn v20_controller(fake: &Fake) {
    use common::fake::{rr_reply, session_responder, unit_reply};
    let cid = [1, 2, 3, 4];
    let mut connected = session_responder(cid, move |sequence, message| match message.first() {
        Some(0x01) => {
            let mut name = vec![4, 0];
            name.extend(b"Main");
            unit_reply(cid, sequence, 0x01, 0, &[], &name)
        }
        Some(0x03) => {
            let mut data = vec![0; 6];
            data.extend(u64::from(sequence).to_le_bytes());
            unit_reply(cid, sequence, 0x03, 0, &[], &data)
        }
        Some(&s) => unit_reply(cid, sequence, s, 0x08, &[], &[]),
        None => Vec::new(),
    });
    fake.respond(move |frame| {
        if frame.first() == Some(&0x6F) && matches!(frame.get(40), Some(0x01 | 0x52)) {
            let mut data = vec![
                1, 0, 0x0E, 0, 0x36, 0, 20, 11, 0x60, 0x30, 0x78, 0x56, 0x34, 0x12,
            ];
            data.push(10);
            data.extend(b"1756-SIM/A");
            return Ok(rr_reply(0x01, 0, &[], &data));
        }
        connected(frame)
    });
}

#[test]
fn concurrent_calls_from_several_threads_each_get_their_own_reply() {
    let fake = Fake::new();
    v20_controller(&fake);
    let options = LogixOptions {
        init_tags: false,
        ..LogixOptions::default()
    };
    let d = LogixDriver::with_connector("127.0.0.1", options, fake.connector()).unwrap();
    assert_eq!(d.open(), Ok(true));
    assert_eq!(d.name().as_deref(), Some("Main"));
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..25 {
                    let t = d.get_plc_time().unwrap();
                    assert_eq!(t.error, None);
                    assert!(matches!(t.value, Some(Value::Struct(_))));
                    assert_eq!(d.get_plc_name().unwrap(), "Main");
                    let _ = (d.tags_py(), d.info_py(), d.to_string(), d.connected());
                }
            });
        }
    });
    // the sequence counts were never reused
    let sequences: Vec<u16> = fake
        .sent()
        .iter()
        .filter(|f| f.first() == Some(&0x70))
        .map(|f| common::fake::sent_sequence(f))
        .collect();
    let mut unique = sequences.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), sequences.len());
    assert!(d.connected());
}

#[test]
fn advancing_the_clock_past_its_range_does_not_panic() {
    let d = closed_driver(LogixOptions::default());
    d.advance_clock(Duration::MAX);
    d.advance_clock(Duration::MAX);
    assert!(d.check_tag_table().is_err()); // not connected
    assert_eq!(d.revision_major(), 0);
}

// ---- robustness: nested templates ----

/// The template instance in a connected request's path (class 0x6C), if any.
fn template_instance(message: &[u8]) -> Option<u16> {
    let words = usize::from(*message.get(1)?);
    let path = message.get(2..2 + 2 * words)?;
    match path {
        [0x20, 0x6C, 0x24, id, ..] => Some(u16::from(*id)),
        [0x20, 0x6C, 0x25, 0, lo, hi, ..] => Some(u16::from_le_bytes([*lo, *hi])),
        _ => None,
    }
}

/// A v20 controller with one tag `T` of template 0x100, template `0x100 + i` holding one member of template
/// `0x100 + i + 1` (`next(i)`, None for a DINT member).
fn nesting_controller(fake: &Fake, next: impl Fn(u16) -> Option<u16> + Send + 'static) {
    use common::fake::{rr_reply, session_responder, unit_reply};
    const BASE: u16 = 0x100;
    let cid = [1, 2, 3, 4];
    let template = move |id: u16| -> Vec<u8> {
        let typ = next(id - BASE).map_or(0x00C4, |n| 0x8000 | (BASE + n));
        let mut data = vec![0, 0];
        data.extend(typ.to_le_bytes());
        data.extend(0u32.to_le_bytes());
        data.extend(format!("T{id};n\0M\0").as_bytes());
        data
    };
    let mut connected = session_responder(cid, move |sequence, message| match message.first() {
        Some(0x01) => {
            let mut name = vec![4, 0];
            name.extend(b"Main");
            unit_reply(cid, sequence, 0x01, 0, &[], &name)
        }
        Some(0x55) => {
            let mut data = 1u32.to_le_bytes().to_vec();
            data.extend([1, 0, b'T']);
            data.extend((0x8000 | BASE).to_le_bytes());
            data.extend([0; 4 * 6]);
            data.push(0); // external access: Read/Write
            unit_reply(cid, sequence, 0x55, 0, &[], &data)
        }
        Some(0x03) => {
            let id = template_instance(message).unwrap_or(BASE);
            let size = u32::try_from(template(id).len()).unwrap().div_ceil(4) + 6;
            let mut data = 4u16.to_le_bytes().to_vec();
            for (attr, value) in [(4u16, size), (5, 4)] {
                data.extend(attr.to_le_bytes());
                data.extend([0, 0]);
                data.extend(value.to_le_bytes());
            }
            for (attr, value) in [(2u16, 1u16), (1, 0x1234)] {
                data.extend(attr.to_le_bytes());
                data.extend([0, 0]);
                data.extend(value.to_le_bytes());
            }
            unit_reply(cid, sequence, 0x03, 0, &[], &data)
        }
        Some(0x4C) => {
            let id = template_instance(message).unwrap_or(BASE);
            unit_reply(cid, sequence, 0x4C, 0, &[], &template(id))
        }
        Some(&s) => unit_reply(cid, sequence, s, 0x08, &[], &[]),
        None => Vec::new(),
    });
    fake.respond(move |frame| {
        if frame.first() == Some(&0x6F) && matches!(frame.get(40), Some(0x01 | 0x52)) {
            let mut data = vec![
                1, 0, 0x0E, 0, 0x36, 0, 20, 11, 0x60, 0x30, 0x78, 0x56, 0x34, 0x12,
            ];
            data.push(10);
            data.extend(b"1756-SIM/A");
            return Ok(rr_reply(0x01, 0, &[], &data));
        }
        connected(frame)
    });
}

/// Opens a driver on a nesting controller in a thread with a `stack` byte stack, then (`render`) renders and
/// looks up its tags. Loading must not grow the stack with the template nesting from the controller: it fits in
/// 256 KiB in a debug build; the recursive renderings (`DataType::to_py`) need about 1 MiB at depth 200.
fn open_nested(
    stack: usize,
    render: bool,
    next: impl Fn(u16) -> Option<u16> + Send + 'static,
) -> (ciplink::Result<bool>, usize) {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || {
            let fake = Fake::new();
            nesting_controller(&fake, next);
            let d =
                LogixDriver::with_connector("127.0.0.1", LogixOptions::default(), fake.connector())
                    .unwrap();
            let opened = d.open();
            if render && opened.is_ok() {
                // renderings and lookups walk the nesting too
                drop((d.tags_py(), d.data_types_py(), d.tags(), d.to_string()));
                let deepest = format!("T{}", ".M".repeat(d.data_types().len()));
                assert!(d.get_tag_info_py(&deepest).is_ok());
            }
            (opened, d.data_types().len())
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn deeply_nested_templates_load_within_a_small_stack() {
    for (stack, render) in [(256 << 10, false), (1 << 20, true)] {
        // 200 templates, the most followed
        let (opened, types) = open_nested(stack, render, |i| (i < 199).then_some(i + 1));
        assert_eq!(opened, Ok(true));
        assert_eq!(types, 200);
    }
}

#[test]
fn templates_nested_too_deep_or_in_a_cycle_fail_the_upload_without_overflowing() {
    for next in [
        Box::new(|i: u16| (i < 400).then_some(i + 1)) as Box<dyn Fn(u16) -> Option<u16> + Send>,
        Box::new(|_| Some(0)),            // the template holds itself
        Box::new(|i| Some(1 - i.min(1))), // two templates holding each other
    ] {
        let (opened, types) = open_nested(256 << 10, false, next);
        let err = opened.unwrap_err();
        assert_eq!(err.to_string(), "failed isolating user tags");
        assert_eq!(types, 0);
    }
}

#[test]
fn plc_time_strings_at_the_ends_of_the_range_do_not_panic() {
    assert_eq!(
        format_plc_time_utc(0),
        "Thursday, January 01, 1970 12:00:00AM"
    );
    assert!(format_plc_time_utc(u64::MAX).contains(", 586524 ")); // Python raises OverflowError past 9999
}
