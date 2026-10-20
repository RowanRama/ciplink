//! Differential parity harness: the reference Python driver (tools/reference/) and the Rust driver run the same
//! scenarios (tools/diff/scenarios.json, written by tools/diff/gen_scenarios.py) against fresh, identically
//! configured simulators. Every request frame each sends must be byte-identical (except the Forward Open
//! connection triad and the encapsulation sender context, which are masked) and every result identical.
//!
//! Python runs tools/diff/py_runner.py with `uv run --no-project --isolated --python 3.12` (or the interpreter
//! named by `CIPLINK_DIFF_PYTHON`) against a simulator served over TCP; Rust uses the in-memory connector. The
//! test is skipped, with a message, when neither can be started. `CIPLINK_DIFF_ONLY=substring` runs only the
//! scenarios whose name contains it. Both sides' frames and results are written to
//! `target/tmp/differential/<scenario>.json`.
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use ciplink::cip::{CipOptions, GenericMessage, RoutePath, TagResult};
use ciplink::epath::LogicalValue;
use ciplink::identity::ModuleIdentity;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::metadata::TextEncoding;
use ciplink::logix::tag_cache::TagCacheFile;
use ciplink::logix::types::PyObj;
use ciplink::slc::driver::SlcDriver;
use ciplink::{Error, Value};
use ciplink_sim::{Fault, LogixConfig, Simulator, TagConfig, TypeConfig};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ------------------------------------------------------------------------------------------------ Python

/// The Python runner process, one for the whole run.
struct Python {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_log: PathBuf,
}

impl Python {
    fn start(out: &Path) -> Option<Python> {
        let stderr_log = out.join("python_stderr.log");
        let mut command = match std::env::var("CIPLINK_DIFF_PYTHON") {
            Ok(python) => Command::new(python),
            Err(_) => {
                let mut c = Command::new("uv");
                c.args([
                    "run",
                    "--no-project",
                    "--isolated",
                    "--python",
                    "3.12",
                    "python",
                ]);
                c
            }
        };
        let child = command
            .arg("tools/diff/py_runner.py")
            .current_dir(repo())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&stderr_log).unwrap())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                eprintln!("differential: skipped, cannot start the reference Python ({e})");
                return None;
            }
        };
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Some(Python {
            child,
            stdin,
            stdout,
            stderr_log,
        })
    }

    fn call(&mut self, request: &Json) -> Json {
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        if line.is_empty() {
            let log = std::fs::read_to_string(&self.stderr_log).unwrap_or_default();
            panic!("the Python runner exited; its stderr:\n{log}");
        }
        let mut answer: Json = serde_json::from_str(&line).unwrap();
        if let Some(crash) = answer.get("crash") {
            panic!(
                "the Python runner failed on {request}:\n{}",
                crash.as_str().unwrap()
            );
        }
        answer["result"].take()
    }
}

impl Drop for Python {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------------------------------------ simulator

/// The scenario's simulator configuration: a file of tools/sim/ with merges and extra tags, or inline.
fn config(spec: &Json) -> String {
    let mut config = match spec.get("inline") {
        Some(inline) => inline.clone(),
        None => {
            let file = repo()
                .join("tools/sim")
                .join(spec["file"].as_str().unwrap());
            serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
        }
    };
    if let Some(merge) = spec.get("merge") {
        merge_into(&mut config, merge);
    }
    for (key, field) in [("extra_tags", "tags"), ("extra_types", "types")] {
        if let Some(extra) = spec.get(key).and_then(Json::as_array) {
            let list = config[field].as_array_mut().unwrap();
            list.extend(extra.iter().cloned());
        }
    }
    config.to_string()
}

fn merge_into(into: &mut Json, from: &Json) {
    match (into, from) {
        (Json::Object(a), Json::Object(b)) => {
            for (k, v) in b {
                merge_into(a.entry(k.clone()).or_insert(Json::Null), v);
            }
        }
        (a, b) => *a = b.clone(),
    }
}

fn fault(spec: &Json) -> Fault {
    let status = |s: &Json| {
        (
            s["status"].as_u64().unwrap() as u8,
            s.get("ext").and_then(Json::as_u64).map(|e| e as u16),
        )
    };
    if let Some(n) = spec.get("drop_replies") {
        return Fault::DropReplies(n.as_u64().unwrap() as u32);
    }
    if let Some(t) = spec.get("tag_status") {
        let (status, ext) = status(t);
        return Fault::TagStatus {
            tag: t["tag"].as_str().unwrap().into(),
            status,
            ext,
        };
    }
    if let Some(s) = spec.get("service_status") {
        let (status, ext) = status(s);
        return Fault::ServiceStatus {
            service: s["service"].as_u64().unwrap() as u8,
            class: s.get("class").and_then(Json::as_u64).map(|c| c as u32),
            status,
            ext,
        };
    }
    panic!("unknown fault {spec}")
}

/// A `{"op": "sim"}` step, applied the same way to both simulators.
fn sim_step(sim: &Simulator, step: &Json) {
    let program = step.get("program").and_then(Json::as_str);
    let logix = |f: &mut dyn FnMut(&mut ciplink_sim::Logix)| sim.with_logix(f).unwrap();
    match step["cmd"].as_str().unwrap() {
        "set" => sim
            .set_value(step["path"].as_str().unwrap(), &step["value"])
            .unwrap(),
        "add_tag" => {
            let tag: TagConfig = serde_json::from_value(step["tag"].clone()).unwrap();
            logix(&mut |plc| {
                plc.add_tag(program, &tag).unwrap();
            });
        }
        "remove_tag" => {
            let name = step["name"].as_str().unwrap();
            logix(&mut |plc| plc.remove_tag(program, name).unwrap());
        }
        "add_type" => {
            let data_type: TypeConfig = serde_json::from_value(step["type"].clone()).unwrap();
            logix(&mut |plc| plc.add_type(&data_type).unwrap());
        }
        "bump" => logix(&mut |plc| plc.bump_tag_table()),
        "download" => {
            let config: LogixConfig = serde_json::from_value(step["config"].clone()).unwrap();
            logix(&mut |plc| plc.download(&config).unwrap());
        }
        "fault" => sim.inject(fault(&step["fault"])),
        "clear_faults" => sim.clear_faults(),
        "bump_requests" => {
            let start = sim.requests();
            let end = start + step["n"].as_u64().unwrap();
            sim.on_request(move |plc, index| {
                if (start..end).contains(&index) {
                    plc.bump_tag_table();
                }
            });
        }
        "clear_hook" => sim.clear_hook(),
        other => panic!("unknown sim step {other}"),
    }
}

/// Waits until the simulator got every frame sent (Python sends UnRegisterSession and closes without a reply).
fn settle(sim: &Simulator) {
    let mut last = sim.requests();
    let mut quiet = 0;
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(10));
        let now = sim.requests();
        quiet = if now == last { quiet + 1 } else { 0 };
        last = now;
        if quiet >= 5 {
            return;
        }
    }
}

// ------------------------------------------------------------------------------------------------ encoding

/// A PyObj as tagged JSON (tools/fixtures/fixturelib.py `enc`).
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

/// Python's str() of a dict key.
fn key(k: &PyObj) -> String {
    match k {
        PyObj::Str(s) => s.clone(),
        PyObj::Int(n) => n.to_string(),
        PyObj::None => "None".into(),
        PyObj::Bool(b) => if *b { "True" } else { "False" }.into(),
        other => panic!("key {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The info dict; its status word is bytes in Python, a list of the two bytes in PyObj.
fn info_json(obj: &PyObj) -> Json {
    let PyObj::Dict(items) = obj else {
        return tagged(obj);
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
                json!(["status", { "bytes": hex(&bytes) }])
            }
            _ => json!([key(k), tagged(v)]),
        })
        .collect();
    json!({ "dict": entries })
}

fn value_json(value: &Value) -> Json {
    match value {
        Value::Bool(b) => json!({ "bool": b }),
        Value::Real(x) => float_json(f64::from(*x)),
        Value::LReal(x) => float_json(*x),
        Value::String(s) => json!({ "str": s }),
        Value::Bytes(b) => json!({ "bytes": hex(b) }),
        Value::Array(items) => json!({ "list": items.iter().map(value_json).collect::<Vec<_>>() }),
        Value::Struct(map) => json!({
            "dict": map.iter().map(|(k, v)| json!([k, value_json(v)])).collect::<Vec<_>>()
        }),
        Value::ULInt(n) => json!({ "int": n }),
        other => json!({ "int": other.as_i128().unwrap() as i64 }),
    }
}

fn float_json(x: f64) -> Json {
    if x.is_finite() {
        json!({ "float": x })
    } else {
        let repr = if x.is_nan() {
            "nan"
        } else if x > 0.0 {
            "inf"
        } else {
            "-inf"
        };
        json!({ "float": repr })
    }
}

/// A write value of scenarios.json (plain JSON, `{"$bytes": hex}` for bytes).
fn write_value(json: &Json) -> Value {
    match json {
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => Value::LInt(i),
            (None, Some(u)) => Value::ULInt(u),
            _ => Value::LReal(n.as_f64().unwrap()),
        },
        Json::String(s) => Value::String(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(write_value).collect()),
        Json::Object(map) => match map.get("$bytes") {
            Some(Json::String(h)) if map.len() == 1 => Value::Bytes(from_hex(h)),
            _ => Value::Struct(
                map.iter()
                    .map(|(k, v)| (k.clone(), write_value(v)))
                    .collect::<IndexMap<_, _>>(),
            ),
        },
        Json::Null => panic!("no None write value in Rust"),
    }
}

fn tag_json(t: &TagResult) -> Json {
    let error = t.error.as_ref();
    json!({
        "tag": t.tag,
        "value": t.value.as_ref().map_or(Json::Null, value_json),
        "type": t.data_type,
        "error": error.map(|e| e.message.clone()),
        "kind": error.map(|e| e.kind.as_str()),
        "status": error.and_then(|e| e.status),
        "ext": error.and_then(|e| e.ext),
    })
}

fn tags_json(results: &[TagResult]) -> Json {
    Json::Array(results.iter().map(tag_json).collect())
}

fn error_class(e: &Error) -> &'static str {
    match e {
        Error::Comm(_) => "CommError",
        Error::Data(_) => "DataError",
        Error::BufferEmpty => "BufferEmptyError",
        Error::Response { .. } => "ResponseError",
        Error::Request { .. } => "RequestError",
    }
}

fn identity_json(id: &ModuleIdentity, keyswitch: Option<&str>) -> Json {
    let mut entries = vec![
        json!(["vendor", { "str": id.vendor }]),
        json!(["product_type", { "str": id.product_type }]),
        json!(["product_code", { "int": id.product_code }]),
        json!(["revision", { "dict": [
            ["major", { "int": id.revision.major }],
            ["minor", { "int": id.revision.minor }],
        ]}]),
        json!(["status", { "bytes": hex(&id.status) }]),
        json!(["serial", { "str": id.serial }]),
        json!(["product_name", { "str": id.product_name }]),
    ];
    if let Some(k) = keyswitch {
        entries.push(json!(["keyswitch", { "str": k }]));
    }
    json!({ "dict": entries })
}

// ------------------------------------------------------------------------------------------------ Rust side

#[allow(clippy::large_enum_variant)] // one per scenario, never moved around
enum Driver {
    Logix(LogixDriver),
    Slc(SlcDriver),
}

struct Rust {
    sim: Simulator,
    dir: PathBuf,
    driver: Option<Driver>,
}

impl Rust {
    fn logix(&self) -> &LogixDriver {
        match &self.driver {
            Some(Driver::Logix(d)) => d,
            _ => panic!("no Logix driver"),
        }
    }

    fn slc(&self) -> &SlcDriver {
        match &self.driver {
            Some(Driver::Slc(d)) => d,
            _ => panic!("no SLC driver"),
        }
    }

    fn state(&self) -> Json {
        let d = self.logix();
        let version = d.tag_table_version().map_or(Json::Null, |v| {
            let items: Vec<Json> = [i32::from(v.0), v.1.into(), v.2, v.3, v.4]
                .iter()
                .map(|n| json!({ "int": n }))
                .collect();
            json!({ "list": items })
        });
        json!({
            "connected": d.connected(),
            "tags": tagged(&d.tags_py()),
            "data_types": tagged(&d.data_types_py()),
            "info": info_json(&d.info_py()),
            "version": version,
            "use_ids": d.use_instance_ids(),
            "micro800": d.micro800(),
            "name": d.name(),
            "revision_major": d.revision_major(),
            "str": d.to_string(),
        })
    }

    fn new_driver(&mut self, step: &Json) {
        if let Some(d) = self.driver.take() {
            let _ = match d {
                Driver::Logix(d) => d.close(),
                Driver::Slc(d) => d.close(),
            };
        }
        let mut cip = if step["driver"] == "slc" {
            SlcDriver::default_options()
        } else {
            CipOptions::default()
        };
        if let Some(size) = step.get("connection_size").and_then(Json::as_u64) {
            cip.connection_size = size as u16;
        }
        if let Some(t) = step.get("socket_timeout").and_then(Json::as_f64) {
            cip.socket_timeout = Some(Duration::from_secs_f64(t));
        }
        let path = "127.0.0.1";
        let connector = self.sim.connector();
        if step["driver"] == "slc" {
            self.driver = Some(Driver::Slc(
                SlcDriver::with_connector(path, cip, connector).unwrap(),
            ));
            return;
        }
        let flag =
            |name: &str, default: bool| step.get(name).and_then(Json::as_bool).unwrap_or(default);
        let options = LogixOptions {
            init_tags: flag("init_tags", true),
            init_program_tags: flag("init_program_tags", true),
            tag_namespace_filter: step
                .get("tag_namespace_filter")
                .and_then(Json::as_str)
                .unwrap_or("")
                .into(),
            lazy_tags: flag("lazy_tags", false),
            tag_cache_file: flag("tag_cache_file", false).then(|| self.dir.join("tag_cache")),
            cip,
        };
        self.driver = Some(Driver::Logix(
            LogixDriver::with_connector(path, options, connector).unwrap(),
        ));
    }

    fn run(&mut self, step: &Json) -> Json {
        match self.call(step) {
            Ok(result) => json!({ "ok": result }),
            Err(e) => json!({ "err": error_class(&e), "msg": e.to_string() }),
        }
    }

    fn call(&mut self, step: &Json) -> ciplink::Result<Json> {
        let op = step["op"].as_str().unwrap();
        let strs = |key: &str| -> Vec<String> {
            step[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap().to_owned())
                .collect()
        };
        Ok(match op {
            "open" => {
                if step.get("new").and_then(Json::as_bool).unwrap_or(true) {
                    self.new_driver(step);
                }
                match self.driver.as_ref().unwrap() {
                    Driver::Slc(d) => {
                        let opened = d.open()?;
                        json!({ "opened": opened, "connected": d.connected() })
                    }
                    Driver::Logix(d) => {
                        let opened = d.open()?;
                        json!({ "opened": opened, "state": self.state() })
                    }
                }
            }
            "close" => {
                match &self.driver {
                    Some(Driver::Logix(d)) => d.close()?,
                    Some(Driver::Slc(d)) => d.close()?,
                    None => {}
                }
                Json::Null
            }
            "state" => self.state(),
            // the formats differ (Python writes JSON): whether there is one, and Rust's must decode
            "cache_file" => match std::fs::read(self.dir.join("tag_cache")) {
                Err(_) => Json::Null,
                Ok(bytes) => match TagCacheFile::decode(&bytes) {
                    Ok(_) => json!({ "exists": true }),
                    Err(err) => json!({ "unreadable": err.to_string() }),
                },
            },
            "read" => {
                let tags = strs("tags");
                let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
                match &self.driver {
                    Some(Driver::Slc(d)) => tags_json(&d.read(&tags)?),
                    _ => tags_json(&self.logix().read(&tags)?),
                }
            }
            "write" => {
                let items: Vec<(String, Value)> = step["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| (i[0].as_str().unwrap().to_owned(), write_value(&i[1])))
                    .collect();
                let items: Vec<(&str, Value)> =
                    items.iter().map(|(t, v)| (t.as_str(), v.clone())).collect();
                match &self.driver {
                    Some(Driver::Slc(d)) => tags_json(&d.write(&items)?),
                    _ => tags_json(&self.logix().write(&items)?),
                }
            }
            "check" => json!(self.logix().check_tag_table()?),
            "tag_info" => tagged(
                &self
                    .logix()
                    .get_tag_info_py(step["name"].as_str().unwrap())?,
            ),
            "tag_list" => {
                let d = self.logix();
                let tags = d.get_tag_list(
                    step.get("program").and_then(Json::as_str),
                    step.get("cache").and_then(Json::as_bool).unwrap_or(true),
                    step.get("filter").and_then(Json::as_str).unwrap_or(""),
                )?;
                tagged(&d.tag_list_py(&tags))
            }
            "plc_info" => {
                let info = self.logix().get_plc_info()?;
                identity_json(&info.identity, Some(&info.keyswitch))
            }
            "plc_name" => json!(self.logix().get_plc_name()?),
            "module_info" => identity_json(
                &self
                    .logix()
                    .get_module_info(step["slot"].as_i64().unwrap())?,
                None,
            ),
            "set_plc_time" => tag_json(&self.logix().set_plc_time(step["us"].as_u64())?),
            "get_plc_time" => {
                let t = self.logix().get_plc_time()?;
                let mut result = tag_json(&t);
                if let Some(Value::Struct(map)) = &t.value {
                    let us = map["microseconds"].as_i128().unwrap();
                    let near =
                        (us - i128::from(step["near_us"].as_u64().unwrap())).abs() < 120_000_000;
                    result["value"] = json!({ "near": near });
                }
                result
            }
            "generic" => tag_json(&self.logix().generic_message(&generic(step))?.tag),
            "descriptions" => {
                let tags = strs("tags");
                let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
                tags_json(
                    &self
                        .logix()
                        .get_tag_descriptions(&tags, 0x007F, TextEncoding::Utf8)?,
                )
            }
            "description" => {
                let language = step.get("language").and_then(Json::as_u64).unwrap_or(0x7F) as u16;
                tag_json(&self.logix().get_tag_description(
                    step["tag"].as_str().unwrap(),
                    language,
                    TextEncoding::Utf8,
                )?)
            }
            "authenticate" => tag_json(&self.logix().authenticate_metadata(None)),
            "sleep" => {
                if let Some(Driver::Logix(d)) = &self.driver {
                    d.advance_clock(Duration::from_secs_f64(step["seconds"].as_f64().unwrap()));
                }
                Json::Null
            }
            "set_connection_size" => {
                let d = self.logix();
                d.set_connection_size(step["value"].as_u64().unwrap() as u16)?;
                json!(d.connection_size())
            }
            "processor_type" => json!(self.slc().get_processor_type()?),
            "file_directory" => {
                let files = self.slc().get_file_directory()?;
                json!({ "dict": files.iter().map(|(name, f)| json!([name, { "dict": [
                    ["elements", { "int": f.elements }],
                    ["length", { "int": f.length }],
                ]}])).collect::<Vec<_>>() })
            }
            "datalog" => {
                let entries = self.slc().get_datalog_queue(
                    step["count"].as_u64().unwrap() as usize,
                    step["queue"].as_u64().unwrap() as u8,
                )?;
                json!({ "list": entries.iter().map(|e| e.as_ref().map_or(Json::Null, value_json)).collect::<Vec<_>>() })
            }
            other => panic!("unknown op {other}"),
        })
    }
}

fn logical(v: &Json) -> LogicalValue {
    match v {
        Json::String(h) => LogicalValue::Raw(from_hex(h)),
        n => LogicalValue::Int(n.as_i64().unwrap()),
    }
}

fn generic(step: &Json) -> GenericMessage {
    GenericMessage {
        service: step["service"].as_u64().unwrap() as u8,
        class_code: logical(&step["class_code"]),
        instance: logical(&step["instance"]),
        attribute: step.get("attribute").map(logical),
        request_data: step
            .get("request_data")
            .and_then(Json::as_str)
            .map(from_hex)
            .unwrap_or_default(),
        name: step
            .get("name")
            .and_then(Json::as_str)
            .unwrap_or("generic")
            .into(),
        connected: step
            .get("connected")
            .and_then(Json::as_bool)
            .unwrap_or(true),
        unconnected_send: step
            .get("unconnected_send")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        route_path: match step.get("route_path") {
            None | Some(Json::Bool(true)) => RoutePath::Current,
            Some(Json::Bool(false)) | Some(Json::Null) => RoutePath::None,
            Some(Json::String(s)) => RoutePath::Text(s.clone()),
            Some(other) => panic!("route_path {other}"),
        },
    }
}

// ------------------------------------------------------------------------------------------------ comparison

/// One side's run of a scenario: the frames sent (with the step that sent each) and the step results.
#[derive(Default)]
struct Run {
    frames: Vec<(usize, Vec<u8>)>,
    results: Vec<Json>,
}

impl Run {
    fn collect(&mut self, sim: &Simulator, step: usize) {
        // The simulator logs every connection's frames in one list. UnRegisterSession is the only request without
        // a reply, so a driver replaced in a step can send it on its old connection while the new driver's
        // RegisterSession is already arriving on another: the two can be logged in either order. Nothing follows
        // an UnRegisterSession on its connection, so its logical place is before the step's other frames
        // (sort_by_key is stable).
        let mut frames = sim.take_received();
        frames.sort_by_key(|f| f.get(..2) != Some(&[0x66, 0x00][..]));
        self.frames.extend(frames.into_iter().map(|f| (step, f)));
    }
}

fn u16_at(f: &[u8], at: usize) -> Option<usize> {
    f.get(at..at + 2)
        .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
}

fn zero(f: &mut [u8], range: std::ops::Range<usize>) {
    if let Some(bytes) = f.get_mut(range) {
        bytes.fill(0);
    }
}

/// A frame with what is random or session specific zeroed: the sender context, the Forward Open / Forward
/// Close connection triad (connection ID, serial, originator serial) and the PCCC requestor serial.
fn mask(frame: &[u8]) -> Vec<u8> {
    let mut f = frame.to_vec();
    zero(&mut f, 12..20);
    // SendRRData: interface 4, timeout 2, count 2, null item 4, data item 4: the message is at 40
    if u16_at(&f, 0) == Some(0x6F) && f.len() > 42 {
        let service = f[40];
        let data = 42 + 2 * usize::from(f[41]);
        let class6 = f.get(42..44) == Some(&[0x20, 0x06]);
        if class6 && (service == 0x54 || service == 0x5B) {
            zero(&mut f, data + 2..data + 12); // O->T and T->O IDs, connection serial
            zero(&mut f, data + 14..data + 18); // originator serial
        } else if class6 && service == 0x4E {
            zero(&mut f, data + 2..data + 4);
            zero(&mut f, data + 6..data + 10);
        }
    }
    // PCCC Execute: 4B 02 20 67 24 01, requestor ID length 7, vendor 2, serial 4
    let pattern = [0x4B, 0x02, 0x20, 0x67, 0x24, 0x01, 0x07];
    if let Some(at) = f.windows(pattern.len()).position(|w| w == pattern) {
        zero(&mut f, at + 9..at + 13);
    }
    f
}

fn hex_dump(bytes: &[u8], mark: usize) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(out, "    {:04x}:", row * 16);
        for (i, b) in chunk.iter().enumerate() {
            let at = row * 16 + i;
            let sep = if at == mark { '>' } else { ' ' };
            let _ = write!(out, "{sep}{b:02x}");
        }
        out.push('\n');
    }
    out
}

/// A dump of at most ~40 rows around `mark`.
fn dump_around(bytes: &[u8], mark: usize) -> String {
    let full = hex_dump(bytes, mark);
    let lines: Vec<&str> = full.lines().collect();
    if lines.len() <= 40 {
        return full;
    }
    let row = (mark / 16).min(lines.len() - 1);
    let from = row.saturating_sub(8);
    let to = (row + 8).min(lines.len());
    format!(
        "    ... ({} rows)\n{}\n    ...\n",
        lines.len(),
        lines[from..to].join("\n")
    )
}

fn step_name(steps: &[Json], i: usize) -> String {
    let text = steps.get(i).map_or("?".into(), Json::to_string);
    let short: String = text.chars().take(160).collect();
    format!("step {i} {short}")
}

fn compare_frames(name: &str, steps: &[Json], py: &Run, rs: &Run) -> Option<String> {
    for (i, ((ps, pf), (_, rf))) in py.frames.iter().zip(&rs.frames).enumerate() {
        let (pm, rm) = (mask(pf), mask(rf));
        if pm != rm {
            let at = pm
                .iter()
                .zip(&rm)
                .position(|(a, b)| a != b)
                .unwrap_or(pm.len().min(rm.len()));
            return Some(format!(
                "{name}: frame {i} ({}) differs at byte {at} (0x{at:x}); lengths python {} rust {}\n  python:\n{}  rust:\n{}",
                step_name(steps, *ps),
                pm.len(),
                rm.len(),
                dump_around(&pm, at),
                dump_around(&rm, at)
            ));
        }
    }
    if py.frames.len() != rs.frames.len() {
        let n = py.frames.len().min(rs.frames.len());
        let (side, extra) = if py.frames.len() > n {
            ("python", &py.frames[n])
        } else {
            ("rust", &rs.frames[n])
        };
        return Some(format!(
            "{name}: python sent {} frames, rust {}; the first extra one ({side}, {}):\n{}",
            py.frames.len(),
            rs.frames.len(),
            step_name(steps, extra.0),
            dump_around(&mask(&extra.1), 0)
        ));
    }
    None
}

/// The JSON path of the first difference.
fn first_difference(a: &Json, b: &Json, path: &str) -> Option<(String, Json, Json)> {
    match (a, b) {
        (Json::Object(x), Json::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.dedup();
            for k in keys {
                let (va, vb) = (
                    x.get(k).unwrap_or(&Json::Null),
                    y.get(k).unwrap_or(&Json::Null),
                );
                if let Some(d) = first_difference(va, vb, &format!("{path}.{k}")) {
                    return Some(d);
                }
            }
            None
        }
        (Json::Array(x), Json::Array(y)) => {
            for (i, (va, vb)) in x.iter().zip(y).enumerate() {
                if let Some(d) = first_difference(va, vb, &format!("{path}[{i}]")) {
                    return Some(d);
                }
            }
            (x.len() != y.len()).then(|| {
                (
                    format!("{path} (lengths {} and {})", x.len(), y.len()),
                    a.clone(),
                    b.clone(),
                )
            })
        }
        _ => (a != b).then(|| (path.to_owned(), a.clone(), b.clone())),
    }
}

fn clip(json: &Json) -> String {
    let text = json.to_string();
    if text.len() > 600 {
        format!(
            "{}... ({} bytes)",
            text.chars().take(600).collect::<String>(),
            text.len()
        )
    } else {
        text
    }
}

fn compare_results(name: &str, steps: &[Json], py: &Run, rs: &Run) -> Vec<String> {
    let mut out = Vec::new();
    for (i, (p, r)) in py.results.iter().zip(&rs.results).enumerate() {
        if let Some((path, a, b)) = first_difference(p, r, "$") {
            out.push(format!(
                "{name}: {} result differs at {path}\n  python: {}\n  rust:   {}",
                step_name(steps, i),
                clip(&a),
                clip(&b)
            ));
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ the test

#[test]
fn python_and_rust_send_the_same_frames_and_return_the_same_results() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("differential");
    std::fs::create_dir_all(&out).unwrap();
    let Some(mut python) = Python::start(&out) else {
        return;
    };
    let text = std::fs::read_to_string(repo().join("tools/diff/scenarios.json")).unwrap();
    let scenarios: Json = serde_json::from_str(&text).unwrap();
    let only = std::env::var("CIPLINK_DIFF_ONLY").unwrap_or_default();
    let mut failures = Vec::new();
    let mut ran = 0;
    for scenario in scenarios["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        if !name.contains(only.as_str()) {
            continue;
        }
        ran += 1;
        let steps = scenario["steps"].as_array().unwrap();
        let config = config(&scenario["config"]);
        let dir = out.join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("python")).unwrap();
        std::fs::create_dir_all(dir.join("rust")).unwrap();

        // Python, over TCP
        let sim = Simulator::from_json(&config).unwrap();
        let server = sim.serve("127.0.0.1:0").unwrap();
        sim.record(true);
        let mut py = Run::default();
        python.call(&json!({
            "cmd": "begin",
            "path": server.addr().to_string(),
            "dir": dir.join("python"),
        }));
        for (i, step) in steps.iter().enumerate() {
            if step["op"] == "sim" {
                sim_step(&sim, step);
                py.results.push(Json::Null);
            } else {
                py.results
                    .push(python.call(&json!({ "cmd": "step", "step": step })));
            }
            if step["op"] == "close" {
                settle(&sim);
            }
            py.collect(&sim, i);
        }
        python.call(&json!({ "cmd": "end" }));
        settle(&sim);
        py.collect(&sim, steps.len());
        drop(server);

        // Rust, in memory
        let sim = Simulator::from_json(&config).unwrap();
        sim.record(true);
        let mut rust = Rust {
            sim: sim.clone(),
            dir: dir.join("rust"),
            driver: None,
        };
        let mut rs = Run::default();
        for (i, step) in steps.iter().enumerate() {
            if step["op"] == "sim" {
                sim_step(&sim, step);
                rs.results.push(Json::Null);
            } else {
                rs.results.push(rust.run(step));
            }
            rs.collect(&sim, i);
        }
        drop(rust);
        rs.collect(&sim, steps.len());

        let record = |run: &Run| {
            json!({
                "frames": run.frames.iter().map(|(s, f)| json!([s, hex(f)])).collect::<Vec<_>>(),
                "results": run.results,
            })
        };
        std::fs::write(
            dir.join("runs.json"),
            serde_json::to_string_pretty(&json!({ "python": record(&py), "rust": record(&rs) }))
                .unwrap(),
        )
        .unwrap();

        let mut found: Vec<String> = compare_frames(name, steps, &py, &rs).into_iter().collect();
        found.extend(compare_results(name, steps, &py, &rs));
        eprintln!(
            "{name}: {} frames, {}",
            py.frames.len(),
            if found.is_empty() {
                "same".to_owned()
            } else {
                format!("{} differences", found.len())
            }
        );
        failures.extend(found);
    }
    assert!(ran > 0, "no scenario matches CIPLINK_DIFF_ONLY={only:?}");
    assert!(
        failures.is_empty(),
        "{} differences between Python and Rust (runs in {}):\n\n{}",
        failures.len(),
        out.display(),
        failures.join("\n\n")
    );
}

// ------------------------------------------------------------------------------------------------ the harness

/// A SendRRData frame carrying a Large Forward Open with this connection triad and sender context.
fn forward_open_frame(context: u8, cid: [u8; 4], csn: [u8; 2], vsn: [u8; 4]) -> Vec<u8> {
    let mut data = vec![0x0A, 0x04, 0, 0, 0, 0];
    data.extend(cid);
    data.extend(csn);
    data.extend([0x09, 0x10]);
    data.extend(vsn);
    let mut message = vec![0x5B, 0x02, 0x20, 0x06, 0x24, 0x01];
    message.extend(data);
    let mut cpf = vec![0, 0, 0, 0, 0x0A, 0, 2, 0, 0, 0, 0, 0, 0xB2, 0];
    cpf.extend((message.len() as u16).to_le_bytes());
    cpf.extend(message);
    let mut frame = vec![0x6F, 0];
    frame.extend((cpf.len() as u16).to_le_bytes());
    frame.extend([1, 0, 1, 0, 0, 0, 0, 0]);
    frame.extend([context; 8]);
    frame.extend([0; 4]);
    frame.extend(cpf);
    frame
}

#[test]
fn mask_hides_the_forward_open_triad_and_sender_context_only() {
    let a = forward_open_frame(1, [1, 2, 3, 4], [5, 6], [7, 8, 9, 10]);
    let b = forward_open_frame(2, [9, 9, 9, 9], [9, 9], [9, 9, 9, 9]);
    assert_ne!(a, b);
    assert_eq!(mask(&a), mask(&b));
    let mut vendor = b.clone();
    let at = vendor.len() - 6; // the vendor ID is not masked
    vendor[at] ^= 1;
    assert_ne!(mask(&a), mask(&vendor));
}

#[test]
fn frame_difference_names_the_step_frame_and_first_byte() {
    let steps = vec![json!({"op": "open"}), json!({"op": "read", "tags": ["x"]})];
    let frame = forward_open_frame(0, [0; 4], [0; 2], [0; 4]);
    let mut other = frame.clone();
    other[58] = 0xEE; // the vendor ID, not masked
    let py = Run {
        frames: vec![(0, frame.clone()), (1, frame.clone())],
        results: vec![],
    };
    let rs = Run {
        frames: vec![(0, frame.clone()), (1, other)],
        results: vec![],
    };
    let report = compare_frames("demo", &steps, &py, &rs).unwrap();
    assert!(report.contains("demo: frame 1 (step 1"), "{report}");
    assert!(report.contains("differs at byte 58"), "{report}");
    assert!(report.contains(">ee"), "{report}");
    let short = Run {
        frames: vec![(0, frame)],
        results: vec![],
    };
    let report = compare_frames("demo", &steps, &py, &short).unwrap();
    assert!(report.contains("python sent 2 frames, rust 1"), "{report}");
}

#[test]
fn result_difference_names_the_json_path() {
    let steps = vec![json!({"op": "read"})];
    let py = Run {
        frames: vec![],
        results: vec![json!({"ok": [{"value": {"int": 1}}]})],
    };
    let rs = Run {
        frames: vec![],
        results: vec![json!({"ok": [{"value": {"float": 1.0}}]})],
    };
    let report = compare_results("demo", &steps, &py, &rs);
    assert_eq!(report.len(), 1);
    assert!(report[0].contains("at $.ok[0].value.int"), "{}", report[0]);
}
