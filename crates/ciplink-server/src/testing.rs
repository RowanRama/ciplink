//! Test support, ported from ciplink-tagserver's tests/conftest.py: a fake driver injected through the factory (so
//! no test opens a socket), the controller structure it serves, and a server with WebSocket and HTTP clients.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ciplink::cip::TagResult;
use ciplink::{ErrorKind, TagError, Value};
use futures_util::{SinkExt, StreamExt};
use indexmap::IndexMap;
use serde_json::{Value as Json, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Config, PlcConfig, load_config};
use crate::planner::{Key, dig};
use crate::plc::{Aoi, Catalog, Factory, Kind, Node, Plc, TypeDef};
use crate::server::ServerHandle;

// ------------------------------------------------------------------------------------------------ structure

/// A tag or member of an atomic type; `dims` as ciplink reports them (a BOOL array tag counts BOOLs, a BOOL array
/// member 32-bit words).
pub fn atomic(type_name: &str, dims: &[u64]) -> Node {
    Node {
        type_name: type_name.into(),
        kind: Kind::Atomic,
        dims: dims.to_vec(),
        member: false,
        instance_id: None,
        structure_size: None,
    }
}

/// A tag or member of a structure type.
pub fn strct(type_name: &str, size: u64, dims: &[u64]) -> Node {
    Node {
        kind: Kind::Struct,
        structure_size: Some(size),
        ..atomic(type_name, dims)
    }
}

/// A STRING tag or member.
pub fn string() -> Node {
    Node {
        kind: Kind::String,
        ..strct("STRING", 88, &[])
    }
}

/// A structure type of these members (all public); `aoi`: (whole_read, readable members).
pub fn udt(size: u64, members: Vec<(&str, Node)>, aoi: Option<(bool, &[&str])>) -> TypeDef {
    TypeDef {
        public: members.iter().map(|(m, _)| (*m).to_owned()).collect(),
        members: members
            .into_iter()
            .map(|(m, n)| (m.to_owned(), Node { member: true, ..n }))
            .collect(),
        structure_size: size,
        aoi: aoi.map(|(whole_read, readable)| Aoi {
            whole_read,
            readable: readable.iter().map(|r| (*r).to_owned()).collect(),
        }),
        whole_readable: true,
    }
}

/// A struct value.
pub fn st(members: Vec<(&str, Value)>) -> Value {
    Value::Struct(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

/// conftest.py's `motor(speed)`.
pub fn motor(speed: f64) -> Value {
    st(vec![
        ("Speed", Value::LReal(speed)),
        ("Current", Value::LReal(speed / 10.0)),
        ("Running", Value::Bool(true)),
        ("Count", Value::DInt(0b101101)),
    ])
}

/// conftest.py's `station(n)`.
pub fn station(n: i32) -> Value {
    st(vec![
        ("Motor", motor(f64::from(n) * 1.5)),
        ("Ready", Value::Bool(n % 2 == 0)),
        ("Data", Value::Array((n..n + 4).map(Value::DInt).collect())),
        ("Bits", Value::Array(vec![Value::Bool(true); 32])),
    ])
}

/// conftest.py's MOTOR, STATION, BIG, VALVE, PUMP and CELL types.
pub fn plant_types() -> Vec<(&'static str, TypeDef)> {
    let b = || atomic("BOOL", &[]);
    let real = || atomic("REAL", &[]);
    let dint = || atomic("DINT", &[]);
    let motor = vec![
        ("Speed", real()),
        ("Current", real()),
        ("Running", b()),
        ("Count", dint()),
    ];
    let station = vec![
        ("Motor", strct("Motor", 40, &[])),
        ("Ready", b()),
        ("Data", atomic("DINT", &[4])),
        ("Bits", atomic("DWORD", &[1])),
    ];
    let valve = vec![
        ("EnableIn", b()),
        ("EnableOut", b()),
        ("Open", b()),
        ("Cmd", b()),
    ];
    let pump = vec![
        ("EnableIn", b()),
        ("EnableOut", b()),
        ("Run", b()),
        ("Speed", real()),
    ];
    let cell = vec![
        ("Valve", strct("Valve_AOI", 60, &[])),
        ("Mode", dint()),
        ("Step", dint()),
    ];
    vec![
        ("Motor", udt(40, motor, None)),
        ("Station", udt(200, station, None)),
        ("Big", udt(4000, vec![("A", dint()), ("B", dint())], None)),
        (
            "Valve_AOI",
            udt(60, valve, Some((false, &["EnableIn", "EnableOut", "Open"]))),
        ),
        (
            "Pump_AOI",
            udt(
                40,
                pump,
                Some((true, &["EnableIn", "EnableOut", "Run", "Speed"])),
            ),
        ),
        ("Cell", udt(300, cell, None)),
    ]
}

/// Generic structs, AOIs and atomics, as conftest.py's `plant(fake)`.
pub fn plant(fake: &mut FakeState) {
    let tags = vec![
        ("Line1", strct("Station", 200, &[])),
        ("Line2", strct("Station", 200, &[])),
        ("Arr", strct("Station", 200, &[5])),
        ("Program:Station1.Motor", strct("Motor", 40, &[])),
        ("Big1", strct("Big", 4000, &[])),
        ("Valve1", strct("Valve_AOI", 60, &[])),
        ("Pump1", strct("Pump_AOI", 40, &[])),
        ("Cell1", strct("Cell", 300, &[])),
        ("Name1", string()),
        ("Speed", atomic("REAL", &[])),
        ("Count", atomic("DINT", &[])),
        ("Flags", atomic("DINT", &[])),
    ];
    fake.tags = tags.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    fake.types = plant_types()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    let b = Value::Bool;
    let values = vec![
        ("Line1", station(1)),
        ("Line2", station(2)),
        ("Arr", Value::Array((0..5).map(station).collect())),
        ("Program:Station1.Motor", motor(7.5)),
        (
            "Big1",
            st(vec![("A", Value::DInt(1)), ("B", Value::DInt(2))]),
        ),
        // Cmd is local: not readable
        (
            "Valve1",
            st(vec![
                ("EnableIn", b(true)),
                ("EnableOut", b(true)),
                ("Open", b(false)),
            ]),
        ),
        (
            "Pump1",
            st(vec![
                ("EnableIn", b(true)),
                ("EnableOut", b(true)),
                ("Run", b(true)),
                ("Speed", Value::LReal(12.5)),
            ]),
        ),
        (
            "Cell1",
            st(vec![
                (
                    "Valve",
                    st(vec![
                        ("EnableIn", b(true)),
                        ("EnableOut", b(false)),
                        ("Open", b(true)),
                    ]),
                ),
                ("Mode", Value::DInt(2)),
                ("Step", Value::DInt(30)),
            ]),
        ),
        ("Name1", Value::String("hello".into())),
        ("Speed", Value::LReal(3.5)),
        ("Count", Value::DInt(9)),
        ("Flags", Value::DInt(0b1010)),
    ];
    for (k, v) in values {
        fake.values.insert(k.to_owned(), v);
    }
}

// ------------------------------------------------------------------------------------------------ fake PLC

/// A TagError of kind `other`, as a plain error string is in the Python fake.
pub fn other(message: &str) -> TagError {
    TagError::new(message, ErrorKind::Other)
}

/// State shared by every driver a worker creates for one PLC (conftest.py's FakePLC).
pub struct FakeState {
    /// tag -> value; tags not here read as "Tag doesn't exist". Member paths, bits and ranges are read out of them.
    pub values: HashMap<String, Value>,
    /// tag -> error of its read.
    pub errors: HashMap<String, TagError>,
    /// open, read and write fail like a lost connection.
    pub fail: bool,
    /// The tag table version.
    pub version: u64,
    /// The tag names of each read call.
    pub reads: Vec<Vec<String>>,
    /// Writes that went through.
    pub writes: Vec<(String, Value)>,
    /// Every write call, failed ones included.
    pub attempts: Vec<(String, Value)>,
    /// The error of every write, if set.
    pub write_error: Option<TagError>,
    /// The controller's tags and types.
    pub tags: IndexMap<String, Node>,
    /// Structure types by name.
    pub types: IndexMap<String, TypeDef>,
    /// Calls of open.
    pub opens: usize,
    /// ("read", names) and ("write", [tag]) in order (tests add their own entries too).
    pub events: Vec<(String, Vec<String>)>,
    /// Runs once, at the next read, without the lock held.
    pub on_read: Option<Box<dyn FnOnce() + Send>>,
    /// Bytes per packet; 0 for the planner's default.
    pub connection_size: usize,
    /// The driver reads descriptions (test_worker.py's DescDriver); the plain fake driver doesn't.
    pub describes: bool,
    /// Controller descriptions by tag.
    pub descriptions: HashMap<String, String>,
    /// The names of each descriptions call.
    pub desc_calls: Vec<Vec<String>>,
    /// A descriptions call with this name fails like a lost reply.
    pub desc_fail: Option<String>,
}

impl Default for FakeState {
    fn default() -> Self {
        FakeState {
            values: HashMap::new(),
            errors: HashMap::new(),
            fail: false,
            version: 1,
            reads: Vec::new(),
            writes: Vec::new(),
            attempts: Vec::new(),
            write_error: None,
            tags: IndexMap::new(),
            types: IndexMap::new(),
            opens: 0,
            events: Vec::new(),
            on_read: None,
            connection_size: 0,
            describes: false,
            descriptions: HashMap::new(),
            desc_calls: Vec::new(),
            desc_fail: None,
        }
    }
}

impl FakeState {
    /// Sets a value.
    pub fn set(&mut self, tag: &str, value: Value) {
        self.values.insert(tag.to_owned(), value);
    }

    /// The written values as (tag, JSON value).
    pub fn written(&self) -> Vec<(String, Json)> {
        self.writes
            .iter()
            .map(|(t, v)| (t.clone(), crate::values::jsonable(v)))
            .collect()
    }

    /// Every write call as (tag, JSON value).
    pub fn tried(&self) -> Vec<(String, Json)> {
        self.attempts
            .iter()
            .map(|(t, v)| (t.clone(), crate::values::jsonable(v)))
            .collect()
    }

    fn value(&self, name: &str) -> Option<Value> {
        if let Some(v) = self.values.get(name) {
            return Some(v.clone());
        }
        let (prefix, rest) = if name.to_lowercase().starts_with("program:") {
            let (p, r) = name.split_once('.')?;
            (format!("{p}."), r)
        } else {
            (String::new(), name)
        };
        let parts = path_parts(rest);
        let base = format!("{prefix}{}", parts.first()?);
        let mut value = self
            .values
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&base))
            .map(|(_, v)| v.clone())?;
        for part in &parts[1..] {
            value = if let Some(i) = part.strip_prefix('[') {
                dig(&value, &[Key::Index(i.trim_end_matches(']').parse().ok()?)])?
            } else if part.bytes().all(|b| b.is_ascii_digit()) {
                let bit: u32 = part.parse().ok()?;
                Value::Bool(value.as_i128()? >> bit & 1 == 1)
            } else {
                dig(&value, &[Key::Member((*part).to_owned())])?
            };
        }
        Some(value)
    }

    fn result(&self, tag: &str) -> TagResult {
        let mut result = TagResult {
            tag: tag.to_owned(),
            value: None,
            data_type: None,
            error: None,
        };
        if let Some(e) = self.errors.get(tag) {
            result.error = Some(e.clone());
            return result;
        }
        let value = match range(tag) {
            Some((base, start, count)) => match self.value(base) {
                Some(Value::Array(items)) if items.len() >= start + count => {
                    Some(Value::Array(items[start..start + count].to_vec()))
                }
                _ => None,
            },
            None => self.value(tag),
        };
        match value {
            Some(v) => {
                result.value = Some(v);
                result.data_type = Some("DINT".into());
            }
            None => {
                let message = format!("Tag doesn't exist - {tag}");
                result.error = Some(TagError::new(message, ErrorKind::NotFound));
            }
        }
        result
    }

    fn catalog(&self) -> Catalog {
        Catalog::new(json!(self.version), self.tags.clone(), self.types.clone())
    }
}

/// `[^.\[\]]+|\[\d+\]` tokens of a path.
fn path_parts(rest: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let c = rest.as_bytes()[i];
        if c == b'[' {
            match rest[i..].find(']') {
                Some(close) => {
                    out.push(&rest[i..=i + close]);
                    i += close + 1;
                }
                None => i += 1,
            }
        } else if c == b'.' || c == b']' {
            i += 1;
        } else {
            let end = rest[i..]
                .find(['.', '[', ']'])
                .map_or(rest.len(), |e| i + e);
            out.push(&rest[i..end]);
            i = end;
        }
    }
    out
}

/// `X[start]{count}` or `X{count}` as (X, start, count).
fn range(tag: &str) -> Option<(&str, usize, usize)> {
    let body = tag.strip_suffix('}')?;
    let open = body.rfind('{')?;
    let count = body[open + 1..].parse().ok()?;
    let base = &body[..open];
    if let Some(inner) = base.strip_suffix(']') {
        if let Some(b) = inner.rfind('[') {
            if let Ok(start) = inner[b + 1..].parse() {
                return Some((&base[..b], start, count));
            }
        }
    }
    Some((base, 0, count))
}

/// A handle on the state of one fake PLC.
#[derive(Clone, Default)]
pub struct Fake(Arc<Mutex<FakeState>>);

impl Fake {
    /// The state.
    pub fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A driver on this state.
    pub fn plc(&self) -> FakePlc {
        FakePlc(self.clone())
    }

    /// A factory whose drivers use the fake of their PLC's name.
    pub fn factory(fakes: &HashMap<String, Fake>) -> Factory {
        let fakes = fakes.clone();
        Arc::new(move |cfg: &PlcConfig| {
            let fake = fakes.get(&cfg.name).cloned().unwrap_or_default();
            Ok(Box::new(fake.plc()) as Box<dyn Plc>)
        })
    }
}

/// conftest.py's FakeDriver.
pub struct FakePlc(Fake);

impl Plc for FakePlc {
    fn open(&mut self) -> Result<(), String> {
        let mut s = self.0.lock();
        s.opens += 1;
        if s.fail {
            return Err("fake: connection refused".into());
        }
        Ok(())
    }

    fn close(&mut self) {}

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String> {
        let names: Vec<String> = tags.iter().map(|t| (*t).to_owned()).collect();
        let on_read = {
            let mut s = self.0.lock();
            s.events.push(("read".into(), names.clone()));
            s.on_read.take()
        };
        if let Some(on_read) = on_read {
            on_read();
        }
        let mut s = self.0.lock();
        if s.fail {
            return Err("fake: connection lost".into());
        }
        s.reads.push(names);
        Ok(tags.iter().map(|tag| s.result(tag)).collect())
    }

    fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String> {
        let mut s = self.0.lock();
        s.events.push(("write".into(), vec![tag.to_owned()]));
        if s.fail {
            return Err("fake: connection lost".into());
        }
        s.attempts.push((tag.to_owned(), value.clone()));
        let mut result = TagResult {
            tag: tag.to_owned(),
            value: Some(value.clone()),
            data_type: None,
            error: None,
        };
        if let Some(error) = s.write_error.clone() {
            result.error = Some(error);
            return Ok(result);
        }
        s.writes.push((tag.to_owned(), value.clone()));
        s.values.insert(tag.to_owned(), value.clone());
        result.data_type = Some("DINT".into());
        Ok(result)
    }

    fn catalog(&mut self) -> Catalog {
        self.0.lock().catalog()
    }

    fn version(&mut self) -> Json {
        json!(self.0.lock().version)
    }

    fn connection_size(&self) -> usize {
        self.0.lock().connection_size
    }

    fn describes(&self) -> bool {
        self.0.lock().describes
    }

    fn descriptions(&mut self, tags: &[&str]) -> Result<Vec<Option<String>>, String> {
        let mut s = self.0.lock();
        s.desc_calls
            .push(tags.iter().map(|t| (*t).to_owned()).collect());
        if s.desc_fail.as_deref().is_some_and(|f| tags.contains(&f)) {
            return Err("no reply".into());
        }
        Ok(tags
            .iter()
            .map(|t| s.descriptions.get(*t).cloned())
            .collect())
    }
}

// ------------------------------------------------------------------------------------------------ files

/// A directory removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    /// A new empty directory under the system temp directory.
    pub fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ciplink-server-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Waits (blocking) until `cond` holds; panics after 5 s.
pub fn wait_for(mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "condition not met");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The JSON lines of an audit log once there are at least `n` (written by a background thread).
pub fn audit_lines(path: &Path, n: usize) -> Vec<Json> {
    let read = || -> Vec<Json> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    };
    wait_for(|| read().len() >= n);
    read()
}

// ------------------------------------------------------------------------------------------------ server

const CONFIG: &str = r#"
[server]
port = 0
cycle_ms = 20
audit_log = "audit.log"
{server}

{plcs}

[token.viewer]
secret = "view"

[token.hmi1]
secret = "s3cret"
write = ["{first}/Speed*", "{first}/Program:Main.Door*"]
"#;

/// conftest.py's `make` fixture options.
pub struct Make<'a> {
    /// The PLC names.
    pub names: &'a [&'a str],
    /// Mock drivers (from each PLC's mock_tags) instead of fakes.
    pub mock: bool,
    /// Lines after each `[plc.X]` path.
    pub extra: &'a str,
    /// Lines of `[server]`.
    pub server: &'a str,
}

impl Default for Make<'_> {
    fn default() -> Self {
        Make {
            names: &["PLC1"],
            mock: false,
            extra: "",
            server: "grace_s = 0",
        }
    }
}

/// A running server on fake (or mock) PLCs and its config.
pub struct TestServer {
    /// The server.
    pub handle: ServerHandle,
    /// The fake of each PLC.
    pub fakes: HashMap<String, Fake>,
    /// The config as loaded.
    pub config: Config,
    /// Where the config, audit log and pages file are.
    pub dir: Arc<TempDir>,
}

impl Make<'_> {
    /// Starts the server; `setup` runs on the fakes before the workers start.
    pub fn start(&self, setup: impl FnOnce(&HashMap<String, Fake>)) -> TestServer {
        self.start_in(Arc::new(TempDir::new()), setup)
    }

    /// Starts the server with its files in `dir` (a restart keeps what the last one learned).
    pub fn start_in(
        &self,
        dir: Arc<TempDir>,
        setup: impl FnOnce(&HashMap<String, Fake>),
    ) -> TestServer {
        let plcs: Vec<String> = self
            .names
            .iter()
            .enumerate()
            .map(|(i, n)| format!("[plc.{n}]\npath = \"192.0.2.{}\"\n{}", i + 1, self.extra))
            .collect();
        let text = CONFIG
            .replace("{server}", self.server)
            .replace("{plcs}", &plcs.join("\n"))
            .replace("{first}", self.names[0]);
        let path = dir.path().join("tagserver.toml");
        std::fs::write(&path, text).unwrap();
        let config = load_config(&path).unwrap();
        let fakes: HashMap<String, Fake> = self
            .names
            .iter()
            .map(|n| ((*n).to_owned(), Fake::default()))
            .collect();
        setup(&fakes);
        let factory = if self.mock {
            crate::mock::factory().0
        } else {
            Fake::factory(&fakes)
        };
        let handle = ServerHandle::start(config.clone(), factory).unwrap();
        TestServer {
            handle,
            fakes,
            config,
            dir,
        }
    }
}

impl TestServer {
    /// The fake of the first PLC.
    pub fn fake(&self) -> MutexGuard<'_, FakeState> {
        self.fakes["PLC1"].lock()
    }

    /// The worker of a PLC.
    pub fn worker(&self, plc: &str) -> Arc<crate::worker::PlcWorker> {
        Arc::clone(&self.handle.shared().workers[plc])
    }

    /// A connected WebSocket client.
    pub async fn ws(&self) -> Ws {
        Ws::connect(self.handle.addr()).await
    }

    /// `GET path` as JSON.
    pub async fn get(&self, path: &str) -> Json {
        http(self.handle.addr(), "GET", path, &[]).await.2
    }

    /// Waits until `cond(GET path)` holds.
    pub async fn wait_get(&self, path: &str, mut cond: impl FnMut(&Json) -> bool) -> Json {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let body = self.get(path).await;
            if cond(&body) {
                return body;
            }
            assert!(Instant::now() < end, "condition on {path} not met: {body}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until the PLC is connected.
    pub async fn connected(&self, plc: &str) {
        self.wait_get("/health", |h| h["plcs"][plc]["state"] == "connected")
            .await;
    }

    /// The audit log path.
    pub fn audit_log(&self) -> PathBuf {
        self.config.audit_log.clone().unwrap()
    }
}

/// (status, lowercase headers, JSON body or null) of an HTTP request.
pub async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, HashMap<String, String>, Json) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_owned()))
        .collect();
    (
        status,
        headers,
        serde_json::from_str(body).unwrap_or(Json::Null),
    )
}

type Stream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A WebSocket client (Starlette's test client as the Python tests use it).
pub struct Ws(Stream);

/// Why `recv` got no message.
#[derive(Debug, PartialEq)]
pub enum Closed {
    /// The server closed with this code.
    Code(u16),
    /// The stream ended.
    Ended,
}

impl Ws {
    /// Connects to `/ws`.
    pub async fn connect(addr: SocketAddr) -> Ws {
        let (stream, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .unwrap();
        Ws(stream)
    }

    /// Sends a JSON message.
    pub async fn send(&mut self, msg: Json) {
        self.send_text(&msg.to_string()).await;
    }

    /// Sends a text message.
    pub async fn send_text(&mut self, text: &str) {
        self.0
            .send(tokio_tungstenite::tungstenite::Message::text(text))
            .await
            .unwrap();
    }

    /// The next message; panics after 5 s.
    pub async fn recv(&mut self) -> Result<Json, Closed> {
        use tokio_tungstenite::tungstenite::Message;
        loop {
            let next = tokio::time::timeout(Duration::from_secs(5), self.0.next())
                .await
                .expect("no message in 5 s");
            match next {
                Some(Ok(Message::Text(text))) => return Ok(serde_json::from_str(&text).unwrap()),
                Some(Ok(Message::Close(frame))) => {
                    return Err(frame.map_or(Closed::Ended, |f| Closed::Code(u16::from(f.code))));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Err(Closed::Ended),
            }
        }
    }

    /// The next message for which `pred` holds.
    pub async fn until(&mut self, mut pred: impl FnMut(&Json) -> bool) -> Json {
        loop {
            let msg = self.recv().await.unwrap();
            if pred(&msg) {
                return msg;
            }
        }
    }

    /// The next message of this op.
    pub async fn until_op(&mut self, op: &str) -> Json {
        self.until(|m| m["op"] == op).await
    }

    /// Says hello with this token; returns the welcome.
    pub async fn hello(&mut self, token: &str) -> Json {
        self.send(json!({"op": "hello", "v": 1, "token": token}))
            .await;
        self.until_op("welcome").await
    }

    /// Sends a write and returns its ack.
    pub async fn write(&mut self, id: u64, tag: &str, value: Json) -> Json {
        self.send(json!({"op": "write", "id": id, "tag": tag, "value": value}))
            .await;
        self.until(|m| m["op"] == "ack" && m["id"] == id).await
    }

    /// Closes the connection.
    pub async fn close(mut self) {
        let _ = self.0.close(None).await;
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(1), self.0.next()).await {}
    }
}

/// `entry[..2]`: value and quality.
pub fn vq(entry: &Json) -> Json {
    json!([entry[0], entry[1]])
}
