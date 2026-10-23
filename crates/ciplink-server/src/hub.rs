//! The hub: subscriptions, fan-out, writes and momentary buttons. One task owns all of it and handles one message
//! at a time (client messages, worker events, timers), so nothing here needs a lock.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use indexmap::IndexMap;
use serde_json::{Map, Value as Json, json};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::config::{Config, TokenConfig, py_repr};
use crate::rules::{Rules, canonical, glob_match, split_bit, truthy};
use crate::values::from_json;
use crate::worker::{Event, PlcWorker, WriteResult};

/// The protocol version.
pub const PROTOCOL: u64 = 1;
/// What `welcome` says the server supports.
pub const FEATURES: [&str; 4] = ["info", "momentary", "readback", "errors"];
const RELEASES: [&str; 3] = ["release", "timeout", "disconnect"];
/// Kinds a retry never fixes; a release failing any other way (refused, comm, table_changed, ...) is owed.
const FINAL: [&str; 7] = [
    "bad_request",
    "not_allowed",
    "not_writable",
    "out_of_range",
    "not_found",
    "access",
    "bad_value",
];
/// Page learning is saved at most this often.
const SAVE_DELAY: Duration = Duration::from_secs(2);
/// Before a release refused while connected is written again.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// A session's id.
pub type SessionId = u64;

/// What the hub queues for one connection: control messages (ack, info, status, meta, error) sent in order, then
/// one values message with everything pending.
#[derive(Default)]
pub struct Outbox {
    queue: Mutex<(VecDeque<Json>, IndexMap<String, Json>)>,
    notify: Notify,
}

impl Outbox {
    /// Queues a control message.
    pub fn send(&self, message: Json) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .push_back(message);
        self.notify.notify_one();
    }

    /// Queues the latest entry of a name; one values message carries all of them.
    pub fn push(&self, name: &str, entry: Json) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .1
            .insert(name.to_owned(), entry);
        self.notify.notify_one();
    }

    /// Waits for messages, then takes them: the control messages, then a values message if any are pending.
    pub async fn next(&self) -> Vec<Json> {
        loop {
            {
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                let mut out: Vec<Json> = queue.0.drain(..).collect();
                if !queue.1.is_empty() {
                    let d: Map<String, Json> = std::mem::take(&mut queue.1).into_iter().collect();
                    out.push(json!({"op": "values", "d": d}));
                }
                if !out.is_empty() {
                    return out;
                }
            }
            self.notify.notified().await;
        }
    }
}

/// Messages to the hub task.
pub enum Msg {
    /// A client said hello with a valid token.
    Open(SessionId, TokenConfig, Arc<Outbox>),
    /// A text message from a client.
    Text(SessionId, String),
    /// A client went away.
    Close(SessionId),
    /// A worker's event.
    Worker(Event),
    /// A write finished.
    WriteDone(Box<WriteDone>),
    /// A pressed button's watchdog fired.
    Timeout(SessionId, String, u64),
    /// Write an owed release again.
    Resend(String),
    /// Save the learned pages.
    SavePages,
    /// Release everything, stop the workers, save, flush the audit log.
    Stop(oneshot::Sender<()>),
}

/// A finished write and where its ack goes.
pub struct WriteDone {
    session: SessionId,
    token: TokenConfig,
    id: Option<Json>,
    qname: String,
    name: Json,
    momentary: Option<&'static str>,
    result: WriteResult,
}

/// What HTTP handlers read without asking the hub task.
pub struct Shared {
    /// The config.
    pub config: Arc<Config>,
    /// The tag settings.
    pub rules: Arc<Rules>,
    /// The PLC workers in config order.
    pub workers: IndexMap<String, Arc<PlcWorker>>,
    /// Open sessions.
    pub sessions: AtomicUsize,
    /// Writes queued to a worker, momentary included.
    pub writes: AtomicU64,
    /// Writes rejected by the hub's checks.
    pub write_rejects: AtomicU64,
    /// Buttons released by their watchdog.
    pub momentary_timeouts: AtomicU64,
}

impl Shared {
    /// PLC name -> connection state.
    pub fn states(&self) -> Map<String, Json> {
        self.workers
            .iter()
            .map(|(name, w)| (name.clone(), json!(w.state())))
            .collect()
    }

    /// The token with this secret (compared in constant time).
    pub fn authenticate(&self, secret: Option<&Json>) -> Option<TokenConfig> {
        let secret = secret?.as_str()?;
        self.config
            .tokens
            .values()
            .find(|t| constant_time_eq(t.secret.as_bytes(), secret.as_bytes()))
            .cloned()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (i, x) in a.iter().enumerate() {
        diff |= usize::from(x ^ b.get(i).copied().unwrap_or(!x));
    }
    diff == 0
}

struct Sub {
    tier: u8,
    /// name as the client sent it -> qualified resolved name
    tags: IndexMap<String, String>,
    follow: Option<String>,
}

struct Session {
    token: TokenConfig,
    outbox: Arc<Outbox>,
    subs: IndexMap<String, Sub>,
    info_sent: HashSet<String>,
    /// qname -> (watchdog generation, name as sent)
    pressed: HashMap<String, (u64, Json)>,
}

/// Python's `str()` of a JSON value, for names that are not strings.
fn py_str(value: &Json) -> String {
    match value {
        Json::Null => "None".into(),
        Json::Bool(true) => "True".into(),
        Json::Bool(false) => "False".into(),
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// min/max check of a number, or of every number in a list or object; bools and non-numbers pass.
fn in_range(value: &Json, lo: Option<f64>, hi: Option<f64>) -> bool {
    match value {
        Json::Object(map) => map.values().all(|v| in_range(v, lo, hi)),
        Json::Array(items) => items.iter().all(|v| in_range(v, lo, hi)),
        Json::Number(n) => {
            let v = n.as_f64().unwrap_or(0.0);
            lo.is_none_or(|lo| v >= lo) && hi.is_none_or(|hi| v <= hi)
        }
        _ => true,
    }
}

/// `2026-10-23T14:17:33.768123+00:00`, Python's `datetime.now(timezone.utc).isoformat()`.
fn iso_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}+00:00",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        now.subsec_micros()
    )
}

/// page path -> qualified tag names, from the pages file; empty if there is none.
fn load_pages(path: Option<&Path>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(path) = path.filter(|p| p.exists()) else {
        return BTreeMap::new();
    };
    let parsed = std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|text| {
            serde_json::from_str::<BTreeMap<String, BTreeSet<String>>>(&text)
                .map_err(|e| e.to_string())
        });
    parsed.unwrap_or_else(|err| {
        log::warn!("cannot read {}: {err}", path.display());
        BTreeMap::new()
    })
}

/// Writes the pages file atomically: a temporary file, then a rename over the old one.
fn save_pages(path: &Path, pages: &BTreeMap<String, BTreeSet<String>>) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut text = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut ser = serde_json::Serializer::with_formatter(&mut text, formatter);
    serde::Serialize::serialize(pages, &mut ser).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// The hub task's state.
pub struct Hub {
    shared: Arc<Shared>,
    tx: mpsc::UnboundedSender<Msg>,
    sessions: HashMap<SessionId, Session>,
    /// qualified name -> tier -> subscriptions across sessions
    refs: HashMap<String, BTreeMap<u8, usize>>,
    /// qualified name -> session -> client names
    subscribers: HashMap<String, HashMap<SessionId, HashSet<String>>>,
    /// page path -> qualified names its tier-1 subs used
    pages: BTreeMap<String, BTreeSet<String>>,
    save_scheduled: bool,
    /// qname -> (token, session, name, momentary) of a release the PLC never got, sent on connect
    owed: HashMap<String, (TokenConfig, SessionId, Json, &'static str)>,
    /// plc -> its always tags, each holding one tier-1 reference
    always: HashMap<String, HashSet<String>>,
    audit: Option<std::sync::mpsc::Sender<String>>,
    audit_thread: Option<std::thread::JoinHandle<()>>,
    generation: u64,
}

impl Hub {
    /// The hub of these workers; `tx` sends to its own task (timers, write results).
    pub fn new(shared: Arc<Shared>, tx: mpsc::UnboundedSender<Msg>) -> Self {
        let config = Arc::clone(&shared.config);
        let pages = load_pages(config.pages_file.as_deref())
            .into_iter()
            .map(|(page, qnames)| {
                // names of a PLC no longer configured are dropped
                let kept = qnames
                    .into_iter()
                    .filter(|q| {
                        q.split_once('/')
                            .is_some_and(|(plc, _)| config.plcs.contains_key(plc))
                    })
                    .collect();
                (page, kept)
            })
            .collect();
        let (audit, audit_thread) = match config.audit_log.clone() {
            Some(path) => {
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                let thread = std::thread::Builder::new()
                    .name("audit".into())
                    .spawn(move || write_audit(&path, &rx))
                    .ok();
                (Some(tx), thread)
            }
            None => (None, None),
        };
        let mut hub = Hub {
            shared,
            tx,
            sessions: HashMap::new(),
            refs: HashMap::new(),
            subscribers: HashMap::new(),
            pages,
            save_scheduled: false,
            owed: HashMap::new(),
            always: HashMap::new(),
            audit,
            audit_thread,
            generation: 0,
        };
        let plcs: Vec<String> = hub.shared.workers.keys().cloned().collect();
        for plc in plcs {
            hub.update_always(&plc);
        }
        hub
    }

    /// Runs the hub until a Stop message; starts the workers first.
    pub async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Msg>) {
        for worker in self.shared.workers.values() {
            worker.start();
        }
        while let Some(msg) = rx.recv().await {
            match msg {
                Msg::Open(id, token, outbox) => {
                    self.sessions.insert(
                        id,
                        Session {
                            token,
                            outbox,
                            subs: IndexMap::new(),
                            info_sent: HashSet::new(),
                            pressed: HashMap::new(),
                        },
                    );
                    self.shared
                        .sessions
                        .store(self.sessions.len(), Ordering::Relaxed);
                }
                Msg::Text(id, text) => self.handle(id, &text),
                Msg::Close(id) => self.drop_session(id),
                Msg::Worker(event) => self.worker_event(event),
                Msg::WriteDone(done) => self.write_done(*done),
                Msg::Timeout(id, qname, generation) => self.timeout(id, &qname, generation),
                Msg::Resend(qname) => self.resend(&qname),
                Msg::SavePages => self.save_pages(),
                Msg::Stop(done) => {
                    self.stop();
                    let _ = done.send(());
                    return;
                }
            }
        }
        self.stop();
    }

    fn stop(&mut self) {
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for id in ids {
            self.drop_session(id); // queues the releases of pressed tags, which the workers still run
        }
        let workers: Vec<Arc<PlcWorker>> = self.shared.workers.values().cloned().collect();
        tokio::task::block_in_place(|| {
            for worker in &workers {
                worker.stop();
            }
        });
        if self.save_scheduled {
            self.save_pages();
        }
        self.audit = None; // the audit thread ends once it has written everything
        if let Some(thread) = self.audit_thread.take() {
            let _ = tokio::task::block_in_place(|| thread.join());
        }
    }

    fn worker(&self, plc: &str) -> Option<&Arc<PlcWorker>> {
        self.shared.workers.get(plc)
    }

    fn later(&self, delay: Duration, msg: Msg) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = tx.send(msg);
        });
    }

    // ------------------------------------------------------------------------------------------ worker events

    fn worker_event(&mut self, event: Event) {
        match event {
            Event::Values(plc, changes) => {
                for (tag, entry) in changes {
                    let Some(subs) = self.subscribers.get(&format!("{plc}/{tag}")) else {
                        continue;
                    };
                    let value = entry.to_json();
                    for (id, names) in subs {
                        if let Some(session) = self.sessions.get(id) {
                            for name in names {
                                session.outbox.push(name, value.clone());
                            }
                        }
                    }
                }
            }
            Event::Status(plc, state) => {
                self.broadcast(&json!({"op": "status", "plcs": self.shared.states()}));
                if state == "connected" {
                    // types are known now
                    self.update_always(&plc);
                    self.requalify(&plc);
                    self.send_info(&plc, None);
                    let owed: Vec<String> = self
                        .owed
                        .keys()
                        .filter(|q| q.split_once('/').is_some_and(|(p, _)| p == plc))
                        .cloned()
                        .collect();
                    for qname in owed {
                        self.resend(&qname);
                    }
                }
            }
            Event::Meta(plc) => {
                self.broadcast(&json!({"op": "meta", "plc": plc}));
                self.update_always(&plc);
                self.requalify(&plc);
                self.send_info(&plc, None);
            }
            Event::Info(plc, tags) => {
                let tags: HashSet<String> = tags.into_iter().collect();
                self.send_info(&plc, Some(&tags));
            }
        }
    }

    fn broadcast(&self, message: &Json) {
        for session in self.sessions.values() {
            session.outbox.send(message.clone());
        }
    }

    /// Holds a tier-1 reference on each always tag; called again once the types are known or reloaded.
    fn update_always(&mut self, plc: &str) {
        let new: HashSet<String> = self.shared.rules.always(plc).into_iter().collect();
        let old = self.always.remove(plc).unwrap_or_default();
        let mut added: Vec<&String> = new.difference(&old).collect();
        added.sort();
        for tag in added {
            self.hold(&format!("{plc}/{tag}"), 1);
        }
        let gone: Vec<String> = old.difference(&new).map(|t| format!("{plc}/{t}")).collect();
        if !gone.is_empty() {
            self.release(1, &gone);
        }
        self.always.insert(plc.to_owned(), new);
    }

    /// Resolves the subscribed names of the PLC again once its types are known or reloaded: a bit alias from a
    /// `[udt]` entry only resolves then. A sub whose names now resolve elsewhere moves its references.
    fn requalify(&mut self, plc: &str) {
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for id in ids {
            let sub_ids: Vec<String> = self.sessions[&id].subs.keys().cloned().collect();
            for sub_id in sub_ids {
                let (tier, old_tags) = {
                    let sub = &self.sessions[&id].subs[&sub_id];
                    (sub.tier, sub.tags.clone())
                };
                let mut tags = old_tags.clone();
                for (name, qname) in &old_tags {
                    if qname.split_once('/').is_some_and(|(p, _)| p == plc) {
                        if let Ok((p, _, tag)) = self.qualify_str(name) {
                            tags.insert(name.clone(), format!("{p}/{tag}"));
                        }
                    }
                }
                if tags == old_tags {
                    continue;
                }
                let old: HashSet<String> = old_tags.values().cloned().collect();
                let new: HashSet<String> = tags.values().cloned().collect();
                for qname in new.difference(&old) {
                    self.hold(qname, tier);
                }
                let gone: Vec<String> = old.difference(&new).cloned().collect();
                self.release(tier, &gone);
                if let Some(sub) = self
                    .sessions
                    .get_mut(&id)
                    .and_then(|s| s.subs.get_mut(&sub_id))
                {
                    sub.tags = tags;
                }
                let all: HashSet<String> = old.union(&new).cloned().collect();
                self.reindex(id, &all);
            }
        }
    }

    /// Sends the info of the PLC's subscribed names again (only of `tags` if given).
    fn send_info(&self, plc: &str, tags: Option<&HashSet<String>>) {
        let mut per_session: HashMap<SessionId, Map<String, Json>> = HashMap::new();
        for (qname, subs) in &self.subscribers {
            let Some((p, tag)) = qname.split_once('/') else {
                continue;
            };
            if p != plc || tags.is_some_and(|t| !t.contains(tag)) {
                continue;
            }
            for (id, names) in subs {
                let Some(session) = self.sessions.get(id) else {
                    continue;
                };
                let d = per_session.entry(*id).or_default();
                let mut names: Vec<&String> = names.iter().collect();
                names.sort();
                for name in names {
                    d.insert(name.clone(), self.info(&session.token, plc, tag, name));
                }
            }
        }
        for (id, d) in per_session {
            if let Some(session) = self.sessions.get(&id) {
                session.outbox.send(json!({"op": "info", "d": d}));
            }
        }
    }

    // ------------------------------------------------------------------------------------------ tag info

    fn allowed(token: &TokenConfig, qnames: &[&str]) -> bool {
        token
            .write
            .iter()
            .any(|p| qnames.iter().any(|q| glob_match(p, q)))
    }

    /// The info record of a resolved tag for a session.
    fn info(&self, token: &TokenConfig, plc: &str, tag: &str, name: &str) -> Json {
        let config = &self.shared.config;
        let rule = self.shared.rules.effective(plc, tag);
        let group = self.shared.rules.group(plc, tag);
        let sent = self.qualify_str(name).map(|q| q.1).unwrap_or_default();
        let writable = truthy(rule.get("writable"))
            && Self::allowed(token, &[&format!("{plc}/{sent}"), &format!("{plc}/{tag}")]);
        let mut record = Map::new();
        if split_bit(tag).is_some() {
            record.insert("type".into(), json!("BOOL"));
        } else {
            let type_info = self
                .worker(plc)
                .map(|w| w.type_info(tag))
                .unwrap_or_default();
            record.insert("type".into(), json!(type_info.type_));
            if let Some(dims) = type_info.dims {
                record.insert("dims".into(), json!(dims));
            }
        }
        record.insert("writable".into(), json!(writable));
        record.insert(
            "rate_ms".into(),
            json!(group.as_ref().map_or(config.cycle_ms, |g| g.rate_ms)),
        );
        record.insert("group".into(), json!(group.map(|g| g.name)));
        if split_bit(tag).is_some() {
            return Json::Object(record);
        }
        for key in ["min", "max", "units", "deadband", "bits"] {
            if let Some(v) = rule.get(key).filter(|v| !v.is_null()) {
                record.insert(key.into(), v.clone());
            }
        }
        let description = rule
            .get("description")
            .filter(|d| truthy(Some(d)))
            .cloned()
            .or_else(|| {
                self.worker(plc)
                    .and_then(|w| w.description(tag))
                    .map(Json::String)
            });
        if let Some(d) = description {
            record.insert("description".into(), d);
        }
        Json::Object(record)
    }

    // ------------------------------------------------------------------------------------------ requests

    /// (plc, tag as sent, resolved tag) of a name.
    fn qualify_str(&self, name: &str) -> Result<(String, String, String), String> {
        let (plc, tag) = self.shared.config.qualify(name)?;
        let tag = canonical(tag);
        let resolved = self.shared.rules.resolve(plc, &tag);
        Ok((plc.to_owned(), tag, resolved))
    }

    fn qualify(&self, name: &Json) -> Result<(String, String, String), String> {
        match name {
            Json::String(s) => self.qualify_str(s),
            _ => Err("tag names must be strings".into()),
        }
    }

    /// One client message; a bad one gets an error message.
    fn handle(&mut self, id: SessionId, text: &str) {
        let Some(outbox) = self.sessions.get(&id).map(|s| Arc::clone(&s.outbox)) else {
            return;
        };
        let msg: Json = match serde_json::from_str(text) {
            Ok(msg) => msg,
            Err(err) => {
                outbox.send(json!({"op": "error", "id": null, "error": err.to_string()}));
                return;
            }
        };
        let Json::Object(msg) = msg else {
            outbox.send(json!({"op": "error", "id": null, "error": format!("{}: not an object", py_repr(text))}));
            return;
        };
        let msg_id = msg.get("id").cloned().unwrap_or(Json::Null);
        if let Err(error) = self.request(id, &msg, &outbox) {
            outbox.send(json!({"op": "error", "id": msg_id, "error": error}));
        }
    }

    fn request(
        &mut self,
        id: SessionId,
        msg: &Map<String, Json>,
        outbox: &Outbox,
    ) -> Result<(), String> {
        let field = |key: &str| {
            msg.get(key)
                .ok_or_else(|| format!("missing field {}", py_repr(key)))
        };
        let msg_id = msg.get("id").cloned().unwrap_or(Json::Null);
        match field("op")? {
            Json::String(op) if op == "sub" => {
                let (tags, page) = (
                    msg.get("tags").filter(|t| !t.is_null()),
                    msg.get("page").filter(|p| !p.is_null()),
                );
                if tags.is_none() && page.is_none() {
                    return Err("missing field 'tags'".into());
                }
                let sub_id = field("id")?.clone();
                let tier = match msg.get("tier") {
                    None => 1,
                    Some(t) => match t.as_f64() {
                        Some(x) if x == 1.0 || x == 2.0 || x == 3.0 => x as u8,
                        _ => return Err("tier must be 1, 2 or 3".into()),
                    },
                };
                let page = match page {
                    None => None,
                    Some(Json::String(p)) => Some(p.clone()),
                    Some(_) => return Err("page must be a string".into()),
                };
                self.subscribe(id, &sub_id, tags, tier, page.as_deref())?;
                outbox.send(json!({"op": "ack", "id": msg_id, "ok": true, "error": null}));
            }
            Json::String(op) if op == "unsub" => {
                let sub_id = field("id")?.clone();
                let ok = self.unsubscribe(id, &sub_id);
                outbox.send(json!({"op": "ack", "id": msg_id, "ok": ok, "error": if ok { Json::Null } else { json!("unknown id") }}));
            }
            Json::String(op) if op == "write" => {
                let write_id = field("id")?.clone();
                let tag = msg.get("tag").cloned().unwrap_or(Json::Null);
                let value = msg.get("value").cloned().unwrap_or(Json::Null);
                self.write(id, Some(write_id), &tag, &value, None);
            }
            Json::String(op) if op == "momentary" => {
                let action = field("action")?;
                let tag = msg.get("tag").cloned().unwrap_or(Json::Null);
                match action.as_str() {
                    Some("hold") => self.hold_button(id, &tag),
                    Some(a @ ("press" | "release")) => {
                        let write_id = field("id")?.clone();
                        let momentary = if a == "press" { "press" } else { "release" };
                        self.write(
                            id,
                            Some(write_id),
                            &tag,
                            &json!(a == "press"),
                            Some(momentary),
                        );
                    }
                    _ => return Err(format!("unknown action {}", py_value_repr(action))),
                }
            }
            op => return Err(format!("unknown op {}", py_value_repr(op))),
        }
        Ok(())
    }

    /// Subscribes names (or, with `names` None, a page's learned tags); queues the info of names new to the
    /// session and the cached values. A tier-1 sub with a page teaches the server that page's tags.
    fn subscribe(
        &mut self,
        id: SessionId,
        sub_id: &Json,
        names: Option<&Json>,
        tier: u8,
        page: Option<&str>,
    ) -> Result<(), String> {
        let mut follow = None;
        let mut tags: IndexMap<String, String> = IndexMap::new();
        match names {
            None => {
                let page = page.ok_or("missing field 'tags'")?;
                follow = Some(page.to_owned());
                let learned: Vec<String> = self
                    .pages
                    .get(page)
                    .map(|p| p.iter().cloned().collect())
                    .unwrap_or_default();
                for qname in learned {
                    tags.insert(self.client_name(&qname), self.resolved(&qname));
                }
            }
            Some(Json::Array(names)) => {
                for name in names {
                    let (plc, _, tag) = self.qualify(name)?;
                    tags.insert(py_str(name), format!("{plc}/{tag}"));
                }
            }
            Some(_) => return Err("tags must be a list".into()),
        }
        let key = sub_id.to_string();
        let Some(session) = self.sessions.get_mut(&id) else {
            return Ok(());
        };
        // replaced: released after the new one counts, so no tag drops out
        let old = session.subs.shift_remove(&key);
        session.subs.insert(
            key,
            Sub {
                tier,
                tags: tags.clone(),
                follow: follow.clone(),
            },
        );
        let qnames: HashSet<String> = tags.values().cloned().collect();
        let mut sorted: Vec<&String> = qnames.iter().collect();
        sorted.sort();
        for qname in sorted {
            self.hold(qname, tier);
        }
        let mut all = qnames.clone();
        if let Some(old) = old {
            let gone: Vec<String> = old
                .tags
                .values()
                .cloned()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            self.release(old.tier, &gone);
            all.extend(gone);
        }
        self.reindex(id, &all);
        let mut info = Map::new();
        let mut snapshot = Vec::new();
        for (name, qname) in &tags {
            let Some((plc, tag)) = qname.split_once('/') else {
                continue;
            };
            let Some(session) = self.sessions.get(&id) else {
                return Ok(());
            };
            if !session.info_sent.contains(name) {
                info.insert(name.clone(), self.info(&session.token, plc, tag, name));
            }
            if let Some(entry) = self.worker(plc).and_then(|w| w.snapshot(tag)) {
                snapshot.push((name.clone(), entry.to_json()));
            }
        }
        if let Some(session) = self.sessions.get_mut(&id) {
            session.info_sent.extend(info.keys().cloned());
            if !info.is_empty() {
                session.outbox.send(json!({"op": "info", "d": info}));
            }
            for (name, entry) in snapshot {
                session.outbox.push(&name, entry);
            }
        }
        if let (Some(page), None, 1) = (page, &follow, tier) {
            self.learn(page, &qnames);
        }
        Ok(())
    }

    fn unsubscribe(&mut self, id: SessionId, sub_id: &Json) -> bool {
        let Some(sub) = self
            .sessions
            .get_mut(&id)
            .and_then(|s| s.subs.shift_remove(&sub_id.to_string()))
        else {
            return false;
        };
        let qnames: HashSet<String> = sub.tags.values().cloned().collect();
        let list: Vec<String> = qnames.iter().cloned().collect();
        self.release(sub.tier, &list);
        self.reindex(id, &qnames);
        true
    }

    /// One more reference at `tier`; the worker reads the tag at the lowest tier held.
    fn hold(&mut self, qname: &str, tier: u8) {
        let counts = self.refs.entry(qname.to_owned()).or_default();
        if counts.keys().next().is_none_or(|&min| tier < min) {
            if let Some((plc, tag)) = qname.split_once('/') {
                if let Some(worker) = self.shared.workers.get(plc) {
                    worker.set_tier(tag, Some(tier));
                }
            }
        }
        *counts.entry(tier).or_default() += 1;
    }

    fn release(&mut self, tier: u8, qnames: &[String]) {
        for qname in qnames {
            let Some(counts) = self.refs.get_mut(qname) else {
                continue;
            };
            let before = counts.keys().next().copied();
            if let Some(n) = counts.get_mut(&tier) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    counts.remove(&tier);
                }
            }
            let after = counts.keys().next().copied();
            if counts.is_empty() {
                self.refs.remove(qname);
            }
            if after != before {
                if let Some((plc, tag)) = qname.split_once('/') {
                    if let Some(worker) = self.shared.workers.get(plc) {
                        worker.set_tier(tag, after);
                    }
                }
            }
        }
    }

    /// Rebuilds the session's entries of `subscribers` for these qualified names from its subs.
    fn reindex(&mut self, id: SessionId, qnames: &HashSet<String>) {
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        let mut names: HashMap<&String, HashSet<String>> = HashMap::new();
        for sub in session.subs.values() {
            for (name, qname) in &sub.tags {
                if qnames.contains(qname) {
                    names.entry(qname).or_default().insert(name.clone());
                }
            }
        }
        for qname in qnames {
            match names.remove(qname) {
                Some(n) => {
                    self.subscribers
                        .entry(qname.clone())
                        .or_default()
                        .insert(id, n);
                }
                None => {
                    if let Some(subs) = self.subscribers.get_mut(qname) {
                        subs.remove(&id);
                        if subs.is_empty() {
                            self.subscribers.remove(qname);
                        }
                    }
                }
            }
        }
        // a name subscribed again later gets fresh info (its type may be known by then)
        let current: HashSet<&String> = session.subs.values().flat_map(|s| s.tags.keys()).collect();
        session.info_sent.retain(|n| current.contains(n));
    }

    /// A learned name with its bit alias resolved as the types now say.
    fn resolved(&self, qname: &str) -> String {
        match qname.split_once('/') {
            Some((plc, tag)) => format!("{plc}/{}", self.shared.rules.resolve(plc, tag)),
            None => qname.to_owned(),
        }
    }

    /// How a page subscription names a learned tag: unqualified when there is only one PLC.
    fn client_name(&self, qname: &str) -> String {
        match qname.split_once('/') {
            Some((_, tag)) if self.shared.workers.len() == 1 => tag.to_owned(),
            _ => qname.to_owned(),
        }
    }

    fn learn(&mut self, page: &str, qnames: &HashSet<String>) {
        let known = self.pages.entry(page.to_owned()).or_default();
        if qnames.iter().all(|q| known.contains(q)) {
            return;
        }
        known.extend(qnames.iter().cloned());
        if self.shared.config.pages_file.is_some() && !self.save_scheduled {
            self.save_scheduled = true;
            self.later(SAVE_DELAY, Msg::SavePages);
        }
        // page subscriptions follow what their page learns
        let mut follows = Vec::new();
        for (id, session) in &self.sessions {
            for (sub_id, sub) in &session.subs {
                if sub.follow.as_deref() == Some(page) {
                    follows.push((*id, sub_id.clone(), sub.tier));
                }
            }
        }
        for (id, sub_id, tier) in follows {
            let sub_id: Json = serde_json::from_str(&sub_id).unwrap_or(Json::String(sub_id));
            let _ = self.subscribe(id, &sub_id, None, tier, Some(page));
        }
    }

    fn save_pages(&mut self) {
        self.save_scheduled = false;
        if let Some(path) = &self.shared.config.pages_file {
            if let Err(err) = save_pages(path, &self.pages) {
                log::warn!("cannot write {}: {err}", path.display());
            }
        }
    }

    /// A closed session: its subscriptions go and its pressed momentary tags are released.
    fn drop_session(&mut self, id: SessionId) {
        let sub_ids: Vec<String> = self
            .sessions
            .get(&id)
            .map(|s| s.subs.keys().cloned().collect())
            .unwrap_or_default();
        for sub_id in sub_ids {
            let key: Json = serde_json::from_str(&sub_id).unwrap_or(Json::String(sub_id));
            self.unsubscribe(id, &key);
        }
        let Some(session) = self.sessions.remove(&id) else {
            return;
        };
        self.shared
            .sessions
            .store(self.sessions.len(), Ordering::Relaxed);
        for (_, (_, name)) in session.pressed {
            self.submit(
                &session.token,
                id,
                None,
                &name,
                &json!(false),
                Some("disconnect"),
            );
        }
    }

    // ------------------------------------------------------------------------------------------ writes

    fn reject(&self, error: &str, kind: &str) -> WriteResult {
        self.shared.write_rejects.fetch_add(1, Ordering::Relaxed);
        WriteResult::failed(error, kind)
    }

    /// The hub's checks, then the write is queued (no await in between, so writes keep their order). Returns
    /// (qualified name, old value, the rejection if any); `done` gets the result either way.
    #[allow(clippy::too_many_arguments)]
    fn submit(
        &mut self,
        token: &TokenConfig,
        session: SessionId,
        id: Option<Json>,
        name: &Json,
        value: &Json,
        momentary: Option<&'static str>,
    ) -> (String, bool) {
        let (qname, old, rejection) = self.check_write(token, name, value, momentary.is_some());
        let audit = self.audit.clone().map(|tx| {
            let line = json!({
                "time": "", "token": token.name, "tag": qname, "old": old, "value": value,
            });
            (tx, line)
        });
        let tx = self.tx.clone();
        let done_msg = WriteDone {
            session,
            token: token.clone(),
            id,
            qname: qname.clone(),
            name: name.clone(),
            momentary,
            result: WriteResult::failed("", ""),
        };
        let done = move |result: WriteResult| {
            if let Some((audit_tx, mut line)) = audit {
                line["time"] = json!(iso_now());
                line["ok"] = json!(result.ok);
                line["error"] = json!(result.error);
                line["kind"] = json!(result.kind);
                if let Some(m) = momentary {
                    line["momentary"] = json!(m);
                }
                let _ = audit_tx.send(line.to_string());
            }
            let _ = tx.send(Msg::WriteDone(Box::new(WriteDone { result, ..done_msg })));
        };
        match rejection {
            Some(result) => {
                done(result);
                (qname, false)
            }
            None => {
                self.shared.writes.fetch_add(1, Ordering::Relaxed);
                let (plc, tag) = qname.split_once('/').unwrap_or_default();
                let value = from_json(value).unwrap_or(ciplink::Value::Bool(false));
                match self.worker(plc) {
                    Some(worker) => worker.write(tag, value, Box::new(done)),
                    None => done(WriteResult::failed("unknown PLC", "bad_request")),
                }
                (qname, true)
            }
        }
    }

    fn check_write(
        &self,
        token: &TokenConfig,
        name: &Json,
        value: &Json,
        momentary: bool,
    ) -> (String, Json, Option<WriteResult>) {
        let (plc, sent, tag) = match self.qualify(name) {
            Ok(q) => q,
            Err(err) => {
                return (
                    py_str(name),
                    Json::Null,
                    Some(self.reject(&err, "bad_request")),
                );
            }
        };
        let qname = format!("{plc}/{tag}");
        if value.is_null() {
            return (
                qname,
                Json::Null,
                Some(self.reject("missing value", "bad_request")),
            );
        }
        if sent.contains('{') {
            // X{1} would match other rules than X: no min/max or writable bypass by spelling
            return (
                qname,
                Json::Null,
                Some(self.reject("element counts are not allowed in writes", "bad_request")),
            );
        }
        let worker = self.worker(&plc);
        let old = worker
            .and_then(|w| w.snapshot(&tag))
            .map_or(Json::Null, |e| e.value);
        let type_info = worker.map(|w| w.type_info(&tag)).unwrap_or_default();
        if type_info.dims.is_some() {
            // written by name, an array takes one value at element 0: its rules would be skipped
            return (
                qname,
                old,
                Some(self.reject("write an element of the array", "bad_request")),
            );
        }
        if momentary && type_info.type_.as_deref().is_some_and(|t| t != "BOOL") {
            return (
                qname,
                old,
                Some(self.reject("momentary needs a BOOL tag or a bit", "bad_request")),
            );
        }
        if !Self::allowed(token, &[&format!("{plc}/{sent}"), &qname]) {
            return (qname, old, Some(self.reject("not allowed", "not_allowed")));
        }
        let rule = self.shared.rules.effective(&plc, &tag);
        if !truthy(rule.get("writable")) {
            return (
                qname,
                old,
                Some(self.reject("not writable", "not_writable")),
            );
        }
        let bound = |key: &str| rule.get(key).and_then(Json::as_f64);
        if !in_range(value, bound("min"), bound("max")) {
            return (
                qname,
                old,
                Some(self.reject("out of range", "out_of_range")),
            );
        }
        (qname, old, None)
    }

    /// A write, press or release from a client; `momentary` is press or release.
    fn write(
        &mut self,
        id: SessionId,
        write_id: Option<Json>,
        name: &Json,
        value: &Json,
        momentary: Option<&'static str>,
    ) {
        let Some(token) = self.sessions.get(&id).map(|s| s.token.clone()) else {
            return;
        };
        let (qname, queued) = self.submit(&token, id, write_id, name, value, momentary);
        match momentary {
            Some("press") if queued => {
                self.owed.remove(&qname);
                self.arm(id, &qname, name);
            }
            Some("release") => self.disarm(id, &qname),
            _ => {}
        }
    }

    fn write_done(&mut self, done: WriteDone) {
        let WriteDone {
            session,
            token,
            id,
            qname,
            name,
            momentary,
            result,
        } = done;
        if let Some(m) = momentary.filter(|m| RELEASES.contains(m)) {
            // a release the PLC never got is sent again
            if result.ok || result.kind.as_deref().is_some_and(|k| FINAL.contains(&k)) {
                self.owed.remove(&qname);
            } else {
                self.owed.insert(qname.clone(), (token, session, name, m));
                let plc = qname.split_once('/').map_or("", |(p, _)| p);
                if self.worker(plc).is_some_and(|w| w.state() == "connected") {
                    // refused while connected (ciplink's reload backoff): no connect comes to resend it
                    self.later(RETRY_DELAY, Msg::Resend(qname.clone()));
                }
            }
        }
        if let (Some(id), Some(session)) = (id, self.sessions.get(&session)) {
            session.outbox.send(json!({
                "op": "ack", "id": id, "ok": result.ok, "error": result.error, "kind": result.kind, "value": result.value,
            }));
        }
    }

    /// Writes an owed release again; left owed while the PLC is not connected (sent on connect), and dropped if
    /// the tag was pressed again meanwhile.
    fn resend(&mut self, qname: &str) {
        let plc = qname.split_once('/').map_or("", |(p, _)| p);
        if self.worker(plc).is_none_or(|w| w.state() != "connected") {
            return;
        }
        let Some((token, session, name, momentary)) = self.owed.remove(qname) else {
            return;
        };
        if self
            .sessions
            .values()
            .any(|s| s.pressed.contains_key(qname))
        {
            return;
        }
        self.submit(&token, session, None, &name, &json!(false), Some(momentary));
    }

    /// Refreshes the watchdog of a pressed tag; ignored if the tag is not pressed.
    fn hold_button(&mut self, id: SessionId, name: &Json) {
        let Ok((plc, _, tag)) = self.qualify(name) else {
            return;
        };
        let qname = format!("{plc}/{tag}");
        let pressed = self
            .sessions
            .get(&id)
            .and_then(|s| s.pressed.get(&qname))
            .map(|(_, name)| name.clone());
        if let Some(name) = pressed {
            self.arm(id, &qname, &name);
        }
    }

    fn arm(&mut self, id: SessionId, qname: &str, name: &Json) {
        self.generation += 1;
        let generation = self.generation;
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        session
            .pressed
            .insert(qname.to_owned(), (generation, name.clone()));
        let delay = Duration::from_millis(self.shared.config.momentary_timeout_ms);
        self.later(delay, Msg::Timeout(id, qname.to_owned(), generation));
    }

    fn disarm(&mut self, id: SessionId, qname: &str) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.pressed.remove(qname);
        }
    }

    fn timeout(&mut self, id: SessionId, qname: &str, generation: u64) {
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        if session
            .pressed
            .get(qname)
            .is_none_or(|(g, _)| *g != generation)
        {
            return; // released, or held again since
        }
        let Some((_, name)) = session.pressed.remove(qname) else {
            return;
        };
        let token = session.token.clone();
        self.shared
            .momentary_timeouts
            .fetch_add(1, Ordering::Relaxed);
        self.submit(&token, id, None, &name, &json!(false), Some("timeout"));
    }
}

/// Python's `repr()` of a JSON value in error messages.
fn py_value_repr(value: &Json) -> String {
    match value {
        Json::String(s) => py_repr(s),
        other => py_str(other),
    }
}

/// The audit thread: appends the queued lines, so a slow disk never blocks the hub.
fn write_audit(path: &Path, rx: &std::sync::mpsc::Receiver<String>) {
    use std::io::Write as _;
    while let Ok(line) = rx.recv() {
        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| writeln!(file, "{line}"));
        if let Err(err) = result {
            log::warn!("cannot write {}: {err}", path.display());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert!(in_range(&json!(5), Some(0.0), Some(10.0)));
        assert!(!in_range(&json!(11), Some(0.0), Some(10.0)));
        assert!(!in_range(&json!({"a": [1, 20]}), None, Some(10.0)));
        assert!(in_range(&json!(true), Some(5.0), None));
        assert!(in_range(&json!("x"), Some(5.0), None));
    }

    #[test]
    fn iso_time_shape() {
        let t = iso_now();
        assert_eq!(t.len(), "2026-10-23T14:17:33.768123+00:00".len());
        assert!(t.ends_with("+00:00"));
    }

    #[test]
    fn secrets_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
