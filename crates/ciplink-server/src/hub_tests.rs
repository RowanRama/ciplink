//! Ports of ciplink-tagserver's tests/test_hub.py. The Python tests run the hub against a fake worker; here the
//! worker is real but its thread is not started: the test runs its queued writes on conftest.py's fake driver
//! between hub messages, on tokio's paused clock, so the timings are exact.
#![allow(clippy::unwrap_used)]

use ciplink::{ErrorKind, TagError, Value};
use serde_json::json;

use super::*;
use crate::config::parse_config;
use crate::testing::{Fake, TempDir, atomic, audit_lines, wait_for};
use crate::values::Entry;

fn config() -> Json {
    json!({
        "server": {"cycle_ms": 100, "momentary_timeout_ms": 100, "pages_file": ""},
        "plc": {"P": {"path": "x", "rule": [
            {"match": "SpeedSP", "writable": true, "min": 0, "max": 1800, "units": "rpm", "description": "Setpoint"},
            {"match": "Speed", "deadband": 0.5, "units": "rpm"},
            {"match": "Word", "writable": true, "bits": {"EStop": 0, "Door": 1}, "always": true},
            {"match": "Recipe", "writable": true, "min": 0, "max": 10},
            {"match": ["Start*", "Mode"], "writable": true},
            {"match": "Locked", "max": 5},
        ], "group": [{"name": "fast", "rate_ms": 20, "match": "Speed"}]}},
        "token": {"op": {"secret": "s", "write": ["P/SpeedSP", "P/Word.EStop", "P/Start*", "P/Recipe", "P/Mode",
                                                  "P/Locked", "P/Nope"]},
                  "viewer": {"secret": "v"}},
    })
}

/// A hub on PLC "P" (a connected worker on a fake) and its message queue.
struct H {
    hub: Hub,
    rx: mpsc::UnboundedReceiver<Msg>,
    fake: Fake,
    dir: TempDir,
    next_id: SessionId,
    next_write: u64,
}

fn hub_with(config: Json, dir: TempDir) -> H {
    let config = parse_config(&config, dir.path()).unwrap();
    let fake = Fake::default();
    let fakes = HashMap::from([("P".to_owned(), fake.clone())]);
    let (tx, rx) = mpsc::unbounded_channel();
    let shared = crate::server::build(config, Fake::factory(&fakes), &tx).unwrap();
    shared.workers["P"].load(&mut fake.plc()); // connected, as the fake worker
    H {
        hub: Hub::new(shared, tx),
        rx,
        fake,
        dir,
        next_id: 1,
        next_write: 1000,
    }
}

fn hub() -> H {
    hub_with(config(), TempDir::new())
}

impl H {
    fn worker(&self) -> &Arc<PlcWorker> {
        &self.hub.shared.workers["P"]
    }

    /// Sets the controller's tags (atomic types) and loads them.
    fn types(&self, tags: &[(&str, &str, &[u64])]) {
        {
            let mut f = self.fake.lock();
            for (name, type_name, dims) in tags {
                f.tags.insert((*name).to_owned(), atomic(type_name, dims));
            }
        }
        self.worker().load(&mut self.fake.plc());
    }

    fn session(&mut self, token: &str) -> (SessionId, Arc<Outbox>) {
        let id = self.next_id;
        self.next_id += 1;
        let outbox = Arc::new(Outbox::default());
        let token = self.hub.shared.config.tokens[token].clone();
        self.hub.dispatch(Msg::Open(id, token, Arc::clone(&outbox)));
        (id, outbox)
    }

    fn subscribe(&mut self, id: SessionId, sub_id: u64, names: Json, tier: u8) {
        self.hub
            .subscribe(id, &json!(sub_id), Some(&names), tier, None)
            .unwrap();
    }

    /// Runs the worker's queued writes and the hub's messages until both are idle.
    fn pump(&mut self) {
        loop {
            let _ = self.worker().run_writes(&mut self.fake.plc());
            let mut busy = false;
            while let Ok(msg) = self.rx.try_recv() {
                busy = true;
                self.hub.dispatch(msg);
            }
            if !busy {
                return;
            }
        }
    }

    /// Lets `ms` pass, handling everything as it comes.
    async fn sleep(&mut self, ms: u64) {
        let end = tokio::time::Instant::now() + Duration::from_millis(ms);
        while tokio::time::Instant::now() < end {
            self.pump();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.pump();
    }

    /// The ack of write `id` (other control messages are dropped).
    async fn ack(&mut self, outbox: &Outbox, id: u64) -> Json {
        for _ in 0..1000 {
            self.pump();
            if let Some(ack) = control(outbox)
                .into_iter()
                .find(|m| m["op"] == "ack" && m["id"] == id)
            {
                return ack;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("no ack {id}");
    }

    /// `hub.write`: (ok, error, kind, value) of the ack.
    async fn write(&mut self, s: (SessionId, &Outbox), name: Json, value: Json) -> Json {
        let id = self.next_write;
        self.next_write += 1;
        self.hub.write(s.0, Some(json!(id)), &name, &value, None);
        result(&self.ack(s.1, id).await)
    }

    /// `hub.momentary`: (ok, error, kind, value) of a press or release, null for a hold, the error message of a
    /// bad action.
    async fn momentary(&mut self, s: (SessionId, &Outbox), name: &str, action: &str) -> Json {
        let id = self.next_write;
        self.next_write += 1;
        let msg = json!({"op": "momentary", "id": id, "tag": name, "action": action});
        self.hub.handle(s.0, &msg.to_string());
        if action == "hold" {
            self.pump();
            return Json::Null;
        }
        if action != "press" && action != "release" {
            return control(s.1)
                .into_iter()
                .find(|m| m["op"] == "error")
                .unwrap();
        }
        result(&self.ack(s.1, id).await)
    }

    fn drop_session(&mut self, id: SessionId) {
        self.hub.drop_session(id);
    }

    fn pressed(&self, id: SessionId) -> Vec<String> {
        self.hub
            .sessions
            .get(&id)
            .map(|s| s.pressed.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn counters(&self) -> (u64, u64, u64) {
        let s = &self.hub.shared;
        (
            s.writes.load(Ordering::Relaxed),
            s.write_rejects.load(Ordering::Relaxed),
            s.momentary_timeouts.load(Ordering::Relaxed),
        )
    }

    fn audit(&self, n: usize) -> Vec<Json> {
        audit_lines(&self.dir.path().join("audit.log"), n)
    }

    fn refs(&self, qname: &str) -> Vec<(u8, usize)> {
        self.hub
            .refs
            .get(qname)
            .map(|c| c.iter().map(|(t, n)| (*t, *n)).collect())
            .unwrap_or_default()
    }

    fn subscribers(&self, qname: &str) -> Vec<(SessionId, Vec<String>)> {
        let mut out: Vec<(SessionId, Vec<String>)> = self
            .hub
            .subscribers
            .get(qname)
            .map(|subs| {
                subs.iter()
                    .map(|(id, names)| {
                        let mut names: Vec<String> = names.iter().cloned().collect();
                        names.sort();
                        (*id, names)
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    fn tiers(&self) -> Vec<(String, u8)> {
        self.worker().tiers().into_iter().collect()
    }
}

/// The control messages queued (taken).
fn control(outbox: &Outbox) -> Vec<Json> {
    lock_queue(outbox).0.drain(..).collect()
}

/// The pending values.
fn pending(outbox: &Outbox) -> Json {
    Json::Object(lock_queue(outbox).1.clone().into_iter().collect())
}

fn lock_queue(
    outbox: &Outbox,
) -> std::sync::MutexGuard<'_, (VecDeque<Json>, IndexMap<String, Json>)> {
    outbox.queue.lock().unwrap_or_else(PoisonError::into_inner)
}

fn result(ack: &Json) -> Json {
    json!([ack["ok"], ack["error"], ack["kind"], ack["value"]])
}

fn entry(value: Json, t: i64) -> Entry {
    Entry {
        value,
        quality: "good",
        t,
        error: Json::Null,
    }
}

fn s(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[tokio::test(start_paused = true)]
async fn always_tags_get_a_permanent_tier1_reference() {
    let mut h = hub();
    assert_eq!(h.tiers(), [("Word".to_owned(), 1)]);
    let (id, _) = h.session("op");
    h.subscribe(id, 1, json!(["Word"]), 3);
    h.hub.unsubscribe(id, &json!(1));
    assert_eq!(h.tiers(), [("Word".to_owned(), 1)]);
    assert_eq!(h.refs("P/Word"), [(1, 1)]);
}

#[tokio::test(start_paused = true)]
async fn write_checks_kinds_and_audit() {
    let mut h = hub();
    h.worker().set_cache("SpeedSP", entry(json!(100), 1));
    let (id, outbox) = h.session("op");
    let mut results = Vec::new();
    for (name, value) in [
        (json!("SpeedSP"), json!(250)),
        (json!("Q/SpeedSP"), json!(1)),
        (json!(5), json!(1)),
        (json!("Other"), json!(1)),
        (json!("Locked"), json!(1)),
        (json!("SpeedSP"), json!(1801)),
        (json!("SpeedSP"), json!(-1)),
        (json!("Recipe"), json!({"A": [1, 11]})),
        (json!("Recipe"), json!({"A": [1, true, 10], "B": "x"})),
        (json!("Word.EStop"), json!(true)),
        (json!("Word.0"), json!(true)),
    ] {
        results.push(h.write((id, &outbox), name, value).await);
    }
    assert_eq!(results[0], json!([true, null, null, 250])); // ack value is the read-back
    assert_eq!(
        results[1],
        json!([false, "unknown PLC 'Q'", "bad_request", null])
    );
    assert_eq!(results[2][2], "bad_request");
    assert_eq!(
        results[3],
        json!([false, "not allowed", "not_allowed", null])
    );
    assert_eq!(
        results[4],
        json!([false, "not writable", "not_writable", null])
    );
    let out_of_range = json!([false, "out of range", "out_of_range", null]);
    assert_eq!(
        results[5..8],
        [out_of_range.clone(), out_of_range.clone(), out_of_range]
    );
    assert_eq!(results[8][0], true); // bools and strings are not range checked
    assert_eq!(results[9][0], true); // the pattern matches the name as sent
    // ... or as resolved, neither here
    assert_eq!(
        results[10],
        json!([false, "not allowed", "not_allowed", null])
    );
    assert_eq!(
        h.fake.lock().written(),
        [
            ("SpeedSP".to_owned(), json!(250)),
            ("Recipe".to_owned(), json!({"A": [1, true, 10], "B": "x"})),
            ("Word.0".to_owned(), json!(true)),
        ]
    );
    let (writes, rejects, _) = h.counters();
    assert_eq!((writes, rejects), (3, 8));

    let lines = h.audit(11);
    assert_eq!(
        lines[0],
        json!({"time": lines[0]["time"], "token": "op", "tag": "P/SpeedSP", "old": 100, "value": 250,
               "ok": true, "error": null, "kind": null})
    );
    assert_eq!(
        (&lines[1]["tag"], &lines[1]["kind"]),
        (&json!("Q/SpeedSP"), &json!("bad_request"))
    );
    assert_eq!(lines[9]["tag"], "P/Word.0"); // resolved
    assert!(lines.iter().all(|l| l.get("momentary").is_none()));
}

#[tokio::test(start_paused = true)]
async fn worker_error_reaches_the_ack() {
    let mut h = hub();
    h.fake.lock().write_error = Some(TagError::new(
        "Value out of range for DINT",
        ErrorKind::BadValue,
    ));
    let (id, outbox) = h.session("op");
    assert_eq!(
        h.write((id, &outbox), json!("Mode"), json!(1_u64 << 40))
            .await,
        json!([false, "Value out of range for DINT", "bad_value", null])
    );
    let (writes, rejects, _) = h.counters();
    assert_eq!((rejects, writes), (0, 1));
}

#[tokio::test(start_paused = true)]
async fn momentary_press_hold_timeout() {
    let mut h = hub();
    let (id, outbox) = h.session("op");
    let s = (id, &*outbox);
    assert_eq!(h.momentary(s, "StartPB", "press").await[0], true);
    for _ in 0..4 {
        // holds keep it pressed past the 100 ms timeout
        h.sleep(20).await;
        assert_eq!(h.momentary(s, "StartPB", "hold").await, Json::Null);
    }
    assert_eq!(
        h.fake.lock().written(),
        [("StartPB".to_owned(), json!(true))]
    );
    h.sleep(250).await; // no hold: the watchdog releases it
    assert_eq!(
        h.fake.lock().written(),
        [
            ("StartPB".to_owned(), json!(true)),
            ("StartPB".to_owned(), json!(false))
        ]
    );
    assert!(h.pressed(id).is_empty());
    assert_eq!(h.counters().2, 1);
    let lines = h.audit(2);
    let got: Vec<Json> = lines
        .iter()
        .map(|l| json!([l["value"], l["momentary"]]))
        .collect();
    assert_eq!(got, [json!([true, "press"]), json!([false, "timeout"])]);
}

#[tokio::test(start_paused = true)]
async fn momentary_release_and_disconnect() {
    let mut h = hub();
    h.types(&[("StartPB", "BOOL", &[]), ("Mode", "DINT", &[])]);
    let (id, outbox) = h.session("op");
    let s = (id, &*outbox);
    h.momentary(s, "StartPB", "press").await;
    assert_eq!(h.momentary(s, "StartPB", "release").await[0], true);
    h.momentary(s, "StartPB", "press").await;
    h.momentary(s, "Word.EStop", "press").await; // a bit: BOOL
    assert_eq!(h.pressed(id), ["P/StartPB", "P/Word.0"]);
    assert_eq!(
        h.momentary(s, "Mode", "press").await,
        json!([
            false,
            "momentary needs a BOOL tag or a bit",
            "bad_request",
            null
        ])
    );
    assert_eq!(h.momentary(s, "Locked", "press").await[2], "not_writable");
    assert!(!h.pressed(id).contains(&"P/Locked".to_owned())); // rejected: no watchdog
    h.momentary(s, "Start2", "hold").await; // not pressed: ignored
    assert_eq!(
        h.momentary(s, "StartPB", "push").await["error"],
        "unknown action 'push'"
    );
    h.drop_session(id);
    h.sleep(110).await;
    let w = |tag: &str, v: bool| (tag.to_owned(), json!(v));
    assert_eq!(
        h.fake.lock().written(),
        [
            w("StartPB", true),
            w("StartPB", false),
            w("StartPB", true),
            w("Word.0", true),
            w("StartPB", false),
            w("Word.0", false)
        ]
    );
    assert_eq!(h.counters().2, 0);
    let lines = h.audit(8);
    let tail: Vec<&Json> = lines[lines.len() - 2..]
        .iter()
        .map(|l| &l["momentary"])
        .collect();
    assert_eq!(tail, [&json!("disconnect"), &json!("disconnect")]);
}

#[tokio::test(start_paused = true)]
async fn info_once_before_values_and_aliases_share_a_tag() {
    let mut h = hub();
    h.types(&[
        ("SpeedSP", "REAL", &[]),
        ("Word", "DINT", &[]),
        ("Trend", "REAL", &[16]),
    ]);
    h.worker()
        .set_description("SpeedSP", Some("from the controller"));
    h.worker().set_description("Trend", Some("Trend data"));
    h.worker().set_cache("Word", entry(json!(5), 1));
    h.worker().set_cache("Word.0", entry(json!(true), 1));
    let (s, so) = h.session("op");
    let (v, vo) = h.session("viewer");

    h.subscribe(
        s,
        1,
        json!([
            "SpeedSP",
            "Speed",
            "Word",
            "Word.EStop",
            "Word.0",
            "Trend",
            "Nope"
        ]),
        1,
    );
    let messages = control(&so);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["op"], "info");
    let d = &messages[0]["d"];
    // the rule description wins
    assert_eq!(
        d["SpeedSP"],
        json!({"type": "REAL", "writable": true, "rate_ms": 100, "group": null, "min": 0, "max": 1800,
               "units": "rpm", "description": "Setpoint"})
    );
    assert_eq!(
        d["Speed"],
        json!({"type": null, "writable": false, "rate_ms": 20, "group": "fast", "units": "rpm",
               "deadband": 0.5})
    );
    // Word itself matches no token pattern
    assert_eq!(
        d["Word"],
        json!({"type": "DINT", "writable": false, "rate_ms": 100, "group": null,
               "bits": {"EStop": 0, "Door": 1}})
    );
    assert_eq!(
        d["Word.EStop"],
        json!({"type": "BOOL", "writable": true, "rate_ms": 100, "group": null})
    );
    assert_eq!(
        d["Word.0"],
        json!({"type": "BOOL", "writable": false, "rate_ms": 100, "group": null})
    );
    assert_eq!(
        d["Trend"],
        json!({"type": "REAL", "dims": [16], "writable": false, "rate_ms": 100, "group": null,
               "description": "Trend data"})
    );
    assert_eq!(
        pending(&so),
        json!({"Word": [5, "good", 1, null], "Word.EStop": [true, "good", 1, null],
               "Word.0": [true, "good", 1, null]})
    );
    assert_eq!(h.refs("P/Word.0"), [(1, 1)]); // two names, one reference
    assert_eq!(
        h.subscribers("P/Word.0"),
        [(s, self::s(&["Word.0", "Word.EStop"]))]
    );

    h.subscribe(v, 1, json!(["SpeedSP"]), 1);
    assert_eq!(control(&vo)[0]["d"]["SpeedSP"]["writable"], false); // per token
    h.subscribe(s, 2, json!(["SpeedSP"]), 1); // already known to this session: no info again
    assert!(control(&so).is_empty());

    lock_queue(&so).1.clear();
    let other = entry(json!(1), 2);
    h.hub.worker_event(Event::Values(
        "P".into(),
        vec![
            ("Word.0".into(), entry(json!(false), 2)),
            ("Other".into(), other),
        ],
    ));
    h.hub.worker_event(Event::Values(
        "P".into(),
        vec![("Word.0".into(), entry(json!(true), 3))],
    ));
    // coalesced
    assert_eq!(
        pending(&so),
        json!({"Word.EStop": [true, "good", 3, null], "Word.0": [true, "good", 3, null]})
    );

    h.hub.unsubscribe(s, &json!(1));
    assert!(h.subscribers("P/Word.0").is_empty() && h.refs("P/Word.0").is_empty());
    let mut both = vec![(s, self::s(&["SpeedSP"])), (v, self::s(&["SpeedSP"]))];
    both.sort();
    assert_eq!(h.subscribers("P/SpeedSP"), both);
    assert_eq!(h.refs("P/Word"), [(1, 1)]); // always
}

#[tokio::test(start_paused = true)]
async fn replacing_a_subscription_keeps_the_index() {
    let mut h = hub();
    let (s, _) = h.session("op");
    h.subscribe(s, 1, json!(["Speed", "P/Speed"]), 1);
    h.subscribe(s, 1, json!(["Speed"]), 1);
    assert_eq!(h.subscribers("P/Speed"), [(s, self::s(&["Speed"]))]);
    assert_eq!(h.refs("P/Speed"), [(1, 1)]);
    assert_eq!(h.worker().tiers()["Speed"], 1);
}

#[tokio::test(start_paused = true)]
async fn info_sent_again_on_meta_connect_and_descriptions() {
    let mut h = hub();
    let (s, so) = h.session("op");
    h.subscribe(s, 1, json!(["Speed", "Word.EStop"]), 1);
    control(&so);
    h.types(&[("Speed", "REAL", &[])]);
    h.hub.worker_event(Event::Status("P".into(), "connected"));
    let messages = control(&so);
    assert_eq!(
        messages[0],
        json!({"op": "status", "plcs": {"P": "connected"}})
    );
    assert_eq!(messages[1]["d"]["Speed"]["type"], "REAL");
    h.hub
        .worker_event(Event::Status("P".into(), "disconnected"));
    let ops: Vec<Json> = control(&so).iter().map(|m| m["op"].clone()).collect();
    assert_eq!(ops, [json!("status")]);
    h.hub.worker_event(Event::Meta("P".into()));
    let messages = control(&so);
    assert_eq!(messages[0], json!({"op": "meta", "plc": "P"}));
    let mut names: Vec<&String> = messages[1]["d"].as_object().unwrap().keys().collect();
    names.sort();
    assert_eq!(names, ["Speed", "Word.EStop"]);
    h.worker().set_description("Speed", Some("Spindle speed"));
    h.hub
        .worker_event(Event::Info("P".into(), vec!["Speed".into()]));
    assert_eq!(
        control(&so)[0]["d"],
        json!({"Speed": {"type": "REAL", "writable": false, "rate_ms": 20, "group": "fast", "units": "rpm",
                         "deadband": 0.5, "description": "Spindle speed"}})
    );
}

#[tokio::test]
async fn sender_sends_control_in_order_then_one_values_message() {
    let outbox = Outbox::default();
    outbox.push("A", json!([1, "good", 1, null]));
    outbox.send(json!({"op": "ack", "id": 1}));
    outbox.push("A", json!([2, "good", 2, null]));
    outbox.push("B", json!([3, "good", 2, null]));
    outbox.send(json!({"op": "info", "d": {}}));
    assert_eq!(
        outbox.next().await,
        [
            json!({"op": "ack", "id": 1}),
            json!({"op": "info", "d": {}}),
            json!({"op": "values", "d": {"A": [2, "good", 2, null], "B": [3, "good", 2, null]}}),
        ]
    );
}

/// The Python press task can run after its session dropped; here the hub handles one message at a time, so the
/// press is handled first and the drop releases it.
#[tokio::test(start_paused = true)]
async fn a_press_handled_before_its_session_dropped_is_released_at_once() {
    let mut h = hub();
    let (id, _) = h.session("op");
    let msg = json!({"op": "momentary", "id": 1, "tag": "StartPB", "action": "press"});
    h.hub.handle(id, &msg.to_string());
    h.drop_session(id); // the close came in before the press was written
    h.pump();
    assert_eq!(
        h.fake.lock().written(),
        [
            ("StartPB".to_owned(), json!(true)),
            ("StartPB".to_owned(), json!(false))
        ]
    );
    assert!(h.pressed(id).is_empty());
    let got: Vec<Json> = h.audit(2).iter().map(|l| l["momentary"].clone()).collect();
    assert_eq!(got, [json!("press"), json!("disconnect")]);
    assert_eq!(h.counters().2, 0);
}

#[tokio::test(start_paused = true)]
async fn a_release_lost_to_comm_is_sent_again_on_connect() {
    let mut h = hub();
    let (id, outbox) = h.session("op");
    let s = (id, &*outbox);
    h.momentary(s, "StartPB", "press").await;
    h.worker().set_state("disconnected"); // writes are refused
    h.sleep(200).await; // the watchdog's release is refused
    let owed: Vec<(String, Json, &str)> = h
        .hub
        .owed
        .iter()
        .map(|(q, (_, sid, name, m))| {
            assert_eq!(*sid, id);
            (q.clone(), name.clone(), *m)
        })
        .collect();
    assert_eq!(
        owed,
        [("P/StartPB".to_owned(), json!("StartPB"), "timeout")]
    );
    h.sleep(200).await; // not retried while disconnected
    assert_eq!(h.fake.lock().attempts.len(), 1);
    assert_eq!(h.audit(2).len(), 2);
    h.worker().set_state("connected");
    h.hub.worker_event(Event::Status("P".into(), "connected"));
    assert!(h.hub.owed.is_empty());
    h.drop_session(id);
    h.pump();
    assert_eq!(
        h.fake.lock().written(),
        [
            ("StartPB".to_owned(), json!(true)),
            ("StartPB".to_owned(), json!(false))
        ]
    );
    let got: Vec<Json> = h
        .audit(3)
        .iter()
        .map(|l| json!([l["ok"], l["momentary"]]))
        .collect();
    assert_eq!(
        got,
        [
            json!([true, "press"]),
            json!([false, "timeout"]),
            json!([true, "timeout"])
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_still_writes_and_audits_the_release_of_a_pressed_button() {
    let config = json!({"server": {"cycle_ms": 50, "pages_file": ""},
                        "plc": {"P": {"path": "x", "rule": [{"match": "StartPB", "writable": true}]}},
                        "token": {"op": {"secret": "s", "write": ["P/StartPB"]}}});
    let mut h = hub_with(config, TempDir::new());
    h.worker().set_state("connecting");
    h.worker().start();
    let worker = Arc::clone(h.worker());
    tokio::task::block_in_place(|| wait_for(|| worker.state() == "connected"));
    let (id, outbox) = h.session("op");
    let msg = json!({"op": "momentary", "id": 1, "tag": "StartPB", "action": "press"});
    h.hub.handle(id, &msg.to_string());
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    let ack = loop {
        while let Ok(msg) = h.rx.try_recv() {
            h.hub.dispatch(msg);
        }
        if let Some(ack) = control(&outbox).into_iter().find(|m| m["op"] == "ack") {
            break ack;
        }
        assert!(tokio::time::Instant::now() < end, "no ack");
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(ack["ok"], true);
    // the session is still open: its release is queued and the worker runs it before it stops
    h.hub.stop();
    assert_eq!(
        h.fake.lock().written(),
        [
            ("StartPB".to_owned(), json!(true)),
            ("StartPB".to_owned(), json!(false))
        ]
    );
    let got: Vec<Json> = h.audit(2).iter().map(|l| l["momentary"].clone()).collect();
    assert_eq!(got, [json!("press"), json!("disconnect")]);
}

#[tokio::test(start_paused = true)]
async fn audit_off_and_the_audit_thread_survives_any_error() {
    let mut off_config = config();
    off_config["server"]["audit_log"] = json!("");
    let mut off = hub_with(off_config, TempDir::new());
    let (id, outbox) = off.session("op");
    off.write((id, &outbox), json!("SpeedSP"), json!(1)).await;
    assert!(off.hub.shared.config.audit_log.is_none() && off.hub.audit.is_none());
    assert_eq!(std::fs::read_dir(off.dir.path()).unwrap().count(), 0);

    // the log's directory is missing: the line is lost, the thread goes on
    let mut broken = config();
    broken["server"]["audit_log"] = json!("missing/audit.log");
    let mut h = hub_with(broken, TempDir::new());
    let (id, outbox) = h.session("op");
    h.write((id, &outbox), json!("SpeedSP"), json!(1)).await;
    let path = h.dir.path().join("missing/audit.log");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!path.exists());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    h.write((id, &outbox), json!("SpeedSP"), json!(2)).await;
    assert_eq!(audit_lines(&path, 1)[0]["value"], 2);
    assert!(
        h.hub
            .audit_thread
            .as_ref()
            .is_some_and(|t| !t.is_finished())
    );
}

#[tokio::test(start_paused = true)]
async fn info_is_sent_again_for_a_name_subscribed_again() {
    let mut h = hub();
    let (s, so) = h.session("op");
    h.worker().set_state("disconnected");
    h.subscribe(s, 1, json!(["Speed"]), 1);
    assert_eq!(control(&so)[0]["d"]["Speed"]["type"], Json::Null);
    h.hub.unsubscribe(s, &json!(1));
    h.types(&[("Speed", "REAL", &[])]);
    h.hub.worker_event(Event::Status("P".into(), "connected"));
    control(&so);
    h.subscribe(s, 2, json!(["Speed"]), 1);
    assert_eq!(control(&so)[0]["d"]["Speed"]["type"], "REAL");
}

#[tokio::test(start_paused = true)]
async fn writes_with_an_element_count_or_no_value_are_bad_requests() {
    let mut h = hub();
    let (id, outbox) = h.session("op");
    let mut got = Vec::new();
    for (name, value) in [
        ("SpeedSP{1}", json!(5000)),
        ("SpeedSP", Json::Null),
        ("StartPB{1}", json!(true)),
    ] {
        let r = h.write((id, &outbox), json!(name), value).await;
        got.push(json!([r[0], r[1], r[2]]));
    }
    assert_eq!(
        got,
        [
            json!([
                false,
                "element counts are not allowed in writes",
                "bad_request"
            ]),
            json!([false, "missing value", "bad_request"]),
            json!([
                false,
                "element counts are not allowed in writes",
                "bad_request"
            ]),
        ]
    );
    assert!(h.fake.lock().attempts.is_empty());
    assert_eq!(h.counters().1, 3);
}

async fn a_release_failing_while_connected_is_retried(kind: ErrorKind) {
    let mut h = hub();
    let (id, outbox) = h.session("op");
    let s = (id, &*outbox);
    h.momentary(s, "StartPB", "press").await;
    // ciplink's reload backoff: still connected
    h.fake.lock().write_error = Some(TagError::new("controller busy", kind));
    assert_eq!(h.momentary(s, "StartPB", "release").await[2], kind.as_str());
    h.sleep(150).await; // retried after retry_delay, failing again
    {
        let f = h.fake.lock();
        assert_eq!(f.attempts.len(), 3);
        assert_eq!(f.attempts[2], ("StartPB".to_owned(), Value::Bool(false)));
    }
    h.fake.lock().write_error = None;
    h.sleep(250).await;
    assert!(h.hub.owed.is_empty());
    let mut expected = vec![("StartPB".to_owned(), json!(true))];
    expected.extend(vec![("StartPB".to_owned(), json!(false)); 3]);
    assert_eq!(h.fake.lock().tried(), expected);
}

#[tokio::test(start_paused = true)]
async fn a_release_refused_while_connected_is_retried() {
    a_release_failing_while_connected_is_retried(ErrorKind::Refused).await;
}

#[tokio::test(start_paused = true)]
async fn a_release_failing_on_a_table_change_is_retried() {
    a_release_failing_while_connected_is_retried(ErrorKind::TableChanged).await;
}

#[tokio::test(start_paused = true)]
async fn an_owed_release_is_not_sent_once_the_tag_is_pressed_again() {
    let mut h = hub();
    let (id, outbox) = h.session("op");
    let s = (id, &*outbox);
    h.momentary(s, "StartPB", "press").await;
    h.fake.lock().write_error = Some(TagError::new("controller busy", ErrorKind::Refused));
    h.momentary(s, "StartPB", "release").await;
    h.fake.lock().write_error = None;
    h.momentary(s, "StartPB", "press").await; // forgets the owed release
    h.sleep(150).await;
    h.drop_session(id);
    h.pump();
    let w = |v: bool| ("StartPB".to_owned(), json!(v));
    assert_eq!(
        h.fake.lock().tried(),
        [w(true), w(false), w(true), w(false)]
    );
}

/// The Python test has a worker thread pop an owed entry while the status handler resends the others; the hub
/// task here is the only one touching `owed`, so what is left to test is that a release no longer owed is not
/// sent and the owed ones are sent once.
#[tokio::test(start_paused = true)]
async fn status_resend_skips_a_release_no_longer_owed() {
    let mut h = hub();
    let (id, _) = h.session("op");
    let token = h.hub.shared.config.tokens["op"].clone();
    h.hub
        .owed
        .insert("P/StartPB".into(), (token, id, json!("StartPB"), "release"));
    h.hub.resend("P/StartX"); // popped meanwhile: nothing to send
    h.hub.worker_event(Event::Status("P".into(), "connected"));
    h.pump();
    assert_eq!(h.fake.lock().attempts.len(), 1);
    assert!(h.hub.owed.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_learned_page_of_a_renamed_plc_and_drop_always_releases() {
    let dir = TempDir::new();
    let pages = dir.path().join("pages.json");
    // OLD was renamed to P
    std::fs::write(&pages, r#"{"/main": ["OLD/Speed", "P/SpeedSP", "junk"]}"#).unwrap();
    let mut config = config();
    config["server"]["pages_file"] = json!(pages.to_str().unwrap());
    let mut h = hub_with(config, dir);
    let learned: Vec<(String, Vec<String>)> = h
        .hub
        .pages
        .iter()
        .map(|(p, q)| (p.clone(), q.iter().cloned().collect()))
        .collect();
    assert_eq!(learned, [("/main".to_owned(), s(&["P/SpeedSP"]))]);
    let (id, outbox) = h.session("op");
    h.hub
        .subscribe(id, &json!(1), None, 1, Some("/main"))
        .unwrap();
    h.momentary((id, &outbox), "StartPB", "press").await;
    h.hub.refs.clear(); // whatever breaks an unsubscribe, drop still releases and forgets the session
    h.drop_session(id);
    h.pump();
    assert!(!h.hub.sessions.contains_key(&id));
    assert_eq!(
        h.fake.lock().written(),
        [
            ("StartPB".to_owned(), json!(true)),
            ("StartPB".to_owned(), json!(false))
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn index_spelling_does_not_bypass_element_rules() {
    let rules = json!([{"match": "Tank[2].Level", "writable": false}, {"match": "Tank[3].Level", "max": 5},
                       {"match": "Tank[*].Level", "writable": true}]);
    let config = json!({"server": config()["server"], "plc": {"P": {"path": "x", "rule": rules}},
                        "token": {"op": {"secret": "s", "write": ["P/*"]}}});
    let mut h = hub_with(config, TempDir::new());
    let (id, outbox) = h.session("op");
    let mut kinds = Vec::new();
    for (name, value) in [
        ("Tank[02].Level", 1.0),
        ("Tank[ 2].Level", 1.0),
        ("Tank[03].Level", 9.0),
        ("Tank[+3].Level", 4.0),
    ] {
        kinds.push(h.write((id, &outbox), json!(name), json!(value)).await[2].clone());
    }
    assert_eq!(
        kinds,
        [
            json!("not_writable"),
            json!("not_writable"),
            json!("out_of_range"),
            Json::Null
        ]
    );
    assert_eq!(
        h.fake.lock().written(),
        [("Tank[3].Level".to_owned(), json!(4.0))]
    );
}

#[tokio::test(start_paused = true)]
async fn an_array_written_by_name_is_refused() {
    let mut h = hub();
    // StartPB is a BOOL[64]: 2 words
    h.types(&[("Recipe", "REAL", &[4]), ("StartPB", "DWORD", &[2])]);
    let (id, outbox) = h.session("op");
    let a = h.write((id, &outbox), json!("Recipe"), json!(99.0)).await;
    let b = h.momentary((id, &outbox), "StartPB", "press").await;
    let refused = json!([false, "write an element of the array", "bad_request"]);
    assert_eq!(json!([a[0], a[1], a[2]]), refused);
    assert_eq!(json!([b[0], b[1], b[2]]), refused);
    assert!(h.fake.lock().attempts.is_empty());
}
