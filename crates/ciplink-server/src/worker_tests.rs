//! Ports of ciplink-tagserver's tests/test_worker.py, the worker parts of tests/test_tiers.py and
//! tests/test_groups.py, on conftest.py's fake driver (crate::testing).
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::sync::mpsc;

use ciplink::{ErrorKind, TagError};
use serde_json::json;

use super::*;
use crate::config::parse_config;
use crate::testing::{Fake, atomic, other, plant, strct, udt, wait_for};

type Step = Box<dyn FnMut(&Shared) + Send>;

struct ClockState {
    now: f64,
    waits: Vec<f64>,
    n: usize,
    at: HashMap<usize, Step>,
}

/// test_tiers.py's FakeClock: wait(s) advances the time by s and returns true after n waits; `at` runs a step
/// after that wait (between ticks).
struct FakeClock(Mutex<ClockState>);

impl FakeClock {
    fn new(n: usize) -> Arc<Self> {
        Arc::new(FakeClock(Mutex::new(ClockState {
            now: 1000.0,
            waits: Vec::new(),
            n,
            at: HashMap::new(),
        })))
    }

    fn advance(&self, seconds: f64) -> f64 {
        let mut s = lock(&self.0);
        s.now += seconds;
        s.now
    }

    fn waits(&self) -> Vec<f64> {
        lock(&self.0).waits.clone()
    }
}

impl FakeTime for FakeClock {
    fn now(&self) -> f64 {
        lock(&self.0).now
    }

    fn wait(&self, shared: &Shared, seconds: f64) -> bool {
        let (count, step, n) = {
            let mut s = lock(&self.0);
            s.waits.push(seconds);
            s.now += seconds;
            let count = s.waits.len();
            (count, s.at.remove(&count), s.n)
        };
        if let Some(mut step) = step {
            step(shared);
        }
        count >= n
    }
}

/// A fake wait on the real clock (the Python tests' `worker.wait = fake_wait`).
struct FakeWait {
    epoch: Instant,
    wait: Mutex<Box<dyn FnMut(f64) -> bool + Send>>,
}

impl FakeTime for FakeWait {
    fn now(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }

    fn wait(&self, _shared: &Shared, seconds: f64) -> bool {
        (lock(&self.wait))(seconds)
    }
}

/// A worker of PLC "P" on a fake, its published events and its fake clock.
struct W {
    worker: Arc<PlcWorker>,
    fake: Fake,
    out: Arc<Mutex<Vec<Event>>>,
    clock: Arc<FakeClock>,
}

fn options(cycle_ms: u64) -> WorkerOptions {
    WorkerOptions {
        cycle: cycle_ms as f64 / 1000.0,
        tier2_period: 3.0,
        grace_s: 10.0,
        planner: true,
        whole_max_bytes: 1500,
    }
}

/// A worker with these rules and groups; events go to `out` (and ("publish", tags) to the fake's events).
fn worker_with(fake: &Fake, rules: Json, groups: Json, options: WorkerOptions) -> W {
    let config = parse_config(
        &json!({"plc": {"P": {"path": "x", "rule": rules, "group": groups}}}),
        Path::new("."),
    )
    .unwrap();
    let rules = Arc::new(Rules::new(&config).unwrap());
    let fakes = HashMap::from([("P".to_owned(), fake.clone())]);
    let out: Arc<Mutex<Vec<Event>>> = Arc::default();
    let (events, log) = (Arc::clone(&out), fake.clone());
    let on_event = Arc::new(move |event: Event| {
        if let Event::Values(_, changes) = &event {
            let mut tags: Vec<String> = changes.iter().map(|(t, _)| t.clone()).collect();
            tags.sort();
            log.lock().events.push(("publish".into(), tags));
        }
        lock(&events).push(event);
    });
    let worker = PlcWorker::new(
        config.plcs["P"].clone(),
        Fake::factory(&fakes),
        options,
        rules,
        on_event,
    );
    W {
        worker: Arc::new(worker),
        fake: fake.clone(),
        out,
        clock: FakeClock::new(usize::MAX),
    }
}

fn make_worker(fake: &Fake, rules: Json) -> W {
    worker_with(fake, rules, json!([]), options(100))
}

impl W {
    fn shared(&self) -> &Shared {
        &self.worker.shared
    }

    fn use_clock(&self) {
        lock(&self.shared().hooks).time = Some(Arc::clone(&self.clock) as Arc<dyn FakeTime>);
    }

    fn use_wait(&self, wait: impl FnMut(f64) -> bool + Send + 'static) {
        lock(&self.shared().hooks).time = Some(Arc::new(FakeWait {
            epoch: Instant::now(),
            wait: Mutex::new(Box::new(wait)),
        }));
    }

    /// Python's `worker.add_tags(tags, tier)`: the tier set at once, no grace.
    fn add_tags(&self, tags: &[&str], tier: u8) {
        let mut inner = lock(&self.shared().inner);
        for tag in tags {
            self.shared().set(&mut inner, tag, Some(tier));
        }
    }

    fn tiers(&self) -> Vec<(String, u8)> {
        self.worker.tiers().into_iter().collect()
    }

    /// Runs n ticks of a connected worker in this thread on the fake clock; returns its waits.
    fn poll(&self, n: usize, at: Vec<(usize, Step)>) -> Vec<f64> {
        self.use_clock();
        {
            let mut s = lock(&self.clock.0);
            s.waits.clear();
            s.n = n;
            s.at = at.into_iter().collect();
        }
        let mut plc = self.fake.plc();
        self.shared().check_version(&mut plc, true);
        *lock(&self.shared().state) = "connected";
        self.shared().poll(&mut plc).unwrap();
        self.clock.waits()
    }

    /// Runs the thread for n waits of the fake clock; returns once it ended.
    fn run_cycles(&self, n: usize) {
        lock(&self.clock.0).n = n;
        self.use_clock();
        self.worker.start();
        let handle = lock(&self.worker.thread).take().unwrap();
        handle.join().unwrap();
    }

    /// The entries published for a tag.
    fn published(&self, tag: &str) -> Vec<Entry> {
        lock(&self.out)
            .iter()
            .filter_map(|e| match e {
                Event::Values(_, changes) => changes
                    .iter()
                    .find(|(t, _)| t == tag)
                    .map(|(_, e)| e.clone()),
                _ => None,
            })
            .collect()
    }

    fn snap(&self, tag: &str) -> Option<Json> {
        self.worker.snapshot(tag).map(|e| e.to_json())
    }

    /// `snapshot[:2]`.
    fn vq(&self, tag: &str) -> Json {
        self.snap(tag).map_or(Json::Null, |e| json!([e[0], e[1]]))
    }

    /// Queues a write; the receiver gets its result.
    fn write(&self, tag: &str, value: Json) -> mpsc::Receiver<WriteResult> {
        let (tx, rx) = mpsc::channel();
        let value = crate::values::from_json(&value).unwrap();
        self.worker.write(
            tag,
            value,
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        );
        rx
    }

    fn run_writes(&self) -> Result<(), String> {
        self.shared().run_writes(&mut self.fake.plc())
    }

    fn stats(&self) -> Stats {
        self.worker.stats()
    }
}

fn ok(value: Json) -> WriteResult {
    WriteResult {
        ok: true,
        error: None,
        kind: None,
        value,
    }
}

fn failed(error: &str, kind: &str) -> WriteResult {
    WriteResult::failed(error, kind)
}

fn result(rx: &mpsc::Receiver<WriteResult>) -> WriteResult {
    rx.recv_timeout(Duration::from_secs(5)).unwrap()
}

fn step(f: impl FnMut(&Shared) + Send + 'static) -> Step {
    Box::new(f)
}

fn ti(type_: Option<&str>, dims: Option<Vec<u64>>) -> TypeInfo {
    TypeInfo {
        type_: type_.map(str::to_owned),
        dims,
    }
}

fn reads_of(fake: &Fake, tag: &str) -> usize {
    fake.lock()
        .reads
        .iter()
        .filter(|r| r.iter().any(|t| t == tag))
        .count()
}

// ------------------------------------------------------------------------------------------------ test_worker.py

#[test]
fn reconnect_backoff_schedule() {
    let fake = Fake::default();
    fake.lock().fail = true;
    let w = worker_with(&fake, json!([]), json!([]), options(250));
    lock(&w.shared().hooks).backoff = vec![1.0, 2.0, 5.0, 10.0];
    let delays: Arc<Mutex<Vec<f64>>> = Arc::default();
    let (d, f) = (Arc::clone(&delays), fake.clone());
    // a fake clock: record the delay and return at once
    w.use_wait(move |seconds| {
        let mut d = lock(&d);
        d.push(seconds);
        if d.len() == 6 {
            f.lock().fail = false; // the 7th attempt connects
        }
        false
    });
    w.worker.start();
    wait_for(|| w.worker.state() == "connected");
    w.worker.stop();
    assert_eq!(lock(&delays)[..6], [1.0, 2.0, 5.0, 10.0, 10.0, 10.0]);
    assert_eq!(fake.lock().opens, 7);
    assert_eq!(w.stats().reconnects, 6);
    let states: Vec<&str> = lock(&w.out)
        .iter()
        .filter_map(|e| match e {
            Event::Status(_, s) => Some(*s),
            _ => None,
        })
        .collect();
    assert_eq!(states[..3], ["disconnected", "connecting", "disconnected"]);
}

#[test]
fn backoff_restarts_after_a_good_connection() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.fail = true;
        f.set("T", Value::DInt(1)); // read every cycle, so the lost connection is noticed
    }
    let w = worker_with(&fake, json!([]), json!([]), options(10));
    lock(&w.shared().hooks).backoff = vec![1.0, 2.0, 5.0, 10.0];
    w.add_tags(&["T"], 1);
    let delays: Arc<Mutex<Vec<f64>>> = Arc::default();
    let (d, f) = (Arc::clone(&delays), fake.clone());
    w.use_wait(move |seconds| {
        if seconds >= 1.0 {
            // a backoff wait; cycle waits are under 10 ms
            let mut d = lock(&d);
            d.push(seconds);
            if d.len() == 2 {
                f.lock().fail = false;
            }
            return d.len() == 3; // stop the worker
        }
        f.lock().fail = true; // lose the connection after one good cycle
        false
    });
    w.worker.start();
    let handle = lock(&w.worker.thread).take().unwrap();
    handle.join().unwrap();
    assert_eq!(*lock(&delays), [1.0, 2.0, 1.0]);
}

#[test]
fn cycle_stats_and_overruns() {
    let fake = Fake::default();
    fake.lock().set("T", Value::DInt(1));
    let w = worker_with(&fake, json!([]), json!([]), options(0)); // every cycle overruns
    w.add_tags(&["T", "U"], 1);
    w.worker.start();
    wait_for(|| w.stats().overruns > 3);
    w.worker.stop();
    let stats = w.stats();
    assert_eq!(stats.reads_per_cycle, 1); // U doesn't exist, so it is skipped after its first read
    assert!(stats.last_cycle_ms.is_some());
    assert!(w.snap("U").is_some());
    assert_eq!(w.vq("T"), json!([1, "good"]));
}

#[test]
fn missing_tags_are_skipped_until_retry_or_reload() {
    let fake = Fake::default();
    fake.lock().set("T", Value::DInt(1));
    let w = worker_with(&fake, json!([]), json!([]), options(10));
    w.add_tags(&["T", "Gone"], 1);
    w.worker.start();
    wait_for(|| fake.lock().reads.len() > 5);
    assert_eq!(reads_of(&fake, "Gone"), 1); // asked once, then skipped
    assert_eq!(w.snap("Gone").unwrap()[1], "missing");

    {
        let mut f = fake.lock();
        f.set("Gone", Value::DInt(7)); // created online: the tag table reloads
        f.version = 2;
    }
    wait_for(|| w.vq("Gone") == json!([7, "good"]));

    lock(&w.shared().hooks).missing_retry = 0.05;
    fake.lock().values.remove("Gone"); // deleted without a reload being seen: retried after missing_retry
    wait_for(|| w.snap("Gone").unwrap()[1] == "missing");
    fake.lock().set("Gone", Value::DInt(8));
    wait_for(|| w.vq("Gone") == json!([8, "good"]));
    w.worker.stop();
}

#[test]
fn deadband_against_the_last_published_value() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.set("Speed", Value::LReal(10.0));
        f.set("Flag", Value::Bool(true));
    }
    let w = make_worker(
        &fake,
        json!([{"match": ["Speed", "Flag"], "deadband": 0.5}]),
    );
    w.add_tags(&["Speed", "Flag"], 1);
    let seen: Arc<Mutex<Vec<Json>>> = Arc::default();
    let stepper = |values: Vec<(&'static str, Value)>| {
        let (seen, fake) = (Arc::clone(&seen), fake.clone());
        step(move |s: &Shared| {
            let speed = lock(&s.inner).cache["Speed"].value.clone();
            lock(&seen).push(speed);
            for (k, v) in &values {
                fake.lock().set(k, v.clone());
            }
        })
    };
    let (f1, f2) = (fake.clone(), fake.clone());
    let fail = step(move |_| {
        f1.lock()
            .errors
            .insert("Speed".into(), TagError::new("lost reply", ErrorKind::Comm));
    });
    let recover = step(move |_| {
        let mut f = f2.lock();
        f.errors.remove("Speed");
        f.set("Speed", Value::LReal(10.7));
    });
    w.poll(
        6,
        vec![
            (1, stepper(vec![("Speed", Value::LReal(10.3))])),
            (
                2,
                stepper(vec![
                    ("Speed", Value::LReal(10.6)),
                    ("Flag", Value::Bool(false)),
                ]),
            ),
            (3, fail),
            (4, recover),
        ],
    );
    // the cache holds the latest value even when it is not published
    assert_eq!(*lock(&seen), [json!(10.0), json!(10.3)]);
    let speeds: Vec<Json> = w
        .published("Speed")
        .iter()
        .map(|e| json!([e.value, e.quality, e.error]))
        .collect();
    assert_eq!(
        speeds,
        [
            json!([10.0, "good", null]),
            json!([10.6, "good", null]), // 10.3 is within 0.5 of 10.0, 10.6 is not
            json!([10.6, "bad", {"kind": "comm", "message": "lost reply"}]), // bad keeps the last value
            json!([10.7, "good", null]), // a quality change always publishes
        ]
    );
    let flags: Vec<Json> = w
        .published("Flag")
        .iter()
        .map(|e| e.value.clone())
        .collect();
    assert_eq!(flags, [json!(true), json!(false)]); // bools have no deadband
}

#[test]
fn missing_has_no_value_and_stale_clears_the_error() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.set("T", Value::DInt(1));
        f.errors
            .insert("Bad".into(), TagError::new("busy", ErrorKind::Refused));
    }
    let w = make_worker(&fake, json!([]));
    w.add_tags(&["T", "Nope", "Bad"], 1);
    w.poll(1, vec![]);
    let nope = w.snap("Nope").unwrap();
    assert_eq!(json!([nope[0], nope[1]]), json!([null, "missing"]));
    assert_eq!(nope[3]["kind"], "not_found");
    assert_eq!(w.snap("Bad").unwrap()[1], "bad");
    assert!(!lock(&w.shared().inner).missing.contains_key("Bad")); // transient: retried next tick
    w.shared().mark_stale();
    for tag in ["T", "Nope", "Bad"] {
        let e = w.snap(tag).unwrap();
        assert_eq!((e[1].clone(), e[3].clone()), (json!("stale"), Json::Null));
    }
    assert_eq!(w.snap("T").unwrap()[0], 1);
}

#[test]
fn a_write_queued_during_a_multi_chunk_cycle_runs_before_the_next_chunk() {
    let fake = Fake::default();
    let tags: Vec<String> = (0..20).map(|i| format!("LongTagName{i:02}")).collect();
    {
        let mut f = fake.lock();
        for (i, t) in tags.iter().enumerate() {
            f.tags.insert(t.clone(), atomic("DINT", &[]));
            f.set(t, Value::DInt(i as i32));
        }
        f.connection_size = 120; // a few tags per packet, so a cycle reads in several chunks
    }
    let w = make_worker(&fake, json!([]));
    let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
    w.add_tags(&refs, 1);
    let (results_tx, results) = mpsc::channel();
    let worker = Arc::clone(&w.worker);
    fake.lock().on_read = Some(Box::new(move || {
        let tx = results_tx.clone();
        worker.write(
            "SpeedSP",
            Value::LInt(5),
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        );
    }));
    w.poll(1, vec![]);
    let events = fake.lock().events.clone();
    let reads: Vec<&(String, Vec<String>)> = events.iter().filter(|e| e.0 == "read").collect();
    assert!(reads.len() > 3); // several chunks
    let first = events.iter().position(|e| e == reads[0]).unwrap();
    // the first chunk's values are published, then the write and its read-back run before the second chunk
    let mut chunk = reads[0].1.clone();
    chunk.sort();
    assert_eq!(events[first + 1], ("publish".to_owned(), chunk));
    assert_eq!(
        events[first + 2..first + 4],
        [
            ("write".to_owned(), vec!["SpeedSP".to_owned()]),
            ("read".to_owned(), vec!["SpeedSP".to_owned()])
        ]
    );
    assert_eq!(&events[first + 4], reads[2]);
    assert!(tags.contains(&reads[2].1[0]));
    assert_eq!(result(&results), ok(json!(5)));
    assert!(tags.iter().all(|t| w.snap(t).is_some()));
}

#[test]
fn read_back_after_a_write() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.set("Speed", Value::LReal(1.0));
        f.set("Flags", Value::DInt(0b1010));
    }
    let w = make_worker(&fake, json!([{"match": "Speed", "deadband": 100}]));
    w.add_tags(&["Speed", "Flags"], 1);
    w.poll(1, vec![]);
    fake.lock().reads.clear();
    let future = w.write("Speed", json!(42.5));
    let bit = w.write("Flags.0", json!(true));
    w.run_writes().unwrap();
    assert_eq!(result(&future), ok(json!(42.5)));
    assert_eq!(result(&bit), ok(json!(true)));
    // a bit is read back with its word
    assert_eq!(
        fake.lock().reads,
        [
            vec!["Speed".to_owned()],
            vec!["Flags.0".into(), "Flags".into()]
        ]
    );
    assert_eq!(w.vq("Speed"), json!([42.5, "good"]));
    assert_eq!(w.published("Speed").last().unwrap().value, json!(42.5)); // published at once, no deadband
}

#[test]
fn write_results() {
    let fake = Fake::default();
    let w = make_worker(&fake, json!([]));
    assert_eq!(
        result(&w.write("T", json!(1))),
        failed("PLC not connected", "refused")
    );
    *lock(&w.shared().state) = "connected";
    fake.lock().write_error = Some(TagError::new("value does not fit", ErrorKind::BadValue));
    let future = w.write("T", json!(1));
    w.run_writes().unwrap();
    assert_eq!(result(&future), failed("value does not fit", "bad_value"));
    {
        let mut f = fake.lock();
        f.write_error = None;
        f.fail = true;
    }
    let future = w.write("T", json!(1));
    assert!(w.run_writes().is_err()); // the connection is gone: the worker reconnects
    let r = result(&future);
    assert!(!r.ok);
    assert_eq!(r.kind.as_deref(), Some("comm"));
    let future = w.write("T", json!(1));
    w.shared().fail_writes("PLC disconnected");
    assert_eq!(result(&future), failed("PLC disconnected", "comm"));
}

#[test]
fn descriptions_are_read_once_per_tag_table_version() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        for (k, v) in [("A", 5), ("B", 1), ("C", 2), ("R", 3)] {
            f.set(k, Value::DInt(v));
        }
        for t in ["A", "C"] {
            f.descriptions.insert(t.into(), format!("about {t}"));
        }
        f.desc_fail = Some("Boom".into());
        f.describes = true;
    }
    let w = make_worker(
        &fake,
        json!([{"match": "R", "description": "from the rule"}]),
    );
    w.add_tags(&["A", "B", "R", "A.1"], 1);
    w.poll(3, vec![]);
    let calls = || fake.lock().desc_calls.clone();
    let infos = || -> Vec<Vec<String>> {
        lock(&w.out)
            .iter()
            .filter_map(|e| match e {
                Event::Info(_, tags) => Some(tags.clone()),
                _ => None,
            })
            .collect()
    };
    // batched, bits and rule descriptions left out, then never again
    assert_eq!(calls(), [vec!["A".to_owned(), "B".into()]]);
    assert_eq!(infos(), [vec!["A".to_owned(), "B".into()]]);
    assert_eq!(w.worker.description("A").as_deref(), Some("about A"));
    assert_eq!(w.worker.description("B"), None);
    w.add_tags(&["C"], 1);
    w.poll(3, vec![]);
    assert_eq!(calls()[1..], [vec!["C".to_owned()]]);
    fake.lock().version = 2; // a reload: asked again for every subscribed tag
    w.poll(3, vec![]);
    assert_eq!(calls()[2..], [vec!["A".to_owned(), "B".into(), "C".into()]]);
    w.add_tags(&["Boom"], 1);
    w.poll(2, vec![]); // failure is not an error: no description
    assert_eq!(w.worker.description("Boom"), None);
    assert_eq!(infos().last().unwrap(), &["Boom".to_owned()]);
}

/// The Python worker skips descriptions for a driver without `get_tag_descriptions` (the mock, the plain fake):
/// no call and no info event.
#[test]
fn no_descriptions_without_a_driver_that_reads_them() {
    let fake = Fake::default();
    fake.lock().set("A", Value::DInt(5));
    let w = make_worker(&fake, json!([]));
    w.add_tags(&["A"], 1);
    w.poll(2, vec![]);
    assert!(fake.lock().desc_calls.is_empty());
    assert!(!lock(&w.out).iter().any(|e| matches!(e, Event::Info(..))));
}

#[test]
fn together_reads_the_struct_whole() {
    let tags = ["Line1.Motor.Speed", "Line1.Ready"];
    for (rules, whole) in [
        (json!([]), false),
        (json!([{"match": "Line1", "together": true}]), true),
    ] {
        let fake = Fake::default();
        plant(&mut fake.lock());
        let w = worker_with(
            &fake,
            rules,
            json!([]),
            WorkerOptions {
                whole_max_bytes: 0, // never whole by cost
                ..options(100)
            },
        );
        w.add_tags(&tags, 1);
        w.poll(1, vec![]);
        assert_eq!(
            fake.lock().reads.last().unwrap() == &["Line1".to_owned()],
            whole
        );
        assert_eq!(w.vq("Line1.Motor.Speed"), json!([1.5, "good"]));
    }
}

#[test]
fn type_info_version_and_types() {
    let fake = Fake::default();
    plant(&mut fake.lock());
    let w = make_worker(&fake, json!([]));
    assert_eq!(w.worker.type_info("Speed"), ti(None, None)); // not connected
    w.poll(1, vec![]);
    assert_eq!(w.worker.version(), json!(1));
    assert_eq!(w.worker.structure().types, fake.plc().catalog().type_map());
    let t = |tag: &str| w.worker.type_info(tag);
    assert_eq!(t("Speed"), ti(Some("REAL"), None));
    assert_eq!(t("Name1"), ti(Some("STRING"), None));
    assert_eq!(t("Arr"), ti(Some("Station"), Some(vec![5])));
    assert_eq!(t("Arr[1]"), ti(Some("Station"), None));
    assert_eq!(t("Line1.Data"), ti(Some("DINT"), Some(vec![4])));
    assert_eq!(t("Line1.Data[2]"), ti(Some("DINT"), None));
    assert_eq!(t("Count.3"), ti(Some("BOOL"), None));
    assert_eq!(t("Nope"), ti(None, None));
}

#[test]
fn read_back_is_published_when_the_deadband_held_back_the_cached_value() {
    let fake = Fake::default();
    fake.lock().set("Speed", Value::LReal(10.0));
    let w = make_worker(&fake, json!([{"match": "Speed", "deadband": 0.5}]));
    w.add_tags(&["Speed"], 1);
    let f = fake.clone();
    w.poll(
        2,
        vec![(1, step(move |_| f.lock().set("Speed", Value::LReal(10.3))))],
    );
    assert_eq!(w.snap("Speed").unwrap()[0], json!(10.3));
    assert_eq!(w.published("Speed").last().unwrap().value, json!(10.0));
    let future = w.write("Speed", json!(10.3));
    w.run_writes().unwrap();
    assert_eq!(result(&future), ok(json!(10.3)));
    assert_eq!(w.published("Speed").last().unwrap().value, json!(10.3));
    let n = lock(&w.out).len();
    let _ = w.write("Speed", json!(10.3));
    w.run_writes().unwrap();
    assert_eq!(lock(&w.out).len(), n); // already published: not again
}

#[test]
fn stop_runs_the_queued_writes_and_refuses_later_ones() {
    let fake = Fake::default();
    let w = worker_with(&fake, json!([]), json!([]), options(60_000)); // sits in its cycle wait
    w.worker.start();
    wait_for(|| w.worker.state() == "connected" && w.stats().last_ok_ts.is_some());
    let future = w.write("StartPB", json!(false));
    w.worker.stop();
    assert_eq!(result(&future), ok(json!(false)));
    assert_eq!(
        fake.lock().written(),
        [("StartPB".to_owned(), json!(false))]
    );
    assert_eq!(
        result(&w.write("StartPB", json!(true))),
        failed("PLC not connected", "refused")
    );
}

/// An intended difference: ciplink reports a BOOL array tag's dims in BOOLs (the Python test multiplies a tag's
/// dims by 32 too, which is a bug there); a BOOL array member's dims count 32-bit words.
#[test]
fn bool_arrays_are_bool_with_dims_in_bools() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.tags.insert("Flags".into(), atomic("DWORD", &[64])); // ciplink's BOOL[64]
        f.tags.insert("Box".into(), strct("BoxT", 8, &[]));
        f.types.insert(
            "BoxT".into(),
            udt(8, vec![("Bits", atomic("DWORD", &[1]))], None),
        );
    }
    let w = make_worker(&fake, json!([]));
    w.poll(1, vec![]);
    assert_eq!(
        w.worker.type_info("Flags"),
        ti(Some("BOOL"), Some(vec![64]))
    );
    assert_eq!(w.worker.type_info("Flags[3]"), ti(Some("BOOL"), None));
    assert_eq!(
        w.worker.type_info("Box.Bits"),
        ti(Some("BOOL"), Some(vec![32]))
    );
    let structure = w.worker.structure();
    assert_eq!(
        structure.tag_list[0],
        json!({"name": "Flags", "type": "BOOL", "dims": [64]})
    );
    assert_eq!(
        structure.types["BoxT"]["members"]["Bits"],
        json!({"type": "BOOL", "dims": [32]})
    );
}

#[test]
fn a_write_queued_while_the_worker_sleeps_runs_at_once() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.set("T", Value::DInt(1));
        f.set("SP", Value::DInt(0));
    }
    let w = worker_with(&fake, json!([]), json!([]), options(500));
    w.add_tags(&["T"], 1);
    w.worker.start();
    wait_for(|| w.worker.state() == "connected" && !fake.lock().reads.is_empty());
    std::thread::sleep(Duration::from_millis(20)); // the tick ran: the worker sleeps the rest of its 500 ms
    let start = Instant::now();
    assert!(result(&w.write("SP", json!(5))).ok);
    let latency = start.elapsed();
    w.worker.stop();
    assert!(latency < Duration::from_millis(100));
    assert_eq!(fake.lock().values["SP"], Value::LInt(5));
}

// ------------------------------------------------------------------------------------------------ test_tiers.py

#[test]
fn tier1_every_cycle_tier2_round_robin_tier3_never() {
    let fake = Fake::default();
    let t2: Vec<String> = (0..10).map(|i| format!("B{i}")).collect();
    {
        let mut f = fake.lock();
        f.set("A", Value::DInt(1));
        f.set("C", Value::DInt(3));
        for t in &t2 {
            f.set(t, Value::DInt(0));
        }
    }
    // 100 ms cycles, 0.5 s period: 5 slices of 2
    let w = worker_with(
        &fake,
        json!([]),
        json!([]),
        WorkerOptions {
            tier2_period: 0.5,
            ..options(100)
        },
    );
    w.add_tags(&["A"], 1);
    w.add_tags(&t2.iter().map(String::as_str).collect::<Vec<_>>(), 2);
    w.add_tags(&["C"], 3);
    w.run_cycles(21);
    let reads = fake.lock().reads.clone();
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let mut first = t2.clone();
    first.push("A".into());
    assert_eq!(sorted(reads[0].clone()), sorted(first)); // new tier-2 tags are read once at once
    let rest = &reads[1..21];
    assert!(rest.iter().all(|r| r.contains(&"A".to_owned())));
    assert!(!reads.iter().any(|r| r.contains(&"C".to_owned())));
    for i in (0..20).step_by(5) {
        // then every tier-2 tag once per 5 cycles
        let window: Vec<String> = rest[i..i + 5]
            .iter()
            .flatten()
            .filter(|t| t.starts_with('B'))
            .cloned()
            .collect();
        assert_eq!(sorted(window), sorted(t2.clone()));
    }
    assert!(rest.iter().all(|r| r.len() == 3));
    assert_eq!(w.stats().tags_per_cycle, 3);
    assert_eq!(
        Json::Object(w.worker.tier_counts()),
        json!({"tier1": 1, "tier2": 10, "tier3": 1})
    );
}

#[test]
fn a_new_tier2_tag_is_read_in_the_next_cycle_then_in_its_slice() {
    let w = worker_with(
        &Fake::default(),
        json!([]),
        json!([]),
        WorkerOptions {
            tier2_period: 10.0, // 100 slices
            ..options(100)
        },
    );
    let names: Vec<String> = (0..5).map(|i| format!("B{i}")).collect();
    w.add_tags(&names.iter().map(String::as_str).collect::<Vec<_>>(), 2);
    let now = 5.0;
    let tags = || w.shared().cycle_tags(&mut lock(&w.shared().inner), now).0;
    assert_eq!(tags().len(), 5);
    assert!(tags().len() <= 1);
    w.add_tags(&["New"], 2);
    assert!(tags().contains(&"New".to_owned()));
    w.worker.set_tier("Up", Some(1));
    w.worker.set_tier("Up", Some(2)); // was read every cycle: no extra read
    let t = tags();
    assert!(!t.contains(&"New".to_owned()) && !t.contains(&"Up".to_owned()));
}

#[test]
fn failed_group_is_read_whole_again_after_group_retry() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        plant(&mut f);
        f.errors
            .insert("Program:Station1.Motor".into(), other("General error"));
    }
    let w = worker_with(&fake, json!([]), json!([]), options(10));
    lock(&w.shared().hooks).group_retry = 1.0;
    w.add_tags(
        &[
            "Program:Station1.Motor.Speed",
            "Program:Station1.Motor.Current",
        ],
        1,
    );
    w.worker.start();
    wait_for(|| w.stats().group_fallbacks == 1);
    let failed_at = Instant::now();
    fake.lock().errors.remove("Program:Station1.Motor");
    wait_for(|| w.stats().reads_per_cycle == 2); // members one by one meanwhile
    wait_for(|| w.stats().reads_per_cycle == 1); // whole again after group_retry
    assert!(failed_at.elapsed() > Duration::from_millis(900));
    assert_eq!(w.stats().group_fallbacks, 1);
    w.worker.stop();
}

#[test]
fn grace_demotion() {
    let w = worker_with(&Fake::default(), json!([]), json!([]), options(100));
    w.use_clock();
    // one cycle that many seconds later
    let after = |seconds: f64| {
        let now = w.clock.advance(seconds);
        w.shared().cycle_tags(&mut lock(&w.shared().inner), now);
    };
    let t = |tier: u8| vec![("T".to_owned(), tier)];
    w.worker.set_tier("T", Some(1));
    w.worker.set_tier("T", None); // last tier-1 subscription gone
    assert_eq!(w.tiers(), t(2));
    after(5.0); // still polled, at tier 2, during the grace
    assert_eq!(w.tiers(), t(2));
    after(6.0);
    assert_eq!(w.tiers(), []);

    w.worker.set_tier("T", Some(1));
    w.worker.set_tier("T", Some(3)); // only a tier-3 subscription left: tier 2 for the grace, then 3
    after(5.0);
    assert_eq!(w.tiers(), t(2));
    after(6.0);
    assert_eq!(w.tiers(), t(3));

    w.worker.set_tier("T", Some(1));
    w.worker.set_tier("T", Some(2)); // still subscribed at tier 2: no grace, stays
    after(11.0);
    assert_eq!(w.tiers(), t(2));
    w.worker.set_tier("T", None); // leaving tier 2 needs no grace
    assert_eq!(w.tiers(), []);

    w.worker.set_tier("T", Some(1));
    w.worker.set_tier("T", None);
    w.worker.set_tier("T", Some(1)); // back within the grace
    after(11.0);
    assert_eq!(w.tiers(), t(1));
}

const MIXED: [&str; 21] = [
    "Line1.Motor.Speed",
    "Line1.Motor.Current",
    "Line1.Ready",
    "Line1.Data[1]",
    "Line1.Motor",
    "Arr[2].Motor.Speed",
    "Arr[2].Ready",
    "Program:Station1.Motor.Speed",
    "Program:Station1.Motor.Count.3",
    "Valve1.Open",
    "Valve1.EnableIn",
    "Pump1.Run",
    "Pump1.Speed",
    "Big1.A",
    "Big1.B",
    "Speed",
    "Count",
    "Line2.Data",
    "Line2.Ready",
    "Nope.X",
    "Name1",
];

fn planner_gives_the_same_results_as_plain_reads(error: Option<&str>) {
    let mut snapshots = Vec::new();
    let mut services = Vec::new();
    for planner_on in [true, false] {
        let fake = Fake::default();
        {
            let mut f = fake.lock();
            plant(&mut f);
            if let Some(e) = error {
                f.errors.insert(e.into(), other("General error"));
            }
        }
        let w = worker_with(
            &fake,
            json!([]),
            json!([]),
            WorkerOptions {
                planner: planner_on,
                ..options(100)
            },
        );
        w.add_tags(&MIXED, 1);
        w.run_cycles(3);
        let snap: HashMap<String, Json> = MIXED
            .iter()
            .filter_map(|t| w.snap(t).map(|e| ((*t).to_owned(), json!([e[0], e[1]]))))
            .collect();
        snapshots.push(snap);
        services.push(w.stats().reads_per_cycle);
        if error.is_some() && planner_on {
            assert_eq!(w.stats().group_fallbacks, 1); // then not grouped again
        }
    }
    assert_eq!(snapshots[0], snapshots[1]);
    assert_eq!(snapshots[0].len(), MIXED.len());
    // Nope.X is skipped once missing
    assert_eq!(services[1], MIXED.len() - 1);
    assert!(services[0] < services[1]);
}

#[test]
fn planner_gives_the_same_results_as_plain_reads_without_errors() {
    planner_gives_the_same_results_as_plain_reads(None);
}

#[test]
fn planner_gives_the_same_results_as_plain_reads_when_a_struct_read_fails() {
    planner_gives_the_same_results_as_plain_reads(Some("Line1"));
}

#[test]
fn replans_after_a_tag_table_reload() {
    let fake = Fake::default();
    plant(&mut fake.lock());
    let w = worker_with(&fake, json!([]), json!([]), options(10));
    w.add_tags(
        &[
            "Big1.A",
            "Big1.B",
            "Line1.Motor.Speed",
            "Line1.Motor.Current",
        ],
        1,
    );
    w.worker.start();
    wait_for(|| w.stats().reads_per_cycle == 3); // Big1 is too big, Line1.Motor read whole
    {
        let mut f = fake.lock();
        f.types["Big"].structure_size = 8; // an online edit: the type is now small
        f.tags["Big1"].structure_size = Some(8);
        f.version = 2;
    }
    wait_for(|| w.stats().reads_per_cycle == 2);
    fake.lock().reads.clear();
    wait_for(|| fake.lock().reads.len() > 2);
    let mut last = fake.lock().reads.last().unwrap().clone();
    last.sort();
    assert_eq!(last, ["Big1", "Line1.Motor"]);
    w.worker.stop();
}

// ------------------------------------------------------------------------------------------------ test_groups.py

fn groups() -> Json {
    json!([{"name": "fast", "rate_ms": 20, "match": "Fast*"}, {"name": "slow", "rate_ms": 500, "match": "Slow"}])
}

#[test]
fn group_rate_applies_only_at_tier1_and_stops_when_the_page_is_left() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.set("FastA", Value::DInt(1));
        f.set("FastB", Value::DInt(2));
        f.set("Plain", Value::DInt(3));
    }
    let w = worker_with(
        &fake,
        json!([]),
        groups(),
        WorkerOptions {
            grace_s: 0.0,
            ..options(100)
        },
    );
    w.add_tags(&["FastA", "FastB", "Plain"], 1);
    let waits = w.poll(20, vec![]); // 20 ticks of 20 ms = 4 cycles of 100 ms
    assert!(waits.iter().all(|&s| s == 0.02));
    assert_eq!(
        (reads_of(&fake, "FastA"), reads_of(&fake, "FastB")),
        (20, 20)
    );
    assert_eq!(reads_of(&fake, "Plain"), 4);
    let mut first = fake.lock().reads[0].clone();
    first.sort();
    assert_eq!(first, ["FastA", "FastB", "Plain"]); // due in the same tick: one plc.read
    assert_eq!(
        Json::Object(w.worker.group_stats()),
        json!({"fast": {"rate_ms": 20, "tags": 2, "last_period_ms": 20.0},
               "slow": {"rate_ms": 500, "tags": 0, "last_period_ms": null}})
    );

    w.worker.set_tier("FastA", Some(2)); // the page that showed them was left: tier 2 ignores groups
    w.worker.set_tier("FastB", Some(2));
    fake.lock().reads.clear();
    let waits = w.poll(10, vec![]);
    assert!(waits.iter().all(|&s| s == 0.1)); // no group has tier-1 tags: the tick is cycle_ms again
    assert_eq!(reads_of(&fake, "Plain"), 10);
    assert!(reads_of(&fake, "FastA") <= 2); // its tier-2 slices (3 s period), not every 20 ms
    assert_eq!(w.worker.group_stats()["fast"]["tags"], 0);

    w.worker.set_tier("FastA", Some(1)); // back on the page: due at the next tick, at the group rate again
    fake.lock().reads.clear();
    let waits = w.poll(5, vec![]);
    assert!(waits.iter().all(|&s| s == 0.02));
    assert_eq!(reads_of(&fake, "FastA"), 5);
}

#[test]
fn slow_group_reads_less_often_than_the_cycle() {
    let fake = Fake::default();
    {
        let mut f = fake.lock();
        f.set("Slow", Value::DInt(1));
        f.set("Plain", Value::DInt(2));
    }
    let w = worker_with(&fake, json!([]), groups(), options(100));
    w.add_tags(&["Slow", "Plain"], 1);
    let waits = w.poll(20, vec![]); // 2 s
    assert!(waits.iter().all(|&s| s == 0.1)); // a group slower than the cycle does not change the tick
    assert_eq!((reads_of(&fake, "Plain"), reads_of(&fake, "Slow")), (20, 4));
    assert_eq!(
        w.worker.group_stats()["slow"],
        json!({"rate_ms": 500, "tags": 1, "last_period_ms": 500.0})
    );
}

#[test]
fn tier2_slices_advance_only_on_cycle_boundaries() {
    let fake = Fake::default();
    let t2: Vec<String> = (0..10).map(|i| format!("B{i}")).collect();
    {
        let mut f = fake.lock();
        f.set("Fast", Value::DInt(0));
        for t in &t2 {
            f.set(t, Value::DInt(0));
        }
    }
    // 100 ms cycles: 5 slices of 2
    let w = worker_with(
        &fake,
        json!([]),
        groups(),
        WorkerOptions {
            tier2_period: 0.5,
            ..options(100)
        },
    );
    w.add_tags(&["Fast"], 1);
    w.add_tags(&t2.iter().map(String::as_str).collect::<Vec<_>>(), 2);
    w.poll(50, vec![]); // 50 ticks of 20 ms = 10 cycles
    let reads = fake.lock().reads.clone();
    assert_eq!(reads.len(), 50);
    assert_eq!(reads_of(&fake, "Fast"), 50);
    let with_t2: Vec<usize> = reads
        .iter()
        .enumerate()
        .filter(|(_, r)| r.iter().any(|t| t.starts_with('B')))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(with_t2, (0..50).step_by(5).collect::<Vec<_>>()); // only on the 100 ms boundaries
    assert!(t2.iter().all(|t| reads_of(&fake, t) >= 2)); // every slice came round twice
}
