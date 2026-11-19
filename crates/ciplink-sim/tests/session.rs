//! The drivers on their sessions against the simulator: reads of several callers packed into one packet,
//! write order, reconnect, keep-alive, subscriptions and shutdown, checked on the wire.
#![allow(clippy::unwrap_used)]

use ciplink::cip::{CipOptions, TagResult};
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::metadata::TextEncoding;
use ciplink::session::{ConnectionEvent, ConnectionState, SessionOptions, SubscribeOptions};
use ciplink::slc::driver::SlcDriver;
use ciplink::transport::Connector;
use ciplink::{Error, Value};
use ciplink_sim::{Fault, FileConfig, Simulator, SlcConfig, TagConfig};
use serde_json::json;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);
const KEEP_ALIVE: [u8; 8] = [0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01];
const READ_TAG: u8 = 0x4C;
const WRITE_TAG: u8 = 0x4D;
const SYMBOL_LIST: u8 = 0x55;

fn sim() -> Simulator {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/sim/");
    Simulator::from_file(format!("{dir}example_controller.json")).unwrap()
}

fn logix_options() -> LogixOptions {
    LogixOptions {
        cip: CipOptions {
            socket_timeout: Some(Duration::from_millis(300)),
            ..CipOptions::default()
        },
        ..LogixOptions::default()
    }
}

fn off() -> SessionOptions {
    SessionOptions::off()
}

fn reconnecting(min_ms: u64, max_ms: u64) -> SessionOptions {
    SessionOptions {
        reconnect: true,
        reconnect_min: Duration::from_millis(min_ms),
        reconnect_max: Duration::from_millis(max_ms),
        keep_alive: None,
    }
}

fn logix(sim: &Simulator, session: SessionOptions) -> LogixDriver {
    let plc =
        LogixDriver::with_session("192.0.2.1", logix_options(), session, sim.connector()).unwrap();
    assert!(plc.open().unwrap());
    plc
}

fn events(set: impl FnOnce(ciplink::session::ConnectionCallback)) -> Receiver<ConnectionEvent> {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    set(Box::new(move |e| {
        let _ = tx.lock().unwrap().send(e.clone());
    }));
    rx
}

/// Holds the next request inside the simulator until the sender sends; the receiver says it is held.
fn hold_next(sim: &Simulator) -> (Sender<()>, Receiver<()>) {
    let (release, gate) = channel::<()>();
    let (started_tx, started) = channel();
    let mut armed = true;
    sim.on_request(move |_, _| {
        if std::mem::take(&mut armed) {
            let _ = started_tx.send(());
            let _ = gate.recv();
        }
    });
    (release, started)
}

/// The CIP message of a SendUnitData or SendRRData frame.
fn message(frame: &[u8]) -> Option<&[u8]> {
    match frame.get(..2)? {
        [0x70, 0x00] => frame.get(46..),
        [0x6F, 0x00] => frame.get(40..),
        _ => None,
    }
}

/// The service codes of a frame's message, those inside a Multiple Service Packet included.
fn services(frame: &[u8]) -> Vec<u8> {
    let Some(msg) = message(frame) else {
        return Vec::new();
    };
    if msg[0] != 0x0A {
        return vec![msg[0]];
    }
    let at = 2 + 2 * usize::from(msg[1]);
    let count = usize::from(u16::from_le_bytes([msg[at], msg[at + 1]]));
    (0..count)
        .map(|i| {
            let o = at + 2 + 2 * i;
            msg[at + usize::from(u16::from_le_bytes([msg[o], msg[o + 1]]))]
        })
        .collect()
}

fn count(frames: &[Vec<u8>], service: u8) -> usize {
    frames
        .iter()
        .map(|f| services(f).iter().filter(|&&s| s == service).count())
        .sum()
}

fn value(results: &[TagResult], i: usize) -> Value {
    assert!(results[i].error.is_none(), "{:?}", results[i]);
    results[i].value.clone().unwrap()
}

/// Waits for the Connected event, skipping the others.
fn reconnected(rx: &Receiver<ConnectionEvent>) -> bool {
    let deadline = Instant::now() + WAIT;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ConnectionEvent::Connected) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

fn until(what: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if what() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

// ------------------------------------------------------------------------------------------------ packing

#[test]
fn logix_reads_from_three_callers_share_one_packet() {
    let sim = sim();
    let plc = logix(&sim, off());
    let solo: Vec<_> = ["dint1", "int1", "real1"]
        .iter()
        .map(|t| value(&plc.read(&[t]).unwrap(), 0))
        .collect();
    sim.record(true);
    let (release, held) = hold_next(&sim);
    let first = plc.read_async(&["bool1"]);
    held.recv_timeout(WAIT).unwrap();
    let a = plc.read_async(&["dint1"]);
    let b = plc.read_async(&["int1"]);
    let c = plc.read_async(&["real1"]);
    release.send(()).unwrap();
    first.wait().unwrap();
    let got = [a.wait().unwrap(), b.wait().unwrap(), c.wait().unwrap()];
    sim.clear_hook();
    for (i, results) in got.iter().enumerate() {
        assert_eq!(results.len(), 1);
        assert_eq!(value(results, 0), solo[i]);
    }
    let frames = sim.take_received();
    assert_eq!(frames.len(), 2, "the held read, then one packet");
    assert_eq!(count(&frames[1..], READ_TAG), 3);
}

#[test]
fn the_same_tag_from_two_callers_is_read_once() {
    let sim = sim();
    let plc = logix(&sim, off());
    sim.record(true);
    let (release, held) = hold_next(&sim);
    let first = plc.read_async(&["bool1"]);
    held.recv_timeout(WAIT).unwrap();
    let a = plc.read_async(&["dint1"]);
    let b = plc.read_async(&["dint1", "int1"]);
    release.send(()).unwrap();
    first.wait().unwrap();
    let (a, b) = (a.wait().unwrap(), b.wait().unwrap());
    sim.clear_hook();
    assert_eq!(value(&a, 0), value(&b, 0));
    assert_eq!(b.len(), 2);
    let frames = sim.take_received();
    assert_eq!(count(&frames[1..], READ_TAG), 2);
}

fn run_sequence(plc: &LogixDriver, asynchronous: bool) -> Vec<Vec<TagResult>> {
    let reads: [&[&str]; 2] = [&["dint1"], &["udt1", "str1", "dint1"]];
    let write = [("dint1", Value::DInt(5))];
    if asynchronous {
        vec![
            plc.read_async(reads[0]).wait().unwrap(),
            plc.write_async(&write).wait().unwrap(),
            plc.read_async(reads[1]).wait().unwrap(),
        ]
    } else {
        vec![
            plc.read(reads[0]).unwrap(),
            plc.write(&write).unwrap(),
            plc.read(reads[1]).unwrap(),
        ]
    }
}

#[test]
fn async_and_sync_single_caller_send_the_same_bytes() {
    let mut sent = Vec::new();
    let mut results = Vec::new();
    for asynchronous in [false, true] {
        let sim = sim();
        let plc = logix(&sim, off());
        sim.record(true);
        results.push(run_sequence(&plc, asynchronous));
        sent.push(sim.take_received());
    }
    assert!(!sent[0].is_empty());
    assert_eq!(sent[0], sent[1]);
    assert_eq!(results[0], results[1]);
}

#[test]
fn write_then_read_from_two_callers_reads_the_write() {
    let sim = sim();
    let plc = logix(&sim, off());
    let (release, held) = hold_next(&sim);
    let first = plc.read_async(&["bool1"]);
    held.recv_timeout(WAIT).unwrap();
    let write = std::thread::scope(|s| {
        s.spawn(|| plc.write_async(&[("dint1", Value::DInt(77))]))
            .join()
            .unwrap()
    });
    let read = std::thread::scope(|s| s.spawn(|| plc.read_async(&["dint1"])).join().unwrap());
    release.send(()).unwrap();
    first.wait().unwrap();
    assert!(write.wait().unwrap()[0].error.is_none());
    assert_eq!(value(&read.wait().unwrap(), 0), Value::DInt(77));
    sim.clear_hook();
}

// ------------------------------------------------------------------------------------------------ reconnect

#[test]
fn logix_reconnects_after_close_connections() {
    let sim = sim();
    let plc = logix(&sim, reconnecting(10, 80));
    let rx = events(|cb| plc.set_connection_callback(Some(cb)));
    sim.inject(Fault::RefuseConnections);
    sim.inject(Fault::CloseConnections);
    let err = plc.read(&["dint1"]).unwrap_err();
    assert!(matches!(err, Error::Comm(_)), "{err:?}");
    assert_eq!(plc.connection_state(), ConnectionState::Reconnecting);
    let fast = plc.read(&["dint1"]).unwrap_err();
    assert!(
        fast.to_string()
            .starts_with("not connected, reconnecting: "),
        "{fast}"
    );
    assert!(matches!(
        rx.recv_timeout(WAIT).unwrap(),
        ConnectionEvent::Disconnected { .. }
    ));
    std::thread::sleep(Duration::from_millis(200));
    sim.clear_faults();
    let mut delays = Vec::new();
    loop {
        match rx.recv_timeout(WAIT).unwrap() {
            ConnectionEvent::Reconnecting { attempt, delay } => {
                assert_eq!(attempt as usize, delays.len() + 1);
                delays.push(delay);
            }
            ConnectionEvent::Connected => break,
            other => panic!("{other:?}"),
        }
    }
    assert!(delays.len() >= 3, "{delays:?}");
    for (i, d) in delays.iter().enumerate() {
        let want = Duration::from_millis(10 << i.min(3)).min(Duration::from_millis(80));
        assert_eq!(*d, want, "{delays:?}");
    }
    assert_eq!(plc.connection_state(), ConnectionState::Connected);
    assert!(plc.read(&["dint1"]).unwrap()[0].error.is_none());
}

#[test]
fn the_triggering_write_is_sent_once() {
    let sim = sim();
    let plc = logix(&sim, reconnecting(5, 5));
    plc.set_use_instance_ids(false); // no version check before the write: the write is the request lost
    let rx = events(|cb| plc.set_connection_callback(Some(cb)));
    sim.record(true);
    sim.inject(Fault::CloseConnections);
    assert!(plc.write(&[("dint1", Value::DInt(3))]).is_err());
    assert!(reconnected(&rx));
    assert!(plc.read(&["dint1"]).unwrap()[0].error.is_none());
    assert_eq!(count(&sim.take_received(), WRITE_TAG), 1);
}

#[test]
fn reconnect_keeps_tags_when_the_table_is_unchanged() {
    let sim = sim();
    let plc = logix(&sim, reconnecting(5, 5));
    let tags = plc.tags();
    assert!(!tags.is_empty());
    let info = plc.info_py();
    let description = || {
        plc.get_tag_description("Program:MainProgram.p_dint", 0x7F, TextEncoding::Utf8)
            .unwrap()
    };
    let described = description();
    let rx = events(|cb| plc.set_connection_callback(Some(cb)));
    sim.record(true);
    sim.inject(Fault::CloseConnections);
    assert!(plc.read(&["dint1"]).is_err());
    assert!(reconnected(&rx));
    assert!(plc.read(&["dint1"]).unwrap()[0].error.is_none());
    let frames = sim.take_received();
    assert!(
        count(&frames, 0x54) + count(&frames, 0x5B) > 0,
        "reconnected"
    );
    assert_eq!(count(&frames, SYMBOL_LIST), 0);
    assert_eq!(plc.tags(), tags);
    // the programs, tasks and modules are kept with the tags: program-scoped descriptions still resolve
    assert_eq!(plc.info_py(), info);
    assert_eq!(description(), described);
}

/// A connector to `sim` whose connects after the first wait for `release` (at most WAIT); `entered` says one
/// waits.
fn gated(sim: &Simulator) -> (Connector, Sender<()>, Receiver<()>) {
    let inner = sim.connector();
    let (release, gate) = channel::<()>();
    let (entered_tx, entered) = channel();
    let (gate, entered_tx) = (Mutex::new(gate), Mutex::new(entered_tx));
    let calls = AtomicU32::new(0);
    let connector: Connector = Box::new(move |host, port, timeout| {
        if calls.fetch_add(1, Ordering::SeqCst) > 0 {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = gate.lock().unwrap().recv_timeout(WAIT);
        }
        inner(host, port, timeout)
    });
    (connector, release, entered)
}

/// Runs `f`, asserting it returns well before a stalled connect would let it.
fn quick<T>(f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let got = f();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
    got
}

#[test]
fn logix_connected_does_not_wait_for_a_reconnect_in_progress() {
    let sim = sim();
    let (connector, release, entered) = gated(&sim);
    let plc =
        LogixDriver::with_session("192.0.2.1", logix_options(), reconnecting(5, 5), connector)
            .unwrap();
    assert!(plc.open().unwrap());
    assert!(quick(|| plc.connected()));
    sim.inject(Fault::CloseConnections);
    assert!(plc.read(&["dint1"]).is_err());
    entered.recv_timeout(WAIT).unwrap();
    assert!(!quick(|| plc.connected()));
    release.send(()).unwrap();
    assert!(until(|| plc.connected()));
}

#[test]
fn slc_connected_does_not_wait_for_a_reconnect_in_progress() {
    let sim = slc_sim();
    let (connector, release, entered) = gated(&sim);
    let d = SlcDriver::with_session(
        "192.0.2.1",
        SlcDriver::default_options(),
        reconnecting(5, 5),
        connector,
    )
    .unwrap();
    assert!(d.open().unwrap());
    d.read(&["N7:0"]).unwrap();
    assert!(quick(|| d.connected() && d.target_connected()));
    sim.inject(Fault::CloseConnections);
    assert!(d.read(&["N7:0"]).is_err());
    entered.recv_timeout(WAIT).unwrap();
    assert!(!quick(|| d.connected() || d.target_connected()));
    release.send(()).unwrap();
    assert!(until(|| d.connected()));
}

#[test]
fn reconnect_uploads_when_the_table_changed() {
    let sim = sim();
    let plc = logix(&sim, reconnecting(5, 5));
    let rx = events(|cb| plc.set_connection_callback(Some(cb)));
    sim.inject(Fault::RefuseConnections);
    sim.inject(Fault::CloseConnections);
    assert!(plc.read(&["dint1"]).is_err());
    sim.with_logix(|l| l.add_tag(None, &TagConfig::new("fresh", "DINT").value(json!(5))))
        .unwrap()
        .unwrap();
    sim.record(true);
    sim.clear_faults();
    assert!(reconnected(&rx));
    assert!(count(&sim.take_received(), SYMBOL_LIST) > 0);
    assert!(plc.tags().contains_key("fresh"));
    assert_eq!(value(&plc.read(&["fresh"]).unwrap(), 0), Value::DInt(5));
}

// ------------------------------------------------------------------------------------------------ keep-alive

#[test]
fn idle_logix_sends_keep_alive() {
    let sim = sim();
    let plc = logix(
        &sim,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(50)),
            ..off()
        },
    );
    sim.record(true);
    std::thread::sleep(Duration::from_millis(300));
    let frames = sim.take_received();
    let sequences: Vec<u16> = frames
        .iter()
        .filter(|f| message(f) == Some(&KEEP_ALIVE[..]))
        .map(|f| {
            assert_eq!(
                f[..2],
                [0x70, 0x00],
                "connected: the CIP connection is open"
            );
            u16::from_le_bytes([f[44], f[45]])
        })
        .collect();
    assert!(sequences.len() >= 3, "{sequences:?}");
    assert_eq!(sequences.len(), frames.len());
    assert!(sequences.windows(2).all(|w| w[1] == w[0] + 1));
    assert_eq!(plc.connection_state(), ConnectionState::Connected);
}

#[test]
fn keep_alive_finds_a_link_lost_while_idle() {
    let sim = sim();
    let plc = logix(
        &sim,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(30)),
            ..reconnecting(1000, 1000)
        },
    );
    let rx = events(|cb| plc.set_connection_callback(Some(cb)));
    sim.inject(Fault::CloseConnections);
    assert!(matches!(
        rx.recv_timeout(WAIT).unwrap(),
        ConnectionEvent::Disconnected { .. }
    ));
    assert_eq!(plc.connection_state(), ConnectionState::Reconnecting);
}

// ------------------------------------------------------------------------------------------------ subscriptions

fn every(ms: u64) -> SubscribeOptions {
    SubscribeOptions {
        interval: Duration::from_millis(ms),
        deadband: None,
    }
}

#[test]
fn subscription_delivers_changes_from_the_sim() {
    let sim = sim();
    let plc = logix(&sim, off());
    let sub = plc.subscribe(&["dint1", "int1"], every(20)).unwrap();
    let first = sub.recv_timeout(WAIT).unwrap();
    assert_eq!(first.results.len(), 2);
    sim.set_value("dint1", &json!(99)).unwrap();
    let next = sub.recv_timeout(WAIT).unwrap();
    assert_eq!(next.results.len(), 1);
    assert_eq!(next.results[0].tag, "dint1");
    assert_eq!(next.results[0].value, Some(Value::DInt(99)));
}

#[test]
fn subscription_reports_a_failing_tag() {
    let sim = sim();
    let plc = logix(&sim, off());
    let sub = plc.subscribe(&["dint1", "int1"], every(20)).unwrap();
    sub.recv_timeout(WAIT).unwrap();
    sim.inject(Fault::TagStatus {
        tag: "int1".into(),
        status: 0x05,
        ext: None,
    });
    let next = sub.recv_timeout(WAIT).unwrap();
    assert_eq!(next.results.len(), 1);
    assert_eq!(next.results[0].tag, "int1");
    assert!(next.results[0].error.is_some());
}

#[test]
fn dropped_subscription_stops_polling() {
    let sim = sim();
    let plc = logix(&sim, off());
    let sub = plc.subscribe(&["dint1"], every(10)).unwrap();
    sub.recv_timeout(WAIT).unwrap();
    assert!(until(|| sim.requests() > 0));
    drop(sub);
    std::thread::sleep(Duration::from_millis(30));
    let requests = sim.requests();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(sim.requests(), requests);
}

// ------------------------------------------------------------------------------------------------ shutdown

#[test]
fn close_with_queued_requests_fails_them() {
    let sim = sim();
    let plc = logix(&sim, off());
    let (release, held) = hold_next(&sim);
    let first = plc.read_async(&["dint1"]);
    held.recv_timeout(WAIT).unwrap();
    let queued = [plc.read_async(&["int1"]), plc.read_async(&["real1"])];
    std::thread::scope(|s| {
        let closer = s.spawn(|| plc.close());
        for q in queued {
            assert_eq!(q.wait(), Err(Error::comm("driver closed")));
        }
        release.send(()).unwrap();
        assert_eq!(closer.join().unwrap(), Ok(()));
    });
    assert!(first.wait().is_ok());
    assert!(!plc.connected());
    assert_eq!(plc.connection_state(), ConnectionState::Closed);
    sim.clear_hook();
}

// ------------------------------------------------------------------------------------------------ SLC

fn slc_sim() -> Simulator {
    Simulator::new(SlcConfig {
        files: vec![FileConfig {
            values: (0..10).map(|i| json!(i * 10)).collect(),
            ..FileConfig::new(7, "N", 10)
        }],
        ..SlcConfig::default()
    })
    .unwrap()
}

fn slc(sim: &Simulator, session: SessionOptions) -> SlcDriver {
    let d = SlcDriver::with_session(
        "192.0.2.1",
        SlcDriver::default_options(),
        session,
        sim.connector(),
    )
    .unwrap();
    assert!(d.open().unwrap());
    d
}

#[test]
fn slc_concurrent_reads_are_correct_and_unmerged() {
    let sim = slc_sim();
    let d = slc(&sim, off());
    d.read(&["N7:0"]).unwrap(); // the Forward Open
    sim.record(true);
    std::thread::scope(|s| {
        for t in 0..4 {
            let d = &d;
            s.spawn(move || {
                for i in 0..10 {
                    let address = format!("N7:{}", (t + i) % 10);
                    let handles = [d.read_async(&[&address]), d.read_async(&[&address])];
                    for h in handles {
                        let r = h.wait().unwrap();
                        assert_eq!(value(&r, 0), Value::Int((((t + i) % 10) * 10) as i16));
                    }
                }
            });
        }
    });
    // one PCCC request per address of each caller: nothing merged
    assert_eq!(sim.take_received().len(), 80);
}

#[test]
fn slc_bad_address_fails_only_its_caller() {
    let sim = slc_sim();
    let d = slc(&sim, off());
    d.read(&["N7:0"]).unwrap();
    let (good, bad, other) = {
        // hold the connection so the three queue together
        let _conn = d.cip().lock();
        (
            d.read_async(&["N7:1"]),
            d.read_async(&["X7:bad"]),
            d.read_async(&["N7:2"]),
        )
    };
    assert_eq!(value(&good.wait().unwrap(), 0), Value::Int(10));
    let err = bad.wait().unwrap_err();
    assert!(matches!(err, Error::Request { .. }), "{err:?}");
    assert_eq!(value(&other.wait().unwrap(), 0), Value::Int(20));
}

#[test]
fn slc_reconnects_and_keeps_alive() {
    let sim = slc_sim();
    let d = slc(
        &sim,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(30)),
            ..reconnecting(5, 5)
        },
    );
    d.read(&["N7:0"]).unwrap();
    sim.record(true);
    std::thread::sleep(Duration::from_millis(150));
    let idle = sim.take_received();
    assert!(
        idle.iter()
            .filter(|f| message(f) == Some(&KEEP_ALIVE[..]))
            .count()
            >= 2
    );
    let rx = events(|cb| d.set_connection_callback(Some(cb)));
    sim.inject(Fault::CloseConnections);
    assert!(reconnected(&rx));
    assert_eq!(value(&d.read(&["N7:3"]).unwrap(), 0), Value::Int(30));
}
