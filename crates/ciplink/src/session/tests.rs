//! The session thread against a scripted fake protocol.
#![allow(clippy::unwrap_used)]

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

/// What the fake does next, and what it was asked to do.
#[derive(Default)]
struct Script {
    /// "open", "reopen", "close", "keep_alive", "read a,b", "write w".
    log: Vec<String>,
    open_ok: bool,
    reopen_ok: bool,
    /// The next read or write loses the link.
    break_next: bool,
    keep_alive_breaks: bool,
    values: HashMap<String, i32>,
}

#[derive(Clone, Default)]
struct Fake {
    script: Arc<Mutex<Script>>,
    link: Arc<AtomicBool>,
    unmerged: bool,
}

impl Fake {
    fn new() -> Self {
        let fake = Fake::default();
        {
            let mut s = fake.script();
            s.open_ok = true;
            s.reopen_ok = true;
        }
        fake
    }

    fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    fn log(&self) -> Vec<String> {
        self.script().log.clone()
    }

    fn count(&self, what: &str) -> usize {
        self.log().iter().filter(|l| l.starts_with(what)).count()
    }

    fn lose_link(&self, s: &mut Script) -> Option<Error> {
        if std::mem::take(&mut s.break_next) {
            self.link.store(false, Ordering::SeqCst);
            return Some(Error::comm("failed to receive reply"));
        }
        None
    }
}

impl Protocol for Fake {
    fn open(&mut self) -> Result<bool> {
        let mut s = self.script();
        s.log.push("open".into());
        if s.open_ok {
            self.link.store(true, Ordering::SeqCst);
            return Ok(true);
        }
        Err(Error::comm("failed to open a connection"))
    }

    fn reopen(&mut self) -> Result<bool> {
        let mut s = self.script();
        s.log.push("reopen".into());
        if s.reopen_ok {
            self.link.store(true, Ordering::SeqCst);
            return Ok(true);
        }
        Err(Error::comm("failed to open a connection"))
    }

    fn close(&mut self) -> Result<()> {
        self.script().log.push("close".into());
        self.link.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn drop_link(&mut self) {
        self.link.store(false, Ordering::SeqCst);
    }

    fn connected(&self) -> bool {
        self.link.load(Ordering::SeqCst)
    }

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>> {
        let mut s = self.script();
        s.log.push(format!("read {}", tags.join(",")));
        if let Some(err) = self.lose_link(&mut s) {
            return Err(err);
        }
        Ok(tags
            .iter()
            .map(|t| TagResult {
                tag: (*t).into(),
                value: Some(Value::DInt(s.values.get(*t).copied().unwrap_or(0))),
                data_type: Some("DINT".into()),
                error: None,
            })
            .collect())
    }

    fn merges_reads(&self) -> bool {
        !self.unmerged
    }

    fn write(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        let mut s = self.script();
        let names: Vec<_> = items.iter().map(|(t, _)| *t).collect();
        s.log.push(format!("write {}", names.join(",")));
        if let Some(err) = self.lose_link(&mut s) {
            return Err(err);
        }
        Ok(items
            .iter()
            .map(|(t, v)| TagResult {
                tag: (*t).into(),
                value: Some(v.clone()),
                data_type: None,
                error: None,
            })
            .collect())
    }

    fn keep_alive(&mut self) -> Result<()> {
        let mut s = self.script();
        s.log.push("keep_alive".into());
        if s.keep_alive_breaks {
            self.link.store(false, Ordering::SeqCst);
            return Err(Error::comm("failed to receive reply"));
        }
        Ok(())
    }
}

const WAIT: Duration = Duration::from_secs(5);

fn session(fake: &Fake, options: SessionOptions) -> Session<Fake> {
    Session::new(fake.clone(), options)
}

fn fast(min_ms: u64, max_ms: u64) -> SessionOptions {
    SessionOptions {
        reconnect: true,
        reconnect_min: Duration::from_millis(min_ms),
        reconnect_max: Duration::from_millis(max_ms),
        keep_alive: None,
    }
}

/// Holds the session thread in a job until the returned sender sends (or is dropped).
fn hold(s: &Session<Fake>) -> (Sender<()>, Handle<()>) {
    let (release, gate) = channel::<()>();
    let (started_tx, started) = channel();
    let h = s.call(move |_| {
        started_tx.send(()).unwrap();
        let _ = gate.recv();
        Ok(())
    });
    started.recv_timeout(WAIT).unwrap();
    (release, h)
}

fn events(s: &Session<Fake>) -> Receiver<ConnectionEvent> {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    s.set_connection_callback(Some(Box::new(move |e| {
        let _ = tx.lock().unwrap().send(e.clone());
    })));
    rx
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

fn values(r: Result<Vec<TagResult>>) -> Vec<(String, Option<Value>)> {
    r.unwrap().into_iter().map(|t| (t.tag, t.value)).collect()
}

// ------------------------------------------------------------------------------------------------ packing

#[test]
fn reads_queued_while_busy_are_one_read() {
    let fake = Fake::new();
    fake.script().values.insert("b".into(), 5);
    let s = session(&fake, SessionOptions::off());
    let (release, held) = hold(&s);
    let a = s.read(&["a"]);
    let b = s.read(&["b", "c"]);
    let c = s.read(&["c", "a"]);
    release.send(()).unwrap();
    held.wait().unwrap();
    assert_eq!(values(a.wait()), [("a".into(), Some(Value::DInt(0)))]);
    assert_eq!(
        values(b.wait()),
        [
            ("b".into(), Some(Value::DInt(5))),
            ("c".into(), Some(Value::DInt(0)))
        ]
    );
    assert_eq!(values(c.wait()).len(), 2);
    assert_eq!(fake.log(), ["read a,b,c"]);
}

#[test]
fn a_read_behind_a_write_waits_for_it() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let (release, _held) = hold(&s);
    let r1 = s.read(&["a"]);
    let w = s.write(&[("w", Value::DInt(1))]);
    let r2 = s.read(&["b"]);
    release.send(()).unwrap();
    r1.wait().unwrap();
    w.wait().unwrap();
    r2.wait().unwrap();
    assert_eq!(fake.log(), ["read a", "write w", "read b"]);
}

#[test]
fn lone_read_passes_its_list_unchanged() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    assert_eq!(s.read(&["a", "b", "a"]).wait().unwrap().len(), 3);
    assert_eq!(fake.log(), ["read a,b,a"]);
}

#[test]
fn unmerged_protocol_reads_each_caller_alone_in_order() {
    let mut fake = Fake::new();
    fake.unmerged = true;
    let s = session(&fake, SessionOptions::off());
    let (release, _held) = hold(&s);
    let a = s.read(&["a"]);
    let b = s.read(&["b", "a"]);
    release.send(()).unwrap();
    a.wait().unwrap();
    b.wait().unwrap();
    assert_eq!(fake.log(), ["read a", "read b,a"]);
}

// ------------------------------------------------------------------------------------------------ reconnect

#[test]
fn lost_link_reconnects_with_doubling_backoff() {
    let fake = Fake::new();
    let s = session(&fake, fast(5, 40));
    let rx = events(&s);
    assert!(s.open().wait().unwrap());
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), ConnectionEvent::Connected);
    assert_eq!(s.state(), ConnectionState::Connected);
    {
        let mut script = fake.script();
        script.reopen_ok = false;
        script.break_next = true;
    }
    assert_eq!(
        s.read(&["a"]).wait(),
        Err(Error::comm("failed to receive reply"))
    );
    assert_eq!(s.state(), ConnectionState::Reconnecting);
    assert_eq!(
        rx.recv_timeout(WAIT).unwrap(),
        ConnectionEvent::Disconnected {
            error: Error::comm("failed to receive reply")
        }
    );
    let mut delays = Vec::new();
    for _ in 0..5 {
        match rx.recv_timeout(WAIT).unwrap() {
            ConnectionEvent::Reconnecting { attempt, delay } => {
                assert_eq!(attempt as usize, delays.len() + 1);
                delays.push(delay.as_millis());
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(delays, [5, 10, 20, 40, 40]);
    fake.script().reopen_ok = true;
    loop {
        match rx.recv_timeout(WAIT).unwrap() {
            ConnectionEvent::Connected => break,
            ConnectionEvent::Reconnecting { delay, .. } => {
                assert_eq!(delay, Duration::from_millis(40))
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(s.state(), ConnectionState::Connected);
    assert!(s.read(&["a"]).wait().is_ok());
}

#[test]
fn failed_write_is_not_sent_again() {
    let fake = Fake::new();
    let s = session(&fake, fast(1, 5));
    let rx = events(&s);
    s.open().wait().unwrap();
    fake.script().break_next = true;
    assert!(s.write(&[("w", Value::DInt(1))]).wait().is_err());
    assert!(until(|| s.state() == ConnectionState::Connected));
    assert!(rx.iter().skip(1).any(|e| e == ConnectionEvent::Connected));
    assert!(s.read(&["a"]).wait().is_ok());
    assert_eq!(fake.count("write"), 1);
}

#[test]
fn requests_fail_fast_while_reconnecting() {
    let fake = Fake::new();
    let s = session(&fake, fast(1000, 1000));
    s.open().wait().unwrap();
    {
        let mut script = fake.script();
        script.reopen_ok = false;
        script.break_next = true;
    }
    let _ = s.read(&["a"]).wait();
    let started = Instant::now();
    let want = Err(Error::comm(
        "not connected, reconnecting: failed to receive reply",
    ));
    assert_eq!(s.read(&["a"]).wait(), want);
    assert_eq!(s.write(&[("w", Value::DInt(1))]).wait(), want);
    assert!(started.elapsed() < Duration::from_millis(20));
    // other calls still run
    assert_eq!(s.call(|_| Ok(3)).wait(), Ok(3));
}

#[test]
fn queued_reads_fail_on_loss_and_calls_still_run() {
    let fake = Fake::new();
    let s = session(&fake, fast(1000, 1000));
    s.open().wait().unwrap();
    fake.script().reopen_ok = false;
    let (release, _held) = hold(&s);
    fake.script().break_next = true;
    let w = s.write(&[("w", Value::DInt(1))]);
    let r = s.read(&["a"]);
    let c = s.call(|_| Ok("ran"));
    release.send(()).unwrap();
    assert_eq!(w.wait(), Err(Error::comm("failed to receive reply")));
    assert_eq!(
        r.wait(),
        Err(Error::comm(
            "not connected, reconnecting: failed to receive reply"
        ))
    );
    assert_eq!(c.wait(), Ok("ran"));
    assert_eq!(fake.count("read"), 0);
}

#[test]
fn reconnect_off_goes_closed() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let rx = events(&s);
    s.open().wait().unwrap();
    fake.script().break_next = true;
    assert!(s.read(&["a"]).wait().is_err());
    assert_eq!(s.state(), ConnectionState::Closed);
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), ConnectionEvent::Connected);
    assert!(matches!(
        rx.recv_timeout(WAIT).unwrap(),
        ConnectionEvent::Disconnected { .. }
    ));
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    // requests run as before
    assert!(s.read(&["a"]).wait().is_ok());
    assert_eq!(fake.count("reopen"), 0);
}

#[test]
fn failed_user_open_does_not_reconnect() {
    let fake = Fake::new();
    fake.script().open_ok = false;
    let s = session(&fake, fast(1, 1));
    assert!(s.open().wait().is_err());
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(s.state(), ConnectionState::Closed);
    assert_eq!(fake.count("reopen"), 0);
}

#[test]
fn close_stops_reconnecting() {
    let fake = Fake::new();
    let s = session(&fake, fast(5, 5));
    s.open().wait().unwrap();
    {
        let mut script = fake.script();
        script.reopen_ok = false;
        script.break_next = true;
    }
    let _ = s.read(&["a"]).wait();
    assert!(until(|| fake.count("reopen") >= 2));
    s.close().unwrap();
    let reopens = fake.count("reopen");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fake.count("reopen"), reopens);
    assert_eq!(s.state(), ConnectionState::Closed);
    assert_eq!(fake.count("close"), 1);
}

// ------------------------------------------------------------------------------------------------ keep-alive

#[test]
fn keep_alive_sent_when_idle() {
    let fake = Fake::new();
    let s = session(
        &fake,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(20)),
            ..SessionOptions::off()
        },
    );
    s.open().wait().unwrap();
    assert!(until(|| fake.count("keep_alive") >= 3));
}

#[test]
fn keep_alive_not_sent_while_busy() {
    let fake = Fake::new();
    let s = session(
        &fake,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(80)),
            ..SessionOptions::off()
        },
    );
    s.open().wait().unwrap();
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(250) {
        s.read(&["a"]).wait().unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fake.count("keep_alive"), 0);
}

#[test]
fn keep_alive_is_not_sent_before_open() {
    let fake = Fake::new();
    let s = session(
        &fake,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(5)),
            ..SessionOptions::off()
        },
    );
    s.read(&["a"]).wait().unwrap();
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(fake.count("keep_alive"), 0);
}

#[test]
fn failed_keep_alive_is_a_lost_link() {
    let fake = Fake::new();
    fake.script().keep_alive_breaks = true;
    let s = session(
        &fake,
        SessionOptions {
            keep_alive: Some(Duration::from_millis(20)),
            ..fast(1000, 1000)
        },
    );
    let rx = events(&s);
    s.open().wait().unwrap();
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), ConnectionEvent::Connected);
    assert_eq!(
        rx.recv_timeout(WAIT).unwrap(),
        ConnectionEvent::Disconnected {
            error: Error::comm("failed to receive reply")
        }
    );
    assert_eq!(s.state(), ConnectionState::Reconnecting);
}

// ------------------------------------------------------------------------------------------------ shutdown

#[test]
fn close_fails_queued_handles_and_joins() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    s.open().wait().unwrap();
    let (release, held) = hold(&s);
    let queued = s.read(&["a"]);
    let closer = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.close())
    };
    assert_eq!(queued.wait(), Err(Error::comm("driver closed")));
    assert!(!closer.is_finished());
    release.send(()).unwrap();
    assert_eq!(closer.join().unwrap(), Ok(()));
    assert_eq!(held.wait(), Ok(()));
    assert_eq!(fake.count("close"), 1);
    assert_eq!(fake.count("read"), 0);
    assert_eq!(s.state(), ConnectionState::Closed);
}

#[test]
fn request_after_close_restarts_the_thread() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    s.open().wait().unwrap();
    s.close().unwrap();
    assert!(s.read(&["a"]).wait().is_ok());
    assert!(s.open().wait().unwrap());
    assert_eq!(s.state(), ConnectionState::Connected);
    // close without a session thread running closes on the caller
    s.stop();
    s.close().unwrap();
    assert_eq!(fake.count("close"), 2);
}

#[test]
fn drop_from_a_callback_does_not_deadlock() {
    let fake = Fake::new();
    let s = Arc::new(Mutex::new(Some(session(&fake, SessionOptions::off()))));
    let (tx, rx) = channel();
    let h = s.lock().unwrap().as_ref().unwrap().read(&["a"]);
    let slot = Arc::clone(&s);
    h.on_complete(move |r| {
        let session = slot.lock().unwrap().take();
        drop(session);
        tx.send(r.is_ok()).unwrap();
    });
    assert_eq!(rx.recv_timeout(WAIT), Ok(true));
}

#[test]
fn stop_while_a_callback_closes_does_not_deadlock() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    let (entered_tx, entered) = channel();
    let (go_tx, go) = channel::<()>();
    let inner = Arc::clone(&s);
    s.read(&["a"]).on_complete(move |_| {
        entered_tx.send(()).unwrap();
        let _ = go.recv();
        inner.close().unwrap();
    });
    entered.recv_timeout(WAIT).unwrap();
    let stopper = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.stop())
    };
    std::thread::sleep(Duration::from_millis(20)); // stop holds close_lock and joins the session thread
    go_tx.send(()).unwrap();
    stopper.join().unwrap();
}

#[test]
fn close_from_a_callback_does_not_deadlock() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    s.open().wait().unwrap();
    let (tx, rx) = channel();
    let inner = Arc::clone(&s);
    s.read(&["a"]).on_complete(move |_| {
        tx.send(inner.close()).unwrap();
    });
    assert_eq!(rx.recv_timeout(WAIT), Ok(Ok(())));
    assert_eq!(fake.count("close"), 1);
}

#[test]
fn sync_read_inside_a_callback_completes() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    let (tx, rx) = channel();
    let inner = Arc::clone(&s);
    s.read(&["a"]).on_complete(move |_| {
        tx.send(inner.read(&["b"]).wait().is_ok()).unwrap();
    });
    assert_eq!(rx.recv_timeout(WAIT), Ok(true));
}

#[test]
fn wait_on_the_session_thread_fails() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    let inner = Arc::clone(&s);
    let got = s.call(move |_| Ok(inner.read(&["a"]).wait())).wait();
    assert_eq!(got, Ok(Err(own_thread_error())));
    assert_eq!(fake.count("read"), 0);
}

#[test]
fn panic_in_a_job_fails_it_and_session_continues() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    s.open().wait().unwrap();
    let h = s.call(|_| -> Result<()> { panic!("boom") });
    assert_eq!(
        h.wait_timeout(WAIT),
        Some(Err(Error::comm("internal error: boom")))
    );
    // the link is dropped: a reply may be unread
    assert!(!fake.link.load(Ordering::SeqCst));
    // a blocking wait resumes the panic on the caller, as before sessions
    s.open().wait().unwrap();
    let h = s.call(|_| -> Result<()> { panic!("boom") });
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.wait())).is_err());
    assert!(s.read(&["a"]).wait().is_ok());
    assert!(s.open().wait().unwrap());
}

#[test]
fn no_callback_after_drop_returns() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let calls = Arc::new(AtomicU32::new(0));
    for _ in 0..20 {
        let calls = Arc::clone(&calls);
        s.read(&["a"]).on_complete(move |_| {
            std::thread::sleep(Duration::from_millis(1));
            calls.fetch_add(1, Ordering::SeqCst);
        });
    }
    drop(s);
    let after_drop = calls.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(calls.load(Ordering::SeqCst), after_drop);
    assert_eq!(after_drop, 20); // all ran, completed or failed, before drop returned
}

#[test]
fn replaced_connection_callback_is_not_called_again() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let rx = events(&s);
    s.set_connection_callback(None);
    s.open().wait().unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
}

// ------------------------------------------------------------------------------------------------ subscriptions

fn every(ms: u64) -> SubscribeOptions {
    SubscribeOptions {
        interval: Duration::from_millis(ms),
        deadband: None,
    }
}

#[test]
fn subscribe_rejects_no_tags_and_a_zero_interval() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    assert!(s.subscribe(&[], every(10)).is_err());
    assert!(s.subscribe(&["a"], every(0)).is_err());
}

#[test]
fn two_subscriptions_due_together_share_one_read() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let (release, _held) = hold(&s);
    let a = s.subscribe(&["a"], every(60_000)).unwrap();
    let b = s.subscribe(&["b", "a"], every(60_000)).unwrap();
    release.send(()).unwrap();
    assert_eq!(a.recv_timeout(WAIT).unwrap().results.len(), 1);
    assert_eq!(b.recv_timeout(WAIT).unwrap().results.len(), 2);
    assert_eq!(fake.log(), ["read a,b"]);
}

#[test]
fn subscription_polls_at_its_interval_and_delivers_changes() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let sub = s.subscribe(&["a"], every(10)).unwrap();
    assert_eq!(
        sub.recv_timeout(WAIT).unwrap().results[0].value,
        Some(Value::DInt(0))
    );
    fake.script().values.insert("a".into(), 7);
    assert_eq!(
        sub.recv_timeout(WAIT).unwrap().results[0].value,
        Some(Value::DInt(7))
    );
    assert!(until(|| fake.count("read") >= 4));
    drop(sub);
    std::thread::sleep(Duration::from_millis(30));
    let reads = fake.count("read");
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(fake.count("read"), reads);
}

#[test]
fn no_polls_while_reconnecting_and_all_due_on_connect() {
    let fake = Fake::new();
    let s = session(&fake, fast(30, 30));
    s.open().wait().unwrap();
    let sub = s.subscribe(&["a"], every(5)).unwrap();
    sub.recv_timeout(WAIT).unwrap();
    {
        let mut script = fake.script();
        script.reopen_ok = false;
        script.break_next = true;
    }
    // the poll that lost the link fails the tag
    let lost = sub.recv_timeout(WAIT).unwrap();
    assert_eq!(
        lost.results[0].error.as_ref().map(|e| e.kind),
        Some(crate::ErrorKind::Comm)
    );
    assert!(until(|| s.state() == ConnectionState::Reconnecting));
    let reads = fake.count("read");
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(fake.count("read"), reads);
    fake.script().reopen_ok = true;
    let back = sub.recv_timeout(WAIT).unwrap();
    assert!(back.results[0].error.is_none());
}

#[test]
fn driver_close_ends_subscriptions() {
    let fake = Fake::new();
    let s = session(&fake, SessionOptions::off());
    let sub = s.subscribe(&["a"], every(10)).unwrap();
    assert!(sub.recv_timeout(WAIT).is_some());
    s.close().unwrap();
    assert!(sub.is_closed());
    while sub.recv().is_some() {}
}

#[test]
fn backoff_doubles_up_to_the_max() {
    let ms = Duration::from_millis;
    let d: Vec<_> = (1..=6).map(|a| backoff(ms(100), ms(1000), a)).collect();
    assert_eq!(d, [ms(100), ms(200), ms(400), ms(800), ms(1000), ms(1000)]);
    assert_eq!(backoff(ms(100), ms(1000), 200), ms(1000));
}

// ------------------------------------------------------------------------------------------------ review fixes

#[test]
fn unsubscribing_from_a_callback_while_stop_joins_does_not_deadlock() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    let slot = Arc::new(Mutex::new(Some(
        s.subscribe(&["a"], every(60_000)).unwrap(),
    )));
    let (entered_tx, entered) = channel();
    let (go_tx, go) = channel::<()>();
    let (done_tx, done) = channel();
    let go = Mutex::new(go);
    let inner = Arc::clone(&slot);
    slot.lock().unwrap().as_ref().unwrap().on_changes(move |_| {
        let _ = entered_tx.send(());
        let _ = go.lock().unwrap().recv_timeout(WAIT);
        let sub = inner.lock().unwrap().take();
        drop(sub);
        let _ = done_tx.send(());
    });
    entered.recv_timeout(WAIT).unwrap();
    let (stopped_tx, stopped) = channel();
    {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            s.stop();
            let _ = stopped_tx.send(());
        });
    }
    std::thread::sleep(Duration::from_millis(30)); // stop is joining the callback thread
    go_tx.send(()).unwrap();
    assert!(done.recv_timeout(WAIT).is_ok(), "the callback returned");
    assert!(stopped.recv_timeout(WAIT).is_ok(), "stop returned");
}

#[test]
fn removing_the_connection_callback_from_itself_while_stop_joins_does_not_deadlock() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    let (entered_tx, entered) = channel();
    let (go_tx, go) = channel::<()>();
    let (done_tx, done) = channel();
    let (entered_tx, go, done_tx) = (Mutex::new(entered_tx), Mutex::new(go), Mutex::new(done_tx));
    let inner = Arc::downgrade(&s);
    s.set_connection_callback(Some(Box::new(move |_| {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = go.lock().unwrap().recv_timeout(WAIT);
        if let Some(s) = inner.upgrade() {
            s.set_connection_callback(None);
        }
        let _ = done_tx.lock().unwrap().send(());
    })));
    s.open().wait().unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let (stopped_tx, stopped) = channel();
    {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            s.stop();
            let _ = stopped_tx.send(());
        });
    }
    std::thread::sleep(Duration::from_millis(30));
    go_tx.send(()).unwrap();
    assert!(done.recv_timeout(WAIT).is_ok(), "the callback returned");
    assert!(stopped.recv_timeout(WAIT).is_ok(), "stop returned");
}

/// Sets its flag to 1 when its drop starts and to 2 when the session it holds is dropped.
struct Holder(Option<Arc<Session<Fake>>>, Arc<AtomicU32>);

impl Drop for Holder {
    fn drop(&mut self) {
        self.1.store(1, Ordering::SeqCst);
        drop(self.0.take());
        self.1.store(2, Ordering::SeqCst);
    }
}

#[test]
fn a_subscription_callback_holding_the_last_session_handle_drops_it() {
    let fake = Fake::new();
    let s = Arc::new(session(&fake, SessionOptions::off()));
    let sub = s.subscribe(&["a"], every(10)).unwrap();
    let flag = Arc::new(AtomicU32::new(0));
    let holder = Holder(Some(Arc::clone(&s)), Arc::clone(&flag));
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    sub.on_changes(move |_| {
        let _ = &holder;
        let _ = tx.lock().unwrap().send(());
    });
    rx.recv_timeout(WAIT).unwrap();
    drop(sub);
    drop(s);
    assert!(
        until(|| flag.load(Ordering::SeqCst) == 2),
        "flag {}",
        flag.load(Ordering::SeqCst)
    );
}

fn due_times(s: &Session<Fake>) -> Vec<Instant> {
    s.shared.lock_queue().subs.iter().map(|e| e.next).collect()
}

#[test]
fn connecting_polls_at_once_and_keeps_each_phase() {
    let fake = Fake::new();
    let s = session(&fake, fast(5, 5));
    let a = s.subscribe(&["a"], every(60_000)).unwrap();
    let b = s.subscribe(&["b"], every(60_000)).unwrap();
    a.recv_timeout(WAIT).unwrap();
    b.recv_timeout(WAIT).unwrap();
    let due = due_times(&s);
    let polls = || fake.log().iter().filter(|l| *l == "read a,b").count();
    let before = polls();
    s.open().wait().unwrap();
    assert!(until(|| polls() > before), "polled on open");
    std::thread::sleep(Duration::from_millis(20)); // the poll finishes
    assert_eq!(due_times(&s), due);
    let before = polls();
    let rx = events(&s);
    fake.script().break_next = true;
    assert!(s.read(&["c"]).wait().is_err());
    assert!(until(|| matches!(
        rx.try_recv(),
        Ok(ConnectionEvent::Connected)
    )));
    assert!(until(|| polls() > before), "polled on reconnect");
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(due_times(&s), due);
}
