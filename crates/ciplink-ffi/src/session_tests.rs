#![allow(clippy::unwrap_used)]

use super::*;
use ciplink_sim::{Fault, Server, Simulator};
use std::sync::atomic::{AtomicUsize, Ordering};

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn take(p: *mut c_char) -> String {
    assert!(!p.is_null());
    // SAFETY: a live string from the library, freed right after copying.
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
    // SAFETY: as above.
    unsafe { ciplink_string_free(p) };
    s
}

fn thread_error() -> String {
    // SAFETY: NULL asks for the calling thread's error.
    take(unsafe { ciplink_last_error(ptr::null()) })
}

fn serve(config: &str) -> (Simulator, Server) {
    let path = format!("{}/../../tools/sim/{config}", env!("CARGO_MANIFEST_DIR"));
    let sim = Simulator::from_file(path).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    (sim, server)
}

struct Driver(*mut CiplinkDriver);

// SAFETY: driver handles are thread-safe; the tests share one across threads on purpose.
unsafe impl Send for Driver {}
// SAFETY: as above.
unsafe impl Sync for Driver {}

impl Drop for Driver {
    fn drop(&mut self) {
        // SAFETY: made by a `_new` in this test, freed once.
        unsafe { ciplink_driver_free(self.0) };
    }
}

type New =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut *mut CiplinkDriver) -> CiplinkStatus;

fn driver(new: New, server: &Server, options: &str) -> Driver {
    let path = cstr(&format!("127.0.0.1:{}", server.port()));
    let options = cstr(options);
    let mut h = ptr::null_mut();
    // SAFETY: valid pointers for the call.
    let st = unsafe { new(path.as_ptr(), options.as_ptr(), &mut h) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    Driver(h)
}

fn open(new: New, server: &Server, options: &str) -> Driver {
    let d = driver(new, server, options);
    // SAFETY: a live handle.
    let st = unsafe { ciplink_open(d.0) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    d
}

/// What the callbacks of a test saw: (status, text) per completion, text per change or event.
#[derive(Default)]
struct Seen {
    items: Mutex<Vec<(CiplinkStatus, String)>>,
    ready: Condvar,
}

impl Seen {
    fn push(&self, status: CiplinkStatus, text: &str) {
        self.items.lock().unwrap().push((status, text.to_owned()));
        self.ready.notify_all();
    }

    fn texts(&self) -> Vec<String> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .map(|(_, t)| t.clone())
            .collect()
    }

    /// Waits up to 5 s until `pred` holds for the items seen.
    fn wait_for(&self, pred: impl Fn(&[(CiplinkStatus, String)]) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut items = self.items.lock().unwrap();
        while !pred(&items) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            items = self.ready.wait_timeout(items, left).unwrap().0;
        }
        true
    }

    fn as_user(&self) -> *mut c_void {
        (self as *const Seen).cast_mut().cast()
    }
}

unsafe extern "C" fn on_done(user: *mut c_void, status: CiplinkStatus, json: *const c_char) {
    // SAFETY: the tests pass a `Seen` that outlives the driver, and a string valid during the call.
    let (seen, text) = unsafe { (&*user.cast::<Seen>(), CStr::from_ptr(json)) };
    seen.push(status, text.to_str().unwrap());
}

unsafe extern "C" fn on_text(user: *mut c_void, json: *const c_char) {
    // SAFETY: as on_done.
    let (seen, text) = unsafe { (&*user.cast::<Seen>(), CStr::from_ptr(json)) };
    seen.push(CiplinkStatus::Ok, text.to_str().unwrap());
}

fn read_async(
    d: &Driver,
    tags: &[&str],
    seen: Option<&Seen>,
) -> (CiplinkStatus, *mut CiplinkRequest) {
    let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
    let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
    let mut req = ptr::null_mut();
    let (done, user): (CiplinkDone, *mut c_void) = match seen {
        Some(s) => (Some(on_done), s.as_user()),
        None => (None, ptr::null_mut()),
    };
    // SAFETY: valid pointers for the call; `seen` outlives the driver.
    let st = unsafe { ciplink_read_async(d.0, ptrs.as_ptr(), ptrs.len(), done, user, &mut req) };
    (st, req)
}

fn write_async(d: &Driver, items: &str, seen: Option<&Seen>) -> *mut CiplinkRequest {
    let items = cstr(items);
    let mut req = ptr::null_mut();
    let (done, user): (CiplinkDone, *mut c_void) = match seen {
        Some(s) => (Some(on_done), s.as_user()),
        None => (None, ptr::null_mut()),
    };
    // SAFETY: valid pointers for the call.
    let st = unsafe { ciplink_write_async(d.0, items.as_ptr(), done, user, &mut req) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    req
}

/// Waits for and frees a request: its status and result (or error message).
fn wait(req: *mut CiplinkRequest, timeout_ms: i64) -> (CiplinkStatus, String) {
    let mut out = ptr::null_mut();
    // SAFETY: a live request; `out` is writable.
    let st = unsafe { ciplink_request_wait(req, timeout_ms, &mut out) };
    let text = if st == CiplinkStatus::Ok {
        take(out)
    } else {
        assert!(out.is_null());
        thread_error()
    };
    (st, text)
}

fn free(req: *mut CiplinkRequest) {
    // SAFETY: a live request, freed once.
    unsafe { ciplink_request_free(req) };
}

fn value_of(json: &str, i: usize) -> Json {
    let parsed: Json = serde_json::from_str(json).unwrap();
    parsed[i]["value"].clone()
}

// ------------------------------------------------------------------------------------------------ requests

#[test]
fn async_write_then_read_complete_through_callback_and_wait() {
    let (_sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    let seen = Seen::default();

    let w = write_async(&d, r#"[["dint_ary[7]", 77]]"#, Some(&seen));
    let (st, r) = read_async(&d, &["dint_ary[7]", "real1"], Some(&seen));
    assert_eq!(st, CiplinkStatus::Ok);

    let (st, json) = wait(r, -1);
    assert_eq!(st, CiplinkStatus::Ok, "{json}");
    assert_eq!(value_of(&json, 0), serde_json::json!(77)); // the write queued first ran first
    // SAFETY: a live request.
    assert!(unsafe { ciplink_request_done(r) });
    let (st, _) = wait(r, 0);
    assert_eq!(st, CiplinkStatus::InvalidArgument); // already taken
    free(r);

    let (st, json) = wait(w, 1000);
    assert_eq!(st, CiplinkStatus::Ok);
    assert!(json.contains("\"error\":null"), "{json}");
    free(w);

    assert!(seen.wait_for(|s| s.len() == 2));
    let texts = seen.texts();
    assert!(texts[0].contains("dint_ary[7]")); // callbacks in completion order: the write first
    assert_eq!(value_of(&texts[1], 0), serde_json::json!(77));
}

#[test]
fn a_request_can_be_freed_before_it_completes_and_done_still_fires() {
    let (sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    sim.inject(Fault::Delay(Duration::from_millis(100)));
    let seen = Seen::default();
    let (st, r) = read_async(&d, &["dint1"], Some(&seen));
    assert_eq!(st, CiplinkStatus::Ok);
    free(r);
    assert!(seen.wait_for(|s| s.len() == 1));
    assert_eq!(seen.items.lock().unwrap()[0].0, CiplinkStatus::Ok);
}

#[test]
fn wait_times_out_and_the_request_carries_on() {
    let (sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    sim.inject(Fault::Delay(Duration::from_millis(300)));
    let (_, r) = read_async(&d, &["dint1"], None);
    // SAFETY: a live request.
    assert!(!unsafe { ciplink_request_done(r) });
    let (st, message) = wait(r, 10);
    assert_eq!(st, CiplinkStatus::Timeout);
    assert_eq!(message, "the request is not done yet");
    let (st, json) = wait(r, -1);
    assert_eq!(st, CiplinkStatus::Ok, "{json}");
    free(r);
}

#[test]
fn reads_from_many_threads_complete_with_their_own_tags() {
    let (_sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    let tags = ["dint_ary[1]", "dint_ary[2]", "dint_ary[3]", "dint_ary[4]"];
    std::thread::scope(|s| {
        for (i, tag) in tags.iter().enumerate() {
            let d = &d;
            s.spawn(move || {
                let requests: Vec<_> = (0..25)
                    .map(|_| {
                        let (st, r) = read_async(d, &[tag, "dint_ary[1]"], None);
                        assert_eq!(st, CiplinkStatus::Ok);
                        r
                    })
                    .collect();
                for r in requests {
                    let (st, json) = wait(r, 5000);
                    assert_eq!(st, CiplinkStatus::Ok, "{json}");
                    assert_eq!(value_of(&json, 0), serde_json::json!(100 * (i + 1)));
                    assert_eq!(value_of(&json, 1), serde_json::json!(100));
                    free(r);
                }
            });
        }
    });
}

#[test]
fn async_calls_check_arguments_and_driver_kind() {
    let (_sim, server) = serve("example_controller.json");
    let cip = driver(ciplink_cip_new, &server, "");
    let seen = Seen::default();
    let (st, r) = read_async(&cip, &["dint1"], Some(&seen));
    assert_eq!(st, CiplinkStatus::Unsupported);
    assert!(r.is_null());
    let mut req = ptr::null_mut();
    let items = cstr("[1]");
    let logix = driver(ciplink_logix_new, &server, "");
    // SAFETY: valid pointers.
    let st =
        unsafe { ciplink_write_async(logix.0, items.as_ptr(), None, ptr::null_mut(), &mut req) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert!(req.is_null());
    // SAFETY: NULL request is checked.
    let st = unsafe { ciplink_request_wait(ptr::null(), 0, ptr::null_mut()) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    // SAFETY: NULL is ignored.
    unsafe {
        ciplink_request_free(ptr::null_mut());
        ciplink_subscription_free(ptr::null_mut());
        assert!(!ciplink_request_done(ptr::null()));
        assert_eq!(
            ciplink_connection_state(ptr::null()),
            CiplinkConnectionState::Closed
        );
    }
    std::thread::sleep(Duration::from_millis(50));
    assert!(seen.texts().is_empty()); // done never called for a call that failed
}

#[test]
fn a_read_without_open_fails_through_done() {
    let (_sim, server) = serve("example_controller.json");
    let d = driver(ciplink_logix_new, &server, "");
    let seen = Seen::default();
    let (st, r) = read_async(&d, &["dint1"], Some(&seen));
    assert_eq!(st, CiplinkStatus::Ok);
    let (st, message) = wait(r, -1);
    assert_eq!(st, CiplinkStatus::Comm, "{message}");
    free(r);
    assert!(seen.wait_for(|s| s.len() == 1 && s[0].0 == CiplinkStatus::Comm));
}

#[test]
fn session_options_are_checked() {
    let (_sim, server) = serve("example_controller.json");
    driver(
        ciplink_logix_new,
        &server,
        r#"{"reconnect": false, "reconnect_min": 0.5, "reconnect_max": 2, "keep_alive": null}"#,
    );
    driver(ciplink_slc_new, &server, r#"{"keep_alive": 5}"#);
    for bad in [
        r#"{"reconnect": 1}"#,
        r#"{"reconnect_min": 0}"#,
        r#"{"reconnect_max": "x"}"#,
        r#"{"keep_alive": -1}"#,
    ] {
        let path = cstr("127.0.0.1");
        let options = cstr(bad);
        let mut h = ptr::null_mut();
        // SAFETY: valid pointers.
        let st = unsafe { ciplink_logix_new(path.as_ptr(), options.as_ptr(), &mut h) };
        assert_eq!(st, CiplinkStatus::InvalidArgument, "{bad}");
        assert!(h.is_null());
    }
}

// ------------------------------------------------------------------------------------------------ subscriptions

fn subscribe(
    d: &Driver,
    tags: &[&str],
    options: &str,
    seen: &Seen,
) -> (CiplinkStatus, *mut CiplinkSubscription) {
    let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
    let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
    let options = cstr(options);
    let mut sub = ptr::null_mut();
    // SAFETY: valid pointers; `seen` outlives the subscription.
    let st = unsafe {
        ciplink_subscribe(
            d.0,
            ptrs.as_ptr(),
            ptrs.len(),
            options.as_ptr(),
            Some(on_text),
            seen.as_user(),
            &mut sub,
        )
    };
    (st, sub)
}

#[test]
fn a_subscription_delivers_first_values_then_changes_until_freed() {
    let (sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    let seen = Seen::default();
    let (st, sub) = subscribe(&d, &["dint_ary[8]", "int1"], r#"{"interval": 0.02}"#, &seen);
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());

    assert!(seen.wait_for(|s| !s.is_empty()));
    let first: Json = serde_json::from_str(&seen.texts()[0]).unwrap();
    assert_eq!(first.as_array().unwrap().len(), 2);
    assert_eq!(first[0]["value"], serde_json::json!(800));

    sim.set_value("dint_ary[8]", &serde_json::json!(808))
        .unwrap();
    assert!(seen.wait_for(|s| s.iter().any(|(_, t)| t.contains("808"))));
    let last: Json = serde_json::from_str(seen.texts().last().unwrap()).unwrap();
    assert_eq!(last.as_array().unwrap().len(), 1); // only the tag that changed
    assert_eq!(last[0]["tag"], "dint_ary[8]");

    // SAFETY: a live subscription, freed once.
    unsafe { ciplink_subscription_free(sub) };
    let count = seen.texts().len();
    sim.set_value("dint_ary[8]", &serde_json::json!(809))
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(seen.texts().len(), count);
}

#[test]
fn subscribe_checks_its_arguments() {
    let (_sim, server) = serve("example_controller.json");
    let d = driver(ciplink_logix_new, &server, "");
    let seen = Seen::default();
    for (tags, options) in [
        (&["dint1"][..], r#"{"interval": 0}"#),
        (&["dint1"][..], r#"{"deadband": "x"}"#),
        (&[][..], "{}"),
    ] {
        let (st, sub) = subscribe(&d, tags, options, &seen);
        assert_ne!(st, CiplinkStatus::Ok, "{options}");
        assert!(sub.is_null());
    }
    let tag = cstr("dint1");
    let ptrs = [tag.as_ptr()];
    let mut sub = ptr::null_mut();
    // SAFETY: valid pointers; NULL callback is checked.
    let st = unsafe {
        ciplink_subscribe(
            d.0,
            ptrs.as_ptr(),
            1,
            ptr::null(),
            None,
            ptr::null_mut(),
            &mut sub,
        )
    };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    let cip = driver(ciplink_cip_new, &server, "");
    assert_eq!(
        subscribe(&cip, &["dint1"], "{}", &seen).0,
        CiplinkStatus::Unsupported
    );
}

#[test]
fn slc_subscriptions_and_async_reads_work() {
    let (sim, server) = serve("example_slc.json");
    let d = open(ciplink_slc_new, &server, "{}");
    let seen = Seen::default();
    let (st, sub) = subscribe(&d, &["N7:2"], r#"{"interval": 0.02}"#, &seen);
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    assert!(seen.wait_for(|s| !s.is_empty()));
    let w = write_async(&d, r#"[["N7:2", 4321]]"#, None);
    assert_eq!(wait(w, -1).0, CiplinkStatus::Ok);
    free(w);
    assert!(seen.wait_for(|s| s.iter().any(|(_, t)| t.contains("4321"))));
    assert_eq!(sim.value("N7:2").unwrap(), serde_json::json!(4321));
    // SAFETY: a live subscription, freed once.
    unsafe { ciplink_subscription_free(sub) };
}

// ------------------------------------------------------------------------------------------------ connection state

#[test]
fn connection_events_follow_a_lost_link_and_its_reconnect() {
    let (sim, server) = serve("example_controller.json");
    let d = driver(
        ciplink_logix_new,
        &server,
        r#"{"reconnect_min": 0.02, "reconnect_max": 0.1}"#,
    );
    let seen = Seen::default();
    // SAFETY: a live handle; `seen` outlives the driver.
    let st = unsafe { ciplink_set_connection_callback(d.0, Some(on_text), seen.as_user()) };
    assert_eq!(st, CiplinkStatus::Ok);
    // SAFETY: a live handle.
    assert_eq!(
        unsafe { ciplink_connection_state(d.0) },
        CiplinkConnectionState::Closed
    );
    // SAFETY: a live handle.
    assert_eq!(unsafe { ciplink_open(d.0) }, CiplinkStatus::Ok);
    assert!(seen.wait_for(|s| s.len() == 1));
    assert_eq!(seen.texts()[0], r#"{"event":"connected"}"#);
    // SAFETY: a live handle.
    assert_eq!(
        unsafe { ciplink_connection_state(d.0) },
        CiplinkConnectionState::Connected
    );

    sim.inject(Fault::CloseConnections);
    let (_, r) = read_async(&d, &["dint1"], None);
    let (st, message) = wait(r, -1);
    free(r);
    assert_eq!(st, CiplinkStatus::Comm, "{message}");
    assert!(seen.wait_for(|s| s.len() >= 4 && s.last().unwrap().1.contains("connected\"}")));
    let events: Vec<Json> = seen
        .texts()
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(events[1]["event"], "disconnected");
    assert!(events[1]["error"].is_string());
    assert_eq!(events[2]["event"], "reconnecting");
    assert_eq!(events[2]["attempt"], 1);
    assert_eq!(events[2]["delay"], 0.02);
    assert_eq!(events.last().unwrap()["event"], "connected");
    // SAFETY: a live handle.
    assert_eq!(
        unsafe { ciplink_connection_state(d.0) },
        CiplinkConnectionState::Connected
    );
    let (_, r) = read_async(&d, &["dint1"], None);
    assert_eq!(wait(r, -1).0, CiplinkStatus::Ok);
    free(r);

    // removing the callback: no more events
    // SAFETY: a live handle.
    unsafe {
        assert_eq!(
            ciplink_set_connection_callback(d.0, None, ptr::null_mut()),
            CiplinkStatus::Ok
        );
        assert_eq!(ciplink_close(d.0), CiplinkStatus::Ok);
        assert_eq!(ciplink_open(d.0), CiplinkStatus::Ok);
    }
    let count = seen.texts().len();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(seen.texts().len(), count);
}

#[test]
fn the_plain_cip_driver_reports_state_but_has_no_callback() {
    let (_sim, server) = serve("example_controller.json");
    let d = open(ciplink_cip_new, &server, "");
    // SAFETY: a live handle.
    unsafe {
        assert_eq!(
            ciplink_connection_state(d.0),
            CiplinkConnectionState::Connected
        );
        assert_eq!(
            ciplink_set_connection_callback(d.0, Some(on_text), ptr::null_mut()),
            CiplinkStatus::Unsupported
        );
    }
}

// ------------------------------------------------------------------------------------------------ shutdown

#[test]
fn close_fails_queued_requests_and_every_done_fires() {
    let (sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    let seen = Seen::default();
    sim.inject(Fault::Delay(Duration::from_millis(100)));
    let before = sim.requests();
    let w = write_async(&d, r#"[["dint_ary[9]", 99]]"#, Some(&seen));
    // only a request the simulator has received is in flight; until then close fails it as queued
    let deadline = Instant::now() + Duration::from_secs(5);
    while sim.requests() == before {
        assert!(
            Instant::now() < deadline,
            "the write never reached the simulator"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let requests: Vec<_> = (0..10)
        .map(|_| read_async(&d, &["dint1"], Some(&seen)).1)
        .collect();
    // SAFETY: a live handle.
    assert_eq!(unsafe { ciplink_close(d.0) }, CiplinkStatus::Ok);
    assert_eq!(wait(w, -1).0, CiplinkStatus::Ok); // in flight: it finishes
    free(w);
    let mut closed = 0;
    for r in requests {
        let (st, message) = wait(r, 1000);
        if st != CiplinkStatus::Ok {
            assert_eq!(
                (st, message.as_str()),
                (CiplinkStatus::Comm, "driver closed")
            );
            closed += 1;
        }
        free(r);
    }
    assert!(closed > 0);
    assert!(seen.wait_for(|s| s.len() == 11));
}

#[test]
fn free_with_pending_work_runs_every_callback_before_it_returns() {
    static DONE: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn count(_: *mut c_void, _: CiplinkStatus, _: *const c_char) {
        std::thread::sleep(Duration::from_millis(2));
        DONE.fetch_add(1, Ordering::SeqCst);
    }
    let (sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    sim.inject(Fault::Delay(Duration::from_millis(50)));
    let tag = cstr("dint1");
    let ptrs = [tag.as_ptr()];
    for _ in 0..10 {
        // SAFETY: valid pointers; no request handle wanted.
        let st = unsafe {
            ciplink_read_async(
                d.0,
                ptrs.as_ptr(),
                1,
                Some(count),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(st, CiplinkStatus::Ok);
    }
    drop(d); // ciplink_driver_free
    assert_eq!(DONE.load(Ordering::SeqCst), 10);
}

#[test]
fn a_callback_can_call_back_into_the_driver() {
    struct Ctx {
        driver: *mut CiplinkDriver,
        seen: Seen,
    }
    unsafe extern "C" fn read_again(user: *mut c_void, _: CiplinkStatus, _: *const c_char) {
        // SAFETY: the test passes a Ctx that outlives the driver.
        let ctx = unsafe { &*user.cast::<Ctx>() };
        let tag = cstr("dint_ary[2]");
        let ptrs = [tag.as_ptr()];
        let mut out = ptr::null_mut();
        // SAFETY: a live handle; a blocking read from the callback thread.
        let st = unsafe { ciplink_read(ctx.driver, ptrs.as_ptr(), 1, &mut out) };
        let text = if st == CiplinkStatus::Ok {
            take(out)
        } else {
            thread_error()
        };
        ctx.seen.push(st, &text);
    }
    let (_sim, server) = serve("example_controller.json");
    let d = open(ciplink_logix_new, &server, "{}");
    let ctx = Ctx {
        driver: d.0,
        seen: Seen::default(),
    };
    let tag = cstr("dint1");
    let ptrs = [tag.as_ptr()];
    // SAFETY: valid pointers; `ctx` outlives the driver.
    let st = unsafe {
        ciplink_read_async(
            d.0,
            ptrs.as_ptr(),
            1,
            Some(read_again),
            (&ctx as *const Ctx).cast_mut().cast(),
            ptr::null_mut(),
        )
    };
    assert_eq!(st, CiplinkStatus::Ok);
    assert!(ctx.seen.wait_for(|s| s.len() == 1));
    let (st, text) = ctx.seen.items.lock().unwrap()[0].clone();
    assert_eq!(st, CiplinkStatus::Ok, "{text}");
    assert_eq!(value_of(&text, 0), serde_json::json!(200));
}
