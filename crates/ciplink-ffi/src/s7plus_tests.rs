#![allow(clippy::unwrap_used)]

use super::*;
use crate::session::*;
use ciplink_sim::s7plus::{S7PlusFault, S7PlusServer, S7PlusSimulator};
use std::sync::Condvar;
use std::time::Instant;

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

fn serve() -> (S7PlusSimulator, S7PlusServer) {
    let path = format!(
        "{}/../../tools/sim/example_s7plus.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let sim = S7PlusSimulator::from_file(path).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    (sim, server)
}

struct Handle(*mut CiplinkDriver);

// SAFETY: driver handles are thread-safe.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: made by a `_new` in this test, freed once.
        unsafe { ciplink_driver_free(self.0) };
    }
}

impl Handle {
    fn new(server: &S7PlusServer, options: &str) -> Result<Handle, (CiplinkStatus, String)> {
        let path = cstr(&format!("127.0.0.1:{}", server.port()));
        let options = cstr(options);
        let mut h = ptr::null_mut();
        // SAFETY: valid pointers for the call.
        let st = unsafe { ciplink_s7plus_new(path.as_ptr(), options.as_ptr(), &mut h) };
        if st == CiplinkStatus::Ok {
            Ok(Handle(h))
        } else {
            assert!(h.is_null());
            Err((st, thread_error()))
        }
    }

    fn open(&self) -> CiplinkStatus {
        // SAFETY: a live handle.
        unsafe { ciplink_open(self.0) }
    }

    fn json(&self, f: impl FnOnce(*mut *mut c_char) -> CiplinkStatus) -> Json {
        let mut out = ptr::null_mut();
        let st = f(&mut out);
        assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
        serde_json::from_str(&take(out)).unwrap()
    }

    fn status(&self, f: impl FnOnce(*mut *mut c_char) -> CiplinkStatus) -> CiplinkStatus {
        let mut out = ptr::null_mut();
        let st = f(&mut out);
        assert!(out.is_null());
        st
    }

    fn read(&self, tags: &[&str]) -> Json {
        let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
        let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
        // SAFETY: valid pointers for the call.
        self.json(|o| unsafe { ciplink_read(self.0, ptrs.as_ptr(), ptrs.len(), o) })
    }

    fn write(&self, items: &str) -> Json {
        let items = cstr(items);
        // SAFETY: valid pointers for the call.
        self.json(|o| unsafe { ciplink_write(self.0, items.as_ptr(), o) })
    }
}

/// Opened with keep-alive and reconnect off, so the simulator's request count is the test's own.
fn open(server: &S7PlusServer) -> Handle {
    let h = Handle::new(server, r#"{"keep_alive": null, "reconnect": false}"#).unwrap();
    assert_eq!(h.open(), CiplinkStatus::Ok, "{}", thread_error());
    h
}

#[test]
fn options_are_checked() {
    let (_sim, server) = serve();
    let (st, msg) = Handle::new(&server, r#"{"tls_fingerprint": "zz"}"#)
        .err()
        .unwrap();
    assert_eq!(st, CiplinkStatus::Request, "{msg}");
    let (st, _) = Handle::new(&server, r#"{"tls_fingerprint": 5}"#)
        .err()
        .unwrap();
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    let (st, _) = Handle::new(&server, r#"{"init_tags": "yes"}"#)
        .err()
        .unwrap();
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    let h = Handle::new(&server, "").unwrap();
    let mut t = 0.0;
    // SAFETY: a live handle and a writable double.
    assert_eq!(
        unsafe { ciplink_socket_timeout(h.0, &mut t) },
        CiplinkStatus::Ok
    );
    assert_eq!(t, 10.0);
    // SAFETY: a live handle.
    assert!(!unsafe { ciplink_connected(h.0) });
}

#[test]
fn reads_writes_and_browses_through_the_generic_calls() {
    let (sim, server) = serve();
    let h = open(&server);
    // SAFETY: a live handle.
    assert!(unsafe { ciplink_connected(h.0) });

    let r = h.read(&["Line1.Conveyor.Speed", "Line1.Status", "Mode", "Line1.Nope"]);
    assert_eq!(r[0]["value"], 1.5);
    assert_eq!(r[0]["type"], "REAL");
    assert_eq!(r[1]["value"], 4660);
    assert_eq!(r[1]["type"], "WORD");
    assert_eq!(r[2]["value"], 3);
    assert_eq!(r[3]["value"], Json::Null);
    assert_eq!(r[3]["error"]["kind"], "not_found");

    let w = h.write(r#"[["Line1.Count", 42], ["Line1.Label", "Batch7"], ["Line1.Count", "x"]]"#);
    assert_eq!(w[0]["error"], Json::Null);
    assert_eq!(w[1]["error"], Json::Null);
    assert_eq!(w[2]["error"]["kind"], "bad_value");
    assert_eq!(sim.value("Line1.Count").unwrap(), 42);
    let r = h.read(&["Line1.Label", "Line1.Recipe"]);
    assert_eq!(r[0]["value"], "Batch7");
    assert_eq!(r[1]["value"]["Speed"], 2.5);

    // SAFETY (all calls below): a live handle and writable out pointers.
    let tags = h.json(|o| unsafe { ciplink_tags(h.0, o) });
    assert_eq!(tags["Line1"]["kind"], "data_block");
    assert_eq!(tags["StartButton"]["type"], "BOOL");
    let types = h.json(|o| unsafe { ciplink_data_types(h.0, o) });
    assert!(
        types
            .as_object()
            .unwrap()
            .values()
            .any(|t| t["members"].get("Speed").is_some())
    );
    let list = h.json(|o| unsafe { ciplink_tag_list(h.0, ptr::null(), true, ptr::null(), o) });
    let names: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"Line1.Conveyor.Speed"));
    let name = cstr("Line1.Hidden");
    let info = h.json(|o| unsafe { ciplink_tag_info(h.0, name.as_ptr(), o) });
    assert_eq!(info["type"], "INT");
    assert_eq!(info["hmi_accessible"], false);
    assert!(info["access"].as_str().unwrap().contains('.'));
    let bad = cstr("Line1.Nope");
    let st = h.status(|o| unsafe { ciplink_tag_info(h.0, bad.as_ptr(), o) });
    assert_eq!(st, CiplinkStatus::Request);

    let plc_name = h.json(|o| unsafe { ciplink_get_plc_name(h.0, o) });
    assert_eq!(plc_name, "PLC_Line1");
    let cpu = h.json(|o| unsafe { ciplink_get_plc_info(h.0, o) });
    assert_eq!(cpu["name"], "PLC_Line1");
    assert_eq!(cpu["firmware"], "V3.1.3");
    assert_eq!(cpu["max_read"], 100);
    let info = h.json(|o| unsafe { ciplink_info(h.0, o) });
    assert_eq!(info["fingerprint"], sim.fingerprint());
    let fp = h.json(|o| unsafe { ciplink_s7plus_fingerprint(h.0, o) });
    assert_eq!(fp, sim.fingerprint());

    let mut changed = true;
    // SAFETY: a live handle and a writable bool.
    let st = unsafe { ciplink_s7plus_refresh_tags(h.0, &mut changed) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    assert!(!changed);
}

#[test]
fn reads_split_at_the_plc_limit() {
    let (sim, server) = serve();
    let h = open(&server);
    let names: Vec<String> = (1..=150).map(|i| format!("Line1.Items[{i}]")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let before = sim.requests();
    let r = h.read(&refs);
    assert_eq!(r.as_array().unwrap().len(), 150);
    assert!(r.as_array().unwrap().iter().all(|t| t["error"].is_null()));
    assert_eq!(sim.requests() - before, 2);
}

#[test]
fn cip_calls_are_unsupported() {
    let (_sim, server) = serve();
    let h = Handle::new(&server, "").unwrap();
    let mut size = 0u16;
    // SAFETY (all calls below): a live handle and writable out pointers.
    let st = unsafe { ciplink_connection_size(h.0, &mut size) };
    assert_eq!(st, CiplinkStatus::Unsupported);
    let route = cstr("");
    let st = h.status(|o| unsafe { ciplink_get_identity(h.0, route.as_ptr(), o) });
    assert_eq!(st, CiplinkStatus::Unsupported);
    let st = h.status(|o| unsafe { ciplink_get_plc_time(h.0, o) });
    assert_eq!(st, CiplinkStatus::Unsupported);
    let st = h.status(|o| unsafe { ciplink_get_module_info(h.0, 0, o) });
    assert_eq!(st, CiplinkStatus::Unsupported);
    let mut changed = false;
    let st = unsafe { ciplink_check_tag_table(h.0, &mut changed) };
    assert_eq!(st, CiplinkStatus::Unsupported);

    // the S7 calls on another kind of driver
    let path = cstr("127.0.0.1:1");
    let mut cip = ptr::null_mut();
    assert_eq!(
        unsafe { ciplink_cip_new(path.as_ptr(), ptr::null(), &mut cip) },
        CiplinkStatus::Ok
    );
    let cip = Handle(cip);
    let st = cip.status(|o| unsafe { ciplink_s7plus_fingerprint(cip.0, o) });
    assert_eq!(st, CiplinkStatus::Unsupported);
    let st = unsafe { ciplink_s7plus_refresh_tags(cip.0, &mut changed) };
    assert_eq!(st, CiplinkStatus::Unsupported);
}

#[test]
fn pin_and_refusal_fail_open() {
    let (sim, server) = serve();
    let pinned = Handle::new(
        &server,
        &format!(r#"{{"tls_fingerprint": "{}"}}"#, sim.fingerprint()),
    )
    .unwrap();
    assert_eq!(pinned.open(), CiplinkStatus::Ok, "{}", thread_error());

    let wrong = format!("{:064}", 0);
    let h = Handle::new(&server, &format!(r#"{{"tls_fingerprint": "{wrong}"}}"#)).unwrap();
    assert_eq!(h.open(), CiplinkStatus::Comm);
    // the refused certificate's fingerprint is still there to show the user
    // SAFETY: a live handle and a writable out pointer.
    let fp = h.json(|o| unsafe { ciplink_s7plus_fingerprint(h.0, o) });
    assert_eq!(fp, sim.fingerprint());

    sim.inject(S7PlusFault::RefuseConnections);
    let h = Handle::new(&server, "").unwrap();
    assert_eq!(h.open(), CiplinkStatus::Comm);
}

/// What the callbacks saw, in order.
#[derive(Default)]
struct Seen {
    items: Mutex<Vec<(CiplinkStatus, String)>>,
    ready: Condvar,
}

impl Seen {
    fn wait_for(&self, pred: impl Fn(&[(CiplinkStatus, String)]) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
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

    fn user(&self) -> *mut c_void {
        (self as *const Seen).cast_mut().cast()
    }
}

unsafe extern "C" fn on_done(user: *mut c_void, status: CiplinkStatus, json: *const c_char) {
    // SAFETY: the tests pass a `Seen` that outlives the driver, and a string valid during the call.
    let (seen, text) = unsafe { (&*user.cast::<Seen>(), CStr::from_ptr(json)) };
    seen.items
        .lock()
        .unwrap()
        .push((status, text.to_str().unwrap().to_owned()));
    seen.ready.notify_all();
}

unsafe extern "C" fn on_text(user: *mut c_void, json: *const c_char) {
    // SAFETY: as on_done.
    unsafe { on_done(user, CiplinkStatus::Ok, json) };
}

#[test]
fn async_requests_subscriptions_and_connection_events() {
    let (sim, server) = serve();
    let seen = Seen::default();
    let events = Seen::default();
    let h = Handle::new(&server, r#"{"reconnect_min": 0.05}"#).unwrap();
    // SAFETY (all calls below): a live handle, valid pointers, and `seen` / `events` outlive the driver.
    let st = unsafe { ciplink_set_connection_callback(h.0, Some(on_text), events.user()) };
    assert_eq!(st, CiplinkStatus::Ok);
    assert_eq!(h.open(), CiplinkStatus::Ok, "{}", thread_error());

    let name = cstr("Line1.Count");
    let ptrs = [name.as_ptr()];
    let mut req = ptr::null_mut();
    let st =
        unsafe { ciplink_read_async(h.0, ptrs.as_ptr(), 1, Some(on_done), seen.user(), &mut req) };
    assert_eq!(st, CiplinkStatus::Ok);
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { ciplink_request_wait(req, 10_000, &mut out) },
        CiplinkStatus::Ok
    );
    let r: Json = serde_json::from_str(&take(out)).unwrap();
    assert_eq!(r[0]["value"], -300);
    unsafe { ciplink_request_free(req) };

    let items = cstr(r#"[["Line1.Count", 7]]"#);
    let st = unsafe {
        ciplink_write_async(
            h.0,
            items.as_ptr(),
            Some(on_done),
            seen.user(),
            ptr::null_mut(),
        )
    };
    assert_eq!(st, CiplinkStatus::Ok);
    assert!(seen.wait_for(|s| s.len() == 2));
    assert_eq!(sim.value("Line1.Count").unwrap(), 7);

    let changes = Seen::default();
    let opts = cstr(r#"{"interval": 0.05}"#);
    let mut sub = ptr::null_mut();
    let st = unsafe {
        ciplink_subscribe(
            h.0,
            ptrs.as_ptr(),
            1,
            opts.as_ptr(),
            Some(on_text),
            changes.user(),
            &mut sub,
        )
    };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    assert!(changes.wait_for(|s| s.len() == 1 && s[0].1.contains("\"value\":7")));
    sim.set_value("Line1.Count", &serde_json::json!(8)).unwrap();
    assert!(changes.wait_for(|s| s.iter().any(|(_, t)| t.contains("\"value\":8"))));
    unsafe { ciplink_subscription_free(sub) };

    sim.inject(S7PlusFault::CloseConnections);
    // the next request finds the link gone (a failed read) and the driver reconnects in the background
    let mut out = ptr::null_mut();
    let st = unsafe { ciplink_read(h.0, ptrs.as_ptr(), 1, &mut out) };
    if st == CiplinkStatus::Ok {
        take(out);
    }
    assert!(events.wait_for(|s| {
        let t: Vec<&str> = s.iter().map(|(_, t)| t.as_str()).collect();
        t.iter().any(|t| t.contains("disconnected"))
            && t.iter().any(|t| t.contains("reconnecting"))
            && t.last().is_some_and(|t| t.contains("\"connected\""))
            && t.len() >= 4
    }));
    assert_eq!(
        unsafe { ciplink_connection_state(h.0) },
        CiplinkConnectionState::Connected
    );
    assert_eq!(h.read(&["Line1.Count"])[0]["value"], 8);
}
