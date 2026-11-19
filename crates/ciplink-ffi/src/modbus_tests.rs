#![allow(clippy::unwrap_used)]

use super::*;
use crate::session::{
    CiplinkConnectionState, ciplink_connection_state, ciplink_read_async, ciplink_request_free,
    ciplink_request_wait, ciplink_set_connection_callback, ciplink_subscribe,
    ciplink_subscription_free, ciplink_write_async,
};
use ciplink_sim::{Framing, ModbusFault, ModbusServer, ModbusSim};
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

fn repo_file(name: &str) -> String {
    format!("{}/../../tools/sim/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn serve(framing: Framing) -> (ModbusSim, ModbusServer) {
    let config = std::fs::read_to_string(repo_file("example_modbus.json")).unwrap();
    let sim = ModbusSim::from_json(&config).unwrap();
    let server = sim.serve("127.0.0.1:0", framing).unwrap();
    (sim, server)
}

fn scheme(framing: Framing) -> &'static str {
    match framing {
        Framing::Mbap => "tcp",
        Framing::Rtu => "rtu+tcp",
    }
}

struct Driver(*mut CiplinkDriver);

impl Drop for Driver {
    fn drop(&mut self) {
        // SAFETY: made by ciplink_modbus_new in this test, freed once.
        unsafe { ciplink_driver_free(self.0) };
    }
}

fn new(path: &str, options: &str) -> Result<Driver, (CiplinkStatus, String)> {
    let path = cstr(path);
    let options = cstr(options);
    let mut h = ptr::null_mut();
    // SAFETY: valid pointers for the call.
    let st = unsafe { ciplink_modbus_new(path.as_ptr(), options.as_ptr(), &mut h) };
    if st == CiplinkStatus::Ok {
        Ok(Driver(h))
    } else {
        assert!(h.is_null());
        Err((st, thread_error()))
    }
}

/// An open driver on `server` with the example map file.
fn open(server: &ModbusServer, framing: Framing, extra: &str) -> Driver {
    let path = format!("{}://127.0.0.1:{}", scheme(framing), server.port());
    let map = Json::String(repo_file("example_modbus_map.csv"));
    let options = format!(r#"{{"map_file": {map}, "socket_timeout": 0.5{extra}}}"#);
    let d = new(&path, &options).unwrap();
    // SAFETY: a live handle.
    let st = unsafe { ciplink_open(d.0) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    d
}

fn read(d: &Driver, tags: &[&str]) -> Json {
    let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
    let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
    let mut out = ptr::null_mut();
    // SAFETY: valid pointers for the call.
    let st = unsafe { ciplink_read(d.0, ptrs.as_ptr(), ptrs.len(), &mut out) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    serde_json::from_str(&take(out)).unwrap()
}

fn write(d: &Driver, items: &str) -> Json {
    let items = cstr(items);
    let mut out = ptr::null_mut();
    // SAFETY: valid pointers for the call.
    let st = unsafe { ciplink_write(d.0, items.as_ptr(), &mut out) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    serde_json::from_str(&take(out)).unwrap()
}

fn json_out(f: impl FnOnce(*mut *mut c_char) -> CiplinkStatus) -> Result<Json, CiplinkStatus> {
    let mut out = ptr::null_mut();
    match f(&mut out) {
        CiplinkStatus::Ok => Ok(serde_json::from_str(&take(out)).unwrap()),
        st => Err(st),
    }
}

/// What the callbacks of a test saw.
#[derive(Default)]
struct Seen {
    items: Mutex<Vec<String>>,
    ready: Condvar,
}

impl Seen {
    fn wait_for(&self, pred: impl Fn(&[String]) -> bool) -> bool {
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

unsafe extern "C" fn on_text(user: *mut c_void, json: *const c_char) {
    // SAFETY: the tests pass a `Seen` that outlives the driver, and a string valid during the call.
    let (seen, text) = unsafe { (&*user.cast::<Seen>(), CStr::from_ptr(json)) };
    seen.items
        .lock()
        .unwrap()
        .push(text.to_str().unwrap().to_owned());
    seen.ready.notify_all();
}

// ------------------------------------------------------------------------------------------------ tests

#[test]
fn reads_map_tags_and_plain_addresses_in_both_framings() {
    for framing in [Framing::Mbap, Framing::Rtu] {
        let (_sim, server) = serve(framing);
        let d = open(&server, framing, "");
        let r = read(
            &d,
            &[
                "Pump1_Speed",
                "Totals",
                "Recipe",
                "Tank_Level",
                "Pump1_Run",
                "hr0",
                "Missing_Tag_X",
            ],
        );
        let speed = r[0]["value"].as_f64().unwrap();
        assert!((speed - 123.456).abs() < 1e-4, "{r}");
        assert_eq!(r[0]["type"], "REAL");
        assert_eq!(r[1]["value"], serde_json::json!([120, 135, 99, 140]));
        assert_eq!(r[2]["value"], "MIX-A");
        assert!((r[3]["value"].as_f64().unwrap() - 52.3).abs() < 1e-9, "{r}");
        assert_eq!(r[4]["value"], true);
        assert_eq!(r[5]["value"], 59769);
        assert_eq!(r[6]["value"], Json::Null);
        assert_eq!(r[6]["error"]["kind"], "not_found", "{r}");
    }
}

#[test]
fn writes_registers_coils_and_a_register_bit() {
    let (sim, server) = serve(Framing::Mbap);
    let d = open(&server, Framing::Mbap, "");
    let r = write(
        &d,
        r#"[["Totals[1]", 7], ["Pump1_Run", false], ["Horn", true], ["Drive_Status", 1], ["hr600:float32", 1.5]]"#,
    );
    assert_eq!(r[0]["error"], Json::Null, "{r}");
    assert_eq!(r[1]["error"], Json::Null, "{r}");
    assert_eq!(r[2]["error"], Json::Null, "{r}");
    assert_eq!(r[3]["error"]["kind"], "access", "{r}"); // not writable in the map
    assert_eq!(r[4]["error"], Json::Null, "{r}");
    assert_eq!(
        sim.registers(1, "holding", 102, 2).unwrap(),
        vec![0, 7] // uint32 ABCD
    );
    assert_eq!(sim.bits(1, "coil", 0, 1).unwrap(), vec![false]);
    assert_eq!(sim.registers(1, "holding", 301, 1).unwrap(), vec![1 << 4]);
    assert_eq!(
        sim.registers(1, "holding", 600, 2).unwrap(),
        vec![0x3FC0, 0]
    );
}

#[test]
fn tags_device_info_and_send_pdu() {
    let (_sim, server) = serve(Framing::Rtu);
    let d = open(&server, Framing::Rtu, "");

    // SAFETY: a live handle; the out pointer is writable.
    let tags = json_out(|out| unsafe { ciplink_modbus_tags(d.0, out) }).unwrap();
    let speed = &tags[0];
    assert_eq!(speed["name"], "Pump1_Speed");
    assert_eq!(speed["area"], "holding");
    assert_eq!(speed["type"], "float32");
    assert_eq!(speed["cip_type"], "REAL");
    assert_eq!(speed["order"], "CDAB");
    assert_eq!(speed["units"], "rpm");
    assert_eq!(speed["description"], "Pump 1 speed setpoint");
    assert_eq!(tags[3]["cip_type"], "LREAL");
    assert_eq!(tags[3]["scale"], 0.1);
    assert_eq!(tags[8]["bit"], 4);
    assert_eq!(tags[9]["unit"], 2);

    // SAFETY: as above.
    let info = json_out(|out| unsafe { ciplink_modbus_device_info(d.0, -1, out) }).unwrap();
    assert_eq!(info["vendor_name"], "ciplink");
    assert_eq!(info["product_code"], "SIM-MB");
    assert_eq!(info["model_name"], "MB-1");
    assert_eq!(info["vendor_url"], Json::Null);
    // SAFETY: as above; unit 2 does not support FC43.
    let st = json_out(|out| unsafe { ciplink_modbus_device_info(d.0, 2, out) }).unwrap_err();
    assert_eq!(st, CiplinkStatus::Response);

    let pdu = [3u8, 0, 0, 0, 1];
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    // SAFETY: valid pointers for the call.
    let st =
        unsafe { ciplink_modbus_send_pdu(d.0, -1, pdu.as_ptr(), pdu.len(), &mut out, &mut len) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    // SAFETY: `len` bytes returned by the library.
    let reply = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
    // SAFETY: freed once with its length.
    unsafe { ciplink_bytes_free(out, len) };
    assert_eq!(reply, vec![3, 2, 0xE9, 0x79]); // 59769

    let bad = [3u8, 0x01, 0xF4, 0, 1]; // holding 500 is a hole: exception 02
    // SAFETY: valid pointers for the call.
    let st =
        unsafe { ciplink_modbus_send_pdu(d.0, -1, bad.as_ptr(), bad.len(), &mut out, &mut len) };
    assert_eq!(st, CiplinkStatus::Response);
    assert!(out.is_null());
}

#[test]
fn cip_calls_are_unsupported_and_options_are_checked() {
    let d = new("tcp://127.0.0.1:1", "{}").unwrap();
    // SAFETY: a live handle; the out pointer is writable.
    let st = json_out(|out| unsafe { ciplink_tags(d.0, out) }).unwrap_err();
    assert_eq!(st, CiplinkStatus::Unsupported);
    let mut size = 0u16;
    // SAFETY: as above.
    assert_eq!(
        unsafe { ciplink_connection_size(d.0, &mut size) },
        CiplinkStatus::Unsupported
    );
    let mut secs = 0.0;
    // SAFETY: as above.
    assert_eq!(
        unsafe { ciplink_socket_timeout(d.0, &mut secs) },
        CiplinkStatus::Ok
    );
    assert_eq!(secs, 1.0);
    // SAFETY: as above.
    assert_eq!(
        unsafe { ciplink_set_socket_timeout(d.0, -1.0) },
        CiplinkStatus::InvalidArgument
    );
    // SAFETY: as above.
    assert_eq!(
        unsafe { ciplink_set_socket_timeout(d.0, 2.5) },
        CiplinkStatus::Ok
    );
    // SAFETY: as above.
    assert_eq!(
        unsafe { ciplink_socket_timeout(d.0, &mut secs) },
        CiplinkStatus::Ok
    );
    assert_eq!(secs, 2.5);
    // SAFETY: a live handle that is not connected.
    assert_eq!(
        unsafe { ciplink_connection_state(d.0) },
        CiplinkConnectionState::Closed
    );

    let csv = Json::String("name,area,address,type\nA,holding,0,int16\n".into());
    let both = format!(r#"{{"map_csv": {csv}, "map_file": "x.csv"}}"#);
    assert_eq!(
        new("tcp://127.0.0.1", &both).err().unwrap().0,
        CiplinkStatus::InvalidArgument
    );
    let (st, msg) = new("tcp://127.0.0.1", r#"{"word_order": "ACBD"}"#)
        .err()
        .unwrap();
    assert_eq!(st, CiplinkStatus::InvalidArgument, "{msg}");
    let (st, _) = new("tcp://127.0.0.1", r#"{"max_registers": 200}"#)
        .err()
        .unwrap();
    assert_eq!(st, CiplinkStatus::Request);
    let (st, _) = new("modbus://127.0.0.1", "{}").err().unwrap();
    assert_eq!(st, CiplinkStatus::Request);
    let (st, _) = new("tcp://127.0.0.1", r#"{"map_file": "no/such/map.csv"}"#)
        .err()
        .unwrap();
    assert_ne!(st, CiplinkStatus::Ok);
    assert!(new("rtu://COM9?baud=19200&parity=E", r#"{"keep_alive": 5}"#).is_ok()); // not opened
    let d = new("tcp://127.0.0.1", &format!(r#"{{"map_csv": {csv}}}"#)).unwrap();
    // SAFETY: a live handle; the out pointer is writable.
    let tags = json_out(|out| unsafe { ciplink_modbus_tags(d.0, out) }).unwrap();
    assert_eq!(tags[0]["name"], "A");
}

#[test]
fn async_reads_writes_and_subscriptions() {
    let (sim, server) = serve(Framing::Mbap);
    let d = open(&server, Framing::Mbap, "");

    let items = cstr(r#"[["Totals[0]", 11]]"#);
    let mut w = ptr::null_mut();
    // SAFETY: valid pointers for the call.
    let st = unsafe { ciplink_write_async(d.0, items.as_ptr(), None, ptr::null_mut(), &mut w) };
    assert_eq!(st, CiplinkStatus::Ok);
    let name = cstr("Totals");
    let names = [name.as_ptr()];
    let mut r = ptr::null_mut();
    // SAFETY: valid pointers for the call.
    let st = unsafe { ciplink_read_async(d.0, names.as_ptr(), 1, None, ptr::null_mut(), &mut r) };
    assert_eq!(st, CiplinkStatus::Ok);
    let mut out = ptr::null_mut();
    // SAFETY: a live request; `out` is writable.
    assert_eq!(
        unsafe { ciplink_request_wait(r, 5000, &mut out) },
        CiplinkStatus::Ok
    );
    let json: Json = serde_json::from_str(&take(out)).unwrap();
    assert_eq!(json[0]["value"][0], 11);
    // SAFETY: live requests, freed once.
    unsafe {
        ciplink_request_free(r);
        ciplink_request_free(w);
    }

    let seen = Seen::default();
    let tag = cstr("Pump1_Run");
    let tags = [tag.as_ptr()];
    let options = cstr(r#"{"interval": 0.05}"#);
    let mut sub = ptr::null_mut();
    // SAFETY: valid pointers; `seen` outlives the subscription.
    let st = unsafe {
        ciplink_subscribe(
            d.0,
            tags.as_ptr(),
            1,
            options.as_ptr(),
            Some(on_text),
            seen.as_user(),
            &mut sub,
        )
    };
    assert_eq!(st, CiplinkStatus::Ok, "{}", thread_error());
    assert!(seen.wait_for(|s| s.iter().any(|t| t.contains("\"value\":true"))));
    sim.set_bits(1, "coil", 0, &[false]).unwrap();
    assert!(seen.wait_for(|s| s.iter().any(|t| t.contains("\"value\":false"))));
    // SAFETY: a live subscription, freed once.
    unsafe { ciplink_subscription_free(sub) };
}

#[test]
fn connection_events_on_a_lost_link() {
    let (sim, server) = serve(Framing::Mbap);
    let d = open(&server, Framing::Mbap, r#", "reconnect_min": 0.05"#);
    let seen = Seen::default();
    // SAFETY: a live handle; `seen` outlives the driver.
    let st = unsafe { ciplink_set_connection_callback(d.0, Some(on_text), seen.as_user()) };
    assert_eq!(st, CiplinkStatus::Ok);
    read(&d, &["hr0"]);
    sim.inject(ModbusFault::CloseConnections);
    let tag = cstr("hr0");
    let tags = [tag.as_ptr()];
    let mut out = ptr::null_mut();
    // SAFETY: valid pointers; the read fails or succeeds, the link is lost either way.
    let _ = unsafe { ciplink_read(d.0, tags.as_ptr(), 1, &mut out) };
    if !out.is_null() {
        take(out);
    }
    assert!(seen.wait_for(|s| s.iter().any(|t| t.contains("disconnected"))));
    assert!(seen.wait_for(|s| s.iter().any(|t| t.contains("\"connected\""))));
    // SAFETY: a live handle.
    assert_eq!(
        unsafe { ciplink_connection_state(d.0) },
        CiplinkConnectionState::Connected
    );
    // SAFETY: a live handle; removes the callback before `seen` drops.
    unsafe { ciplink_set_connection_callback(d.0, None, ptr::null_mut()) };
}
