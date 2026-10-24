#![allow(clippy::unwrap_used)]

use super::*;
use ciplink_sim::{Server, Simulator};
use std::ffi::CString;

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Takes ownership of a library string.
fn take(p: *mut c_char) -> String {
    assert!(!p.is_null());
    // SAFETY: a live string from the library, freed right after copying.
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
    // SAFETY: as above.
    unsafe { ciplink_string_free(p) };
    s
}

fn last_error(h: *const CiplinkDriver) -> String {
    // SAFETY: NULL or a live handle.
    take(unsafe { ciplink_last_error(h) })
}

fn serve(config: &str) -> (Simulator, Server) {
    let path = format!("{}/../../tools/sim/{config}", env!("CARGO_MANIFEST_DIR"));
    let sim = Simulator::from_file(path).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    (sim, server)
}

struct Handle(*mut CiplinkDriver);

// SAFETY: the handle is Sync (drivers lock internally); tests share it across threads on purpose.
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
    fn read(&self, tags: &[&str]) -> Json {
        let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
        let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
        let mut out = ptr::null_mut();
        // SAFETY: valid pointers for the duration of the call.
        let st = unsafe { ciplink_read(self.0, ptrs.as_ptr(), ptrs.len(), &mut out) };
        assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(self.0));
        serde_json::from_str(&take(out)).unwrap()
    }

    fn write(&self, items: &str) -> Json {
        let items = cstr(items);
        let mut out = ptr::null_mut();
        // SAFETY: valid pointers for the duration of the call.
        let st = unsafe { ciplink_write(self.0, items.as_ptr(), &mut out) };
        assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(self.0));
        serde_json::from_str(&take(out)).unwrap()
    }
}

fn open(
    new: unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *mut *mut CiplinkDriver,
    ) -> CiplinkStatus,
    server: &Server,
) -> Handle {
    let path = cstr(&format!("127.0.0.1:{}", server.port()));
    let mut h = ptr::null_mut();
    // SAFETY: valid pointers; NULL options mean defaults.
    assert_eq!(
        unsafe { new(path.as_ptr(), ptr::null(), &mut h) },
        CiplinkStatus::Ok
    );
    let h = Handle(h);
    // SAFETY: a live handle.
    let st = unsafe { ciplink_open(h.0) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    h
}

// ------------------------------------------------------------------------------------------------ arguments

#[test]
fn null_handle_is_invalid_argument_with_thread_error() {
    let mut out = ptr::null_mut();
    // SAFETY: NULL handle is allowed and reported.
    assert_eq!(
        unsafe { ciplink_open(ptr::null()) },
        CiplinkStatus::InvalidArgument
    );
    assert_eq!(last_error(ptr::null()), "driver handle is NULL");
    // SAFETY: as above.
    let st = unsafe { ciplink_read(ptr::null(), ptr::null(), 0, &mut out) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert!(out.is_null());
    // SAFETY: NULL is ignored.
    unsafe {
        ciplink_driver_free(ptr::null_mut());
        ciplink_string_free(ptr::null_mut());
        assert!(!ciplink_connected(ptr::null()));
    }
}

#[test]
fn null_path_and_null_out_are_invalid_arguments() {
    let mut h = ptr::null_mut();
    // SAFETY: NULL arguments are checked.
    assert_eq!(
        unsafe { ciplink_logix_new(ptr::null(), ptr::null(), &mut h) },
        CiplinkStatus::InvalidArgument
    );
    assert!(h.is_null());
    assert_eq!(last_error(ptr::null()), "path is NULL");
    let path = cstr("127.0.0.1");
    // SAFETY: NULL out is checked.
    assert_eq!(
        unsafe { ciplink_logix_new(path.as_ptr(), ptr::null(), ptr::null_mut()) },
        CiplinkStatus::InvalidArgument
    );
}

#[test]
fn bad_utf8_is_invalid_argument() {
    let bad = [0x31u8, 0xff, 0xfe, 0];
    let mut h = ptr::null_mut();
    // SAFETY: NUL-terminated bytes.
    let st = unsafe { ciplink_slc_new(bad.as_ptr().cast(), ptr::null(), &mut h) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert_eq!(last_error(ptr::null()), "path is not valid UTF-8");
}

#[test]
fn bad_options_are_invalid_arguments() {
    let path = cstr("127.0.0.1");
    for (opts, want) in [
        ("{", "options is not valid JSON"),
        ("[1]", "options must be a JSON object"),
        (
            r#"{"connection_size": 70000}"#,
            "option connection_size must be 1 to 65535",
        ),
        (r#"{"init_tags": 1}"#, "option init_tags must be a boolean"),
        (
            r#"{"socket_timeout": -1}"#,
            "option socket_timeout must be seconds or null",
        ),
    ] {
        let o = cstr(opts);
        let mut h = ptr::null_mut();
        // SAFETY: valid pointers.
        let st = unsafe { ciplink_logix_new(path.as_ptr(), o.as_ptr(), &mut h) };
        assert_eq!(st, CiplinkStatus::InvalidArgument, "{opts}");
        assert!(last_error(ptr::null()).starts_with(want), "{opts}");
    }
}

#[test]
fn bad_path_is_request_error_and_good_options_are_accepted() {
    let o = cstr(
        r#"{"socket_timeout": 1.5, "connection_size": 500, "lazy_tags": true, "tag_namespace_filter": "x"}"#,
    );
    let path = cstr("127.0.0.1/abc/def/");
    let mut h = ptr::null_mut();
    // SAFETY: valid pointers.
    let st = unsafe { ciplink_logix_new(path.as_ptr(), o.as_ptr(), &mut h) };
    assert_ne!(st, CiplinkStatus::Ok);
    let path = cstr("127.0.0.1");
    // SAFETY: valid pointers.
    assert_eq!(
        unsafe { ciplink_logix_new(path.as_ptr(), o.as_ptr(), &mut h) },
        CiplinkStatus::Ok
    );
    let h = Handle(h);
    // SAFETY: a live handle, never opened.
    assert!(!unsafe { ciplink_connected(h.0) });
}

#[test]
fn last_error_is_null_on_a_fresh_handle() {
    let path = cstr("127.0.0.1");
    let mut h = ptr::null_mut();
    // SAFETY: valid pointers.
    assert_eq!(
        unsafe { ciplink_cip_new(path.as_ptr(), ptr::null(), &mut h) },
        CiplinkStatus::Ok
    );
    let h = Handle(h);
    // SAFETY: a live handle.
    assert!(unsafe { ciplink_last_error(h.0) }.is_null());
}

#[test]
fn panics_are_caught() {
    let st = guard(None, || panic!("boom"));
    assert_eq!(st, CiplinkStatus::Panic);
    assert_eq!(last_error(ptr::null()), "internal error: boom");
}

#[test]
fn version_is_the_crate_version() {
    // SAFETY: a static NUL-terminated string.
    let v = unsafe { CStr::from_ptr(ciplink_version()) };
    assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}

// ------------------------------------------------------------------------------------------------ JSON

#[test]
fn value_json_roundtrips_every_form() {
    let mut s = IndexMap::new();
    s.insert("b".to_owned(), Value::Bool(true));
    s.insert("a".to_owned(), Value::LInt(i64::MIN));
    let cases = [
        (Value::Bool(false), "false"),
        (Value::ULInt(u64::MAX), "18446744073709551615"),
        (Value::LInt(i64::MIN), "-9223372036854775808"),
        (Value::Real(1.1), "1.1"),
        (Value::LReal(1e100), "1e100"),
        (Value::LReal(2.0), "2.0"),
        (Value::LReal(f64::NAN), r#"{"$float":"NaN"}"#),
        (Value::Real(f32::NEG_INFINITY), r#"{"$float":"-Infinity"}"#),
        (Value::String("a\"b\n".into()), r#""a\"b\n""#),
        (Value::Bytes(vec![0, 0xab, 0xff]), r#"{"$bytes":"00abff"}"#),
        (
            Value::Array(vec![Value::DInt(1), Value::DInt(-2)]),
            "[1,-2]",
        ),
        (Value::Struct(s), r#"{"b":true,"a":-9223372036854775808}"#),
    ];
    for (v, want) in cases {
        let mut out = String::new();
        value_json(&v, &mut out);
        assert_eq!(out, want);
        let back = json_value(&serde_json::from_str(&out).unwrap())
            .ok()
            .unwrap();
        let mut again = String::new();
        value_json(&back, &mut again);
        assert_eq!(again, want, "roundtrip of {want}");
    }
}

#[test]
fn json_value_rejects_null_and_bad_hex() {
    for bad in [
        "null",
        r#"{"$bytes":"abc"}"#,
        r#"{"$bytes":"zz"}"#,
        r#"{"$float":"x"}"#,
        "[1,null]",
    ] {
        assert!(
            json_value(&serde_json::from_str(bad).unwrap()).is_err(),
            "{bad}"
        );
    }
}

// ------------------------------------------------------------------------------------------------ Logix over TCP

#[test]
fn logix_reads_and_writes_atomic_array_struct_string_and_bits() {
    let (sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    let r = h.read(&[
        "dint1",
        "ulint1",
        "real1",
        "str1",
        "dint_ary[2]{3}",
        "udt1.dint",
        "bool1",
        "dint1.0",
    ]);
    let values: Vec<&Json> = r.as_array().unwrap().iter().map(|t| &t["value"]).collect();
    assert_eq!(values[0], &serde_json::json!(2147483647));
    assert_eq!(values[1], &serde_json::json!(18446744073709551615u64));
    assert_eq!(values[2], &serde_json::json!(3.25));
    assert_eq!(values[3], &serde_json::json!("Hello Logix"));
    assert_eq!(values[4], &serde_json::json!([200, 300, 400]));
    assert_eq!(values[5], &serde_json::json!(10));
    assert_eq!(values[6], &serde_json::json!(true));
    assert_eq!(values[7], &serde_json::json!(true));
    assert_eq!(r[0]["type"], "DINT");
    assert!(r[0]["error"].is_null());

    let w = h.write(r#"[["dint1", 5], ["real1", 1.5], ["str1", "hi"], ["dint_ary[0]{2}", [7, 8]],
        ["udt1", {"bool": false, "sint": 1, "int": 2, "dint": 3, "lint": 4, "real": 0.5}], ["bool2", true]]"#);
    assert!(
        w.as_array().unwrap().iter().all(|t| t["error"].is_null()),
        "{w}"
    );
    assert_eq!(sim.value("dint1").unwrap(), serde_json::json!(5));
    assert_eq!(sim.value("str1").unwrap(), serde_json::json!("hi"));
    assert_eq!(sim.value("dint_ary[1]").unwrap(), serde_json::json!(8));
    assert_eq!(sim.value("udt1.lint").unwrap(), serde_json::json!(4));
    assert_eq!(sim.value("bool2").unwrap(), serde_json::json!(true));
}

#[test]
fn logix_per_tag_errors_are_data() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    let r = h.read(&["no_such_tag", "dint1"]);
    assert!(r[0]["value"].is_null());
    assert_eq!(r[0]["error"]["kind"], "not_found");
    assert_eq!(r[1]["value"], 2147483647);
    let w = h.write(r#"[["sint1", 1000]]"#);
    assert_eq!(w[0]["error"]["kind"], "bad_value", "{w}");
}

#[test]
fn bad_write_items_are_invalid_arguments() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    for items in ["{}", "[1]", r#"[["a"]]"#, r#"[["a", null]]"#, "not json"] {
        let items = cstr(items);
        let mut out = ptr::null_mut();
        // SAFETY: valid pointers.
        let st = unsafe { ciplink_write(h.0, items.as_ptr(), &mut out) };
        assert_eq!(st, CiplinkStatus::InvalidArgument);
        assert!(out.is_null());
        assert!(!last_error(h.0).is_empty());
    }
}

#[test]
fn logix_tags_info_time_and_generic_message() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    let call = |f: &dyn Fn(*mut *mut c_char) -> CiplinkStatus| {
        let mut out = ptr::null_mut();
        assert_eq!(f(&mut out), CiplinkStatus::Ok, "{}", last_error(h.0));
        serde_json::from_str::<Json>(&take(out)).unwrap()
    };
    // SAFETY (all closures): a live handle and valid pointers.
    let tags = call(&|o| unsafe { ciplink_tags(h.0, o) });
    assert_eq!(tags["dint1"]["data_type"], "DINT");
    let info = call(&|o| unsafe { ciplink_info(h.0, o) });
    assert_eq!(info["product_name"], "1756-SIM/A");
    let name = cstr("udt1.dint");
    let ti = call(&|o| unsafe { ciplink_tag_info(h.0, name.as_ptr(), o) });
    assert_eq!(ti["data_type"], "DINT");
    let types = call(&|o| unsafe { ciplink_data_types(h.0, o) });
    assert!(types.get("AtomicUDT").is_some());
    let list = call(&|o| unsafe { ciplink_tag_list(h.0, ptr::null(), true, ptr::null(), o) });
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|t| t["tag_name"] == "dint1")
    );

    let set = call(&|o| unsafe { ciplink_set_plc_time(h.0, 1_700_000_000_000_000, o) });
    assert!(set["error"].is_null(), "{set}");
    let time = call(&|o| unsafe { ciplink_get_plc_time(h.0, o) });
    let us = time["value"]["microseconds"].as_u64().unwrap();
    assert!(us >= 1_700_000_000_000_000, "{time}");

    // Get Attribute Single of the identity's product code
    let msg = CiplinkMessage {
        service: 0x0e,
        class_code: 1,
        instance: 1,
        attribute: 3,
        request_data: ptr::null(),
        request_data_len: 0,
        connected: false,
        unconnected_send: false,
        route_path: ptr::null(),
        name: ptr::null(),
    };
    let reply = call(&|o| unsafe { ciplink_generic_message(h.0, &msg, o) });
    assert_eq!(reply["tag"], "generic");
    assert_eq!(reply["value"]["$bytes"], "a600", "{reply}");
}

#[test]
fn cip_driver_rejects_tag_calls_as_unsupported() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_cip_new, &server);
    let mut out = ptr::null_mut();
    // SAFETY: a live handle.
    assert_eq!(
        unsafe { ciplink_read(h.0, ptr::null(), 0, &mut out) },
        CiplinkStatus::Unsupported
    );
    assert_eq!(last_error(h.0), "read is not supported by this driver");
    // SAFETY: a live handle.
    assert_eq!(
        unsafe { ciplink_tags(h.0, &mut out) },
        CiplinkStatus::Unsupported
    );
    // SAFETY: a live handle.
    assert_eq!(unsafe { ciplink_close(h.0) }, CiplinkStatus::Ok);
}

#[test]
fn list_identity_returns_the_device() {
    let (_sim, server) = serve("example_controller.json");
    let path = cstr(&format!("127.0.0.1:{}", server.port()));
    let mut out = ptr::null_mut();
    // SAFETY: valid pointers.
    assert_eq!(
        unsafe { ciplink_list_identity(path.as_ptr(), &mut out) },
        CiplinkStatus::Ok
    );
    let id: Json = serde_json::from_str(&take(out)).unwrap();
    assert_eq!(id["product_name"], "1756-SIM/A");
}

#[test]
fn connection_failure_is_comm_error() {
    let (sim, server) = serve("example_controller.json");
    sim.inject(ciplink_sim::Fault::RefuseConnections);
    let path = cstr(&format!("127.0.0.1:{}", server.port()));
    let o = cstr(r#"{"socket_timeout": 2}"#);
    let mut h = ptr::null_mut();
    // SAFETY: valid pointers.
    assert_eq!(
        unsafe { ciplink_logix_new(path.as_ptr(), o.as_ptr(), &mut h) },
        CiplinkStatus::Ok
    );
    let h = Handle(h);
    // SAFETY: a live handle.
    assert_eq!(unsafe { ciplink_open(h.0) }, CiplinkStatus::Comm);
    assert!(!last_error(h.0).is_empty());
}

// ------------------------------------------------------------------------------------------------ SLC

#[test]
fn slc_reads_and_writes_data_files() {
    let (sim, server) = serve("example_slc.json");
    let h = open(ciplink_slc_new, &server);
    let w = h.write(r#"[["N7:1", 42]]"#);
    assert!(w[0]["error"].is_null(), "{w}");
    assert_eq!(sim.value("N7:1").unwrap(), serde_json::json!(42));
    let r = h.read(&["N7:1", "N7:0{2}"]);
    assert_eq!(r[0]["value"], 42);
    assert_eq!(r[1]["value"].as_array().unwrap().len(), 2);
}

// ------------------------------------------------------------------------------------------------ threads

#[test]
fn handles_work_concurrently_and_one_handle_is_shared_safely() {
    let (_sim, server) = serve("example_controller.json");
    let shared = open(ciplink_logix_new, &server);
    std::thread::scope(|s| {
        for i in 0..4 {
            let server = &server;
            let shared = &shared;
            s.spawn(move || {
                let own = open(ciplink_logix_new, server);
                for _ in 0..20 {
                    assert_eq!(own.read(&["int1"])[0]["value"], -1234);
                    assert_eq!(shared.read(&["sint1"])[0]["value"], 100);
                    // errors from other threads never leak into this thread's error
                    let r = shared.read(&[&format!("missing{i}")]);
                    assert_eq!(r[0]["error"]["kind"], "not_found");
                }
            });
        }
    });
}

// ------------------------------------------------------------------------------------------------ controller info

fn call_json(f: impl FnOnce(*mut *mut c_char) -> CiplinkStatus, h: &Handle) -> Json {
    let mut out = ptr::null_mut();
    let st = f(&mut out);
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    serde_json::from_str(&take(out)).unwrap()
}

#[test]
fn logix_plc_name_info_module_info_and_tag_table() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    // SAFETY (all calls below): a live handle and writable out pointers.
    let name = call_json(|o| unsafe { ciplink_get_plc_name(h.0, o) }, &h);
    assert_eq!(name, "SimPLC");
    let info = call_json(|o| unsafe { ciplink_get_plc_info(h.0, o) }, &h);
    assert_eq!(info["keyswitch"], "REMOTE RUN");
    assert!(info["product_name"].is_string(), "{info}");
    let module = call_json(|o| unsafe { ciplink_get_module_info(h.0, 1, o) }, &h);
    assert_eq!(module["product_name"], "1756-EN2T/D");
    let version = call_json(|o| unsafe { ciplink_tag_table_version(h.0, o) }, &h);
    assert_eq!(version.as_array().map(Vec::len), Some(5), "{version}");
    let mut changed = true;
    // SAFETY: as above.
    assert_eq!(
        unsafe { ciplink_check_tag_table(h.0, &mut changed) },
        CiplinkStatus::Ok
    );
    assert!(!changed);
    // SAFETY: a NULL out pointer is checked.
    assert_eq!(
        unsafe { ciplink_check_tag_table(h.0, ptr::null_mut()) },
        CiplinkStatus::InvalidArgument
    );
}

#[test]
fn logix_descriptions_need_authentication_then_read_in_batch() {
    let config = r#"{"metadata_auth": true, "tags": [
        {"name": "Array", "type": "DINT", "dims": [30],
         "descriptions": {"": "Array text", "[0]": "Element text"}},
        {"name": "Scalar", "type": "DINT"}]}"#;
    let sim = Simulator::from_json(config).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    let h = open(ciplink_logix_new, &server);
    let describe = |tags: &[&str], encoding: *const c_char| {
        let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
        let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
        let mut out = ptr::null_mut();
        // SAFETY: valid pointers for the duration of the call.
        let st = unsafe {
            ciplink_get_tag_descriptions(h.0, ptrs.as_ptr(), ptrs.len(), 0x7F, encoding, &mut out)
        };
        (st, out)
    };
    let (st, out) = describe(&["Array[0]"], ptr::null());
    assert_eq!(st, CiplinkStatus::Ok);
    let before: Json = serde_json::from_str(&take(out)).unwrap();
    let msg = before[0]["error"]["message"].as_str().unwrap();
    assert!(msg.contains("Permission denied"), "{before}");
    // SAFETY: a live handle and a writable out pointer.
    let auth = call_json(
        |o| unsafe { ciplink_authenticate_metadata(h.0, ptr::null(), 0, ptr::null(), 0, o) },
        &h,
    );
    assert_eq!(auth["value"], true, "{auth}");
    let enc = cstr("cp1252");
    let (st, out) = describe(&["Array[0]", "Array[3]", "Scalar"], enc.as_ptr());
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    let r: Json = serde_json::from_str(&take(out)).unwrap();
    assert_eq!(r[0]["tag"], "Array[0].@Description");
    assert_eq!(r[0]["value"], "Element text");
    assert_eq!(r[1]["value"], "Array text");
    assert_eq!(r[2]["error"]["kind"], "not_found", "{r}");
    let bad = cstr("klingon");
    let (st, out) = describe(&["Array"], bad.as_ptr());
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert!(out.is_null());
}

#[test]
fn slc_processor_type_file_directory_and_datalog() {
    let (_sim, server) = serve("example_slc.json");
    let h = open(ciplink_slc_new, &server);
    // SAFETY (all calls below): a live handle and writable out pointers.
    let t = call_json(|o| unsafe { ciplink_slc_processor_type(h.0, o) }, &h);
    assert_eq!(t, "1747-L552");
    let dir = call_json(|o| unsafe { ciplink_slc_file_directory(h.0, o) }, &h);
    assert_eq!(
        dir["N7"]["length"],
        dir["N7"]["elements"].as_u64().unwrap() * 2,
        "{dir}"
    );
    let logs = call_json(|o| unsafe { ciplink_slc_datalog_queue(h.0, 2, 1, o) }, &h);
    assert_eq!(
        logs,
        serde_json::json!(["2026/10/19,10:00:00,1,2", "2026/10/19,10:01:00,3,4"])
    );
    let drained = call_json(|o| unsafe { ciplink_slc_datalog_queue(h.0, 2, 1, o) }, &h);
    assert_eq!(drained, serde_json::json!([null, null]));
    let module = call_json(|o| unsafe { ciplink_get_module_info(h.0, 0, o) }, &h);
    assert!(module.is_object());
    let mut out = ptr::null_mut();
    // SAFETY: as above; Logix-only calls are unsupported on an SLC handle.
    assert_eq!(
        unsafe { ciplink_get_plc_name(h.0, &mut out) },
        CiplinkStatus::Unsupported
    );
}

// ------------------------------------------------------------------------------------------------ raw, settings, tag list, credentials

/// Get Attribute Single of the identity's product code (class 1, instance 1, attribute 3).
const PRODUCT_CODE_REQUEST: [u8; 8] = [0x0e, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x03];
/// The end of its reply: service 0x8E, status 0, product code 0x00A6.
const PRODUCT_CODE_REPLY: [u8; 6] = [0x8e, 0x00, 0x00, 0x00, 0xa6, 0x00];

type RawSend = unsafe extern "C" fn(
    *const CiplinkDriver,
    *const u8,
    usize,
    *mut *mut u8,
    *mut usize,
) -> CiplinkStatus;

fn raw(send: RawSend, h: &Handle, message: &[u8]) -> (CiplinkStatus, Vec<u8>) {
    let mut data = ptr::null_mut();
    let mut len = 0usize;
    // SAFETY: a live handle, `message` readable, writable out pointers.
    let st = unsafe { send(h.0, message.as_ptr(), message.len(), &mut data, &mut len) };
    let bytes = if data.is_null() {
        Vec::new()
    } else {
        // SAFETY: a library buffer of `len` bytes, copied then freed once.
        let v = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
        // SAFETY: as above.
        unsafe { ciplink_bytes_free(data, len) };
        v
    };
    (st, bytes)
}

#[test]
fn raw_sends_return_the_reply_frames() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    let (st, frame) = raw(ciplink_send_unconnected, &h, &PRODUCT_CODE_REQUEST);
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    assert_eq!(frame[..2], [0x6f, 0x00], "SendRRData reply");
    assert!(frame.ends_with(&PRODUCT_CODE_REPLY), "{frame:02x?}");
    // the Logix open made the Forward Open, so a connected send goes straight out
    let (st, frame) = raw(ciplink_send_connected, &h, &PRODUCT_CODE_REQUEST);
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    assert_eq!(frame[..2], [0x70, 0x00], "SendUnitData reply");
    assert!(frame.ends_with(&PRODUCT_CODE_REPLY), "{frame:02x?}");

    // SLC and CIP handles pass raw messages through too
    let (_slc_sim, slc_server) = serve("example_slc.json");
    let slc = open(ciplink_slc_new, &slc_server);
    let (st, frame) = raw(ciplink_send_unconnected, &slc, &PRODUCT_CODE_REQUEST);
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(slc.0));
    assert_eq!(frame[..2], [0x6f, 0x00]);
    let cip = open(ciplink_cip_new, &server);
    let (st, frame) = raw(ciplink_send_unconnected, &cip, &PRODUCT_CODE_REQUEST);
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(cip.0));
    assert!(frame.ends_with(&PRODUCT_CODE_REPLY), "{frame:02x?}");
}

#[test]
fn raw_send_arguments_are_checked() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_cip_new, &server);
    let mut data = ptr::null_mut();
    let mut len = 7usize;
    // SAFETY: a NULL message with a length is reported, not read.
    let st = unsafe { ciplink_send_unconnected(h.0, ptr::null(), 4, &mut data, &mut len) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert_eq!(last_error(h.0), "message is NULL");
    assert!(data.is_null());
    // SAFETY: a NULL length pointer is checked.
    let st = unsafe {
        ciplink_send_unconnected(
            h.0,
            PRODUCT_CODE_REQUEST.as_ptr(),
            8,
            &mut data,
            ptr::null_mut(),
        )
    };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    // SAFETY: NULL is ignored.
    unsafe { ciplink_bytes_free(ptr::null_mut(), 0) };
    // after close there is no session: a connection error, not a crash
    // SAFETY: a live handle.
    assert_eq!(unsafe { ciplink_close(h.0) }, CiplinkStatus::Ok);
    let (st, frame) = raw(ciplink_send_unconnected, &h, &PRODUCT_CODE_REQUEST);
    assert_eq!(st, CiplinkStatus::Comm, "{frame:02x?}");
}

fn connection_size(h: &Handle) -> u16 {
    let mut size = 0;
    // SAFETY: a live handle and a writable u16.
    let st = unsafe { ciplink_connection_size(h.0, &mut size) };
    assert_eq!(st, CiplinkStatus::Ok);
    size
}

fn socket_timeout(h: &Handle) -> f64 {
    let mut t = 0.0;
    // SAFETY: a live handle and a writable double.
    let st = unsafe { ciplink_socket_timeout(h.0, &mut t) };
    assert_eq!(st, CiplinkStatus::Ok);
    t
}

#[test]
fn connection_size_changes_only_while_not_connected() {
    let (_sim, server) = serve("example_controller.json");
    let path = cstr(&format!("127.0.0.1:{}", server.port()));
    let mut raw_h = ptr::null_mut();
    // SAFETY: valid pointers.
    let st = unsafe { ciplink_logix_new(path.as_ptr(), ptr::null(), &mut raw_h) };
    assert_eq!(st, CiplinkStatus::Ok);
    let h = Handle(raw_h);
    assert_eq!(connection_size(&h), 4000);
    // SAFETY (all calls below): a live handle.
    unsafe {
        assert_eq!(ciplink_set_connection_size(h.0, 500), CiplinkStatus::Ok);
        assert_eq!(
            ciplink_set_connection_size(h.0, 0),
            CiplinkStatus::InvalidArgument
        );
        assert_eq!(
            last_error(h.0),
            "connection_size must be an integer between 1 and 65535"
        );
        assert_eq!(connection_size(&h), 500);
        // a small Forward Open still reads an array larger than one reply, in fragments
        assert_eq!(ciplink_open(h.0), CiplinkStatus::Ok, "{}", last_error(h.0));
        let r = h.read(&["big_ary{2000}"]);
        assert!(r[0]["error"].is_null(), "{r}");
        assert_eq!(r[0]["value"].as_array().map(Vec::len), Some(2000), "{r}");
        assert_eq!(
            ciplink_set_connection_size(h.0, 4000),
            CiplinkStatus::Request
        );
        assert_eq!(
            last_error(h.0),
            "Close the connection before changing connection_size"
        );
        assert_eq!(ciplink_close(h.0), CiplinkStatus::Ok);
        assert_eq!(ciplink_set_connection_size(h.0, 4000), CiplinkStatus::Ok);
        assert_eq!(
            ciplink_connection_size(h.0, ptr::null_mut()),
            CiplinkStatus::InvalidArgument
        );
    }
    assert_eq!(connection_size(&h), 4000);
}

#[test]
fn socket_timeout_is_set_on_open_and_closed_handles() {
    let (_sim, server) = serve("example_slc.json");
    let h = open(ciplink_slc_new, &server);
    assert_eq!(socket_timeout(&h), 5.0);
    // SAFETY (all calls below): a live handle.
    unsafe {
        assert_eq!(ciplink_set_socket_timeout(h.0, 2.5), CiplinkStatus::Ok);
        assert_eq!(socket_timeout(&h), 2.5);
        assert_eq!(ciplink_set_socket_timeout(h.0, -1.0), CiplinkStatus::Ok);
        assert_eq!(socket_timeout(&h), -1.0);
        for bad in [0.0, f64::NAN, f64::INFINITY] {
            assert_eq!(
                ciplink_set_socket_timeout(h.0, bad),
                CiplinkStatus::InvalidArgument,
                "{bad}"
            );
        }
        assert_eq!(socket_timeout(&h), -1.0);
        assert_eq!(ciplink_set_socket_timeout(h.0, 1.0), CiplinkStatus::Ok);
        assert_eq!(
            ciplink_socket_timeout(h.0, ptr::null_mut()),
            CiplinkStatus::InvalidArgument
        );
    }
    let r = h.read(&["N7:0"]);
    assert!(r[0]["error"].is_null(), "{r}");
}

fn tag_list(h: &Handle, program: Option<&str>, cache: bool, filter: Option<&str>) -> Json {
    let program = program.map(cstr);
    let filter = filter.map(cstr);
    let p = program.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    let f = filter.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    // SAFETY: a live handle, NULL or valid strings, a writable out pointer.
    call_json(|o| unsafe { ciplink_tag_list(h.0, p, cache, f, o) }, h)
}

fn tag_names(list: &Json) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|t| t["tag_name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn tag_list_takes_program_cache_and_namespace_filter() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    // SAFETY: a live handle and a writable out pointer.
    let tags = |h: &Handle| call_json(|o| unsafe { ciplink_tags(h.0, o) }, h);
    assert!(tags(&h).get("dint1").is_some());

    // one program, not cached: the cached tags stay as they were
    let program = tag_names(&tag_list(&h, Some("MainProgram"), false, None));
    assert!(!program.is_empty());
    assert!(
        program
            .iter()
            .all(|n| n.starts_with("Program:MainProgram.")),
        "{program:?}"
    );
    assert!(tags(&h).get("dint1").is_some());

    // filtered by namespace
    let filtered = tag_names(&tag_list(&h, None, false, Some("dint")));
    assert!(!filtered.is_empty());
    assert!(
        filtered.iter().all(|n| n.starts_with("dint")),
        "{filtered:?}"
    );
    // an empty filter is no filter
    let all = tag_names(&tag_list(&h, None, false, Some("")));
    assert!(all.len() > filtered.len());

    // cached: the definitions are replaced by the program's
    tag_list(&h, Some("MainProgram"), true, None);
    let cached = tags(&h);
    assert!(cached.get("dint1").is_none(), "{cached}");
    assert!(
        cached
            .as_object()
            .unwrap()
            .keys()
            .all(|k| k.starts_with("Program:MainProgram.")),
        "{cached}"
    );
}

/// The synthetic test credentials of the reference fixtures (not the bundled ones).
fn synthetic_credentials() -> (Vec<u8>, Vec<u8>) {
    let path = format!(
        "{}/../ciplink/tests/fixtures/logix_descriptions.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let fixture: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |k: &str| {
        parse_hex(fixture["credentials"][k].as_str().unwrap())
            .ok()
            .unwrap()
    };
    (hex("certificate"), hex("key"))
}

fn authenticate(
    h: &Handle,
    cert: Option<&[u8]>,
    key: Option<&[u8]>,
) -> (CiplinkStatus, Option<Json>) {
    let (cp, cl) = cert.map_or((ptr::null(), 0), |c| (c.as_ptr(), c.len()));
    let (kp, kl) = key.map_or((ptr::null(), 0), |k| (k.as_ptr(), k.len()));
    let mut out = ptr::null_mut();
    // SAFETY: a live handle, NULL or readable buffers, a writable out pointer.
    let st = unsafe { ciplink_authenticate_metadata(h.0, cp, cl, kp, kl, &mut out) };
    let json = (!out.is_null()).then(|| serde_json::from_str(&take(out)).unwrap());
    (st, json)
}

#[test]
fn authenticate_metadata_with_caller_credentials_unlocks_descriptions() {
    let config = r#"{"metadata_auth": true, "tags": [
        {"name": "Scalar", "type": "DINT", "descriptions": {"": "Scalar text"}}]}"#;
    let sim = Simulator::from_json(config).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    let h = open(ciplink_logix_new, &server);
    let (cert, key) = synthetic_credentials();

    let (st, _) = authenticate(&h, Some(&cert), None);
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    let (st, out) = authenticate(&h, Some(&cert), Some(&key[..10]));
    assert_eq!(st, CiplinkStatus::Request, "{}", last_error(h.0));
    assert!(out.is_none());

    let (st, out) = authenticate(&h, Some(&cert), Some(&key));
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    let out = out.unwrap();
    assert_eq!(out["tag"], "metadata_authentication");
    assert_eq!(out["value"], true, "{out}");
    let name = cstr("Scalar");
    let ptrs = [name.as_ptr()];
    let r = call_json(
        // SAFETY: a live handle, one valid name, a writable out pointer.
        |o| unsafe { ciplink_get_tag_descriptions(h.0, ptrs.as_ptr(), 1, 0x7F, ptr::null(), o) },
        &h,
    );
    assert_eq!(r[0]["value"], "Scalar text", "{r}");
}

#[test]
fn logix_only_calls_on_an_slc_handle_are_unsupported() {
    let (_sim, server) = serve("example_slc.json");
    let h = open(ciplink_slc_new, &server);
    let mut out = ptr::null_mut();
    // SAFETY: a live handle and a writable out pointer.
    let st = unsafe { ciplink_tag_list(h.0, ptr::null(), true, ptr::null(), &mut out) };
    assert_eq!(st, CiplinkStatus::Unsupported);
    let (st, _) = authenticate(&h, None, None);
    assert_eq!(st, CiplinkStatus::Unsupported);
}

// ------------------------------------------------------------------------------------------------ trends

fn trend_start(h: &Handle, tags: &[&str], options: &str) -> (CiplinkStatus, *mut CiplinkTrend) {
    let names: Vec<CString> = tags.iter().map(|t| cstr(t)).collect();
    let ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
    let options = cstr(options);
    let mut trend = ptr::null_mut();
    // SAFETY: a live handle and valid pointers for the duration of the call.
    let st = unsafe {
        ciplink_trend_start(h.0, ptrs.as_ptr(), ptrs.len(), options.as_ptr(), &mut trend)
    };
    (st, trend)
}

fn trend_json(
    trend: *const CiplinkTrend,
    f: unsafe extern "C" fn(*const CiplinkTrend, *mut *mut c_char) -> CiplinkStatus,
) -> Json {
    let mut out = ptr::null_mut();
    // SAFETY: a live trend and a writable out pointer.
    let st = unsafe { f(trend, &mut out) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(ptr::null()));
    serde_json::from_str(&take(out)).unwrap()
}

#[test]
fn a_trend_samples_tags_as_json_and_stops_on_close() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    let (st, trend) = trend_start(
        &h,
        &["int1", "real1", "bool1", "timer1.ACC"],
        r#"{"period_ms": 5}"#,
    );
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(ptr::null()));
    let info = trend_json(trend, ciplink_trend_info);
    assert_eq!(
        info["pens"][1],
        serde_json::json!({"tag": "real1", "type": "REAL"})
    );
    assert_eq!(info["period_us"], 5000);
    assert_eq!(info["running"], true);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut samples = Vec::new();
    while samples.len() < 2 && std::time::Instant::now() < deadline {
        samples.extend(
            trend_json(trend, ciplink_trend_read)
                .as_array()
                .unwrap()
                .clone(),
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(samples.len() >= 2);
    assert_eq!(
        samples[0]["values"],
        serde_json::json!([-1234, 3.25, true, 1234])
    );
    assert_eq!(
        samples[0]["timestamp_us"].as_u64().unwrap(),
        info["start_time_us"].as_u64().unwrap() + samples[0]["elapsed_us"].as_u64().unwrap()
    );
    // SAFETY: a live trend, freed once.
    unsafe {
        assert_eq!(ciplink_trend_close(trend), CiplinkStatus::Ok);
        assert_eq!(trend_json(trend, ciplink_trend_info)["running"], false);
        ciplink_trend_free(trend);
    }
}

#[test]
fn trend_errors_are_statuses() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_logix_new, &server);
    let (st, trend) = trend_start(&h, &["lint1"], "");
    assert_eq!(st, CiplinkStatus::Request);
    assert!(trend.is_null());
    assert!(last_error(ptr::null()).contains("LINT"));
    let (st, _) = trend_start(&h, &["dint1"], r#"{"period_ms": -1}"#);
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    // SAFETY: NULL trends are checked or ignored.
    unsafe {
        assert_eq!(
            ciplink_trend_close(ptr::null()),
            CiplinkStatus::InvalidArgument
        );
        ciplink_trend_free(ptr::null_mut());
    }
    let (_sim, server) = serve("example_slc.json");
    let slc = open(ciplink_slc_new, &server);
    assert_eq!(
        trend_start(&slc, &["N7:0"], "").0,
        CiplinkStatus::Unsupported
    );
}

// ------------------------------------------------------------------------------------------------ browsing

fn json_out(f: impl FnOnce(*mut *mut c_char) -> CiplinkStatus, h: &Handle) -> Json {
    let mut out = ptr::null_mut();
    let st = f(&mut out);
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    serde_json::from_str(&take(out)).unwrap()
}

#[test]
fn browsing_lists_ports_slots_and_the_devices_on_the_network() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_cip_new, &server);
    // SAFETY (every call below): a live handle, NULL or valid strings, a writable out pointer.
    let id = json_out(|o| unsafe { ciplink_get_identity(h.0, ptr::null(), o) }, &h);
    assert_eq!(id["product_name"], "1756-SIM/A");
    let route = cstr("bp/1");
    let id = json_out(
        |o| unsafe { ciplink_get_identity(h.0, route.as_ptr(), o) },
        &h,
    );
    assert_eq!(id["product_name"], "1756-EN2T/D");

    let ports = json_out(|o| unsafe { ciplink_get_ports(h.0, ptr::null(), o) }, &h);
    assert_eq!(ports[0]["type_name"], "Backplane");
    assert_eq!(ports[0]["nodes"].as_array().unwrap().len(), 10);
    assert_eq!(ports[1]["type_name"], "EtherNet/IP");
    assert_eq!(
        (ports[1]["ip"].as_str(), ports[1]["netmask"].as_str()),
        (Some("192.168.1.10"), Some("255.255.255.0"))
    );

    let slots = cstr("[1, 2, 3]");
    let nodes = json_out(
        |o| unsafe { ciplink_browse_port(h.0, ptr::null(), 1, slots.as_ptr(), 2, o) },
        &h,
    );
    let names: Vec<_> = nodes
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["identity"]["product_name"].clone())
        .collect();
    assert_eq!(
        names,
        [
            Json::from("1756-EN2T/D"),
            Json::from("1756-IB16/A"),
            Json::Null
        ]
    );
    assert_eq!(nodes[0]["route"], "1/1");
    assert!(nodes[2]["error"].is_string());

    // the subnet of the EtherNet/IP port by default, in address order
    let nodes = json_out(
        |o| unsafe { ciplink_browse_port(h.0, ptr::null(), 2, ptr::null(), 16, o) },
        &h,
    );
    let nodes = nodes.as_array().unwrap();
    assert_eq!(nodes.len(), 254);
    let found: Vec<_> = nodes
        .iter()
        .filter(|n| !n["identity"].is_null())
        .map(|n| n["route"].clone())
        .collect();
    assert_eq!(found, [Json::from("2/192.168.1.20")]);
}

#[test]
fn a_scan_calls_back_with_each_node_until_told_to_stop() {
    let (_sim, server) = serve("example_controller.json");
    let h = open(ciplink_cip_new, &server);

    unsafe extern "C" fn until_found(user: *mut c_void, node_json: *const c_char) -> bool {
        // SAFETY: `user` is the Vec below and `node_json` a string valid during the call.
        let seen = unsafe { &mut *user.cast::<Vec<Json>>() };
        let text = unsafe { CStr::from_ptr(node_json) }.to_str().unwrap();
        seen.push(serde_json::from_str(text).unwrap());
        seen.last().unwrap()["identity"].is_null()
    }
    let mut seen: Vec<Json> = Vec::new();
    // SAFETY: a live handle, a callback that does not unwind, and `user` the Vec it expects.
    let st = unsafe {
        ciplink_scan_port(
            h.0,
            ptr::null(),
            2,
            ptr::null(),
            4,
            Some(until_found),
            (&raw mut seen).cast(),
        )
    };
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(h.0));
    assert_eq!(
        seen.last().unwrap()["identity"]["product_name"],
        "1734-AENTR/C"
    );
    assert!(seen.len() < 254, "the scan went on after the stop");

    // SAFETY: as above, but with no callback.
    let st =
        unsafe { ciplink_scan_port(h.0, ptr::null(), 2, ptr::null(), 4, None, ptr::null_mut()) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    let bad = cstr("{\"not\": \"a list\"}");
    let mut out = ptr::null_mut();
    // SAFETY: valid pointers.
    let st = unsafe { ciplink_browse_port(h.0, ptr::null(), 1, bad.as_ptr(), 1, &mut out) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
}

// ------------------------------------------------------------------------------------------------ tag server

/// A one-PLC mock server config in a fresh temp dir.
fn server_config(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ciplink-ffi-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("tags.json"),
        r#"{"Speed": "REAL", "Count": "DINT"}"#,
    )
    .unwrap();
    let config = dir.join("tagserver.toml");
    std::fs::write(
        &config,
        "[server]\naudit_log = \"\"\npages_file = \"\"\n[plc.P]\npath = \"192.0.2.1\"\nmock_tags = \"tags.json\"\n[token.t]\nsecret = \"s\"\n",
    )
    .unwrap();
    config
}

fn http_get(addr: &str, path: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn server_starts_serves_and_stops() {
    let config = cstr(server_config("serve").to_str().unwrap());
    let options = cstr(r#"{"mock": true, "port": 0}"#);
    let mut server = ptr::null_mut();
    // SAFETY: valid strings and out pointer.
    let st = unsafe { ciplink_server_start(config.as_ptr(), options.as_ptr(), &mut server) };
    assert_eq!(st, CiplinkStatus::Ok, "{}", last_error(ptr::null()));
    let mut addr = ptr::null_mut();
    // SAFETY: a live server and a writable out pointer.
    assert_eq!(
        unsafe { ciplink_server_address(server, &mut addr) },
        CiplinkStatus::Ok
    );
    let addr = take(addr);
    assert!(addr.starts_with("127.0.0.1:"), "{addr}");
    let mut health = String::new();
    for _ in 0..50 {
        health = http_get(&addr, "/health");
        if health.contains("\"connected\"") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.contains(r#""P":{"state":"connected""#), "{health}");
    // SAFETY: the server from ciplink_server_start, stopped once.
    assert_eq!(unsafe { ciplink_server_stop(server) }, CiplinkStatus::Ok);
    // SAFETY: NULL is ignored.
    assert_eq!(
        unsafe { ciplink_server_stop(ptr::null_mut()) },
        CiplinkStatus::Ok
    );
}

#[test]
fn server_start_reports_bad_configs() {
    let missing = cstr("no/such/tagserver.toml");
    let mut server = ptr::null_mut();
    // SAFETY: valid strings and out pointer.
    let st = unsafe { ciplink_server_start(missing.as_ptr(), ptr::null(), &mut server) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert!(server.is_null());
    assert!(last_error(ptr::null()).contains("tagserver.toml"));
    let config = cstr(server_config("bad").to_str().unwrap());
    let bad = cstr(r#"{"port": 70000}"#);
    // SAFETY: valid strings and out pointer.
    let st = unsafe { ciplink_server_start(config.as_ptr(), bad.as_ptr(), &mut server) };
    assert_eq!(st, CiplinkStatus::InvalidArgument);
    assert_eq!(last_error(ptr::null()), "option port must be 0 to 65535");
    let mut addr = ptr::null_mut();
    // SAFETY: NULL server is reported, out pointer writable.
    assert_eq!(
        unsafe { ciplink_server_address(ptr::null(), &mut addr) },
        CiplinkStatus::InvalidArgument
    );
}
