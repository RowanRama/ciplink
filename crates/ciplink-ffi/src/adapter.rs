//! The adapter: ciplink as an EtherNet/IP I/O device that a Logix controller owns (see `ciplink::adapter`).

use super::{
    CiplinkStatus, FfiError, FfiResult, arg_str, check_out, guard, opt_bytes, options_map,
    parse_hex, put_bytes, put_string,
};
use ciplink_core::adapter::{
    Adapter, AdapterConfig, AdapterIdentity, Assembly, ConnectionInfo, Event,
};
use serde_json::{Map, Value as Json, json};
use std::ffi::c_char;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The longest a next_event waits in the core before it looks whether the adapter was stopped.
const SLICE: Duration = Duration::from_millis(100);

/// A running adapter, made by [`ciplink_adapter_start`], stopped by [`ciplink_adapter_stop`] (other threads' calls
/// then fail or return no event) and freed by [`ciplink_adapter_free`]. The adapter functions report failures on
/// the calling thread: [`ciplink_last_error`](super::ciplink_last_error) with NULL.
pub struct CiplinkAdapter {
    // shared by the calls in flight, so a thread waiting in next_event does not block set_input
    adapter: Mutex<Option<Arc<Adapter>>>,
}

impl CiplinkAdapter {
    fn get(&self) -> FfiResult<Arc<Adapter>> {
        self.adapter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| FfiError::Invalid("the adapter is stopped".into()))
    }

    /// Stops the adapter once the calls in flight let go of it (each holds it for at most a SLICE).
    fn stop(&self) {
        let taken = self
            .adapter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let Some(mut adapter) = taken else { return };
        loop {
            match Arc::try_unwrap(adapter) {
                Ok(a) => return a.stop(),
                Err(shared) => {
                    adapter = shared;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
}

/// Runs an adapter entry point; a NULL adapter is an invalid argument.
fn with_adapter(
    adapter: *const CiplinkAdapter,
    f: impl FnOnce(&CiplinkAdapter) -> FfiResult<()>,
) -> CiplinkStatus {
    // SAFETY: the caller passes NULL or a live adapter from `ciplink_adapter_start` not yet freed.
    match unsafe { adapter.as_ref() } {
        Some(a) => guard(None, || f(a)),
        None => guard(None, || {
            Err(FfiError::Invalid("adapter handle is NULL".into()))
        }),
    }
}

fn invalid<T>(message: String) -> FfiResult<T> {
    Err(FfiError::Invalid(message))
}

/// An unsigned integer option of at most `max`, `default` when absent.
fn uint(o: &Map<String, Json>, key: &str, default: u64, max: u64) -> FfiResult<u64> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(default),
        Some(j) => match j.as_u64().filter(|n| *n <= max) {
            Some(n) => Ok(n),
            None => invalid(format!("option {key} must be an integer from 0 to {max}")),
        },
    }
}

fn text(o: &Map<String, Json>, key: &str, default: &str) -> FfiResult<String> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(default.to_owned()),
        Some(Json::String(s)) => Ok(s.clone()),
        Some(_) => invalid(format!("option {key} must be a string")),
    }
}

fn seconds(o: &Map<String, Json>, key: &str, default: Duration) -> FfiResult<Duration> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(default),
        Some(j) => match j.as_f64().and_then(|s| Duration::try_from_secs_f64(s).ok()) {
            Some(d) => Ok(d),
            None => invalid(format!("option {key} must be a number of seconds >= 0")),
        },
    }
}

/// The assemblies of an `{"instance": size}` option.
fn assemblies(
    o: &Map<String, Json>,
    key: &str,
    make: fn(u32, usize) -> Assembly,
) -> FfiResult<Vec<Assembly>> {
    let Some(map) = o.get(key) else {
        return Ok(Vec::new());
    };
    let Some(map) = map.as_object() else {
        return invalid(format!("option {key} must be an object of instance: size"));
    };
    let mut out = Vec::with_capacity(map.len());
    for (instance, size) in map {
        let (Ok(instance), Some(size)) = (instance.parse::<u32>(), size.as_u64()) else {
            return invalid(format!("option {key} must map instance numbers to sizes"));
        };
        let size = usize::try_from(size)
            .map_err(|_| FfiError::Invalid(format!("{key}: size too large")))?;
        out.push(make(instance, size));
    }
    out.sort_by_key(|a| a.instance);
    Ok(out)
}

fn identity(o: &Map<String, Json>) -> FfiResult<AdapterIdentity> {
    let d = AdapterIdentity::default();
    let revision = match o.get("revision") {
        None | Some(Json::Null) => d.revision,
        Some(Json::Array(r)) => match r.as_slice() {
            [major, minor] => match (major.as_u64(), minor.as_u64()) {
                (Some(major @ 0..=255), Some(minor @ 0..=255)) => (major as u8, minor as u8),
                _ => {
                    return invalid(
                        "identity revision must be [major, minor], each 0 to 255".into(),
                    );
                }
            },
            _ => return invalid("identity revision must be [major, minor]".into()),
        },
        Some(_) => return invalid("identity revision must be [major, minor]".into()),
    };
    Ok(AdapterIdentity {
        vendor_id: uint(o, "vendor_id", d.vendor_id.into(), 0xFFFF)? as u16,
        device_type: uint(o, "device_type", d.device_type.into(), 0xFFFF)? as u16,
        product_code: uint(o, "product_code", d.product_code.into(), 0xFFFF)? as u16,
        revision,
        serial: uint(o, "serial", d.serial.into(), 0xFFFF_FFFF)? as u32,
        product_name: text(o, "product_name", &d.product_name)?,
    })
}

fn adapter_config(o: &Map<String, Json>) -> FfiResult<AdapterConfig> {
    let d = AdapterConfig::default();
    let identity = match o.get("identity") {
        None | Some(Json::Null) => d.identity.clone(),
        Some(Json::Object(id)) => identity(id)?,
        Some(_) => return invalid("option identity must be an object".into()),
    };
    let mut all = assemblies(o, "inputs", Assembly::input)?;
    all.extend(assemblies(o, "outputs", Assembly::output)?);
    all.extend(assemblies(o, "configs", Assembly::config)?);
    let eds = match (o.get("eds"), o.get("eds_file")) {
        (None | Some(Json::Null), None | Some(Json::Null)) => None,
        (Some(Json::Object(b)), None | Some(Json::Null)) => match b.get("$bytes") {
            Some(Json::String(hex)) if b.len() == 1 => Some(parse_hex(hex)?),
            _ => return invalid("option eds must be {\"$bytes\": hex}".into()),
        },
        (None | Some(Json::Null), Some(Json::String(path))) => Some(
            std::fs::read(path)
                .map_err(|e| FfiError::Invalid(format!("cannot read eds_file {path}: {e}")))?,
        ),
        _ => return invalid("give eds ({\"$bytes\": hex}) or eds_file (a path), not both".into()),
    };
    let bind = text(o, "bind", "0.0.0.0")?;
    let bind: Ipv4Addr = match bind.parse() {
        Ok(ip) => ip,
        Err(_) => return invalid(format!("bind {bind:?} is not an IPv4 address")),
    };
    let mac = match o.get("mac") {
        None | Some(Json::Null) => d.mac,
        Some(Json::Array(m)) if m.len() == 6 => {
            let mut mac = [0u8; 6];
            for (byte, j) in mac.iter_mut().zip(m) {
                *byte = match j.as_u64() {
                    Some(b @ 0..=255) => b as u8,
                    _ => return invalid("option mac must be 6 bytes".into()),
                };
            }
            mac
        }
        Some(_) => return invalid("option mac must be 6 bytes".into()),
    };
    Ok(AdapterConfig {
        identity,
        assemblies: all,
        input_only_heartbeat: uint(
            o,
            "input_only_heartbeat",
            d.input_only_heartbeat.into(),
            0xFFFF,
        )? as u32,
        listen_only_heartbeat: uint(
            o,
            "listen_only_heartbeat",
            d.listen_only_heartbeat.into(),
            0xFFFF,
        )? as u32,
        eds,
        eds_name: text(o, "eds_name", &d.eds_name)?,
        app_name: text(o, "app_name", &d.app_name)?,
        app_version: text(o, "app_version", &d.app_version)?,
        bind,
        port: uint(o, "port", d.port.into(), 0xFFFF)? as u16,
        io_port: uint(o, "io_port", d.io_port.into(), 0xFFFF)? as u16,
        rpi_min: seconds(o, "rpi_min", d.rpi_min)?,
        rpi_max: seconds(o, "rpi_max", d.rpi_max)?,
        mac,
    })
}

/// A connection as JSON, with the keys of the Python binding's dicts (RPIs in seconds).
fn connection_json(c: &ConnectionInfo) -> Json {
    json!({
        "kind": c.kind.as_str(),
        "originator": c.originator.to_string(),
        "o_t_rpi": c.o_t_rpi.as_secs_f64(),
        "t_o_rpi": c.t_o_rpi.as_secs_f64(),
        "input": c.input,
        "input_size": c.input_size,
        "output": c.output,
        "output_size": c.output_size,
        "multicast": c.multicast,
        "o_t_id": c.o_t_id,
        "t_o_id": c.t_o_id,
    })
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn event_json(e: &Event) -> Json {
    match e {
        Event::Opened(c) => json!({"event": "opened", "connection": connection_json(c)}),
        Event::Closed(c) => json!({"event": "closed", "connection": connection_json(c)}),
        Event::TimedOut(c) => json!({"event": "timed_out", "connection": connection_json(c)}),
        Event::Config { instance, data } => {
            json!({"event": "config", "instance": instance, "data": {"$bytes": hex(data)}})
        }
        Event::Output { instance } => json!({"event": "output", "instance": instance}),
    }
}

/// Starts an adapter: binds its ports (TCP/UDP 44818 and UDP 2222 by default) and starts its I/O threads. A config
/// the adapter refuses (e.g. one instance used twice) is a [`CiplinkStatus::Request`] error, a port that is taken a
/// [`CiplinkStatus::Comm`] error.
///
/// `config_json` keys (all optional): `inputs`, `outputs` and `configs` (assemblies as `{"instance": size in
/// bytes}`), `identity` (`{"vendor_id", "device_type", "product_code", "revision": [major, minor], "serial",
/// "product_name"}`), `app_name`, `app_version`, `eds` (`{"$bytes": hex}`) or `eds_file` (a path), `eds_name`, `bind`
/// (the local IPv4 address, default `"0.0.0.0"`), `port` (44818) and `io_port` (2222; 0 picks a free port),
/// `rpi_min` and `rpi_max` (seconds, default 0.002 and 3.2), `input_only_heartbeat` (238), `listen_only_heartbeat`
/// (237) and `mac` (6 numbers).
///
/// # Safety
/// `config_json` is NULL or NUL-terminated; `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_start(
    config_json: *const c_char,
    out: *mut *mut CiplinkAdapter,
) -> CiplinkStatus {
    guard(None, || {
        check_out(out)?;
        let config = adapter_config(&options_map(config_json)?)?;
        let adapter = Adapter::start(config)?;
        let adapter = CiplinkAdapter {
            adapter: Mutex::new(Some(Arc::new(adapter))),
        };
        // SAFETY: `out` was checked not NULL by check_out.
        unsafe { *out = Box::into_raw(Box::new(adapter)) };
        Ok(())
    })
}

/// The addresses the adapter listens on, as JSON `{"address": "ip:port", "io_address": "ip:port"}`: explicit
/// messages and ListIdentity, and class 1 I/O.
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_addresses(
    adapter: *const CiplinkAdapter,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out_json)?;
        let a = a.get()?;
        let addresses =
            json!({"address": a.addr().to_string(), "io_address": a.io_addr().to_string()});
        put_string(out_json, addresses.to_string())
    })
}

/// Sets an input assembly's data, sent in the next T->O packets; shorter data leaves the rest zero.
///
/// # Safety
/// `adapter` is NULL or a live adapter; `data` is NULL (with `len` 0) or `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_set_input(
    adapter: *const CiplinkAdapter,
    instance: u32,
    data: *const u8,
    len: usize,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        let data = opt_bytes(data, len, "data")?.unwrap_or_default();
        Ok(a.get()?.set_input(instance, data)?)
    })
}

/// An input assembly's current data; free it with [`ciplink_bytes_free`](super::ciplink_bytes_free).
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out` and `out_len` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_input(
    adapter: *const CiplinkAdapter,
    instance: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out)?;
        put_bytes(out, out_len, a.get()?.input(instance)?)
    })
}

/// An output assembly's latest data (free it with [`ciplink_bytes_free`](super::ciplink_bytes_free)) and in
/// `*out_run` the controller's run bit (false before the first packet and after the owner closed or timed out).
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out`, `out_len` and `out_run` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_output(
    adapter: *const CiplinkAdapter,
    instance: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
    out_run: *mut bool,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out)?;
        if out_run.is_null() {
            return invalid("output pointer is NULL".into());
        }
        let output = a.get()?.output(instance)?;
        put_bytes(out, out_len, output.data)?;
        // SAFETY: checked not NULL; the caller passes a writable bool.
        unsafe { *out_run = output.run };
        Ok(())
    })
}

/// A configuration assembly's data, as the last Forward Open with data sent it; free it with
/// [`ciplink_bytes_free`](super::ciplink_bytes_free).
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out` and `out_len` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_config(
    adapter: *const CiplinkAdapter,
    instance: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out)?;
        put_bytes(out, out_len, a.get()?.config(instance)?)
    })
}

/// The next event as JSON, waiting up to `timeout_seconds` (negative: until one comes or the adapter is stopped);
/// `null` if none came. An event is `{"event": "opened" | "closed" | "timed_out", "connection": {...}}` (a
/// connection as [`ciplink_adapter_connections`] lists it), `{"event": "output", "instance": int}` (an output
/// assembly's data or run bit changed; sent once until it is read) or `{"event": "config", "instance": int,
/// "data": {"$bytes": hex}}`.
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_next_event(
    adapter: *const CiplinkAdapter,
    timeout_seconds: f64,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out_json)?;
        let deadline = match timeout_seconds {
            t if t < 0.0 => None,
            t => match Duration::try_from_secs_f64(t) {
                Ok(t) => Some(Instant::now() + t),
                Err(_) => return invalid("timeout_seconds must be a number".into()),
            },
        };
        loop {
            // short waits, so ciplink_adapter_stop gets through while a thread waits here
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            let slice = left.map_or(SLICE, |l| l.min(SLICE));
            let Ok(adapter) = a.get() else {
                return put_string(out_json, "null".into()); // stopped
            };
            if let Some(e) = adapter.next_event(Some(slice)) {
                return put_string(out_json, event_json(&e).to_string());
            }
            if left.is_some_and(|l| l <= slice) {
                return put_string(out_json, "null".into());
            }
        }
    })
}

/// The open class 1 connections as a JSON array of `{"kind": "exclusive_owner" | "input_only" | "listen_only",
/// "originator": str, "o_t_rpi": seconds, "t_o_rpi": seconds, "input": int, "input_size": int, "output": int |
/// null, "output_size": int, "multicast": bool, "o_t_id": int, "t_o_id": int}`.
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_connections(
    adapter: *const CiplinkAdapter,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out_json)?;
        let list: Vec<Json> = a.get()?.connections().iter().map(connection_json).collect();
        put_string(out_json, Json::Array(list).to_string())
    })
}

/// Sets the application's status text that device browsers show, e.g. `"station 2"`.
///
/// # Safety
/// `adapter` is NULL or a live adapter; `detail` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_set_detail(
    adapter: *const CiplinkAdapter,
    detail: *const c_char,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        let detail = arg_str(detail, "detail")?;
        a.get()?.set_detail(detail);
        Ok(())
    })
}

/// I/O timing counters as JSON `{"produced": int, "late": int, "max_late": seconds}`: packets sent, those 1 ms or
/// more late, and the latest one.
///
/// # Safety
/// `adapter` is NULL or a live adapter; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_stats(
    adapter: *const CiplinkAdapter,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        check_out(out_json)?;
        let s = a.get()?.stats();
        let stats =
            json!({"produced": s.produced, "late": s.late, "max_late": s.max_late.as_secs_f64()});
        put_string(out_json, stats.to_string())
    })
}

/// Stops the adapter: closes its sockets and joins its threads, and controllers then time out. A thread waiting in
/// [`ciplink_adapter_next_event`] returns `null` within 0.1 s; later calls fail. Stopping twice is fine.
///
/// # Safety
/// `adapter` is NULL or a live adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_stop(adapter: *const CiplinkAdapter) -> CiplinkStatus {
    with_adapter(adapter, |a| {
        a.stop();
        Ok(())
    })
}

/// Frees an adapter, stopping it first if needed. NULL is ignored.
///
/// # Safety
/// `adapter` is NULL or an adapter from [`ciplink_adapter_start`] not yet freed, and no other thread is using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_adapter_free(adapter: *mut CiplinkAdapter) {
    if !adapter.is_null() {
        // SAFETY: made by Box::into_raw in `ciplink_adapter_start`, freed once (caller contract).
        let _ = std::panic::catch_unwind(|| {
            let adapter = unsafe { Box::from_raw(adapter) };
            adapter.stop();
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        CiplinkStatus, ciplink_bytes_free, ciplink_cip_new, ciplink_driver_free, ciplink_get_app,
    };
    use crate::{ciplink_last_error, ciplink_open, ciplink_string_free};
    use ciplink_sim::{IoRequest, Scanner};
    use std::ffi::{CStr, CString};
    use std::ptr;

    struct Handle(*mut CiplinkAdapter);

    // SAFETY: the adapter is Sync (its state is locked inside); the tests call it from several threads on purpose.
    unsafe impl Send for Handle {}
    // SAFETY: as above.
    unsafe impl Sync for Handle {}

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: made by `ciplink_adapter_start` in this test, freed once.
            unsafe { ciplink_adapter_free(self.0) };
        }
    }

    fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        // SAFETY: a live string from the library, freed right after copying.
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        // SAFETY: as above.
        unsafe { ciplink_string_free(p) };
        s
    }

    fn error() -> String {
        // SAFETY: NULL asks for this thread's latest error.
        take(unsafe { ciplink_last_error(ptr::null()) })
    }

    fn start(config: &str) -> Result<Handle, (CiplinkStatus, String)> {
        let config = CString::new(config).unwrap();
        let mut out = ptr::null_mut();
        // SAFETY: a NUL-terminated config and a writable out pointer.
        match unsafe { ciplink_adapter_start(config.as_ptr(), &mut out) } {
            CiplinkStatus::Ok => Ok(Handle(out)),
            status => Err((status, error())),
        }
    }

    fn json(
        a: &Handle,
        f: unsafe extern "C" fn(*const CiplinkAdapter, *mut *mut c_char) -> CiplinkStatus,
    ) -> Json {
        let mut out = ptr::null_mut();
        // SAFETY: a live adapter and a writable out pointer.
        assert_eq!(
            unsafe { f(a.0, &mut out) },
            CiplinkStatus::Ok,
            "{}",
            error()
        );
        serde_json::from_str(&take(out)).unwrap()
    }

    fn next_event(a: &Handle, timeout: f64) -> Json {
        let mut out = ptr::null_mut();
        // SAFETY: a live adapter and a writable out pointer.
        let status = unsafe { ciplink_adapter_next_event(a.0, timeout, &mut out) };
        assert_eq!(status, CiplinkStatus::Ok, "{}", error());
        serde_json::from_str(&take(out)).unwrap()
    }

    fn bytes(out: *mut u8, len: usize) -> Vec<u8> {
        if out.is_null() {
            return Vec::new();
        }
        // SAFETY: a library buffer of `len` bytes, freed right after copying.
        let data = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
        // SAFETY: as above.
        unsafe { ciplink_bytes_free(out, len) };
        data
    }

    const STATION: &str = r#"{"inputs": {"100": 8}, "outputs": {"150": 4}, "configs": {"199": 0},
        "identity": {"product_name": "Station", "product_code": 7, "serial": 4660},
        "app_name": "Station", "bind": "127.0.0.1", "port": 0, "io_port": 0}"#;

    #[test]
    fn a_scanner_owns_the_adapter_through_the_c_abi() {
        let a = start(STATION).unwrap();
        let addresses = json(&a, ciplink_adapter_addresses);
        let tcp = addresses["address"].as_str().unwrap().parse().unwrap();
        let io = addresses["io_address"].as_str().unwrap().parse().unwrap();
        // SAFETY (every call below): a live adapter, valid buffers and writable out pointers.
        assert_eq!(
            unsafe { ciplink_adapter_set_input(a.0, 100, [1, 2].as_ptr(), 2) },
            CiplinkStatus::Ok
        );

        let scanner = Scanner::open(
            tcp,
            io,
            IoRequest::owner(150, 4, 100, 8, Duration::from_millis(10)),
        )
        .unwrap();
        let opened = next_event(&a, 2.0);
        assert_eq!(opened["event"], "opened");
        let c = &opened["connection"];
        assert_eq!(
            (
                c["kind"].as_str(),
                c["input"].as_u64(),
                c["output"].as_u64()
            ),
            (Some("exclusive_owner"), Some(100), Some(150))
        );

        scanner.set_output(&[9, 8, 7, 6], true);
        // each change is an output event: the scanner's first packets carry zeros, then the new data
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < deadline, "the new output never came");
            if next_event(&a, 0.5) != json!({"event": "output", "instance": 150}) {
                continue;
            }
            let (mut out, mut len, mut run) = (ptr::null_mut(), 0, false);
            let status = unsafe { ciplink_adapter_output(a.0, 150, &mut out, &mut len, &mut run) };
            assert_eq!(status, CiplinkStatus::Ok);
            if (bytes(out, len), run) == (vec![9, 8, 7, 6], true) {
                break;
            }
        }
        assert!(scanner.wait_for_packets(2, Duration::from_secs(2)));
        assert_eq!(scanner.input().unwrap(), [1, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(json(&a, ciplink_adapter_connections)[0]["output_size"], 4);
        assert!(
            json(&a, ciplink_adapter_stats)["produced"]
                .as_u64()
                .unwrap()
                > 0
        );

        // a browser sees what it runs and who owns it
        let path = CString::new(tcp.to_string()).unwrap();
        let mut driver = ptr::null_mut();
        assert_eq!(
            unsafe { ciplink_cip_new(path.as_ptr(), ptr::null(), &mut driver) },
            CiplinkStatus::Ok
        );
        assert_eq!(unsafe { ciplink_open(driver) }, CiplinkStatus::Ok);
        let mut app = ptr::null_mut();
        assert_eq!(
            unsafe { ciplink_get_app(driver, ptr::null(), &mut app) },
            CiplinkStatus::Ok
        );
        let app: Json = serde_json::from_str(&take(app)).unwrap();
        unsafe { ciplink_driver_free(driver) };
        assert_eq!(app["summary"], "Station · owned by 127.0.0.1, RPI 10 ms");

        assert_eq!(scanner.close().unwrap().0, 0);
        assert_eq!(next_event(&a, 2.0)["event"], "closed");
        let (mut out, mut len) = (ptr::null_mut(), 0);
        assert_eq!(
            unsafe { ciplink_adapter_config(a.0, 199, &mut out, &mut len) },
            CiplinkStatus::Ok
        );
        assert_eq!(bytes(out, len), Vec::<u8>::new());
    }

    #[test]
    fn stop_wakes_a_waiting_thread_and_later_calls_fail() {
        let a = start(STATION).unwrap();
        assert_eq!(next_event(&a, 0.05), Json::Null);
        let waiter = std::thread::scope(|s| {
            let waiting = s.spawn(|| next_event(&a, -1.0));
            std::thread::sleep(Duration::from_millis(200));
            let stopped = Instant::now();
            // SAFETY: a live adapter.
            assert_eq!(unsafe { ciplink_adapter_stop(a.0) }, CiplinkStatus::Ok);
            (waiting.join().unwrap(), stopped.elapsed())
        });
        assert_eq!(waiter.0, Json::Null);
        assert!(waiter.1 < Duration::from_secs(1));
        // SAFETY: a live (stopped) adapter.
        let status = unsafe { ciplink_adapter_set_input(a.0, 100, ptr::null(), 0) };
        assert_eq!(
            (status, error()),
            (
                CiplinkStatus::InvalidArgument,
                "the adapter is stopped".to_owned()
            )
        );
        // SAFETY: as above; stopping twice is fine.
        assert_eq!(unsafe { ciplink_adapter_stop(a.0) }, CiplinkStatus::Ok);
    }

    #[test]
    fn bad_configs_are_refused() {
        let twice =
            start(r#"{"inputs": {"100": 8}, "outputs": {"100": 4}, "port": 0, "io_port": 0}"#);
        assert_eq!(twice.err().map(|e| e.0), Some(CiplinkStatus::Request));
        let (status, message) = start(r#"{"bind": "nowhere"}"#).err().unwrap();
        assert_eq!(
            (status, message.as_str()),
            (
                CiplinkStatus::InvalidArgument,
                "bind \"nowhere\" is not an IPv4 address"
            )
        );
        let (status, _) = start(r#"{"inputs": [8]}"#).err().unwrap();
        assert_eq!(status, CiplinkStatus::InvalidArgument);
        // SAFETY: NULL is ignored.
        unsafe { ciplink_adapter_free(ptr::null_mut()) };
    }
}
