//! C ABI over the ciplink Rust core, used by the C++ and C# bindings.
//!
//! # Design
//!
//! - One opaque handle type, [`CiplinkDriver`], made by [`ciplink_logix_new`], [`ciplink_slc_new`] or
//!   [`ciplink_cip_new`] and freed with [`ciplink_driver_free`]. Calls a driver kind does not support return
//!   [`CiplinkStatus::Unsupported`]. A handle can be used from several threads at once (calls are serialized
//!   inside the driver).
//! - Every function returns a [`CiplinkStatus`]; 0 is success. The message of the latest failure is kept on the
//!   handle and on the calling thread: [`ciplink_last_error`] with the handle, or with NULL for the calling
//!   thread's latest failure (the one to use for constructors, handle-less calls, or a handle shared by threads).
//! - Values cross the ABI as UTF-8 JSON text. Every `char*` the library returns is owned by the caller and freed
//!   with [`ciplink_string_free`]; the raw reply frames of [`ciplink_send_connected`] and
//!   [`ciplink_send_unconnected`] are freed with [`ciplink_bytes_free`]. Nothing else is allocated by the
//!   library except handles.
//! - Per-tag failures are data in the result JSON, not a failed status.
//!
//! # Value JSON
//!
//! BOOL is `true`/`false`; integers are JSON numbers (full 64-bit range, signed and unsigned); REAL/LREAL are
//! numbers that always contain `.` or `e`; non-finite floats are `{"$float": "NaN" | "Infinity" | "-Infinity"}`;
//! strings are strings; raw bytes are `{"$bytes": "<lowercase hex>"}`; arrays are arrays; structures are
//! objects in member order. Writes accept the same forms (any number for a REAL, any integer for an integer
//! type, range checked by the driver).
//!
//! A tag result is `{"tag": str, "value": value|null, "type": str|null, "error": null|{"message": str,
//! "kind": str, "status": int|null, "ext": int|null}}`, `kind` being one of `not_found`, `bad_value`,
//! `bad_request`, `access`, `refused`, `table_changed`, `comm`, `device`, `other`.
#![allow(unsafe_code)] // the C ABI needs raw pointers; every unsafe block says why it is sound
#![warn(missing_docs)]

use ciplink_core::cip::{CipDriver, CipOptions, GenericMessage, RoutePath, TagResult};
use ciplink_core::epath::LogicalValue;
use ciplink_core::logix::auth::LogixMetadataCredentials;
use ciplink_core::logix::driver::{LogixDriver, LogixOptions};
use ciplink_core::logix::metadata::TextEncoding;
use ciplink_core::logix::types::PyObj;
use ciplink_core::slc::driver::SlcDriver;
use ciplink_core::{Error, Value};
use indexmap::IndexMap;
use serde_json::{Map, Value as Json};
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;
use std::time::Duration;

// ------------------------------------------------------------------------------------------------ types

/// Status code returned by every function.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiplinkStatus {
    /// Success.
    Ok = 0,
    /// Connection failure (Python `CommError`).
    Comm = 1,
    /// Encoding or decoding failure (Python `DataError`, `BufferEmptyError`).
    Data = 2,
    /// The reply could not be used (Python `ResponseError`).
    Response = 3,
    /// The request could not be built from the input (Python `RequestError`).
    Request = 4,
    /// A NULL pointer, bad UTF-8 or bad JSON was passed.
    InvalidArgument = 5,
    /// This driver kind does not support the call.
    Unsupported = 6,
    /// The library panicked (a bug); the handle stays usable.
    Panic = 7,
}

/// A driver handle: a Logix, SLC or plain CIP driver.
pub struct CiplinkDriver {
    driver: Driver,
    last_error: Mutex<Option<String>>,
}

enum Driver {
    Logix(Box<LogixDriver>),
    Slc(SlcDriver),
    Cip(CipDriver),
}

/// A generic CIP message (like a Logix MSG instruction).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CiplinkMessage {
    /// Service code.
    pub service: u8,
    /// Class code.
    pub class_code: u32,
    /// Instance, 0 for the class attributes.
    pub instance: u32,
    /// Attribute, negative for none.
    pub attribute: i32,
    /// Request data (may be NULL when `request_data_len` is 0).
    pub request_data: *const u8,
    /// Length of `request_data`.
    pub request_data_len: usize,
    /// Send over the CIP connection (Forward Open first if needed), else unconnected.
    pub connected: bool,
    /// Unconnected only: wrap in an Unconnected Send along `route_path`.
    pub unconnected_send: bool,
    /// Route of the Unconnected Send: NULL for the driver's path, "" for none, else e.g. "bp/2".
    pub route_path: *const c_char,
    /// Name given to the result, NULL for "generic".
    pub name: *const c_char,
}

enum FfiError {
    Core(Error),
    Invalid(String),
    Unsupported(&'static str),
}

impl From<Error> for FfiError {
    fn from(e: Error) -> Self {
        FfiError::Core(e)
    }
}

type FfiResult<T> = Result<T, FfiError>;

thread_local! {
    static THREAD_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn status_of(err: &FfiError) -> (CiplinkStatus, String) {
    match err {
        FfiError::Core(e) => {
            let status = match e {
                Error::Comm(_) => CiplinkStatus::Comm,
                Error::Data(_) | Error::BufferEmpty => CiplinkStatus::Data,
                Error::Response { .. } => CiplinkStatus::Response,
                Error::Request { .. } => CiplinkStatus::Request,
            };
            let message = match e {
                Error::BufferEmpty => "buffer empty".to_owned(),
                e => e.to_string(),
            };
            (status, message)
        }
        FfiError::Invalid(m) => (CiplinkStatus::InvalidArgument, m.clone()),
        FfiError::Unsupported(what) => (
            CiplinkStatus::Unsupported,
            format!("{what} is not supported by this driver"),
        ),
    }
}

fn set_error(handle: Option<&CiplinkDriver>, message: String) {
    if let Some(h) = handle {
        *h.last_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(message.clone());
    }
    THREAD_ERROR.with(|e| *e.borrow_mut() = Some(message));
}

/// Runs an entry point: catches panics, records the error, returns the status.
fn guard(handle: Option<&CiplinkDriver>, f: impl FnOnce() -> FfiResult<()>) -> CiplinkStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CiplinkStatus::Ok,
        Ok(Err(e)) => {
            let (status, message) = status_of(&e);
            set_error(handle, message);
            status
        }
        Err(panic) => {
            let message = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            set_error(handle, format!("internal error: {message}"));
            CiplinkStatus::Panic
        }
    }
}

/// Runs an entry point taking a handle; a NULL handle is an invalid argument.
fn with_handle(
    handle: *const CiplinkDriver,
    f: impl FnOnce(&CiplinkDriver) -> FfiResult<()>,
) -> CiplinkStatus {
    // SAFETY: the caller passes NULL or a live handle from a `ciplink_*_new` not yet freed.
    match unsafe { handle.as_ref() } {
        Some(h) => guard(Some(h), || f(h)),
        None => guard(None, || {
            Err(FfiError::Invalid("driver handle is NULL".into()))
        }),
    }
}

/// A required UTF-8 string argument.
fn arg_str<'a>(p: *const c_char, what: &str) -> FfiResult<&'a str> {
    if p.is_null() {
        return Err(FfiError::Invalid(format!("{what} is NULL")));
    }
    // SAFETY: not NULL, and the caller passes a NUL-terminated string that outlives the call.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| FfiError::Invalid(format!("{what} is not valid UTF-8")))
}

/// An optional UTF-8 string argument (NULL is None).
fn opt_str<'a>(p: *const c_char, what: &str) -> FfiResult<Option<&'a str>> {
    if p.is_null() {
        Ok(None)
    } else {
        arg_str(p, what).map(Some)
    }
}

/// An optional byte buffer argument: NULL is None (its length must then be 0).
fn opt_bytes<'a>(p: *const u8, len: usize, what: &str) -> FfiResult<Option<&'a [u8]>> {
    if p.is_null() {
        return if len == 0 {
            Ok(None)
        } else {
            Err(FfiError::Invalid(format!("{what} is NULL")))
        };
    }
    // SAFETY: not NULL, and the caller passes `len` readable bytes that outlive the call.
    Ok(Some(unsafe { std::slice::from_raw_parts(p, len) }))
}

/// Writes `bytes` to a pair of out pointers as a library-owned buffer (NULL and 0 when empty).
fn put_bytes(out: *mut *mut u8, out_len: *mut usize, bytes: Vec<u8>) -> FfiResult<()> {
    if out.is_null() || out_len.is_null() {
        return Err(FfiError::Invalid("output pointer is NULL".into()));
    }
    let len = bytes.len();
    let data = if len == 0 {
        ptr::null_mut()
    } else {
        Box::into_raw(bytes.into_boxed_slice()).cast::<u8>()
    };
    // SAFETY: both checked not NULL; the caller passes writable locations.
    unsafe {
        *out = data;
        *out_len = len;
    }
    Ok(())
}

fn parse_json(text: &str, what: &str) -> FfiResult<Json> {
    serde_json::from_str(text)
        .map_err(|e| FfiError::Invalid(format!("{what} is not valid JSON: {e}")))
}

/// Writes `text` to an out pointer as a new C string.
fn put_string(out: *mut *mut c_char, text: String) -> FfiResult<()> {
    if out.is_null() {
        return Err(FfiError::Invalid("output pointer is NULL".into()));
    }
    let c =
        CString::new(text).map_err(|_| FfiError::Invalid("result contains a NUL byte".into()))?;
    // SAFETY: `out` is not NULL and the caller passes a writable `char*` location.
    unsafe { *out = c.into_raw() };
    Ok(())
}

fn check_out<T>(out: *mut *mut T) -> FfiResult<()> {
    if out.is_null() {
        return Err(FfiError::Invalid("output pointer is NULL".into()));
    }
    // SAFETY: not NULL; clear it so a failed call never leaves garbage for the caller to free.
    unsafe { *out = ptr::null_mut() };
    Ok(())
}

// ------------------------------------------------------------------------------------------------ JSON

/// A value as JSON text (see the crate docs for the forms).
fn value_json(v: &Value, out: &mut String) {
    fn float(x: f64, debug: String, out: &mut String) {
        if x.is_finite() {
            out.push_str(&debug);
        } else {
            let name = if x.is_nan() {
                "NaN"
            } else if x > 0.0 {
                "Infinity"
            } else {
                "-Infinity"
            };
            let _ = write!(out, "{{\"$float\":\"{name}\"}}");
        }
    }
    match v {
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Real(x) => float(f64::from(*x), format!("{x:?}"), out),
        Value::LReal(x) => float(*x, format!("{x:?}"), out),
        Value::String(s) => out.push_str(&Json::String(s.clone()).to_string()),
        Value::Bytes(b) => {
            out.push_str("{\"$bytes\":\"");
            for byte in b {
                let _ = write!(out, "{byte:02x}");
            }
            out.push_str("\"}");
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                value_json(item, out);
            }
            out.push(']');
        }
        Value::Struct(map) => {
            out.push('{');
            for (i, (k, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Json::String(k.clone()).to_string());
                out.push(':');
                value_json(item, out);
            }
            out.push('}');
        }
        other => {
            let _ = write!(out, "{}", other.as_i128().unwrap_or_default());
        }
    }
}

/// A write value from JSON.
fn json_value(j: &Json) -> FfiResult<Value> {
    Ok(match j {
        Json::Null => return Err(FfiError::Invalid("null is not a value".into())),
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::LInt(i)
            } else if let Some(u) = n.as_u64() {
                Value::ULInt(u)
            } else {
                Value::LReal(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Json::String(s) => Value::String(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(json_value).collect::<FfiResult<_>>()?),
        Json::Object(map) => {
            if map.len() == 1 {
                if let Some(Json::String(hex)) = map.get("$bytes") {
                    return Ok(Value::Bytes(parse_hex(hex)?));
                }
                if let Some(Json::String(name)) = map.get("$float") {
                    return Ok(Value::LReal(match name.as_str() {
                        "NaN" => f64::NAN,
                        "Infinity" => f64::INFINITY,
                        "-Infinity" => f64::NEG_INFINITY,
                        _ => return Err(FfiError::Invalid(format!("bad $float {name:?}"))),
                    }));
                }
            }
            let mut members = IndexMap::with_capacity(map.len());
            for (k, v) in map {
                members.insert(k.clone(), json_value(v)?);
            }
            Value::Struct(members)
        }
    })
}

fn parse_hex(hex: &str) -> FfiResult<Vec<u8>> {
    let bad = || FfiError::Invalid(format!("bad $bytes hex {hex:?}"));
    if hex.len() % 2 != 0 {
        return Err(bad());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(bad)
        })
        .collect()
}

fn result_json(r: &TagResult, out: &mut String) {
    out.push_str("{\"tag\":");
    out.push_str(&Json::String(r.tag.clone()).to_string());
    out.push_str(",\"value\":");
    match &r.value {
        Some(v) => value_json(v, out),
        None => out.push_str("null"),
    }
    out.push_str(",\"type\":");
    match &r.data_type {
        Some(t) => out.push_str(&Json::String(t.clone()).to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"error\":");
    match &r.error {
        None => out.push_str("null"),
        Some(e) => {
            let mut err = Map::new();
            err.insert("message".into(), Json::String(e.message.clone()));
            err.insert("kind".into(), Json::String(e.kind.as_str().into()));
            err.insert("status".into(), e.status.map_or(Json::Null, |s| s.into()));
            err.insert("ext".into(), e.ext.map_or(Json::Null, |s| s.into()));
            out.push_str(&Json::Object(err).to_string());
        }
    }
    out.push('}');
}

fn results_json(results: &[TagResult]) -> String {
    let mut out = String::from("[");
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        result_json(r, &mut out);
    }
    out.push(']');
    out
}

fn py_json(obj: &PyObj) -> Json {
    match obj {
        PyObj::None => Json::Null,
        PyObj::Bool(b) => Json::Bool(*b),
        PyObj::Int(i) => i64::try_from(*i)
            .map(Json::from)
            .or_else(|_| u64::try_from(*i).map(Json::from))
            .unwrap_or_else(|_| Json::String(i.to_string())),
        PyObj::Str(s) => Json::String(s.clone()),
        PyObj::List(items) => Json::Array(items.iter().map(py_json).collect()),
        PyObj::Dict(items) => Json::Object(
            items
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        PyObj::Str(s) => s.clone(),
                        PyObj::None => "null".into(),
                        other => match py_json(other) {
                            Json::String(s) => s,
                            j => j.to_string(),
                        },
                    };
                    (key, py_json(v))
                })
                .collect(),
        ),
    }
}

// ------------------------------------------------------------------------------------------------ options

fn get_bool(o: &Map<String, Json>, key: &str, default: bool) -> FfiResult<bool> {
    match o.get(key) {
        None => Ok(default),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(FfiError::Invalid(format!("option {key} must be a boolean"))),
    }
}

fn cip_options(o: &Map<String, Json>, mut opts: CipOptions) -> FfiResult<CipOptions> {
    match o.get("socket_timeout") {
        None => {}
        Some(Json::Null) => opts.socket_timeout = None,
        Some(j) => {
            let secs = j
                .as_f64()
                .filter(|s| s.is_finite() && *s >= 0.0)
                .ok_or_else(|| {
                    FfiError::Invalid("option socket_timeout must be seconds or null".into())
                })?;
            opts.socket_timeout = Some(Duration::from_secs_f64(secs));
        }
    }
    if let Some(j) = o.get("connection_size") {
        opts.connection_size = j
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| FfiError::Invalid("option connection_size must be 1 to 65535".into()))?;
    }
    Ok(opts)
}

fn options_map(p: *const c_char) -> FfiResult<Map<String, Json>> {
    match opt_str(p, "options")? {
        None => Ok(Map::new()),
        Some(t) if t.trim().is_empty() => Ok(Map::new()),
        Some(t) => match parse_json(t, "options")? {
            Json::Object(m) => Ok(m),
            _ => Err(FfiError::Invalid("options must be a JSON object".into())),
        },
    }
}

fn logix_options(o: &Map<String, Json>) -> FfiResult<LogixOptions> {
    let d = LogixOptions::default();
    let tag_namespace_filter = match o.get("tag_namespace_filter") {
        None | Some(Json::Null) => d.tag_namespace_filter,
        Some(Json::String(s)) => s.clone(),
        Some(_) => {
            return Err(FfiError::Invalid(
                "option tag_namespace_filter must be a string".into(),
            ));
        }
    };
    let tag_cache_file = match o.get("tag_cache_file") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => Some(PathBuf::from(s)),
        Some(_) => {
            return Err(FfiError::Invalid(
                "option tag_cache_file must be a string".into(),
            ));
        }
    };
    Ok(LogixOptions {
        init_tags: get_bool(o, "init_tags", d.init_tags)?,
        init_program_tags: get_bool(o, "init_program_tags", d.init_program_tags)?,
        tag_namespace_filter,
        lazy_tags: get_bool(o, "lazy_tags", d.lazy_tags)?,
        tag_cache_file,
        cip: cip_options(o, d.cip)?,
    })
}

fn create(
    path: *const c_char,
    options: *const c_char,
    out: *mut *mut CiplinkDriver,
    make: impl FnOnce(&str, &Map<String, Json>) -> FfiResult<Driver>,
) -> CiplinkStatus {
    guard(None, || {
        check_out(out)?;
        let path = arg_str(path, "path")?;
        let opts = options_map(options)?;
        let driver = make(path, &opts)?;
        let handle = Box::new(CiplinkDriver {
            driver,
            last_error: Mutex::new(None),
        });
        // SAFETY: `out` was checked not NULL by check_out.
        unsafe { *out = Box::into_raw(handle) };
        Ok(())
    })
}

// ------------------------------------------------------------------------------------------------ handles

/// Creates a Logix driver (ControlLogix, CompactLogix, Micro800) for `path` (`ip`, `ip/slot` or a
/// CIP route, `ip:port` for a non-standard port). Not connected until [`ciplink_open`].
///
/// `options_json` may be NULL or `{}`; keys (all optional): `socket_timeout` (seconds, null to block forever,
/// default 5), `connection_size` (default 4000), `init_tags` (true), `init_program_tags` (true),
/// `tag_namespace_filter` (""), `lazy_tags` (false), `tag_cache_file` (null).
///
/// # Safety
/// `path` and `options_json` are NULL or NUL-terminated strings; `out` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_logix_new(
    path: *const c_char,
    options_json: *const c_char,
    out: *mut *mut CiplinkDriver,
) -> CiplinkStatus {
    create(path, options_json, out, |path, o| {
        Ok(Driver::Logix(Box::new(LogixDriver::new(
            path,
            logix_options(o)?,
        )?)))
    })
}

/// Creates an SLC 500 / MicroLogix driver. Options: `socket_timeout` (default 5), `connection_size` (500).
///
/// # Safety
/// As [`ciplink_logix_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_slc_new(
    path: *const c_char,
    options_json: *const c_char,
    out: *mut *mut CiplinkDriver,
) -> CiplinkStatus {
    create(path, options_json, out, |path, o| {
        let opts = cip_options(o, SlcDriver::default_options())?;
        Ok(Driver::Slc(SlcDriver::new(path, opts)?))
    })
}

/// Creates a plain CIP driver (generic messages only). Options: `socket_timeout` (default 5),
/// `connection_size` (4000).
///
/// # Safety
/// As [`ciplink_logix_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_cip_new(
    path: *const c_char,
    options_json: *const c_char,
    out: *mut *mut CiplinkDriver,
) -> CiplinkStatus {
    create(path, options_json, out, |path, o| {
        let opts = cip_options(o, CipOptions::default())?;
        Ok(Driver::Cip(CipDriver::new(path, opts)?))
    })
}

/// Closes (errors ignored) and frees a driver. NULL is ignored.
///
/// # Safety
/// `handle` is NULL or a handle from a `ciplink_*_new` not yet freed, and no other thread is using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_driver_free(handle: *mut CiplinkDriver) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        // SAFETY: a live handle made by Box::into_raw in `create`, freed once (caller contract).
        let h = unsafe { Box::from_raw(handle) };
        let _ = match &h.driver {
            Driver::Logix(d) => d.close(),
            Driver::Slc(d) => d.close(),
            Driver::Cip(d) => d.close(),
        };
    });
}

/// Opens the connection (and, for Logix, reads the controller info and tag list). A refused session is a
/// [`CiplinkStatus::Comm`] error.
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_open(handle: *const CiplinkDriver) -> CiplinkStatus {
    with_handle(handle, |h| {
        let ok = match &h.driver {
            Driver::Logix(d) => d.open()?,
            Driver::Slc(d) => d.open()?,
            Driver::Cip(d) => d.open()?,
        };
        if ok {
            Ok(())
        } else {
            Err(Error::Comm("the target refused the session".into()).into())
        }
    })
}

/// Closes the connection; the handle can be opened again.
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_close(handle: *const CiplinkDriver) -> CiplinkStatus {
    with_handle(handle, |h| {
        match &h.driver {
            Driver::Logix(d) => d.close()?,
            Driver::Slc(d) => d.close()?,
            Driver::Cip(d) => d.close()?,
        }
        Ok(())
    })
}

/// True if the session is open; false for NULL.
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_connected(handle: *const CiplinkDriver) -> bool {
    // SAFETY: NULL or a live handle (caller contract).
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return false;
    };
    catch_unwind(AssertUnwindSafe(|| match &h.driver {
        Driver::Logix(d) => d.connected(),
        Driver::Slc(d) => d.connected(),
        Driver::Cip(d) => d.connected(),
    }))
    .unwrap_or(false)
}

// ------------------------------------------------------------------------------------------------ settings

/// The connection size used by the next Forward Open, in `*out_size`.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_size` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_connection_size(
    handle: *const CiplinkDriver,
    out_size: *mut u16,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        if out_size.is_null() {
            return Err(FfiError::Invalid("output pointer is NULL".into()));
        }
        let size = match &h.driver {
            Driver::Logix(d) => d.connection_size(),
            Driver::Slc(d) => d.cip().connection_size(),
            Driver::Cip(d) => d.connection_size(),
        };
        // SAFETY: not NULL and the caller passes a writable u16.
        unsafe { *out_size = size };
        Ok(())
    })
}

/// Sets the connection size (1 to 65535) used by the next Forward Open; sizes above 511 use a Large Forward
/// Open. 0 is an invalid argument; changing it while the CIP connection is open is a
/// [`CiplinkStatus::Request`] error (close first), as in the Python driver.
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_set_connection_size(
    handle: *const CiplinkDriver,
    size: u16,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        if size == 0 {
            return Err(FfiError::Invalid(
                "connection_size must be an integer between 1 and 65535".into(),
            ));
        }
        match &h.driver {
            Driver::Logix(d) => d.set_connection_size(size)?,
            Driver::Slc(d) => d.cip().set_connection_size(size)?,
            Driver::Cip(d) => d.set_connection_size(size)?,
        }
        Ok(())
    })
}

/// The socket timeout in seconds in `*out_seconds`, or -1 if the socket blocks forever.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_seconds` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_socket_timeout(
    handle: *const CiplinkDriver,
    out_seconds: *mut f64,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        if out_seconds.is_null() {
            return Err(FfiError::Invalid("output pointer is NULL".into()));
        }
        let t = match &h.driver {
            Driver::Logix(d) => d.socket_timeout(),
            Driver::Slc(d) => d.cip().socket_timeout(),
            Driver::Cip(d) => d.socket_timeout(),
        };
        // SAFETY: not NULL and the caller passes a writable double.
        unsafe { *out_seconds = t.map_or(-1.0, |t| t.as_secs_f64()) };
        Ok(())
    })
}

/// Sets the socket timeout to `seconds` (a positive finite number), or makes the socket block forever if
/// `seconds` is negative. It applies to an open connection at once. 0, NaN and infinity are invalid arguments.
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_set_socket_timeout(
    handle: *const CiplinkDriver,
    seconds: f64,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        let timeout = if seconds < 0.0 {
            None
        } else if seconds.is_finite() && seconds > 0.0 {
            Some(Duration::from_secs_f64(seconds))
        } else {
            return Err(FfiError::Invalid(
                "socket_timeout must be a positive finite number, or negative to block forever"
                    .into(),
            ));
        };
        match &h.driver {
            Driver::Logix(d) => d.set_socket_timeout(timeout)?,
            Driver::Slc(d) => d.cip().set_socket_timeout(timeout)?,
            Driver::Cip(d) => d.set_socket_timeout(timeout)?,
        }
        Ok(())
    })
}

// ------------------------------------------------------------------------------------------------ read / write

/// Reads `count` tags (Logix names such as `udt.member[2]`, or SLC addresses such as `N7:0{3}`) into a JSON
/// array of tag results (see the crate docs), one per tag in order.
///
/// # Safety
/// `tags` points to `count` NUL-terminated strings (may be NULL if `count` is 0); `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_read(
    handle: *const CiplinkDriver,
    tags: *const *const c_char,
    count: usize,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let names = arg_names(tags, count)?;
        let results = match &h.driver {
            Driver::Logix(d) => d.read(&names)?,
            Driver::Slc(d) => d.read(&names)?,
            Driver::Cip(_) => return Err(FfiError::Unsupported("read")),
        };
        put_string(out_json, results_json(&results))
    })
}

/// Writes tags from `items_json`, a JSON array of `[tag, value]` pairs, e.g. `[["dint1", 5], ["str1", "hi"]]`,
/// into a JSON array of tag results.
///
/// # Safety
/// `items_json` is a NUL-terminated string; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_write(
    handle: *const CiplinkDriver,
    items_json: *const c_char,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let items = match parse_json(arg_str(items_json, "items")?, "items")? {
            Json::Array(items) => items,
            _ => {
                return Err(FfiError::Invalid(
                    "items must be a JSON array of [tag, value]".into(),
                ));
            }
        };
        let mut pairs = Vec::with_capacity(items.len());
        for item in &items {
            match item.as_array().map(Vec::as_slice) {
                Some([Json::String(tag), value]) => pairs.push((tag.as_str(), json_value(value)?)),
                _ => return Err(FfiError::Invalid("each item must be [tag, value]".into())),
            }
        }
        let results = match &h.driver {
            Driver::Logix(d) => d.write(&pairs)?,
            Driver::Slc(d) => d.write(&pairs)?,
            Driver::Cip(_) => return Err(FfiError::Unsupported("write")),
        };
        put_string(out_json, results_json(&results))
    })
}

// ------------------------------------------------------------------------------------------------ tags and info

fn logix<'a>(h: &'a CiplinkDriver, what: &'static str) -> FfiResult<&'a LogixDriver> {
    match &h.driver {
        Driver::Logix(d) => Ok(d),
        _ => Err(FfiError::Unsupported(what)),
    }
}

/// The uploaded tag definitions (Logix `tags`) as a JSON object by tag name, as the Python driver's dict.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_tags(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        put_string(out_json, py_json(&logix(h, "tags")?.tags_py()).to_string())
    })
}

/// Uploads the tag list of `program` (NULL for controller tags, `"*"` for all, else a program name) as a JSON
/// array of tag dicts (Logix `get_tag_list`). With `cache` the result replaces the cached definitions
/// ([`ciplink_tags`]); `tag_namespace_filter` (NULL or `""` for none) keeps only the tags whose name, without
/// `Program:X.`, starts with it.
///
/// # Safety
/// `program` and `tag_namespace_filter` are NULL or NUL-terminated strings; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_tag_list(
    handle: *const CiplinkDriver,
    program: *const c_char,
    cache: bool,
    tag_namespace_filter: *const c_char,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let d = logix(h, "tag_list")?;
        let program = opt_str(program, "program")?;
        let filter = opt_str(tag_namespace_filter, "tag_namespace_filter")?.unwrap_or("");
        let list = d.get_tag_list(program, cache, filter)?;
        put_string(out_json, py_json(&d.tag_list_py(&list)).to_string())
    })
}

/// The definition of a tag or member (Logix `get_tag_info`) as a JSON object.
///
/// # Safety
/// `tag_name` is a NUL-terminated string; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_tag_info(
    handle: *const CiplinkDriver,
    tag_name: *const c_char,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let name = arg_str(tag_name, "tag_name")?;
        put_string(
            out_json,
            py_json(&logix(h, "tag_info")?.get_tag_info_py(name)?).to_string(),
        )
    })
}

/// The structure data types (Logix `data_types`) as a JSON object by type name.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_data_types(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        put_string(
            out_json,
            py_json(&logix(h, "data_types")?.data_types_py()).to_string(),
        )
    })
}

/// The controller info read on open (Logix `info`) as a JSON object.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_info(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        put_string(out_json, py_json(&logix(h, "info")?.info_py()).to_string())
    })
}

/// Reads the PLC clock (Logix) as a tag result whose value is `{"microseconds": us since 1970 UTC}`.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_get_plc_time(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let r = logix(h, "get_plc_time")?.get_plc_time()?;
        let mut out = String::new();
        result_json(&r, &mut out);
        put_string(out_json, out)
    })
}

/// Sets the PLC clock (Logix) to `microseconds` since 1970 UTC, or to this computer's clock if negative; the
/// result is a tag result.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_set_plc_time(
    handle: *const CiplinkDriver,
    microseconds: i64,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let us = u64::try_from(microseconds).ok();
        let r = logix(h, "set_plc_time")?.set_plc_time(us)?;
        let mut out = String::new();
        result_json(&r, &mut out);
        put_string(out_json, out)
    })
}

/// Sends a generic CIP message; the result is a tag result whose value is the reply data as
/// `{"$bytes": hex}` (null if the reply had none). A failed reply status is the result's error.
///
/// # Safety
/// `message` points to a valid [`CiplinkMessage`] whose pointers follow its field docs; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_generic_message(
    handle: *const CiplinkDriver,
    message: *const CiplinkMessage,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        // SAFETY: NULL or a valid message (caller contract).
        let m = unsafe { message.as_ref() }
            .ok_or_else(|| FfiError::Invalid("message is NULL".into()))?;
        let data = if m.request_data_len == 0 {
            Vec::new()
        } else if m.request_data.is_null() {
            return Err(FfiError::Invalid("request_data is NULL".into()));
        } else {
            // SAFETY: not NULL and the caller passes `request_data_len` readable bytes.
            unsafe { std::slice::from_raw_parts(m.request_data, m.request_data_len) }.to_vec()
        };
        let route_path = match opt_str(m.route_path, "route_path")? {
            None => RoutePath::Current,
            Some("") => RoutePath::None,
            Some(t) => RoutePath::Text(t.to_owned()),
        };
        let msg = GenericMessage {
            service: m.service,
            class_code: LogicalValue::Int(m.class_code.into()),
            instance: LogicalValue::Int(m.instance.into()),
            attribute: u32::try_from(m.attribute).ok().map(LogicalValue::from),
            request_data: data,
            name: opt_str(m.name, "name")?.unwrap_or("generic").to_owned(),
            connected: m.connected,
            unconnected_send: m.unconnected_send,
            route_path,
        };
        let reply = match &h.driver {
            Driver::Logix(d) => d.generic_message(&msg)?,
            Driver::Slc(d) => d.cip().generic_message(&msg)?,
            Driver::Cip(d) => d.generic_message(&msg)?,
        };
        let mut out = String::new();
        result_json(&reply.tag, &mut out);
        put_string(out_json, out)
    })
}

/// Which raw send of [`raw_send`].
#[derive(Clone, Copy)]
enum Raw {
    Connected,
    Unconnected,
}

fn raw_send(
    handle: *const CiplinkDriver,
    kind: Raw,
    message: *const u8,
    message_len: usize,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_reply)?;
        if out_reply_len.is_null() {
            return Err(FfiError::Invalid("output pointer is NULL".into()));
        }
        let message = opt_bytes(message, message_len, "message")?.unwrap_or_default();
        let cip = match &h.driver {
            Driver::Logix(d) => {
                let reply = match kind {
                    Raw::Connected => d.send_connected_raw(message)?,
                    Raw::Unconnected => d.send_unconnected_raw(message)?,
                };
                return put_bytes(out_reply, out_reply_len, reply);
            }
            Driver::Slc(d) => d.cip(),
            Driver::Cip(d) => d,
        };
        let reply = match kind {
            Raw::Connected => cip.send_connected_raw(message)?,
            Raw::Unconnected => cip.send_unconnected_raw(message)?,
        };
        put_bytes(out_reply, out_reply_len, reply)
    })
}

/// Sends a raw connected CIP message (service, request path and data, without the sequence count) in a
/// SendUnitData over the current CIP connection, with the driver's next sequence count, and returns the raw
/// reply frame (encapsulation header included) in `*out_reply` / `*out_reply_len`; free it with
/// [`ciplink_bytes_free`]. It does not make the Forward Open: open the connection first (a Logix
/// [`ciplink_open`] does), or send a connected [`ciplink_generic_message`]. The reply is not checked; a
/// connection failure is a [`CiplinkStatus::Comm`] error.
///
/// # Safety
/// `message` is NULL (with length 0) or `message_len` readable bytes; `out_reply` and `out_reply_len` are
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_send_connected(
    handle: *const CiplinkDriver,
    message: *const u8,
    message_len: usize,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> CiplinkStatus {
    raw_send(
        handle,
        Raw::Connected,
        message,
        message_len,
        out_reply,
        out_reply_len,
    )
}

/// Sends a raw unconnected CIP message (service, request path and data; wrap it in an Unconnected Send
/// yourself to route it) in a SendRRData over the session and returns the raw reply frame, as
/// [`ciplink_send_connected`].
///
/// # Safety
/// As [`ciplink_send_connected`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_send_unconnected(
    handle: *const CiplinkDriver,
    message: *const u8,
    message_len: usize,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> CiplinkStatus {
    raw_send(
        handle,
        Raw::Unconnected,
        message,
        message_len,
        out_reply,
        out_reply_len,
    )
}

// ------------------------------------------------------------------------------------------------ controller info

fn value_string(v: &Value) -> String {
    let mut out = String::new();
    value_json(v, &mut out);
    out
}

fn tag_result_string(r: &TagResult) -> String {
    let mut out = String::new();
    result_json(r, &mut out);
    out
}

/// Reads the controller program name (Logix `get_plc_name`) as a JSON string.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_get_plc_name(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let name = logix(h, "get_plc_name")?.get_plc_name()?;
        put_string(out_json, Json::String(name).to_string())
    })
}

/// Reads the controller identity and keyswitch (Logix `get_plc_info`) as a JSON object.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_get_plc_info(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let info = logix(h, "get_plc_info")?.get_plc_info()?;
        let mut obj = match parse_json(&value_string(&info.identity.to_value()), "identity")? {
            Json::Object(m) => m,
            _ => Map::new(),
        };
        obj.insert("keyswitch".into(), Json::String(info.keyswitch));
        put_string(out_json, Json::Object(obj).to_string())
    })
}

/// Reads the identity of the module in `slot` of the backplane (`get_module_info`) as a JSON object.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_get_module_info(
    handle: *const CiplinkDriver,
    slot: i64,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let id = match &h.driver {
            Driver::Logix(d) => d.get_module_info(slot)?,
            Driver::Slc(d) => d.cip().get_module_info(slot)?,
            Driver::Cip(d) => d.get_module_info(slot)?,
        };
        put_string(out_json, value_string(&id.to_value()))
    })
}

/// Checks the controller's tag table version (Logix `check_tag_table`) and reloads the tag list if it changed;
/// `*out_changed` is true if it did.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_changed` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_check_tag_table(
    handle: *const CiplinkDriver,
    out_changed: *mut bool,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        if out_changed.is_null() {
            return Err(FfiError::Invalid("output pointer is NULL".into()));
        }
        let changed = logix(h, "check_tag_table")?.check_tag_table()?;
        // SAFETY: not NULL and the caller passes a writable bool.
        unsafe { *out_changed = changed };
        Ok(())
    })
}

/// The tag table version the tag list was loaded at (Logix) as a JSON array `[edit counter, ..., ...]` of five
/// numbers, or `null` if unknown.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_tag_table_version(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let v = logix(h, "tag_table_version")?.tag_table_version();
        let j = match v {
            None => Json::Null,
            Some((a, b, c, d, e)) => {
                Json::Array(vec![a.into(), b.into(), c.into(), d.into(), e.into()])
            }
        };
        put_string(out_json, j.to_string())
    })
}

fn arg_names<'a>(tags: *const *const c_char, count: usize) -> FfiResult<Vec<&'a str>> {
    let ptrs: &[*const c_char] = if count == 0 {
        &[]
    } else if tags.is_null() {
        return Err(FfiError::Invalid("tags is NULL".into()));
    } else {
        // SAFETY: not NULL, and the caller passes `count` readable pointers.
        unsafe { std::slice::from_raw_parts(tags, count) }
    };
    ptrs.iter().map(|p| arg_str(*p, "tag name")).collect()
}

fn text_encoding(name: Option<&str>) -> FfiResult<TextEncoding> {
    match name.unwrap_or("utf-8") {
        "utf-8" | "utf8" => Ok(TextEncoding::Utf8),
        "ascii" => Ok(TextEncoding::Ascii),
        "latin-1" | "latin1" | "iso8859-1" | "iso-8859-1" => Ok(TextEncoding::Latin1),
        "cp1252" | "windows-1252" => Ok(TextEncoding::Cp1252),
        other => Err(FfiError::Invalid(format!(
            "unsupported description encoding {other:?} (utf-8, ascii, latin-1 or cp1252)"
        ))),
    }
}

/// Reads the Descriptions of `count` tags (Logix `get_tag_descriptions`) into a JSON array of tag results whose
/// value is the Description text. `language` is the language code (0x7F for the project default); `encoding` is
/// NULL for utf-8, or `ascii`, `latin-1` or `cp1252`.
///
/// # Safety
/// `tags` points to `count` NUL-terminated strings; `encoding` is NULL or a NUL-terminated string; `out_json`
/// is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_get_tag_descriptions(
    handle: *const CiplinkDriver,
    tags: *const *const c_char,
    count: usize,
    language: u16,
    encoding: *const c_char,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let names = arg_names(tags, count)?;
        let encoding = text_encoding(opt_str(encoding, "encoding")?)?;
        let results =
            logix(h, "get_tag_descriptions")?.get_tag_descriptions(&names, language, encoding)?;
        put_string(out_json, results_json(&results))
    })
}

/// Authenticates the connection for metadata reads (Logix `authenticate_metadata`); the result is a tag result
/// whose value is `true` on success, and a refused handshake is the result's error. It applies to the current
/// connection only (call again after a reconnect).
///
/// Pass both `certificate` and `private_key_der` (an unencrypted PKCS #1 or PKCS #8 DER RSA key) for
/// caller-supplied credentials, or both NULL for the bundled ones. Credentials that do not parse, lack the
/// metadata claim or do not match each other are a [`CiplinkStatus::Request`] error.
///
/// # Safety
/// `certificate` is NULL or `certificate_len` readable bytes, likewise `private_key_der`; `out_json` is
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_authenticate_metadata(
    handle: *const CiplinkDriver,
    certificate: *const u8,
    certificate_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let d = logix(h, "authenticate_metadata")?;
        let cert = opt_bytes(certificate, certificate_len, "certificate")?;
        let key = opt_bytes(private_key_der, private_key_der_len, "private_key_der")?;
        let credentials = match (cert, key) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some(LogixMetadataCredentials::new(cert, key)?),
            _ => {
                return Err(FfiError::Invalid(
                    "pass both certificate and private_key_der, or neither for the bundled credentials"
                        .into(),
                ));
            }
        };
        let r = d.authenticate_metadata(credentials.as_ref());
        put_string(out_json, tag_result_string(&r))
    })
}

fn slc<'a>(h: &'a CiplinkDriver, what: &'static str) -> FfiResult<&'a SlcDriver> {
    match &h.driver {
        Driver::Slc(d) => Ok(d),
        _ => Err(FfiError::Unsupported(what)),
    }
}

/// Reads the SLC processor type (`get_processor_type`) as a JSON string, or `null` if not known.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_slc_processor_type(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let t = slc(h, "get_processor_type")?.get_processor_type()?;
        put_string(out_json, t.map_or(Json::Null, Json::String).to_string())
    })
}

/// Reads `num_data_logs` records of SLC data log queue `queue_num` (`get_datalog_queue`) as a JSON array (an
/// entry is `null` where a record could not be read).
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_slc_datalog_queue(
    handle: *const CiplinkDriver,
    num_data_logs: usize,
    queue_num: u8,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let logs = slc(h, "get_datalog_queue")?.get_datalog_queue(num_data_logs, queue_num)?;
        let mut out = String::from("[");
        for (i, v) in logs.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            match v {
                Some(v) => value_json(v, &mut out),
                None => out.push_str("null"),
            }
        }
        out.push(']');
        put_string(out_json, out)
    })
}

/// Reads the SLC data file directory (`get_file_directory`) as a JSON object
/// `{"N7": {"elements": n, "length": bytes}, ...}`.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_slc_file_directory(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let files = slc(h, "get_file_directory")?.get_file_directory()?;
        let obj: Map<String, Json> = files
            .into_iter()
            .map(|(name, f)| {
                let mut m = Map::new();
                m.insert("elements".into(), f.elements.into());
                m.insert("length".into(), f.length.into());
                (name, Json::Object(m))
            })
            .collect();
        put_string(out_json, Json::Object(obj).to_string())
    })
}

// ------------------------------------------------------------------------------------------------ discovery

/// Identifies the device at `path` with ListIdentity: a JSON object, or `null` if it refused.
///
/// # Safety
/// `path` is a NUL-terminated string; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_list_identity(
    path: *const c_char,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    guard(None, || {
        check_out(out_json)?;
        let path = arg_str(path, "path")?;
        let mut out = String::new();
        match CipDriver::list_identity(path)? {
            Some(id) => value_json(&id.to_value(), &mut out),
            None => out.push_str("null"),
        }
        put_string(out_json, out)
    })
}

/// Broadcasts ListIdentity to `broadcast` (NULL for `255.255.255.255`) and returns the devices that answered as
/// a JSON array. Takes a few seconds.
///
/// # Safety
/// `broadcast` is NULL or a NUL-terminated string; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_discover(
    broadcast: *const c_char,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    guard(None, || {
        check_out(out_json)?;
        let broadcast = opt_str(broadcast, "broadcast")?.unwrap_or("255.255.255.255");
        let devices = Value::Array(
            CipDriver::discover(broadcast)
                .iter()
                .map(|d| d.to_value())
                .collect(),
        );
        let mut out = String::new();
        value_json(&devices, &mut out);
        put_string(out_json, out)
    })
}

// ------------------------------------------------------------------------------------------------ errors, memory

/// The message of the latest failed call on `handle`, or of the calling thread's latest failure if `handle` is
/// NULL; NULL if there was none. Free it with [`ciplink_string_free`].
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_last_error(handle: *const CiplinkDriver) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: NULL or a live handle (caller contract).
        let message = match unsafe { handle.as_ref() } {
            Some(h) => h
                .last_error
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
            None => THREAD_ERROR.with(|e| e.borrow().clone()),
        };
        message
            .and_then(|m| CString::new(m.replace('\0', " ")).ok())
            .map_or(ptr::null_mut(), CString::into_raw)
    }))
    .unwrap_or(ptr::null_mut())
}

/// Frees a string returned by the library. NULL is ignored.
///
/// # Safety
/// `s` is NULL or a string returned by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: made by CString::into_raw in this library, freed once (caller contract).
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Frees a byte buffer returned by the library, with the length it was returned with. NULL is ignored.
///
/// # Safety
/// `data` is NULL or a buffer returned by this library with length `len`, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_bytes_free(data: *mut u8, len: usize) {
    if !data.is_null() {
        // SAFETY: made by Box::into_raw of a boxed slice of `len` bytes in put_bytes, freed once (caller
        // contract).
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(data, len)) });
    }
}

/// The library version, a static string (do not free).
#[unsafe(no_mangle)]
pub extern "C" fn ciplink_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[cfg(test)]
mod tests;
