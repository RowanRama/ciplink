//! `ciplink._core`: the Python extension module over the ciplink Rust core.
//!
//! A thin layer: the classes here hold the Rust drivers, convert values and results to Python objects, release
//! the GIL around every call that may touch the network or the driver lock, and raise the exception classes of
//! the pure-Python `ciplink.exceptions` module.  The `ciplink` package wraps these classes in its public API.

mod defs;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ciplink::cip::{CipDriver, CipOptions, GenericMessage, RoutePath, TagResult};
use ciplink::epath::LogicalValue;
use ciplink::logix::auth::LogixMetadataCredentials;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::metadata::TextEncoding;
use ciplink::logix::types::PyObj;
use ciplink::slc::driver::SlcDriver;
use ciplink::transport::{Connector, Transport, tcp_connector};
use ciplink::{Error, Value};
use defs::DefsCache;
use indexmap::IndexMap;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::{MutexExt, PyOnceLock};
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

// ------------------------------------------------------------------------------------------------ errors

/// The ciplink exception class of an error, with its message (a `TagError` when the error is classified).
fn to_py_err(err: Error) -> PyErr {
    Python::attach(|py| match make_py_err(py, &err) {
        Ok(e) => e,
        Err(e) => e,
    })
}

fn make_py_err(py: Python<'_>, err: &Error) -> PyResult<PyErr> {
    let module = py.import("ciplink.exceptions")?;
    let class = match err {
        Error::Comm(_) => "CommError",
        Error::Data(_) => "DataError",
        Error::BufferEmpty => "BufferEmptyError",
        Error::Response { .. } => "ResponseError",
        Error::Request { .. } => "RequestError",
    };
    let message: Py<PyAny> = match err {
        Error::Response {
            message,
            kind: Some(kind),
            status,
            ext,
        } => tag_error(py, message, kind.as_str(), *status, *ext)?.unbind(),
        Error::Request {
            message,
            kind: Some(kind),
        } => tag_error(py, message, kind.as_str(), None, None)?.unbind(),
        other => PyString::new(py, &other.to_string()).into_any().unbind(),
    };
    let instance = module.getattr(class)?.call1((message,))?;
    Ok(PyErr::from_value(instance))
}

trait IntoPy<T> {
    fn py(self) -> PyResult<T>;
}

impl<T> IntoPy<T> for ciplink::Result<T> {
    fn py(self) -> PyResult<T> {
        self.map_err(to_py_err)
    }
}

// ------------------------------------------------------------------------------------------------ cached classes

static TAG_CLASS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static TAG_ERROR_CLASS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static TUPLE_NEW: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn cached<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyAny>>,
    module: &str,
    name: &str,
) -> PyResult<Bound<'py, PyAny>> {
    cell.get_or_try_init(py, || Ok(py.import(module)?.getattr(name)?.unbind()))
        .map(|obj| obj.bind(py).clone())
}

fn tag_error<'py>(
    py: Python<'py>,
    message: &str,
    kind: &str,
    status: Option<u8>,
    ext: Option<u16>,
) -> PyResult<Bound<'py, PyAny>> {
    cached(py, &TAG_ERROR_CLASS, "ciplink.tag", "TagError")?.call1((message, kind, status, ext))
}

/// A `ciplink.tag.Tag`, built with `tuple.__new__` (a C call) instead of the NamedTuple's Python `__new__`.
fn tag_result<'py>(py: Python<'py>, result: &TagResult) -> PyResult<Bound<'py, PyAny>> {
    tag_result_as(py, result, None)
}

/// A `Tag` whose value, if it has one, is `written` (a write's result carries the caller's value object).
fn tag_result_as<'py>(
    py: Python<'py>,
    result: &TagResult,
    written: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let class = cached(py, &TAG_CLASS, "ciplink.tag", "Tag")?;
    let new = TUPLE_NEW.get_or_try_init(py, || {
        Ok::<_, PyErr>(
            py.import("builtins")?
                .getattr("tuple")?
                .getattr("__new__")?
                .unbind(),
        )
    })?;
    let value = match (&result.value, written) {
        (Some(_), Some(obj)) => obj.clone(),
        (Some(v), None) => value_to_py(py, v)?,
        (None, _) => py.None().into_bound(py),
    };
    let error = match &result.error {
        Some(e) => tag_error(py, &e.message, e.kind.as_str(), e.status, e.ext)?,
        None => py.None().into_bound(py),
    };
    let items = PyTuple::new(
        py,
        [
            PyString::new(py, &result.tag).into_any(),
            value,
            result.data_type.as_deref().into_pyobject(py)?.into_any(),
            error,
        ],
    )?;
    new.bind(py).call1((class, items))
}

fn tag_results<'py>(py: Python<'py>, results: &[TagResult]) -> PyResult<Bound<'py, PyList>> {
    let items = results
        .iter()
        .map(|r| tag_result(py, r))
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, items)
}

fn written_results<'py>(
    py: Python<'py>,
    results: &[TagResult],
    written: &[Bound<'py, PyAny>],
) -> PyResult<Bound<'py, PyList>> {
    let items = results
        .iter()
        .enumerate()
        .map(|(i, r)| tag_result_as(py, r, written.get(i)))
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, items)
}

// ------------------------------------------------------------------------------------------------ values

fn value_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
        Value::SInt(v) => v.into_pyobject(py)?.into_any(),
        Value::Int(v) => v.into_pyobject(py)?.into_any(),
        Value::DInt(v) => v.into_pyobject(py)?.into_any(),
        Value::LInt(v) => v.into_pyobject(py)?.into_any(),
        Value::USInt(v) => v.into_pyobject(py)?.into_any(),
        Value::UInt(v) => v.into_pyobject(py)?.into_any(),
        Value::UDInt(v) => v.into_pyobject(py)?.into_any(),
        Value::ULInt(v) => v.into_pyobject(py)?.into_any(),
        Value::Real(v) => PyFloat::new(py, f64::from(*v)).into_any(),
        Value::LReal(v) => PyFloat::new(py, *v).into_any(),
        Value::String(s) => PyString::new(py, s).into_any(),
        Value::Bytes(b) => PyBytes::new(py, b).into_any(),
        Value::Array(items) => {
            let items = items
                .iter()
                .map(|v| value_to_py(py, v))
                .collect::<PyResult<Vec<_>>>()?;
            PyList::new(py, items)?.into_any()
        }
        Value::Struct(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, value_to_py(py, v)?)?;
            }
            dict.into_any()
        }
    })
}

/// A write value: bool, int, float, str, bytes, a list/tuple of values or a dict of member values.
fn value_from_py(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if let Ok(b) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if obj.is_instance_of::<PyInt>() {
        if let Ok(v) = obj.extract::<i64>() {
            return Ok(Value::LInt(v));
        }
        if let Ok(v) = obj.extract::<u64>() {
            return Ok(Value::ULInt(v));
        }
        // beyond 64 bits nothing fits: let the core reject it as a float out of range of the type
        return Ok(Value::LReal(obj.extract::<f64>().unwrap_or(f64::INFINITY)));
    }
    if obj.is_instance_of::<PyFloat>() {
        return Ok(Value::LReal(obj.extract::<f64>()?));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        return Ok(Value::String(s.to_cow()?.into_owned()));
    }
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(Value::Bytes(b.as_bytes().to_vec()));
    }
    if let Ok(d) = obj.cast::<PyDict>() {
        let mut map = IndexMap::with_capacity(d.len());
        for (k, v) in d.iter() {
            map.insert(k.str()?.to_cow()?.into_owned(), value_from_py(&v)?);
        }
        return Ok(Value::Struct(map));
    }
    if obj.is_instance_of::<PyList>() || obj.is_instance_of::<PyTuple>() {
        let mut items = Vec::with_capacity(obj.len()?);
        for item in obj.try_iter()? {
            items.push(value_from_py(&item?)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(b) = obj.extract::<Vec<u8>>() {
        return Ok(Value::Bytes(b)); // bytearray
    }
    Err(PyTypeError::new_err(format!(
        "unsupported value type: {}",
        obj.get_type().name()?
    )))
}

fn pyobj_to_py<'py>(py: Python<'py>, obj: &PyObj) -> PyResult<Bound<'py, PyAny>> {
    Ok(match obj {
        PyObj::None => py.None().into_bound(py),
        PyObj::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
        PyObj::Int(n) => n.into_pyobject(py)?.into_any(),
        PyObj::Str(s) => PyString::new(py, s).into_any(),
        PyObj::List(items) => {
            let items = items
                .iter()
                .map(|v| pyobj_to_py(py, v))
                .collect::<PyResult<Vec<_>>>()?;
            PyList::new(py, items)?.into_any()
        }
        PyObj::Dict(items) => {
            let dict = PyDict::new(py);
            for (k, v) in items {
                dict.set_item(pyobj_to_py(py, k)?, pyobj_to_py(py, v)?)?;
            }
            dict.into_any()
        }
    })
}

// ------------------------------------------------------------------------------------------------ logging

/// Forwards the core's `log` records to Python's `logging`, under the reference driver's logger names.
struct PyLogger;

fn logger_name(target: &str) -> &'static str {
    if target.starts_with("ciplink::logix") {
        "ciplink.logix_driver.LogixDriver"
    } else if target.starts_with("ciplink::slc") {
        "ciplink.slc_driver.SLCDriver"
    } else if target.starts_with("ciplink::cip") || target.starts_with("ciplink::transport") {
        "ciplink.cip_driver.CIPDriver"
    } else {
        "ciplink"
    }
}

fn py_level(level: log::Level) -> u8 {
    match level {
        log::Level::Error => 40,
        log::Level::Warn => 30,
        log::Level::Info => 20,
        log::Level::Debug => 10,
        log::Level::Trace => 5, // LOG_VERBOSE
    }
}

impl log::Log for PyLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        Python::attach(|py| {
            let message = record.args().to_string();
            let result = py
                .import("logging")
                .and_then(|logging| {
                    logging.call_method1("getLogger", (logger_name(record.target()),))
                })
                .and_then(|logger| {
                    logger.call_method1("log", (py_level(record.level()), "%s", message))
                });
            if let Err(err) = result {
                err.print(py);
            }
        });
    }

    fn flush(&self) {}
}

static LOGGING: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

/// Sets the core's log level from the effective level of the `ciplink` logger, so disabled records cost
/// nothing (no GIL, no formatting).  Called on the way into every driver call.
fn sync_log_level(py: Python<'_>) {
    let level = cached(py, &LOGGING, "logging", "getLogger")
        .and_then(|get| get.call1(("ciplink",)))
        .and_then(|logger| logger.call_method0("getEffectiveLevel"))
        .and_then(|level| level.extract::<i64>())
        .unwrap_or(30);
    let filter = match level {
        ..=5 => log::LevelFilter::Trace,
        6..=10 => log::LevelFilter::Debug,
        11..=20 => log::LevelFilter::Info,
        21..=30 => log::LevelFilter::Warn,
        31..=40 => log::LevelFilter::Error,
        _ => log::LevelFilter::Off,
    };
    log::set_max_level(filter);
}

// ------------------------------------------------------------------------------------------------ options

fn timeout(seconds: Option<f64>) -> PyResult<Option<Duration>> {
    match seconds {
        None => Ok(None),
        Some(s) if s.is_finite() && s > 0.0 => Ok(Some(Duration::from_secs_f64(s))),
        Some(_) => Err(PyValueError::new_err(
            "socket_timeout must be a positive finite number or None",
        )),
    }
}

fn connection_size(size: i64) -> PyResult<u16> {
    match u16::try_from(size) {
        Ok(s) if s >= 1 => Ok(s),
        _ => Err(PyValueError::new_err(
            "connection_size must be an integer between 1 and 65535",
        )),
    }
}

fn cip_options(socket_timeout: Option<f64>, size: i64) -> PyResult<CipOptions> {
    Ok(CipOptions {
        socket_timeout: timeout(socket_timeout)?,
        connection_size: connection_size(size)?,
    })
}

fn logical(obj: &Bound<'_, PyAny>, what: &str) -> PyResult<LogicalValue> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(LogicalValue::Raw(b.as_bytes().to_vec()));
    }
    obj.extract::<i64>()
        .map(LogicalValue::Int)
        .map_err(|_| PyTypeError::new_err(format!("{what} must be an int or bytes")))
}

fn service_code(obj: &Bound<'_, PyAny>) -> PyResult<u8> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        if let [code] = b.as_bytes() {
            return Ok(*code);
        }
    }
    obj.extract::<u8>()
        .map_err(|_| PyValueError::new_err("service must be a single byte"))
}

/// A generic message from the Python arguments.  `route_path`: True (current path), None/False (none), a
/// path string or encoded bytes (the Python layer encodes segment lists).
#[allow(clippy::too_many_arguments)]
fn generic(
    service: &Bound<'_, PyAny>,
    class_code: &Bound<'_, PyAny>,
    instance: &Bound<'_, PyAny>,
    attribute: &Bound<'_, PyAny>,
    request_data: &[u8],
    name: &str,
    connected: bool,
    unconnected_send: bool,
    route_path: &Bound<'_, PyAny>,
) -> PyResult<GenericMessage> {
    let attribute = if attribute.is_none()
        || attribute
            .cast::<PyBytes>()
            .is_ok_and(|b| b.as_bytes().is_empty())
    {
        None
    } else {
        match logical(attribute, "attribute")? {
            LogicalValue::Int(0) => None,
            other => Some(other),
        }
    };
    let route_path = if let Ok(b) = route_path.cast::<PyBool>() {
        if b.is_true() {
            RoutePath::Current
        } else {
            RoutePath::None
        }
    } else if route_path.is_none() {
        RoutePath::None
    } else if let Ok(s) = route_path.cast::<PyString>() {
        RoutePath::Text(s.to_cow()?.into_owned())
    } else if let Ok(b) = route_path.cast::<PyBytes>() {
        RoutePath::Encoded(b.as_bytes().to_vec())
    } else {
        return Err(PyTypeError::new_err(
            "route_path must be True, False, None, a str or bytes",
        ));
    };
    Ok(GenericMessage {
        service: service_code(service)?,
        class_code: logical(class_code, "class_code")?,
        instance: logical(instance, "instance")?,
        attribute,
        request_data: request_data.to_vec(),
        name: name.to_owned(),
        connected,
        unconnected_send,
        route_path,
    })
}

/// The raw reply frame of a generic message, for the Python response packet to parse (and decode with its
/// data type) exactly as the reference driver does.
fn generic_reply<'py>(
    py: Python<'py>,
    reply: ciplink::cip::GenericReply,
) -> PyResult<Bound<'py, PyAny>> {
    Ok(match reply.reply.raw {
        Some(raw) => PyBytes::new(py, &raw).into_any(),
        None => py.None().into_bound(py),
    })
}

fn identity<'py>(
    py: Python<'py>,
    id: Option<ciplink::identity::ListIdentity>,
) -> PyResult<Bound<'py, PyAny>> {
    match id {
        Some(id) => value_to_py(py, &id.to_value()),
        None => Ok(PyDict::new(py).into_any()),
    }
}

fn discover_py(py: Python<'_>, broadcast: &str) -> PyResult<Py<PyList>> {
    sync_log_level(py);
    let devices = py.detach(|| CipDriver::discover(broadcast));
    let items = devices
        .iter()
        .map(|d| value_to_py(py, &d.to_value()))
        .collect::<PyResult<Vec<_>>>()?;
    Ok(PyList::new(py, items)?.unbind())
}

fn bytes_result(py: Python<'_>, raw: ciplink::Result<Vec<u8>>) -> PyResult<Py<PyBytes>> {
    Ok(PyBytes::new(py, &raw.py()?).unbind())
}

// ------------------------------------------------------------------------------------------------ CIPDriver

/// The generic CIP driver (`ciplink.CIPDriver`'s core).
#[pyclass(frozen, module = "ciplink._core", name = "CIPDriver")]
struct PyCipDriver {
    inner: CipDriver,
}

#[pymethods]
impl PyCipDriver {
    #[new]
    #[pyo3(signature = (path, socket_timeout=Some(5.0), connection_size=4000))]
    fn new(path: &str, socket_timeout: Option<f64>, connection_size: i64) -> PyResult<Self> {
        Ok(PyCipDriver {
            inner: CipDriver::new(path, cip_options(socket_timeout, connection_size)?).py()?,
        })
    }

    fn open(&self, py: Python<'_>) -> PyResult<bool> {
        sync_log_level(py);
        py.detach(|| self.inner.open()).py()
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        sync_log_level(py);
        py.detach(|| self.inner.close()).py()
    }

    #[getter]
    fn connected(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.connected())
    }

    #[getter]
    fn target_connected(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.lock().target_connected())
    }

    #[getter]
    fn get_connection_size(&self, py: Python<'_>) -> u16 {
        py.detach(|| self.inner.connection_size())
    }

    fn set_connection_size(&self, py: Python<'_>, size: i64) -> PyResult<()> {
        let size = connection_size(size)?;
        py.detach(|| self.inner.set_connection_size(size)).py()
    }

    #[getter]
    fn get_socket_timeout(&self, py: Python<'_>) -> Option<f64> {
        py.detach(|| self.inner.socket_timeout())
            .map(|d| d.as_secs_f64())
    }

    fn set_socket_timeout(&self, py: Python<'_>, seconds: Option<f64>) -> PyResult<()> {
        let t = timeout(seconds)?;
        py.detach(|| self.inner.set_socket_timeout(t)).py()
    }

    #[allow(clippy::too_many_arguments)]
    fn generic_message<'py>(
        &self,
        py: Python<'py>,
        service: &Bound<'py, PyAny>,
        class_code: &Bound<'py, PyAny>,
        instance: &Bound<'py, PyAny>,
        attribute: &Bound<'py, PyAny>,
        request_data: Vec<u8>,
        name: &str,
        connected: bool,
        unconnected_send: bool,
        route_path: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let msg = generic(
            service,
            class_code,
            instance,
            attribute,
            &request_data,
            name,
            connected,
            unconnected_send,
            route_path,
        )?;
        sync_log_level(py);
        let reply = py.detach(|| self.inner.generic_message(&msg)).py()?;
        generic_reply(py, reply)
    }

    /// Sends a connected CIP message (without sequence count) with the next sequence count; the raw reply.
    fn send_connected(&self, py: Python<'_>, message: Vec<u8>) -> PyResult<Py<PyBytes>> {
        let raw = py.detach(|| self.inner.send_connected_raw(&message));
        bytes_result(py, raw)
    }

    /// Sends an unconnected CIP message; the raw reply.
    fn send_unconnected(&self, py: Python<'_>, message: Vec<u8>) -> PyResult<Py<PyBytes>> {
        let raw = py.detach(|| self.inner.send_unconnected_raw(&message));
        bytes_result(py, raw)
    }

    fn get_module_info<'py>(&self, py: Python<'py>, slot: i64) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let id = py.detach(|| self.inner.get_module_info(slot)).py()?;
        value_to_py(py, &id.to_value())
    }

    #[staticmethod]
    fn list_identity<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let id = py.detach(|| CipDriver::list_identity(path)).py()?;
        identity(py, id)
    }

    #[staticmethod]
    fn discover(py: Python<'_>, broadcast: &str) -> PyResult<Py<PyList>> {
        discover_py(py, broadcast)
    }
}

// ------------------------------------------------------------------------------------------------ SLCDriver

/// The SLC 500 / MicroLogix driver (`ciplink.SLCDriver`'s core).
#[pyclass(frozen, module = "ciplink._core", name = "SLCDriver")]
struct PySlcDriver {
    inner: SlcDriver,
}

/// The (tag, value) pairs of a write, as names, values and the value objects.
type WriteItems<'py> = (Vec<String>, Vec<Value>, Vec<Bound<'py, PyAny>>);

fn write_items<'py>(items: &Bound<'py, PyAny>) -> PyResult<WriteItems<'py>> {
    let mut names = Vec::new();
    let mut values = Vec::new();
    let mut objects = Vec::new();
    for item in items.try_iter()? {
        let item = item?;
        let (tag, value): (String, Bound<'py, PyAny>) = item.extract()?;
        names.push(tag);
        values.push(value_from_py(&value)?);
        objects.push(value);
    }
    Ok((names, values, objects))
}

fn pairs(names: &[String], values: Vec<Value>) -> Vec<(&str, Value)> {
    names.iter().map(String::as_str).zip(values).collect()
}

#[pymethods]
impl PySlcDriver {
    #[new]
    #[pyo3(signature = (path, socket_timeout=Some(5.0), connection_size=500))]
    fn new(path: &str, socket_timeout: Option<f64>, connection_size: i64) -> PyResult<Self> {
        Ok(PySlcDriver {
            inner: SlcDriver::new(path, cip_options(socket_timeout, connection_size)?).py()?,
        })
    }

    fn open(&self, py: Python<'_>) -> PyResult<bool> {
        sync_log_level(py);
        py.detach(|| self.inner.open()).py()
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        sync_log_level(py);
        py.detach(|| self.inner.close()).py()
    }

    #[getter]
    fn connected(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.connected())
    }

    #[getter]
    fn target_connected(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.cip().lock().target_connected())
    }

    #[getter]
    fn get_connection_size(&self, py: Python<'_>) -> u16 {
        py.detach(|| self.inner.cip().connection_size())
    }

    fn set_connection_size(&self, py: Python<'_>, size: i64) -> PyResult<()> {
        let size = connection_size(size)?;
        py.detach(|| self.inner.cip().set_connection_size(size))
            .py()
    }

    #[getter]
    fn get_socket_timeout(&self, py: Python<'_>) -> Option<f64> {
        py.detach(|| self.inner.cip().socket_timeout())
            .map(|d| d.as_secs_f64())
    }

    fn set_socket_timeout(&self, py: Python<'_>, seconds: Option<f64>) -> PyResult<()> {
        let t = timeout(seconds)?;
        py.detach(|| self.inner.cip().set_socket_timeout(t)).py()
    }

    #[allow(clippy::too_many_arguments)]
    fn generic_message<'py>(
        &self,
        py: Python<'py>,
        service: &Bound<'py, PyAny>,
        class_code: &Bound<'py, PyAny>,
        instance: &Bound<'py, PyAny>,
        attribute: &Bound<'py, PyAny>,
        request_data: Vec<u8>,
        name: &str,
        connected: bool,
        unconnected_send: bool,
        route_path: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let msg = generic(
            service,
            class_code,
            instance,
            attribute,
            &request_data,
            name,
            connected,
            unconnected_send,
            route_path,
        )?;
        sync_log_level(py);
        let reply = py.detach(|| self.inner.cip().generic_message(&msg)).py()?;
        generic_reply(py, reply)
    }

    fn send_connected(&self, py: Python<'_>, message: Vec<u8>) -> PyResult<Py<PyBytes>> {
        let raw = py.detach(|| self.inner.cip().send_connected_raw(&message));
        bytes_result(py, raw)
    }

    fn send_unconnected(&self, py: Python<'_>, message: Vec<u8>) -> PyResult<Py<PyBytes>> {
        let raw = py.detach(|| self.inner.cip().send_unconnected_raw(&message));
        bytes_result(py, raw)
    }

    fn get_module_info<'py>(&self, py: Python<'py>, slot: i64) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let id = py.detach(|| self.inner.cip().get_module_info(slot)).py()?;
        value_to_py(py, &id.to_value())
    }

    #[staticmethod]
    fn list_identity<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let id = py.detach(|| SlcDriver::list_identity(path)).py()?;
        identity(py, id)
    }

    #[staticmethod]
    fn discover(py: Python<'_>, broadcast: &str) -> PyResult<Py<PyList>> {
        discover_py(py, broadcast)
    }

    fn read<'py>(&self, py: Python<'py>, addresses: Vec<String>) -> PyResult<Bound<'py, PyList>> {
        sync_log_level(py);
        let results = py
            .detach(|| {
                let refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
                self.inner.read(&refs)
            })
            .py()?;
        tag_results(py, &results)
    }

    fn write<'py>(
        &self,
        py: Python<'py>,
        items: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyList>> {
        let (names, values, objects) = write_items(items)?;
        sync_log_level(py);
        let results = py
            .detach(|| self.inner.write(&pairs(&names, values)))
            .py()?;
        written_results(py, &results, &objects)
    }

    fn get_processor_type(&self, py: Python<'_>) -> PyResult<Option<String>> {
        sync_log_level(py);
        py.detach(|| self.inner.get_processor_type()).py()
    }

    fn get_datalog_queue<'py>(
        &self,
        py: Python<'py>,
        num_data_logs: usize,
        queue_num: u8,
    ) -> PyResult<Bound<'py, PyList>> {
        sync_log_level(py);
        let logs = py
            .detach(|| self.inner.get_datalog_queue(num_data_logs, queue_num))
            .py()?;
        let items = logs
            .iter()
            .map(|v| match v {
                Some(v) => value_to_py(py, v),
                None => Ok(py.None().into_bound(py)),
            })
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, items)
    }

    fn get_file_directory<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        sync_log_level(py);
        let files = py.detach(|| self.inner.get_file_directory()).py()?;
        let dict = PyDict::new(py);
        for (name, file) in files {
            let entry = PyDict::new(py);
            entry.set_item("elements", file.elements)?;
            entry.set_item("length", file.length)?;
            dict.set_item(name, entry)?;
        }
        Ok(dict)
    }
}

// ------------------------------------------------------------------------------------------------ LogixDriver

/// The ControlLogix / CompactLogix / Micro800 driver (`ciplink.LogixDriver`'s core).
#[pyclass(frozen, weakref, module = "ciplink._core", name = "LogixDriver")]
struct PyLogixDriver {
    inner: LogixDriver,
    hook: Arc<SendHook>,
    /// `tags`, `data_types` and what they are built from, kept until the definitions change.
    defs: Mutex<DefsCache>,
}

impl PyLogixDriver {
    /// The built definitions, rebuilt first if the core's changed since they were built.
    fn defs<'a>(slf: &'a Bound<'_, Self>) -> PyResult<MutexGuard<'a, DefsCache>> {
        let py = slf.py();
        let this = slf.get();
        let mut cache = this
            .defs
            .lock_py_attached(py)
            .unwrap_or_else(PoisonError::into_inner);
        if !cache.is_current(this.inner.definitions_version()) {
            let (generation, count) = cache.since();
            let defs = py.detach(|| this.inner.definitions_since(generation, count));
            cache.rebuild(py, &defs, slf.as_any())?;
        }
        Ok(cache)
    }
}

/// A Python callable that replaces the driver's sends (the reference driver's `plc._send = f` for tests and
/// tools): each request frame goes to it instead of the socket, and the frame it passes on to
/// `forward_frame` (the original `_send`) is sent after it returns.
#[derive(Default)]
struct SendHook {
    installed: AtomicBool,
    hook: Mutex<Option<Py<PyAny>>>,
    pending: Mutex<Option<Vec<u8>>>,
}

struct HookTransport {
    inner: Box<dyn Transport>,
    hook: Arc<SendHook>,
}

impl Transport for HookTransport {
    fn send(&mut self, frame: &[u8]) -> ciplink::Result<()> {
        if !self.hook.installed.load(Ordering::Acquire) {
            return self.inner.send(frame);
        }
        let called = Python::attach(|py| {
            let hook = self
                .hook
                .hook
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .map(|h| h.clone_ref(py));
            match hook {
                Some(hook) => hook.call1(py, (PyBytes::new(py, frame),)).map(|_| true),
                None => Ok(false),
            }
        });
        let pending = self
            .hook
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match called {
            Ok(false) => self.inner.send(frame),
            Ok(true) => pending.map_or(Ok(()), |f| self.inner.send(&f)),
            Err(err) => {
                Python::attach(|py| err.print(py));
                Err(Error::comm("failed to send message"))
            }
        }
    }

    fn receive(&mut self) -> ciplink::Result<Vec<u8>> {
        self.inner.receive()
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> ciplink::Result<()> {
        self.inner.set_timeout(timeout)
    }
}

fn hook_connector(hook: Arc<SendHook>) -> Connector {
    let tcp = tcp_connector();
    Box::new(move |host, port, timeout| {
        Ok(Box::new(HookTransport {
            inner: tcp(host, port, timeout)?,
            hook: Arc::clone(&hook),
        }) as Box<dyn Transport>)
    })
}

fn text_encoding(name: &str) -> PyResult<TextEncoding> {
    match name {
        "utf-8" | "utf8" => Ok(TextEncoding::Utf8),
        "ascii" => Ok(TextEncoding::Ascii),
        "latin-1" | "latin1" | "iso8859-1" | "iso-8859-1" => Ok(TextEncoding::Latin1),
        "cp1252" | "windows-1252" => Ok(TextEncoding::Cp1252),
        other => Err(PyValueError::new_err(format!(
            "unsupported description encoding {other:?} (utf-8, ascii, latin-1 or cp1252)"
        ))),
    }
}

#[pymethods]
impl PyLogixDriver {
    #[new]
    #[pyo3(signature = (path, init_tags=true, init_program_tags=true, tag_namespace_filter=String::new(),
                        lazy_tags=false, tag_cache_file=None, socket_timeout=Some(5.0), connection_size=4000))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: &str,
        init_tags: bool,
        init_program_tags: bool,
        tag_namespace_filter: String,
        lazy_tags: bool,
        tag_cache_file: Option<std::path::PathBuf>,
        socket_timeout: Option<f64>,
        connection_size: i64,
    ) -> PyResult<Self> {
        let options = LogixOptions {
            init_tags,
            init_program_tags,
            tag_namespace_filter,
            lazy_tags,
            tag_cache_file,
            cip: cip_options(socket_timeout, connection_size)?,
        };
        let hook = Arc::new(SendHook::default());
        Ok(PyLogixDriver {
            inner: LogixDriver::with_connector(path, options, hook_connector(Arc::clone(&hook)))
                .py()?,
            hook,
            defs: Mutex::default(),
        })
    }

    /// Installs (or with None removes) the callable that replaces the driver's sends.
    fn set_send_hook(&self, hook: Option<Py<PyAny>>) {
        let installed = hook.is_some();
        *self
            .hook
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = hook;
        self.hook.installed.store(installed, Ordering::Release);
    }

    /// Sends `frame` after the send hook returns (the original `_send` called from inside a hook).
    fn forward_frame(&self, frame: Vec<u8>) {
        *self
            .hook
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(frame);
    }

    fn open(&self, py: Python<'_>) -> PyResult<bool> {
        sync_log_level(py);
        py.detach(|| self.inner.open()).py()
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        sync_log_level(py);
        py.detach(|| self.inner.close()).py()
    }

    #[getter]
    fn connected(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.connected())
    }

    #[getter]
    fn get_connection_size(&self, py: Python<'_>) -> u16 {
        py.detach(|| self.inner.connection_size())
    }

    fn set_connection_size(&self, py: Python<'_>, size: i64) -> PyResult<()> {
        let size = connection_size(size)?;
        py.detach(|| self.inner.set_connection_size(size)).py()
    }

    #[getter]
    fn get_socket_timeout(&self, py: Python<'_>) -> Option<f64> {
        py.detach(|| self.inner.socket_timeout())
            .map(|d| d.as_secs_f64())
    }

    fn set_socket_timeout(&self, py: Python<'_>, seconds: Option<f64>) -> PyResult<()> {
        let t = timeout(seconds)?;
        py.detach(|| self.inner.set_socket_timeout(t)).py()
    }

    #[allow(clippy::too_many_arguments)]
    fn generic_message<'py>(
        &self,
        py: Python<'py>,
        service: &Bound<'py, PyAny>,
        class_code: &Bound<'py, PyAny>,
        instance: &Bound<'py, PyAny>,
        attribute: &Bound<'py, PyAny>,
        request_data: Vec<u8>,
        name: &str,
        connected: bool,
        unconnected_send: bool,
        route_path: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let msg = generic(
            service,
            class_code,
            instance,
            attribute,
            &request_data,
            name,
            connected,
            unconnected_send,
            route_path,
        )?;
        sync_log_level(py);
        let reply = py.detach(|| self.inner.generic_message(&msg)).py()?;
        generic_reply(py, reply)
    }

    fn send_connected(&self, py: Python<'_>, message: Vec<u8>) -> PyResult<Py<PyBytes>> {
        let raw = py.detach(|| self.inner.send_connected_raw(&message));
        bytes_result(py, raw)
    }

    fn send_unconnected(&self, py: Python<'_>, message: Vec<u8>) -> PyResult<Py<PyBytes>> {
        let raw = py.detach(|| self.inner.send_unconnected_raw(&message));
        bytes_result(py, raw)
    }

    fn get_module_info<'py>(&self, py: Python<'py>, slot: i64) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let id = py.detach(|| self.inner.get_module_info(slot)).py()?;
        value_to_py(py, &id.to_value())
    }

    #[staticmethod]
    fn list_identity<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let id = py.detach(|| LogixDriver::list_identity(path)).py()?;
        identity(py, id)
    }

    #[staticmethod]
    fn discover(py: Python<'_>, broadcast: &str) -> PyResult<Py<PyList>> {
        discover_py(py, broadcast)
    }

    fn get_plc_info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let info = py.detach(|| self.inner.get_plc_info()).py()?;
        let dict = value_to_py(py, &info.identity.to_value())?;
        dict.set_item("keyswitch", info.keyswitch)?;
        Ok(dict)
    }

    fn get_plc_name(&self, py: Python<'_>) -> PyResult<String> {
        sync_log_level(py);
        py.detach(|| self.inner.get_plc_name()).py()
    }

    #[getter]
    fn name(&self, py: Python<'_>) -> Option<String> {
        py.detach(|| self.inner.name())
    }

    #[getter]
    fn revision_major(&self, py: Python<'_>) -> u32 {
        py.detach(|| self.inner.revision_major())
    }

    #[getter]
    fn micro800(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.micro800())
    }

    #[getter]
    fn get_use_instance_ids(&self, py: Python<'_>) -> bool {
        py.detach(|| self.inner.use_instance_ids())
    }

    fn set_use_instance_ids(&self, py: Python<'_>, on: bool) {
        py.detach(|| self.inner.set_use_instance_ids(on))
    }

    #[getter]
    fn tag_table_version(&self, py: Python<'_>) -> Option<(i16, i16, i32, i32, i32)> {
        py.detach(|| self.inner.tag_table_version())
    }

    /// The PLC clock as a Tag whose value is the microseconds since 1970 UTC.
    fn get_plc_time<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let mut result = py.detach(|| self.inner.get_plc_time()).py()?;
        if let Some(Value::Struct(map)) = &result.value {
            result.value = map.get("microseconds").cloned();
        }
        tag_result(py, &result)
    }

    #[pyo3(signature = (microseconds=None))]
    fn set_plc_time<'py>(
        &self,
        py: Python<'py>,
        microseconds: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let result = py.detach(|| self.inner.set_plc_time(microseconds)).py()?;
        tag_result(py, &result)
    }

    /// The tag dicts of a tag list upload: with `cache` those of `tags`, else new ones sharing the data type
    /// dicts of `data_types`.
    #[pyo3(signature = (program=None, cache=true, tag_namespace_filter=""))]
    fn get_tag_list<'py>(
        slf: &Bound<'py, Self>,
        program: Option<String>,
        cache: bool,
        tag_namespace_filter: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let py = slf.py();
        sync_log_level(py);
        let this = slf.get();
        let tags = py
            .detach(|| {
                this.inner
                    .get_tag_list(program.as_deref(), cache, tag_namespace_filter)
            })
            .py()?;
        let mut defs = Self::defs(slf)?;
        if cache {
            if let Some(cached) = defs.tags(py) {
                let found = tags
                    .iter()
                    .map(|t| cached.get_item(&t.tag_name))
                    .collect::<PyResult<Option<Vec<_>>>>()?;
                if let Some(found) = found {
                    return PyList::new(py, found);
                }
            }
        }
        defs.tag_dicts(py, &tags, &[])
    }

    fn check_tag_table(&self, py: Python<'_>) -> PyResult<bool> {
        sync_log_level(py);
        py.detach(|| self.inner.check_tag_table()).py()
    }

    fn get_tag_info<'py>(&self, py: Python<'py>, tag_name: &str) -> PyResult<Bound<'py, PyAny>> {
        sync_log_level(py);
        let info = py.detach(|| self.inner.get_tag_info_py(tag_name)).py()?;
        pyobj_to_py(py, &info)
    }

    /// The reference driver's `tags`: {name: tag dict}, type classes included, kept until the definitions
    /// change.
    #[getter]
    fn tags<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyDict>> {
        let defs = Self::defs(slf)?;
        Ok(defs.tags(slf.py()).unwrap_or_else(|| PyDict::new(slf.py())))
    }

    /// The reference driver's `data_types`: {name: data type dict}, the dicts of `tags`.
    #[getter]
    fn data_types<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyDict>> {
        let defs = Self::defs(slf)?;
        Ok(defs
            .data_types(slf.py())
            .unwrap_or_else(|| PyDict::new(slf.py())))
    }

    /// The reference driver's `tags_json`: a new copy of `tags` without type classes.
    fn tags_json<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyDict>> {
        let tags = Self::tags(slf)?;
        defs::tags_json(slf.py(), &tags)
    }

    /// The dict of a tag or member in `tags`, None if it is not there (`get_tag_info` then asks the core,
    /// which loads a lazy tag or raises the reference driver's error).
    fn cached_tag_info<'py>(
        slf: &Bound<'py, Self>,
        tag_name: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let Ok((_, base, attrs)) = ciplink::logix::types::split_tag_name(tag_name) else {
            return Ok(None);
        };
        let mut defs = Self::defs(slf)?;
        defs.tag_info(slf.py(), &base, &attrs)
    }

    /// Changes whenever the tag definitions change.
    #[getter]
    fn definitions_version(&self) -> u64 {
        self.inner.definitions_version()
    }

    /// The reference driver's `info` (a new dict).
    fn info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let info = py.detach(|| self.inner.info_py());
        let dict = pyobj_to_py(py, &info)?;
        // PyObj has no bytes: the status word is rendered as a list of its two byte values
        if let Ok(d) = dict.cast::<PyDict>() {
            if let Some(status) = d.get_item(pyo3::intern!(py, "status"))? {
                if let Ok(list) = status.cast::<PyList>() {
                    let bytes: Vec<u8> = list.extract()?;
                    d.set_item(pyo3::intern!(py, "status"), PyBytes::new(py, &bytes))?;
                }
            }
        }
        Ok(dict)
    }

    /// Shares the tag definitions of another connection to the same controller.
    fn share_tags_from(&self, py: Python<'_>, other: &Bound<'_, PyLogixDriver>) {
        let other = other.get();
        py.detach(|| self.inner.share_tags_from(&other.inner))
    }

    /// Drops the tag definitions.
    fn clear_tags(&self, py: Python<'_>) {
        py.detach(|| self.inner.set_tags(IndexMap::new()))
    }

    fn read<'py>(&self, py: Python<'py>, tags: Vec<String>) -> PyResult<Bound<'py, PyList>> {
        sync_log_level(py);
        let results = py
            .detach(|| {
                let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                self.inner.read(&refs)
            })
            .py()?;
        tag_results(py, &results)
    }

    fn write<'py>(
        &self,
        py: Python<'py>,
        items: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyList>> {
        let (names, values, objects) = write_items(items)?;
        sync_log_level(py);
        let results = py
            .detach(|| self.inner.write(&pairs(&names, values)))
            .py()?;
        written_results(py, &results, &objects)
    }

    #[pyo3(signature = (tag_names, language=0x007F, encoding="utf-8"))]
    fn get_tag_descriptions<'py>(
        &self,
        py: Python<'py>,
        tag_names: Vec<String>,
        language: u16,
        encoding: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let encoding = text_encoding(encoding)?;
        sync_log_level(py);
        let results = py
            .detach(|| {
                let refs: Vec<&str> = tag_names.iter().map(String::as_str).collect();
                self.inner.get_tag_descriptions(&refs, language, encoding)
            })
            .py()?;
        tag_results(py, &results)
    }

    /// Metadata authentication with (certificate, DER private key), or the bundled credentials if None.
    #[pyo3(signature = (certificate=None, private_key_der=None))]
    fn authenticate_metadata<'py>(
        &self,
        py: Python<'py>,
        certificate: Option<Vec<u8>>,
        private_key_der: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let credentials = match (certificate, private_key_der) {
            (Some(cert), Some(key)) => Some(LogixMetadataCredentials::new(&cert, &key).py()?),
            _ => None,
        };
        sync_log_level(py);
        let result = py.detach(|| self.inner.authenticate_metadata(credentials.as_ref()));
        tag_result(py, &result)
    }

    /// Moves the reload backoff clock forward (tests).
    fn advance_clock(&self, py: Python<'_>, seconds: f64) {
        let by = Duration::from_secs_f64(seconds.max(0.0));
        py.detach(|| self.inner.advance_clock(by))
    }

    fn __str__(&self, py: Python<'_>) -> String {
        py.detach(|| self.inner.to_string())
    }
}

// ------------------------------------------------------------------------------------------------ module

static LOGGER: PyLogger = PyLogger;

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // another extension in the process may have installed a logger already: then the records go there
    if log::set_logger(&LOGGER).is_ok() {
        sync_log_level(m.py());
    }
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PyCipDriver>()?;
    m.add_class::<PySlcDriver>()?;
    m.add_class::<PyLogixDriver>()?;
    Ok(())
}
