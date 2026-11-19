//! `ciplink._core.ModbusDriver`: Modbus TCP, RTU and RTU over TCP (`ciplink.ModbusDriver`'s core).

use std::time::Duration;

use ciplink::modbus::{
    DeviceInfo, ModbusDriver, ModbusOptions, TagMap, WordOrder, modbus_connector,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};

use crate::session::{self, PySubscription};
use crate::{IntoPy, pairs, sync_log_level, tag_results, write_items, written_results};

#[pyclass(frozen, module = "ciplink._core", name = "ModbusDriver")]
pub(crate) struct PyModbusDriver {
    inner: ModbusDriver,
}

// as the other drivers: stopping the session joins threads that may wait for the GIL
impl Drop for PyModbusDriver {
    fn drop(&mut self) {
        Python::attach(|py| py.detach(|| self.inner.stop()));
    }
}

fn seconds(s: f64, what: &str) -> PyResult<Duration> {
    if s.is_finite() && s > 0.0 {
        Ok(Duration::from_secs_f64(s))
    } else {
        Err(PyValueError::new_err(format!(
            "{what} must be a positive finite number of seconds"
        )))
    }
}

fn device_info_dict<'py>(py: Python<'py>, info: DeviceInfo) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("vendor_name", info.vendor_name)?;
    d.set_item("product_code", info.product_code)?;
    d.set_item("revision", info.revision)?;
    d.set_item("vendor_url", info.vendor_url)?;
    d.set_item("product_name", info.product_name)?;
    d.set_item("model_name", info.model_name)?;
    d.set_item("user_application_name", info.user_application_name)?;
    Ok(d)
}

/// The map rows by name, with the keys of `ciplink_modbus_tags`.
fn tags_dict<'py>(py: Python<'py>, map: &TagMap) -> PyResult<Bound<'py, PyDict>> {
    let tags = PyDict::new(py);
    for t in map.tags() {
        let row = PyDict::new(py);
        row.set_item("name", &t.name)?;
        row.set_item("area", t.area.as_str())?;
        row.set_item("address", t.address)?;
        row.set_item("bit", t.bit)?;
        row.set_item("type", t.data_type.as_str())?;
        row.set_item("cip_type", t.type_name())?;
        row.set_item("count", t.count)?;
        row.set_item("order", t.order.map(WordOrder::as_str))?;
        row.set_item("unit", t.unit)?;
        row.set_item("scale", t.scale)?;
        row.set_item("offset", t.offset)?;
        row.set_item("units", &t.units)?;
        row.set_item("description", &t.description)?;
        row.set_item("writable", t.writable)?;
        tags.set_item(&t.name, row)?;
    }
    Ok(tags)
}

#[pymethods]
impl PyModbusDriver {
    /// `keep_alive`: seconds, None (off) or "auto" (30 s over TCP, off for rtu://).
    #[new]
    #[pyo3(signature = (path, map_file=None, socket_timeout=1.0, max_registers=125, max_bits=2000, max_gap=8,
                        word_order="ABCD", write_multiple=false, keep_alive_address=None, reconnect=true,
                        keep_alive=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: &str,
        map_file: Option<&str>,
        socket_timeout: f64,
        max_registers: u16,
        max_bits: u16,
        max_gap: u16,
        word_order: &str,
        write_multiple: bool,
        keep_alive_address: Option<String>,
        reconnect: bool,
        keep_alive: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let map = map_file.map(TagMap::load).transpose().py()?;
        let word_order = WordOrder::parse(word_order).ok_or_else(|| {
            PyValueError::new_err(format!(
                "word_order {word_order:?} is not ABCD, CDAB, BADC or DCBA"
            ))
        })?;
        let options = ModbusOptions {
            map,
            socket_timeout: seconds(socket_timeout, "socket_timeout")?,
            max_registers,
            max_bits,
            max_gap,
            word_order,
            write_multiple,
            keep_alive_address,
        };
        let session = match keep_alive {
            Some(k) if k.extract::<String>().is_ok_and(|s| s == "auto") => {
                let mut s = ModbusDriver::default_session(path).py()?;
                s.reconnect = reconnect;
                s
            }
            Some(k) if !k.is_none() => session::session_options(reconnect, Some(k.extract()?))?,
            _ => session::session_options(reconnect, None)?,
        };
        Ok(PyModbusDriver {
            inner: ModbusDriver::with_session(path, options, session, modbus_connector()).py()?,
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
    fn connected(&self) -> bool {
        self.inner.connected()
    }

    /// 'closed', 'connected' or 'reconnecting'.
    #[getter]
    fn connection_state(&self) -> &'static str {
        session::state_name(self.inner.connection_state())
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

    /// Queues a read; `done(results, error)` is called on the driver's callback thread.
    fn read_async(&self, py: Python<'_>, tags: Vec<String>, done: Py<PyAny>) {
        sync_log_level(py);
        let callback = session::completion(done, None);
        py.detach(|| {
            let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
            self.inner.read_async(&refs).on_complete(callback);
        });
    }

    /// Queues a write; `done(results, error)` is called on the driver's callback thread.
    fn write_async(
        &self,
        py: Python<'_>,
        items: &Bound<'_, PyAny>,
        done: Py<PyAny>,
    ) -> PyResult<()> {
        let (names, values, objects) = write_items(items)?;
        let callback =
            session::completion(done, Some(objects.into_iter().map(Bound::unbind).collect()));
        sync_log_level(py);
        py.detach(|| {
            self.inner
                .write_async(&pairs(&names, values))
                .on_complete(callback)
        });
        Ok(())
    }

    #[pyo3(signature = (tags, interval=1.0, deadband=None))]
    fn subscribe(
        &self,
        py: Python<'_>,
        tags: Vec<String>,
        interval: f64,
        deadband: Option<f64>,
    ) -> PyResult<PySubscription> {
        let options = session::subscribe_options(interval, deadband)?;
        let sub = py
            .detach(|| {
                let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                self.inner.subscribe(&refs, options)
            })
            .py()?;
        Ok(PySubscription::new(sub))
    }

    /// Sets (or with None removes) `callback(event, error, attempt, delay)`, called on connection changes.
    fn set_connection_callback(&self, py: Python<'_>, callback: Option<Py<PyAny>>) {
        let callback = callback.map(session::connection_callback);
        py.detach(|| self.inner.set_connection_callback(callback));
    }

    #[getter]
    fn get_socket_timeout(&self, py: Python<'_>) -> f64 {
        py.detach(|| self.inner.socket_timeout()).as_secs_f64()
    }

    fn set_socket_timeout(&self, py: Python<'_>, seconds_: f64) -> PyResult<()> {
        let timeout = seconds(seconds_, "socket_timeout")?;
        py.detach(|| self.inner.set_socket_timeout(timeout)).py()
    }

    #[pyo3(signature = (unit=None))]
    fn device_info<'py>(&self, py: Python<'py>, unit: Option<u8>) -> PyResult<Bound<'py, PyDict>> {
        sync_log_level(py);
        let info = py.detach(|| self.inner.device_info(unit)).py()?;
        device_info_dict(py, info)
    }

    #[pyo3(signature = (pdu, unit=None))]
    fn send_pdu<'py>(
        &self,
        py: Python<'py>,
        pdu: Vec<u8>,
        unit: Option<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        sync_log_level(py);
        let reply = py.detach(|| self.inner.send_pdu(unit, &pdu)).py()?;
        Ok(PyBytes::new(py, &reply))
    }

    #[getter]
    fn tags<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        tags_dict(py, self.inner.map())
    }

    fn __str__<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        PyString::new(py, &self.inner.to_string())
    }
}
