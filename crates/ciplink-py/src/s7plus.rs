//! The S7comm-plus driver for Python (`ciplink.S7PlusDriver`'s core): Siemens S7-1500 / S7-1200 over TLS.

use ciplink::s7plus::{CpuInfo, S7Kind, S7PlusDriver, S7PlusOptions, S7Symbol, S7Tag, S7Type};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::session::{self, PySubscription};
use crate::{IntoPy, pairs, sync_log_level, tag_results, timeout, write_items, written_results};

fn kind_name(kind: S7Kind) -> &'static str {
    match kind {
        S7Kind::Elementary => "elementary",
        S7Kind::String => "string",
        S7Kind::Struct => "struct",
        S7Kind::DataBlock => "data_block",
        S7Kind::Area => "area",
    }
}

fn tag_dict<'py>(py: Python<'py>, tag: &S7Tag) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("name", &tag.name)?;
    d.set_item("type", &tag.type_name)?;
    d.set_item("kind", kind_name(tag.kind))?;
    d.set_item("softdatatype", tag.softdatatype)?;
    d.set_item("dims", &tag.dims)?;
    d.set_item("lower_bounds", &tag.lower_bounds)?;
    d.set_item("string_length", tag.string_length)?;
    d.set_item("lid", tag.lid)?;
    d.set_item("member_crc", tag.member_crc)?;
    d.set_item("hmi_visible", tag.hmi_visible)?;
    d.set_item("hmi_accessible", tag.hmi_accessible)?;
    d.set_item("hmi_read_only", tag.hmi_read_only)?;
    Ok(d)
}

fn type_dict<'py>(py: Python<'py>, t: &S7Type) -> PyResult<Bound<'py, PyDict>> {
    let members = PyDict::new(py);
    for (name, m) in &t.members {
        members.set_item(name, tag_dict(py, m)?)?;
    }
    let d = PyDict::new(py);
    d.set_item("name", &t.name)?;
    d.set_item("rid", t.rid)?;
    d.set_item("interface_timestamp", t.interface_timestamp)?;
    d.set_item("members", members)?;
    Ok(d)
}

fn symbol_dict<'py>(py: Python<'py>, s: &S7Symbol) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("name", &s.name)?;
    d.set_item("type", &s.type_name)?;
    d.set_item("dims", &s.dims)?;
    d.set_item("access", &s.access)?;
    d.set_item("crc", s.crc)?;
    d.set_item("hmi_visible", s.hmi_visible)?;
    d.set_item("hmi_accessible", s.hmi_accessible)?;
    d.set_item("hmi_read_only", s.hmi_read_only)?;
    Ok(d)
}

fn info_dict<'py>(py: Python<'py>, i: &CpuInfo) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("name", &i.name)?;
    d.set_item("order_number", &i.order_number)?;
    d.set_item("serial_number", &i.serial_number)?;
    d.set_item("hardware_version", i.hardware_version)?;
    d.set_item("firmware", &i.firmware)?;
    d.set_item("engineering_version", &i.engineering_version)?;
    d.set_item("project", &i.project)?;
    d.set_item("protection_level", i.protection_level)?;
    d.set_item("max_read", i.max_read)?;
    d.set_item("max_write", i.max_write)?;
    Ok(d)
}

/// The S7comm-plus driver (`ciplink.S7PlusDriver`'s core).
#[pyclass(frozen, module = "ciplink._core", name = "S7PlusDriver")]
pub(crate) struct PyS7PlusDriver {
    inner: S7PlusDriver,
}

// as for the other drivers: stopping the session joins threads that may be waiting for the GIL
impl Drop for PyS7PlusDriver {
    fn drop(&mut self) {
        Python::attach(|py| py.detach(|| self.inner.stop()));
    }
}

#[pymethods]
impl PyS7PlusDriver {
    #[new]
    #[pyo3(signature = (path, socket_timeout=Some(10.0), init_tags=true, tls_fingerprint=None,
                        reconnect=true, keep_alive=Some(15.0)))]
    fn new(
        path: &str,
        socket_timeout: Option<f64>,
        init_tags: bool,
        tls_fingerprint: Option<String>,
        reconnect: bool,
        keep_alive: Option<f64>,
    ) -> PyResult<Self> {
        let options = S7PlusOptions {
            socket_timeout: timeout(socket_timeout)?,
            init_tags,
            tls_fingerprint,
        };
        let session = session::session_options(reconnect, keep_alive)?;
        Ok(PyS7PlusDriver {
            inner: S7PlusDriver::with_session(path, options, session).py()?,
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

    /// Sets (or with None removes) `callback(event, error, attempt, delay)`, called on connection changes.
    fn set_connection_callback(&self, py: Python<'_>, callback: Option<Py<PyAny>>) {
        let callback = callback.map(session::connection_callback);
        py.detach(|| self.inner.set_connection_callback(callback));
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

    /// Top-level tags (data blocks and PLC tags of I, Q and M) by name; empty before the first browse.
    #[getter]
    fn tags<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let tags = py.detach(|| self.inner.tags());
        let d = PyDict::new(py);
        for (name, tag) in &tags {
            d.set_item(name, tag_dict(py, tag)?)?;
        }
        Ok(d)
    }

    /// The structure types by name.
    #[getter]
    fn data_types<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let types = py.detach(|| self.inner.data_types());
        let d = PyDict::new(py);
        for (name, t) in &types {
            d.set_item(name, type_dict(py, t)?)?;
        }
        Ok(d)
    }

    /// Every symbol as a flat list of dicts; browses first if needed.
    fn tag_list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        sync_log_level(py);
        let symbols = py.detach(|| self.inner.tag_list()).py()?;
        let items = symbols
            .iter()
            .map(|s| symbol_dict(py, s))
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, items)
    }

    /// One name resolved; browses first if needed.
    fn get_tag_info<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyDict>> {
        sync_log_level(py);
        let symbol = py.detach(|| self.inner.get_tag_info(name)).py()?;
        symbol_dict(py, &symbol)
    }

    /// Browses again now; True if the table changed.
    fn refresh_tags(&self, py: Python<'_>) -> PyResult<bool> {
        sync_log_level(py);
        py.detach(|| self.inner.refresh_tags()).py()
    }

    fn get_plc_info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        sync_log_level(py);
        let info = py.detach(|| self.inner.get_plc_info()).py()?;
        info_dict(py, &info)
    }

    #[getter]
    fn name(&self, py: Python<'_>) -> Option<String> {
        py.detach(|| self.inner.name())
    }

    #[getter]
    fn certificate_fingerprint(&self) -> Option<String> {
        self.inner.certificate_fingerprint()
    }

    fn get_socket_timeout(&self, py: Python<'_>) -> Option<f64> {
        py.detach(|| self.inner.socket_timeout())
            .map(|d| d.as_secs_f64())
    }

    fn set_socket_timeout(&self, py: Python<'_>, seconds: Option<f64>) -> PyResult<()> {
        let t = timeout(seconds)?;
        py.detach(|| self.inner.set_socket_timeout(t)).py()
    }

    fn __str__(&self, py: Python<'_>) -> String {
        py.detach(|| self.inner.to_string())
    }
}
