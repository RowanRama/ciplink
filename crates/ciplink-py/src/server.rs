//! The tag server for Python: the `ciplink-server` command line and a server embedded in the process.

use std::path::PathBuf;
use std::sync::Mutex;

use ciplink_server::{ServerHandle, factory, load_config};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::MutexExt;

/// Runs the `ciplink-server` command line on `argv` (the program name first) and returns its exit code;
/// `launcher` is how a Task Scheduler task starts it again.
#[pyfunction]
pub fn server_main(py: Python<'_>, argv: Vec<String>, launcher: Vec<String>) -> PyResult<u8> {
    crate::sync_log_level(py); // the caller has set up logging by now
    py.detach(|| ciplink_server::cli::main_as(argv.into_iter().map(Into::into), &launcher))
        .map_err(PyRuntimeError::new_err)
}

/// A tag server running in this process on threads of its own, until `stop()`.
#[pyclass(name = "TagServer", module = "ciplink._core")]
pub struct PyTagServer {
    handle: Mutex<Option<ServerHandle>>,
    address: (String, u16),
}

#[pymethods]
impl PyTagServer {
    /// Starts the server of a config file; `host` and `port` override the config's (port 0: a free one).
    #[new]
    #[pyo3(signature = (config, mock = false, host = None, port = None))]
    fn new(
        py: Python<'_>,
        config: PathBuf,
        mock: bool,
        host: Option<String>,
        port: Option<u16>,
    ) -> PyResult<Self> {
        crate::sync_log_level(py);
        let mut cfg = load_config(&config).map_err(PyValueError::new_err)?;
        if let Some(host) = host {
            cfg.host = host;
        }
        if let Some(port) = port {
            cfg.port = port;
        }
        let handle = py
            .detach(|| ServerHandle::start(cfg, factory(mock)))
            .map_err(PyRuntimeError::new_err)?;
        let addr = handle.addr();
        Ok(PyTagServer {
            handle: Mutex::new(Some(handle)),
            address: (addr.ip().to_string(), addr.port()),
        })
    }

    /// (host, port) the server listens on.
    #[getter]
    fn address(&self) -> (String, u16) {
        self.address.clone()
    }

    /// Stops the server: pressed buttons are released, the PLC connections closed, the audit log flushed.
    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        let handle = self
            .handle
            .lock_py_attached(py)
            .map_or(None, |mut h| h.take());
        match handle {
            Some(handle) => py.detach(|| handle.stop()).map_err(PyRuntimeError::new_err),
            None => Ok(()),
        }
    }
}
