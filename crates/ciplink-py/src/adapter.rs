//! The adapter for Python: ciplink as an EtherNet/IP I/O device that a Logix controller owns.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciplink::adapter::{Adapter, AdapterConfig, AdapterIdentity, Assembly, ConnectionInfo, Event};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::MutexExt;
use pyo3::types::{PyBytes, PyDict};

use crate::IntoPy;

/// The longest next_event waits in the core before it looks for stop() and signals.
const SLICE: Duration = Duration::from_millis(100);

/// A running adapter, on threads of its own, until `stop()`.
#[pyclass(name = "Adapter", module = "ciplink._core")]
pub struct PyAdapter {
    // shared by the calls in flight, so a thread waiting in next_event does not block set_input
    adapter: Mutex<Option<Arc<Adapter>>>,
}

impl PyAdapter {
    fn get(&self, py: Python<'_>) -> PyResult<Arc<Adapter>> {
        self.adapter
            .lock_py_attached(py)
            .ok()
            .and_then(|a| a.clone())
            .ok_or_else(|| PyRuntimeError::new_err("the adapter is stopped"))
    }
}

fn assemblies(
    sizes: Option<HashMap<u32, usize>>,
    make: fn(u32, usize) -> Assembly,
) -> Vec<Assembly> {
    let mut out: Vec<_> = sizes
        .unwrap_or_default()
        .into_iter()
        .map(|(i, n)| make(i, n))
        .collect();
    out.sort_by_key(|a| a.instance);
    out
}

fn connection<'py>(py: Python<'py>, c: &ConnectionInfo) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("kind", c.kind.as_str())?;
    d.set_item("originator", c.originator.to_string())?;
    d.set_item("o_t_rpi", c.o_t_rpi.as_secs_f64())?;
    d.set_item("t_o_rpi", c.t_o_rpi.as_secs_f64())?;
    d.set_item("input", c.input)?;
    d.set_item("input_size", c.input_size)?;
    d.set_item("output", c.output)?;
    d.set_item("output_size", c.output_size)?;
    d.set_item("multicast", c.multicast)?;
    d.set_item("o_t_id", c.o_t_id)?;
    d.set_item("t_o_id", c.t_o_id)?;
    Ok(d)
}

fn event<'py>(py: Python<'py>, e: &Event) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    match e {
        Event::Opened(c) | Event::Closed(c) | Event::TimedOut(c) => {
            let name = match e {
                Event::Opened(_) => "opened",
                Event::Closed(_) => "closed",
                _ => "timed_out",
            };
            d.set_item("event", name)?;
            d.set_item("connection", connection(py, c)?)?;
        }
        Event::Config { instance, data } => {
            d.set_item("event", "config")?;
            d.set_item("instance", instance)?;
            d.set_item("data", PyBytes::new(py, data))?;
        }
        Event::Output { instance } => {
            d.set_item("event", "output")?;
            d.set_item("instance", instance)?;
        }
    }
    Ok(d)
}

#[pymethods]
impl PyAdapter {
    /// Starts an adapter: binds its ports and starts its threads. Assemblies are {instance: size in bytes};
    /// RPIs are in seconds.
    #[new]
    #[pyo3(signature = (
        inputs = None, outputs = None, configs = None, *,
        vendor_id = 0, device_type = 0x2B, product_code = 1, revision = (1, 1), serial = 0,
        product_name = "ciplink adapter".to_string(), app_name = String::new(), app_version = String::new(),
        eds = None, eds_name = "ciplink.eds".to_string(), bind = "0.0.0.0".to_string(), port = 44818,
        io_port = 2222, rpi_min = 0.002, rpi_max = 3.2, input_only_heartbeat = 238,
        listen_only_heartbeat = 237, mac = [0; 6],
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        inputs: Option<HashMap<u32, usize>>,
        outputs: Option<HashMap<u32, usize>>,
        configs: Option<HashMap<u32, usize>>,
        vendor_id: u16,
        device_type: u16,
        product_code: u16,
        revision: (u8, u8),
        serial: u32,
        product_name: String,
        app_name: String,
        app_version: String,
        eds: Option<Vec<u8>>,
        eds_name: String,
        bind: String,
        port: u16,
        io_port: u16,
        rpi_min: f64,
        rpi_max: f64,
        input_only_heartbeat: u32,
        listen_only_heartbeat: u32,
        mac: [u8; 6],
    ) -> PyResult<Self> {
        crate::sync_log_level(py);
        let bind: Ipv4Addr = bind
            .parse()
            .map_err(|_| PyValueError::new_err(format!("bind {bind:?} is not an IPv4 address")))?;
        let secs = |s: f64, what: &str| {
            Duration::try_from_secs_f64(s).map_err(|_| {
                PyValueError::new_err(format!("{what} must be a number of seconds >= 0"))
            })
        };
        let mut all = assemblies(inputs, Assembly::input);
        all.extend(assemblies(outputs, Assembly::output));
        all.extend(assemblies(configs, Assembly::config));
        let config = AdapterConfig {
            identity: AdapterIdentity {
                vendor_id,
                device_type,
                product_code,
                revision,
                serial,
                product_name,
            },
            assemblies: all,
            input_only_heartbeat,
            listen_only_heartbeat,
            eds,
            eds_name,
            app_name,
            app_version,
            bind,
            port,
            io_port,
            rpi_min: secs(rpi_min, "rpi_min")?,
            rpi_max: secs(rpi_max, "rpi_max")?,
            mac,
        };
        let adapter = py.detach(|| Adapter::start(config)).py()?;
        Ok(PyAdapter {
            adapter: Mutex::new(Some(Arc::new(adapter))),
        })
    }

    /// (host, port) explicit messages are served on.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<(String, u16)> {
        let a = self.get(py)?.addr();
        Ok((a.ip().to_string(), a.port()))
    }

    /// (host, port) class 1 I/O is received on.
    #[getter]
    fn io_address(&self, py: Python<'_>) -> PyResult<(String, u16)> {
        let a = self.get(py)?.io_addr();
        Ok((a.ip().to_string(), a.port()))
    }

    /// Sets an input assembly's data, sent in the next T->O packets; shorter data leaves the rest zero.
    fn set_input(&self, py: Python<'_>, instance: u32, data: &[u8]) -> PyResult<()> {
        self.get(py)?.set_input(instance, data).py()
    }

    /// An input assembly's current data.
    fn input<'py>(&self, py: Python<'py>, instance: u32) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.get(py)?.input(instance).py()?))
    }

    /// (data, run) of an output assembly: its latest data and the scanner's run bit.
    fn output<'py>(&self, py: Python<'py>, instance: u32) -> PyResult<(Bound<'py, PyBytes>, bool)> {
        let out = self.get(py)?.output(instance).py()?;
        Ok((PyBytes::new(py, &out.data), out.run))
    }

    /// A configuration assembly's data, as the last Forward Open with data sent it.
    fn config<'py>(&self, py: Python<'py>, instance: u32) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.get(py)?.config(instance).py()?))
    }

    /// The next event as a dict, waiting up to `timeout` seconds (None: until one comes or the adapter
    /// stops); None if none came.
    #[pyo3(signature = (timeout = None))]
    fn next_event<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let timeout = timeout
            .map(|t| {
                Duration::try_from_secs_f64(t)
                    .map_err(|_| PyValueError::new_err("timeout must be a number of seconds >= 0"))
            })
            .transpose()?;
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            // short waits, so stop() and Ctrl+C get through while a thread waits here
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            let slice = left.map_or(SLICE, |l| l.min(SLICE));
            let Ok(adapter) = self.get(py) else {
                return Ok(None); // stopped, as the core's next_event says
            };
            if let Some(e) = py.detach(|| adapter.next_event(Some(slice))) {
                return Ok(Some(event(py, &e)?));
            }
            drop(adapter);
            py.check_signals()?;
            if left.is_some_and(|l| l <= slice) {
                return Ok(None);
            }
        }
    }

    /// The open class 1 connections, as dicts.
    fn connections<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.get(py)?
            .connections()
            .iter()
            .map(|c| connection(py, c))
            .collect()
    }

    /// Sets the application's status text that device browsers show, e.g. "station 2".
    fn set_detail(&self, py: Python<'_>, detail: &str) -> PyResult<()> {
        self.get(py)?.set_detail(detail);
        Ok(())
    }

    /// I/O timing counters: produced, late and max_late (seconds).
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.get(py)?.stats();
        let d = PyDict::new(py);
        d.set_item("produced", s.produced)?;
        d.set_item("late", s.late)?;
        d.set_item("max_late", s.max_late.as_secs_f64())?;
        Ok(d)
    }

    /// Stops the adapter: closes its sockets and joins its threads. Scanners then time out.
    fn stop(&self, py: Python<'_>) {
        let taken = self
            .adapter
            .lock_py_attached(py)
            .map_or(None, |mut a| a.take());
        let Some(mut adapter) = taken else { return };
        py.detach(|| {
            loop {
                // a call in flight holds a clone for at most one SLICE
                match Arc::try_unwrap(adapter) {
                    Ok(a) => break a.stop(),
                    Err(shared) => {
                        adapter = shared;
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        });
    }
}
