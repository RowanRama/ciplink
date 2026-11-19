//! The session API for Python: async read/write completions, subscriptions and connection events.
//!
//! Every Python callback here runs on the driver's callback thread and takes the GIL there (`try_attach`, so
//! nothing runs once the interpreter is shutting down). Everything that can wait for the session, the callback
//! thread or a subscription runs with the GIL released, so a callback waiting for the GIL never deadlocks a
//! thread that holds it.

use std::time::Duration;

use ciplink::Error;
use ciplink::cip::TagResult;
use ciplink::session::{
    Changes, ConnectionCallback, ConnectionEvent, ConnectionState, SessionOptions,
    SubscribeOptions, Subscription,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::{make_py_err, tag_results, written_results};

/// Session options from the drivers' `reconnect` and `keep_alive` (seconds or None) arguments.
pub(crate) fn session_options(
    reconnect: bool,
    keep_alive: Option<f64>,
) -> PyResult<SessionOptions> {
    let keep_alive = match keep_alive {
        None => None,
        Some(s) if s.is_finite() && s > 0.0 => Some(Duration::from_secs_f64(s)),
        Some(_) => {
            return Err(PyValueError::new_err(
                "keep_alive must be a positive finite number of seconds or None",
            ));
        }
    };
    Ok(SessionOptions {
        reconnect,
        keep_alive,
        ..SessionOptions::default()
    })
}

pub(crate) fn subscribe_options(
    interval: f64,
    deadband: Option<f64>,
) -> PyResult<SubscribeOptions> {
    if !(interval.is_finite() && interval > 0.0) {
        return Err(PyValueError::new_err(
            "interval must be a positive finite number of seconds",
        ));
    }
    Ok(SubscribeOptions {
        interval: Duration::from_secs_f64(interval),
        deadband,
    })
}

pub(crate) fn state_name(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Closed => "closed",
        ConnectionState::Connected => "connected",
        ConnectionState::Reconnecting => "reconnecting",
    }
}

/// Calls `f(*args)` and reports an exception it raises as unraisable: a callback has no caller to raise to.
fn call_reporting<'py>(py: Python<'py>, f: &Py<PyAny>, args: impl pyo3::call::PyCallArgs<'py>) {
    if let Err(err) = f.call1(py, args) {
        err.write_unraisable(py, Some(f.bind(py)));
    }
}

/// The completion of `read_async`/`write_async`: `done(results, None)` with the Tag list, or
/// `done(None, exception)`. `written` holds a write's value objects, which its results carry as `write` does.
pub(crate) fn completion(
    done: Py<PyAny>,
    written: Option<Vec<Py<PyAny>>>,
) -> impl FnOnce(ciplink::Result<Vec<TagResult>>) + Send + 'static {
    move |result| {
        // `move`: the callable and the value objects are released with the GIL held
        Python::try_attach(move |py| {
            let args = match result {
                Ok(results) => {
                    let list = match &written {
                        Some(objects) => {
                            let bound: Vec<_> =
                                objects.iter().map(|o| o.bind(py).clone()).collect();
                            written_results(py, &results, &bound)
                        }
                        None => tag_results(py, &results),
                    };
                    match list {
                        Ok(list) => (list.into_any().unbind(), py.None()),
                        Err(err) => (py.None(), err.into_value(py).into_any()),
                    }
                }
                Err(err) => (py.None(), exception(py, &err)),
            };
            call_reporting(py, &done, args);
        });
    }
}

/// The ciplink exception instance of an error.
fn exception(py: Python<'_>, err: &Error) -> Py<PyAny> {
    match make_py_err(py, err) {
        Ok(e) | Err(e) => e.into_value(py).into_any(),
    }
}

/// A subscription callback: `f(tags)` with the changed tags as a Tag list.
fn changes_callback(f: Py<PyAny>) -> impl Fn(Changes) + Send + Sync + 'static {
    move |changes| {
        Python::try_attach(|py| match tag_results(py, &changes.results) {
            Ok(list) => call_reporting(py, &f, (list,)),
            Err(err) => err.write_unraisable(py, Some(f.bind(py))),
        });
    }
}

/// The connection callback: `f(event, error, attempt, delay)` with `event` 'connected', 'disconnected'
/// (`error` its message) or 'reconnecting' (`attempt` from 1, `delay` in seconds).
pub(crate) fn connection_callback(f: Py<PyAny>) -> ConnectionCallback {
    Box::new(move |event| {
        Python::try_attach(|py| {
            let args = match event {
                ConnectionEvent::Connected => ("connected", None, None, None),
                ConnectionEvent::Disconnected { error } => {
                    ("disconnected", Some(error.to_string()), None, None)
                }
                ConnectionEvent::Reconnecting { attempt, delay } => (
                    "reconnecting",
                    None,
                    Some(*attempt),
                    Some(delay.as_secs_f64()),
                ),
            };
            call_reporting(py, &f, args);
        });
    })
}

/// A running subscription (`ciplink.Subscription`'s core). Dropping it unsubscribes.
#[pyclass(frozen, module = "ciplink._core", name = "Subscription")]
pub(crate) struct PySubscription {
    inner: Subscription,
}

impl PySubscription {
    pub(crate) fn new(inner: Subscription) -> Self {
        PySubscription { inner }
    }
}

// Unsubscribing waits for a callback in progress, which may be waiting for the GIL: release it first.
impl Drop for PySubscription {
    fn drop(&mut self) {
        Python::try_attach(|py| py.detach(|| self.inner.close()));
    }
}

fn changes_list<'py>(
    py: Python<'py>,
    changes: Option<Changes>,
) -> PyResult<Option<Bound<'py, PyList>>> {
    changes.map(|c| tag_results(py, &c.results)).transpose()
}

#[pymethods]
impl PySubscription {
    /// The subscribed tags, in order.
    #[getter]
    fn tags(&self) -> Vec<String> {
        self.inner.tags().to_vec()
    }

    /// The changed tags (a Tag list), waiting up to `timeout` seconds (None: until there are some); None on
    /// timeout or once the subscription has ended.
    #[pyo3(signature = (timeout=None))]
    fn recv<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Option<Bound<'py, PyList>>> {
        let changes = py.detach(|| match timeout {
            None => self.inner.recv(),
            Some(s) => self
                .inner
                .recv_timeout(Duration::from_secs_f64(s.clamp(0.0, 1e9))),
        });
        changes_list(py, changes)
    }

    /// The pending changed tags without waiting, None if there are none.
    fn try_recv<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyList>>> {
        let changes = py.detach(|| self.inner.try_recv());
        changes_list(py, changes)
    }

    /// Delivers pending and later changes to `f(tags)` on the driver's callback thread instead of `recv`.
    fn on_changes(&self, py: Python<'_>, f: Py<PyAny>) {
        let callback = changes_callback(f);
        py.detach(|| self.inner.on_changes(callback));
    }

    /// True once unsubscribed, or the driver was closed.
    #[getter]
    fn closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Unsubscribes; returns once a callback in progress has returned (unless called from a callback).
    fn close(&self, py: Python<'_>) {
        py.detach(|| self.inner.close());
    }
}
