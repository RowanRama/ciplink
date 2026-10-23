//! Simulated controllers that speak real EtherNet/IP and CIP, for testing ciplink (and any other driver) in
//! every language without hardware.
//!
//! A [`Simulator`] holds one device: a Logix controller (ControlLogix, CompactLogix or Micro800) with tags,
//! data types, programs and AOIs, or an SLC 500 / MicroLogix with data files. It is configured from JSON
//! ([`Config::from_json`]) or in Rust ([`LogixConfig`], [`SlcConfig`]), and reached three ways:
//!
//! - in memory, through [`Simulator::connector`] (a [`ciplink::transport::Connector`]) or
//!   [`Simulator::transport`], so Rust tests run a driver without sockets;
//! - over TCP, [`Simulator::serve`] on `127.0.0.1:0`, for drivers in other languages;
//! - from the `ciplink-sim` binary: `ciplink-sim --config controller.json --port 0` prints
//!   `listening on 127.0.0.1:PORT`.
//!
//! Faults ([`Fault`]) drop or delay replies, answer a tag or service with a status, or refuse connections, and
//! [`Simulator::on_request`] edits the controller between two requests.
//!
//! ```
//! use ciplink_sim::{LogixConfig, Simulator, TagConfig};
//! use serde_json::json;
//!
//! let sim = Simulator::new(LogixConfig::default().with_tag(TagConfig::new("count", "DINT").value(json!(42))))
//!     .expect("config");
//! let server = sim.serve("127.0.0.1:0").expect("bind");
//! assert!(server.port() > 0);
//! assert_eq!(sim.value("count").expect("tag"), json!(42));
//! ```
#![warn(missing_docs)]

mod cip;
mod config;
mod encap;
mod identity;
mod logix;
mod metadata;
mod model;
mod path;
mod server;
mod slc;
mod transport;

pub use config::{
    Config, ConfigError, FileConfig, IdentityConfig, LogixConfig, MemberConfig, ModuleConfig,
    NamedConfig, NetworkDeviceConfig, ProgramConfig, SlcConfig, SystemTagConfig, TagConfig,
    TypeConfig,
};
pub use logix::Logix;
pub use server::{Server, UdpServer};
pub use slc::Slc;
pub use transport::SimTransport;

use ciplink::Error;
use ciplink::transport::{Connector, Transport};
use encap::{Device, Inner};
use serde_json::Value as Json;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// A fault injected into a simulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The replies to the next `n` requests are not sent (the connection stays open).
    DropReplies(u32),
    /// Every reply is sent this late.
    Delay(Duration),
    /// New connections are refused (closed at once over TCP, an error from the connector).
    RefuseConnections,
    /// Requests of a tag (its path as `Program:Main.tag[1].member`, or its base tag) are answered with this
    /// general status and extended status.
    TagStatus {
        /// Tag path.
        tag: String,
        /// General status.
        status: u8,
        /// Extended status word.
        ext: Option<u16>,
    },
    /// A service (on a class, or any) is answered with this general status and extended status.
    ServiceStatus {
        /// Service code.
        service: u8,
        /// Class code, None for any.
        class: Option<u32>,
        /// General status.
        status: u8,
        /// Extended status word.
        ext: Option<u16>,
    },
}

/// A simulated device, shared by every connection to it; clones refer to the same device.
#[derive(Clone)]
pub struct Simulator {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Simulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        let kind = match inner.device {
            Device::Logix(_) => "Logix",
            Device::Slc(_) => "SLC",
        };
        f.debug_struct("Simulator")
            .field("device", &kind)
            .field("requests", &inner.requests)
            .finish()
    }
}

impl Simulator {
    /// A simulator of this device.
    pub fn new(config: impl Into<Config>) -> Result<Self, ConfigError> {
        let device = match config.into() {
            Config::Logix(c) => Device::Logix(Box::new(Logix::new(&c)?)),
            Config::Slc(c) => Device::Slc(Box::new(Slc::new(&c)?)),
        };
        Ok(Simulator {
            inner: Arc::new(Mutex::new(Inner::new(device))),
        })
    }

    /// A simulator configured from JSON (see [`Config::from_json`]).
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        Self::new(Config::from_json(text)?)
    }

    /// A simulator configured from a JSON file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        Self::new(Config::from_file(path)?)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A connector for a driver: every `open()` gets a new in-memory connection, whatever host and port.
    pub fn connector(&self) -> Connector {
        let sim = self.clone();
        Box::new(move |host, port, timeout| {
            if sim.lock().faults.refuse_connections {
                return Err(Error::comm(format!(
                    "Failed to open socket to {host}:{port}"
                )));
            }
            Ok(
                Box::new(SimTransport::new(Arc::clone(&sim.inner), port, timeout))
                    as Box<dyn Transport>,
            )
        })
    }

    /// A new in-memory connection.
    pub fn transport(&self) -> SimTransport {
        SimTransport::new(Arc::clone(&self.inner), 44818, Some(Duration::from_secs(5)))
    }

    /// Serves EtherNet/IP over TCP on `addr`, e.g. `"127.0.0.1:0"` for a free port.
    pub fn serve(&self, addr: &str) -> std::io::Result<Server> {
        Server::start(Arc::clone(&self.inner), addr)
    }

    /// Answers ListIdentity over UDP on `addr`, e.g. `"127.0.0.1:44818"`.
    pub fn serve_udp(&self, addr: &str) -> std::io::Result<UdpServer> {
        UdpServer::start(Arc::clone(&self.inner), addr)
    }

    /// Runs `f` on the Logix controller (edits, values), None for an SLC.
    ///
    /// `f` runs with the simulator locked: it must not call this simulator's methods (that deadlocks), and
    /// every connection waits for it.
    pub fn with_logix<R>(&self, f: impl FnOnce(&mut Logix) -> R) -> Option<R> {
        match &mut self.lock().device {
            Device::Logix(logix) => Some(f(logix)),
            Device::Slc(_) => None,
        }
    }

    /// Runs `f` on the SLC, None for a Logix controller. Like [`Simulator::with_logix`], `f` must not call
    /// this simulator's methods.
    pub fn with_slc<R>(&self, f: impl FnOnce(&mut Slc) -> R) -> Option<R> {
        match &mut self.lock().device {
            Device::Slc(slc) => Some(f(slc)),
            Device::Logix(_) => None,
        }
    }

    /// The value of a Logix tag path (`Program:Main.tag[1].member`) or an SLC element (`N7:0`) as JSON.
    pub fn value(&self, path: &str) -> Result<Json, ConfigError> {
        match &self.lock().device {
            Device::Logix(logix) => logix.value(path),
            Device::Slc(slc) => slc.value(path),
        }
    }

    /// Sets the value of a Logix tag path or an SLC element from JSON.
    pub fn set_value(&self, path: &str, value: &Json) -> Result<(), ConfigError> {
        match &mut self.lock().device {
            Device::Logix(logix) => logix.set_value(path, value),
            Device::Slc(slc) => slc.set_value(path, value),
        }
    }

    /// Injects a fault; several can be active at once.
    pub fn inject(&self, fault: Fault) {
        let faults = &mut self.lock().faults;
        match fault {
            Fault::DropReplies(n) => faults.drop_replies = faults.drop_replies.saturating_add(n),
            Fault::Delay(delay) => faults.delay = delay,
            Fault::RefuseConnections => faults.refuse_connections = true,
            Fault::TagStatus { tag, status, ext } => {
                faults.tags.push((tag, status, ext.into_iter().collect()))
            }
            Fault::ServiceStatus {
                service,
                class,
                status,
                ext,
            } => faults
                .services
                .push((service, class, status, ext.into_iter().collect())),
        }
    }

    /// Removes every fault.
    pub fn clear_faults(&self) {
        self.lock().faults = Default::default();
    }

    /// Calls `hook` before each request with the controller and the request's index (from 0, counting every
    /// encapsulation frame), e.g. to change the tag table between two requests. Replaces an earlier hook.
    ///
    /// The hook runs with the simulator locked, so it edits through the `&mut Logix` it is given and must not
    /// call this simulator's methods (that deadlocks). A hook that panics ends that request (over TCP the
    /// connection closes, in memory the panic reaches the caller of `send`) and the simulator stays usable.
    pub fn on_request(&self, hook: impl FnMut(&mut Logix, u64) + Send + 'static) {
        self.lock().hook = Some(Box::new(hook));
    }

    /// Removes the request hook.
    pub fn clear_hook(&self) {
        self.lock().hook = None;
    }

    /// The number of requests (encapsulation frames) received so far.
    pub fn requests(&self) -> u64 {
        self.lock().requests
    }

    /// Starts or stops keeping every request frame received (see [`Simulator::take_received`]).
    pub fn record(&self, on: bool) {
        let mut inner = self.lock();
        inner.recording = on;
        if !on {
            inner.log.clear();
        }
    }

    /// The request frames received since recording started or the last call, in order.
    pub fn take_received(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.lock().log)
    }
}
