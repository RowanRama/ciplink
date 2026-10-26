//! An EtherNet/IP adapter: a CIP target that a Logix scanner owns like an I/O module or a camera.
//!
//! An [`Adapter`] answers sessions, explicit messages and Forward Opens on TCP 44818, ListIdentity on UDP 44818,
//! and exchanges class 1 I/O on UDP 2222: an input assembly is produced to the scanner every RPI (T->O), an output
//! assembly is consumed from it (O->T, with the run/idle header). It accepts exclusive-owner, input-only and
//! listen-only connections, T->O multicast or point-to-point. The I/O runs on threads of its own, so the
//! application's timing never makes a packet late; the application reads and writes the assemblies and takes
//! [`Event`]s from a queue.
//!
//! It also serves what browsers read: the Identity, Port, TCP/IP Interface and Ethernet Link objects, the EDS
//! through the File object (so "Upload EDS from device" works), and a ciplink object (class 0x64) that marks it as
//! a ciplink device and describes the application.
//!
//! The adapter needs TCP/UDP 44818 and UDP 2222 of its IP address to itself: a controller reaches a module only
//! on those ports, so it cannot run beside FactoryTalk Linx, RSLinx or another adapter on the same address. See
//! `docs/adapter.md` in the repository.
//!
//! ```no_run
//! use ciplink::adapter::{Adapter, AdapterConfig, Assembly, Event};
//! use std::time::Duration;
//!
//! let adapter = Adapter::start(AdapterConfig {
//!     assemblies: vec![Assembly::input(100, 148), Assembly::output(150, 32), Assembly::config(199, 0)],
//!     app_name: "Station".into(),
//!     ..AdapterConfig::default()
//! })?;
//! adapter.set_input(100, &[1, 2, 3])?;
//! while let Some(event) = adapter.next_event(Some(Duration::from_secs(1))) {
//!     if let Event::Output { instance } = event {
//!         let output = adapter.output(instance)?;
//!         println!("trigger {} (run {})", output.data[0] & 1, output.run);
//!     }
//! }
//! # Ok::<(), ciplink::Error>(())
//! ```

mod objects;
mod server;
mod state;
mod wire;

use crate::{Error, Result};
use server::Shared;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Class code of the ciplink object, which marks a ciplink device and describes its application.
pub const CIPLINK_OBJECT: u16 = 0x64;
/// The signature the ciplink object's reply starts with.
pub const CIPLINK_SIGNATURE: &str = "ciplink";

/// The Identity Object of an adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    /// ODVA vendor ID. The default 0 is a placeholder: a device shipped with an EDS needs its vendor's own ID.
    pub vendor_id: u16,
    /// Device type, by default 0x2B (generic device, keyable).
    pub device_type: u16,
    /// Product code.
    pub product_code: u16,
    /// Major and minor revision.
    pub revision: (u8, u8),
    /// Serial number.
    pub serial: u32,
    /// Product name, ASCII, at most 32 characters.
    pub product_name: String,
}

impl Default for AdapterIdentity {
    fn default() -> Self {
        AdapterIdentity {
            vendor_id: 0,
            device_type: 0x2B,
            product_code: 1,
            revision: (1, 1),
            serial: 0,
            product_name: "ciplink adapter".into(),
        }
    }
}

/// What an assembly carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssemblyKind {
    /// Produced to the scanner (T->O): the scanner's input.
    Input,
    /// Consumed from the scanner (O->T): the scanner's output.
    Output,
    /// Configuration data the scanner sends with the Forward Open.
    Config,
}

/// An assembly instance of the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assembly {
    /// Instance number (connection point), 1 to 65535.
    pub instance: u32,
    /// Input, output or configuration.
    pub kind: AssemblyKind,
    /// Size in bytes (without the sequence count or run/idle header).
    pub size: usize,
}

impl Assembly {
    /// An input assembly (T->O) of `size` bytes.
    pub fn input(instance: u32, size: usize) -> Self {
        Assembly {
            instance,
            kind: AssemblyKind::Input,
            size,
        }
    }

    /// An output assembly (O->T) of `size` bytes.
    pub fn output(instance: u32, size: usize) -> Self {
        Assembly {
            instance,
            kind: AssemblyKind::Output,
            size,
        }
    }

    /// A configuration assembly of `size` bytes.
    pub fn config(instance: u32, size: usize) -> Self {
        Assembly {
            instance,
            kind: AssemblyKind::Config,
            size,
        }
    }
}

/// How an [`Adapter`] is set up.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    /// The Identity Object.
    pub identity: AdapterIdentity,
    /// The assemblies; connection points must name them.
    pub assemblies: Vec<Assembly>,
    /// The O->T connection point of input-only connections (a heartbeat, no data).
    pub input_only_heartbeat: u32,
    /// The O->T connection point of listen-only connections.
    pub listen_only_heartbeat: u32,
    /// The EDS file served by the File object (instance 0xC8), None for no File object.
    pub eds: Option<Vec<u8>>,
    /// The EDS file name the File object reports.
    pub eds_name: String,
    /// The application's name and version, shown by device browsers.
    pub app_name: String,
    /// The application's version.
    pub app_version: String,
    /// The local address to listen on; a concrete address picks the network card (and the one multicast
    /// leaves from), `0.0.0.0` listens on all of them.
    pub bind: Ipv4Addr,
    /// TCP and UDP port of explicit messages and ListIdentity (44818; 0 for a free one).
    pub port: u16,
    /// UDP port of class 1 I/O (2222; 0 for a free one).
    pub io_port: u16,
    /// The shortest and longest RPI accepted.
    pub rpi_min: Duration,
    /// The longest RPI accepted.
    pub rpi_max: Duration,
    /// MAC address the Ethernet Link object reports.
    pub mac: [u8; 6],
}

impl Default for AdapterConfig {
    fn default() -> Self {
        AdapterConfig {
            identity: AdapterIdentity::default(),
            assemblies: Vec::new(),
            // the heartbeat instances EDS files commonly use
            input_only_heartbeat: 238,
            listen_only_heartbeat: 237,
            eds: None,
            eds_name: "ciplink.eds".into(),
            app_name: String::new(),
            app_version: String::new(),
            bind: Ipv4Addr::UNSPECIFIED,
            port: 44818,
            io_port: 2222,
            rpi_min: Duration::from_millis(2),
            rpi_max: Duration::from_millis(3200),
            mac: [0; 6],
        }
    }
}

impl AdapterConfig {
    fn validate(&self) -> Result<()> {
        let id = &self.identity;
        if id.product_name.len() > 32 || !id.product_name.is_ascii() {
            return Err(Error::request(
                "product_name must be ASCII, at most 32 characters",
            ));
        }
        for (i, a) in self.assemblies.iter().enumerate() {
            if !(1..=0xFFFF).contains(&a.instance) {
                return Err(Error::request(format!(
                    "assembly instance {} is not 1 to 65535",
                    a.instance
                )));
            }
            if self.assemblies[..i]
                .iter()
                .any(|b| b.instance == a.instance)
                || [self.input_only_heartbeat, self.listen_only_heartbeat].contains(&a.instance)
            {
                return Err(Error::request(format!(
                    "assembly instance {} is used twice",
                    a.instance
                )));
            }
            if a.kind != AssemblyKind::Config && a.size > 65_000 {
                return Err(Error::request(format!(
                    "assembly {} of {} bytes is larger than a connection can carry",
                    a.instance, a.size
                )));
            }
        }
        if self.input_only_heartbeat == self.listen_only_heartbeat {
            return Err(Error::request(
                "the input-only and listen-only heartbeats must differ",
            ));
        }
        if self.rpi_min > self.rpi_max || self.rpi_min.is_zero() {
            return Err(Error::request(
                "rpi_min must be above 0 and at most rpi_max",
            ));
        }
        Ok(())
    }
}

/// The kind of a class 1 connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionKind {
    /// Owns the output assembly and receives the input assembly.
    ExclusiveOwner,
    /// Receives the input assembly; sends heartbeats.
    InputOnly,
    /// Receives an owner's multicast input; closes when the owner (and every input-only connection) does.
    ListenOnly,
}

/// A class 1 connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// Exclusive owner, input only or listen only.
    pub kind: ConnectionKind,
    /// The scanner's address.
    pub originator: Ipv4Addr,
    /// O->T requested packet interval.
    pub o_t_rpi: Duration,
    /// T->O packet interval.
    pub t_o_rpi: Duration,
    /// The input assembly sent to the scanner.
    pub input: u32,
    /// Its size in bytes.
    pub input_size: usize,
    /// The output assembly received from the scanner (exclusive owner only).
    pub output: Option<u32>,
    /// Its size in bytes (0 without an output assembly).
    pub output_size: usize,
    /// T->O is multicast.
    pub multicast: bool,
    /// O->T connection ID.
    pub o_t_id: u32,
    /// T->O connection ID.
    pub t_o_id: u32,
}

/// Something that happened to an [`Adapter`], taken with [`Adapter::next_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A scanner opened a connection.
    Opened(ConnectionInfo),
    /// A scanner closed a connection (or the owner of a listen-only connection went away).
    Closed(ConnectionInfo),
    /// A scanner went quiet for the connection timeout; the connection is closed.
    TimedOut(ConnectionInfo),
    /// A Forward Open carried configuration data.
    Config {
        /// The configuration assembly.
        instance: u32,
        /// The data.
        data: Vec<u8>,
    },
    /// An output assembly changed (its data or run flag). Sent once until [`Adapter::output`] reads it.
    Output {
        /// The output assembly.
        instance: u32,
    },
}

/// The latest data of an output assembly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The data.
    pub data: Vec<u8>,
    /// The scanner is in run mode (the run/idle header's run bit); false before the first packet and after
    /// the owner closed or timed out.
    pub run: bool,
}

/// I/O timing counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// T->O packets sent.
    pub produced: u64,
    /// Packets sent 1 ms or more after they were due.
    pub late: u64,
    /// The latest a packet was sent after it was due.
    pub max_late: Duration,
}

/// A running adapter. It stops when dropped or [`stop`](Adapter::stop)ped; scanners then time out.
pub struct Adapter {
    shared: Arc<Shared>,
    server: Option<server::Threads>,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter")
            .field("addr", &self.addr())
            .field("io_addr", &self.io_addr())
            .finish()
    }
}

impl Adapter {
    /// Starts an adapter: binds its ports and starts its threads.
    pub fn start(config: AdapterConfig) -> Result<Adapter> {
        config.validate()?;
        let (shared, threads) = server::start(config)?;
        Ok(Adapter {
            shared,
            server: Some(threads),
        })
    }

    /// The address explicit messages are served on.
    pub fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    /// The address class 1 I/O is received on.
    pub fn io_addr(&self) -> SocketAddr {
        self.shared.io_addr
    }

    /// Sets an input assembly's data, sent in the next T->O packets; shorter data leaves the rest zero.
    pub fn set_input(&self, instance: u32, data: &[u8]) -> Result<()> {
        self.shared
            .lock()
            .set_input(instance, data)
            .map_err(Error::request)
    }

    /// An input assembly's current data.
    pub fn input(&self, instance: u32) -> Result<Vec<u8>> {
        self.assembly(instance, AssemblyKind::Input)
    }

    /// The latest data and run flag of an output assembly.
    pub fn output(&self, instance: u32) -> Result<Output> {
        self.shared
            .lock()
            .output(instance)
            .ok_or_else(|| Error::request(format!("no output assembly {instance}")))
    }

    /// A configuration assembly's data, as the last Forward Open with data sent it.
    pub fn config(&self, instance: u32) -> Result<Vec<u8>> {
        self.assembly(instance, AssemblyKind::Config)
    }

    fn assembly(&self, instance: u32, kind: AssemblyKind) -> Result<Vec<u8>> {
        self.shared
            .lock()
            .assembly(instance)
            .filter(|a| a.kind == kind)
            .map(|a| a.data.clone())
            .ok_or_else(|| Error::request(format!("no {kind:?} assembly {instance}")))
    }

    /// The next event, waiting up to `timeout` (None: until one comes); None if none came in time.
    pub fn next_event(&self, timeout: Option<Duration>) -> Option<Event> {
        self.shared.next_event(timeout)
    }

    /// The open class 1 connections.
    pub fn connections(&self) -> Vec<ConnectionInfo> {
        self.shared.lock().connections()
    }

    /// Sets the application's status text that device browsers show, e.g. `"station 2"`.
    pub fn set_detail(&self, detail: &str) {
        detail.clone_into(&mut self.shared.lock().detail);
    }

    /// I/O timing counters.
    pub fn stats(&self) -> Stats {
        self.shared.lock().stats
    }

    /// Stops the adapter: closes its sockets and joins its threads.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(threads) = self.server.take() {
            threads.stop(&self.shared);
        }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.shutdown();
    }
}
