//! A simulated Modbus device (or a gateway with several units) for testing Modbus drivers without hardware.
//!
//! [`ModbusSim`] holds, per unit, four tables (coils, discrete inputs, holding and input registers) and answers
//! function codes 1, 2, 3, 4, 5, 6, 8 (sub-function 0, echo), 15, 16, 22 (mask write), 23 (read/write multiple)
//! and 43/14 (device identification). It is reached over TCP ([`ModbusSim::serve`]) with MBAP framing (Modbus
//! TCP) or RTU framing (RTU over TCP, as a serial gateway), or in memory through a [`ModbusLink`].
//!
//! Addresses are 0-based protocol addresses: holding register "40001" is holding address 0.
//!
//! The frames are coded here by hand, not with `ciplink`'s Modbus code, so the simulator is an independent
//! check of a driver's bytes.

use crate::ConfigError;
use serde::Deserialize;
use serde_json::Value as Json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// How requests and replies are framed on the byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// Modbus TCP: the 7-byte MBAP header, no CRC.
    Mbap,
    /// Modbus RTU: unit, PDU, CRC-16/MODBUS (over TCP: an RTU gateway).
    Rtu,
}

/// A fault injected into a [`ModbusSim`]; several can be active at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModbusFault {
    /// The next `n` requests are handled but get no reply.
    DropReplies(u32),
    /// Every reply is sent this late.
    Delay(Duration),
    /// New connections are closed at once (in memory: [`ModbusSim::link`] fails).
    RefuseConnections,
    /// Connections open now are closed at their next request. [`ModbusSim::clear_faults`] does not undo it.
    /// Over TCP a connection counts as open once its server thread has started; one answered request proves it.
    CloseConnections,
    /// This unit never answers (a silent gateway or a dead device).
    NoReply {
        /// The unit.
        unit: u8,
    },
    /// Requests to this unit (of one function, or any) are answered with this exception code.
    Exception {
        /// The unit.
        unit: u8,
        /// The function code, None for any.
        function: Option<u8>,
        /// The exception code.
        code: u8,
    },
    /// RTU: the next `n` replies carry a wrong CRC.
    BadCrc(u32),
}

/// One of the four Modbus tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Area {
    Coil,
    Discrete,
    Holding,
    Input,
}

impl Area {
    fn parse(name: &str) -> Result<Self, ConfigError> {
        match name.to_ascii_lowercase().as_str() {
            "coil" | "coils" | "co" => Ok(Area::Coil),
            "discrete" | "di" => Ok(Area::Discrete),
            "holding" | "hr" => Ok(Area::Holding),
            "input" | "ir" => Ok(Area::Input),
            _ => Err(ConfigError::new(format!(
                "unknown area {name:?} (coil, discrete, holding, input)"
            ))),
        }
    }
}

/// The configuration of a [`ModbusSim`], as JSON:
///
/// ```json
/// {"kind": "modbus", "max_registers": 125, "max_bits": 2000,
///  "units": [{"unit": 1, "holding": 1000, "holes": [{"area": "holding", "start": 500, "count": 10}],
///             "identity": {"vendor_name": "ciplink", "product_code": "SIM-MB", "revision": "1.0"},
///             "values": {"holding": {"0": [59769, 17142]}, "coil": {"0": [true, false]}}}]}
/// ```
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModbusSimConfig {
    /// Always `"modbus"` when given.
    #[serde(default)]
    pub kind: Option<String>,
    /// The most registers one read may ask for (exception 03 above it), at most 125.
    #[serde(default = "default_max_registers")]
    pub max_registers: u16,
    /// The most coils or discrete inputs one read may ask for, at most 2000.
    #[serde(default = "default_max_bits")]
    pub max_bits: u16,
    /// The units (slaves) that answer.
    pub units: Vec<UnitConfig>,
}

fn default_max_registers() -> u16 {
    125
}

fn default_max_bits() -> u16 {
    2000
}

fn default_table() -> u32 {
    10000
}

/// One unit (slave) of a [`ModbusSimConfig`].
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitConfig {
    /// The unit id, 1..=255 (0 is the RTU broadcast address).
    pub unit: u8,
    /// Number of coils (default 10000, at most 65536).
    #[serde(default = "default_table")]
    pub coils: u32,
    /// Number of discrete inputs.
    #[serde(default = "default_table")]
    pub discrete: u32,
    /// Number of holding registers.
    #[serde(default = "default_table")]
    pub holding: u32,
    /// Number of input registers.
    #[serde(default = "default_table")]
    pub input: u32,
    /// Ranges that answer exception 02 when a request touches them.
    #[serde(default)]
    pub holes: Vec<HoleConfig>,
    /// Answers function 43/14 when set.
    #[serde(default)]
    pub identity: Option<ModbusIdentity>,
    /// Objects per 43/14 reply, to test "more follows" paging; None: as many as fit.
    #[serde(default)]
    pub identity_page: Option<u8>,
    /// Function codes answered with exception 01.
    #[serde(default)]
    pub unsupported: Vec<u8>,
    /// Initial values: area name -> start address (as a string) -> values (numbers for registers, booleans or
    /// 0/1 for bits).
    #[serde(default)]
    pub values: HashMap<String, HashMap<String, Vec<Json>>>,
}

/// A range of addresses that does not exist on the device.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoleConfig {
    /// `coil`, `discrete`, `holding` or `input`.
    pub area: String,
    /// First address.
    pub start: u16,
    /// Number of addresses.
    pub count: u16,
}

/// The objects function 43/14 (Read Device Identification) answers; objects 0-2 are basic, 3-6 regular.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModbusIdentity {
    /// Object 0.
    #[serde(default)]
    pub vendor_name: String,
    /// Object 1.
    #[serde(default)]
    pub product_code: String,
    /// Object 2 (major.minor revision).
    #[serde(default)]
    pub revision: String,
    /// Object 3.
    #[serde(default)]
    pub vendor_url: Option<String>,
    /// Object 4.
    #[serde(default)]
    pub product_name: Option<String>,
    /// Object 5.
    #[serde(default)]
    pub model_name: Option<String>,
    /// Object 6.
    #[serde(default)]
    pub user_application_name: Option<String>,
}

impl ModbusIdentity {
    fn objects(&self) -> Vec<(u8, Vec<u8>)> {
        let mut objects = vec![
            (0, self.vendor_name.as_bytes().to_vec()),
            (1, self.product_code.as_bytes().to_vec()),
            (2, self.revision.as_bytes().to_vec()),
        ];
        let regular = [
            &self.vendor_url,
            &self.product_name,
            &self.model_name,
            &self.user_application_name,
        ];
        for (id, value) in (3u8..).zip(regular) {
            if let Some(value) = value {
                objects.push((id, value.as_bytes().to_vec()));
            }
        }
        objects
    }
}

/// The tables of one unit.
struct Unit {
    coils: Vec<bool>,
    discrete: Vec<bool>,
    holding: Vec<u16>,
    input: Vec<u16>,
    holes: Vec<(Area, u32, u32)>,
    identity: Option<ModbusIdentity>,
    identity_page: Option<u8>,
    unsupported: Vec<u8>,
}

impl Unit {
    fn new(config: &UnitConfig) -> Result<Self, ConfigError> {
        let size = |n: u32| -> Result<usize, ConfigError> {
            if n > 65536 {
                return Err(ConfigError::new(format!(
                    "unit {}: a table has at most 65536 entries, not {n}",
                    config.unit
                )));
            }
            Ok(n as usize)
        };
        let mut unit = Unit {
            coils: vec![false; size(config.coils)?],
            discrete: vec![false; size(config.discrete)?],
            holding: vec![0; size(config.holding)?],
            input: vec![0; size(config.input)?],
            holes: Vec::new(),
            identity: config.identity.clone(),
            identity_page: config.identity_page.filter(|&n| n > 0),
            unsupported: config.unsupported.clone(),
        };
        for hole in &config.holes {
            let start = u32::from(hole.start);
            unit.holes.push((
                Area::parse(&hole.area)?,
                start,
                start + u32::from(hole.count),
            ));
        }
        for (area, starts) in &config.values {
            let area = Area::parse(area)?;
            for (start, values) in starts {
                let start: u16 = start.parse().map_err(|_| {
                    ConfigError::new(format!(
                        "unit {}: start address {start:?} is not 0..65535",
                        config.unit
                    ))
                })?;
                let bad = |v: &Json| {
                    ConfigError::new(format!("unit {}: bad initial value {v}", config.unit))
                };
                match area {
                    Area::Coil | Area::Discrete => {
                        let bits = values
                            .iter()
                            .map(|v| match v {
                                Json::Bool(b) => Ok(*b),
                                Json::Number(n) if n.as_u64() == Some(0) => Ok(false),
                                Json::Number(n) if n.as_u64() == Some(1) => Ok(true),
                                _ => Err(bad(v)),
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        unit.set_bits(area, start, &bits)?;
                    }
                    Area::Holding | Area::Input => {
                        let registers = values
                            .iter()
                            .map(|v| {
                                v.as_u64()
                                    .and_then(|n| u16::try_from(n).ok())
                                    .or_else(|| {
                                        v.as_i64()
                                            .and_then(|n| i16::try_from(n).ok())
                                            .map(|n| n as u16)
                                    })
                                    .ok_or_else(|| bad(v))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        unit.set_registers(area, start, &registers)?;
                    }
                }
            }
        }
        Ok(unit)
    }

    fn table_len(&self, area: Area) -> usize {
        match area {
            Area::Coil => self.coils.len(),
            Area::Discrete => self.discrete.len(),
            Area::Holding => self.holding.len(),
            Area::Input => self.input.len(),
        }
    }

    /// Whether `count` addresses from `address` exist (in the table and not in a hole).
    fn exists(&self, area: Area, address: u16, count: u16) -> bool {
        let start = u32::from(address);
        let end = start + u32::from(count);
        end as usize <= self.table_len(area)
            && !self
                .holes
                .iter()
                .any(|&(a, s, e)| a == area && start < e && s < end)
    }

    fn range(&self, area: Area, address: u16, count: u16) -> Result<(usize, usize), ConfigError> {
        let start = usize::from(address);
        let end = start + usize::from(count);
        if end > self.table_len(area) {
            return Err(ConfigError::new(format!(
                "{area:?} {address}..{end} is past the table of {}",
                self.table_len(area)
            )));
        }
        Ok((start, end))
    }

    fn registers(&self, area: Area, address: u16, count: u16) -> Result<Vec<u16>, ConfigError> {
        let (s, e) = self.range(area, address, count)?;
        match area {
            Area::Holding => Ok(self.holding[s..e].to_vec()),
            Area::Input => Ok(self.input[s..e].to_vec()),
            _ => Err(ConfigError::new(format!("{area:?} holds bits"))),
        }
    }

    fn set_registers(
        &mut self,
        area: Area,
        address: u16,
        values: &[u16],
    ) -> Result<(), ConfigError> {
        let count = u16::try_from(values.len()).map_err(|_| ConfigError::new("too many values"))?;
        let (s, e) = self.range(area, address, count)?;
        match area {
            Area::Holding => self.holding[s..e].copy_from_slice(values),
            Area::Input => self.input[s..e].copy_from_slice(values),
            _ => return Err(ConfigError::new(format!("{area:?} holds bits"))),
        }
        Ok(())
    }

    fn bits(&self, area: Area, address: u16, count: u16) -> Result<Vec<bool>, ConfigError> {
        let (s, e) = self.range(area, address, count)?;
        match area {
            Area::Coil => Ok(self.coils[s..e].to_vec()),
            Area::Discrete => Ok(self.discrete[s..e].to_vec()),
            _ => Err(ConfigError::new(format!("{area:?} holds registers"))),
        }
    }

    fn set_bits(&mut self, area: Area, address: u16, values: &[bool]) -> Result<(), ConfigError> {
        let count = u16::try_from(values.len()).map_err(|_| ConfigError::new("too many values"))?;
        let (s, e) = self.range(area, address, count)?;
        match area {
            Area::Coil => self.coils[s..e].copy_from_slice(values),
            Area::Discrete => self.discrete[s..e].copy_from_slice(values),
            _ => return Err(ConfigError::new(format!("{area:?} holds registers"))),
        }
        Ok(())
    }
}

/// The tables of every unit of a [`ModbusSim`], as a request hook sees them.
pub struct ModbusData {
    units: BTreeMap<u8, Unit>,
    max_registers: u16,
    max_bits: u16,
}

impl ModbusData {
    fn unit(&self, unit: u8) -> Result<&Unit, ConfigError> {
        self.units
            .get(&unit)
            .ok_or_else(|| ConfigError::new(format!("no unit {unit}")))
    }

    fn unit_mut(&mut self, unit: u8) -> Result<&mut Unit, ConfigError> {
        self.units
            .get_mut(&unit)
            .ok_or_else(|| ConfigError::new(format!("no unit {unit}")))
    }

    /// `count` registers of `area` (`holding` or `input`) from `address`.
    pub fn registers(
        &self,
        unit: u8,
        area: &str,
        address: u16,
        count: u16,
    ) -> Result<Vec<u16>, ConfigError> {
        self.unit(unit)?
            .registers(Area::parse(area)?, address, count)
    }

    /// Sets registers of `area` (`holding` or `input`) from `address`.
    pub fn set_registers(
        &mut self,
        unit: u8,
        area: &str,
        address: u16,
        values: &[u16],
    ) -> Result<(), ConfigError> {
        let area = Area::parse(area)?;
        self.unit_mut(unit)?.set_registers(area, address, values)
    }

    /// `count` bits of `area` (`coil` or `discrete`) from `address`.
    pub fn bits(
        &self,
        unit: u8,
        area: &str,
        address: u16,
        count: u16,
    ) -> Result<Vec<bool>, ConfigError> {
        self.unit(unit)?.bits(Area::parse(area)?, address, count)
    }

    /// Sets bits of `area` (`coil` or `discrete`) from `address`.
    pub fn set_bits(
        &mut self,
        unit: u8,
        area: &str,
        address: u16,
        values: &[bool],
    ) -> Result<(), ConfigError> {
        let area = Area::parse(area)?;
        self.unit_mut(unit)?.set_bits(area, address, values)
    }
}

#[derive(Default)]
struct Faults {
    drop_replies: u32,
    delay: Duration,
    refuse_connections: bool,
    no_reply: Vec<u8>,
    exceptions: Vec<(u8, Option<u8>, u8)>,
    bad_crc: u32,
}

type Hook = Box<dyn FnMut(&mut ModbusData, u64) + Send>;

struct State {
    data: ModbusData,
    faults: Faults,
    /// Bumped by CloseConnections; a connection opened in an earlier epoch is closed at its next request.
    epoch: u64,
    requests: u64,
    recording: bool,
    log: Vec<Vec<u8>>,
    hook: Option<Hook>,
}

enum Outcome {
    Reply(Vec<u8>, Duration),
    Silent,
    Close,
}

/// A simulated Modbus device; clones refer to the same device.
#[derive(Clone)]
pub struct ModbusSim {
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for ModbusSim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock();
        f.debug_struct("ModbusSim")
            .field("units", &state.data.units.keys().collect::<Vec<_>>())
            .field("requests", &state.requests)
            .finish()
    }
}

impl ModbusSim {
    /// A simulator of these units.
    pub fn new(config: ModbusSimConfig) -> Result<Self, ConfigError> {
        if config.kind.as_deref().is_some_and(|k| k != "modbus") {
            return Err(ConfigError::new(
                "a Modbus configuration has kind \"modbus\"",
            ));
        }
        let mut units = BTreeMap::new();
        for unit in &config.units {
            if units.insert(unit.unit, Unit::new(unit)?).is_some() {
                return Err(ConfigError::new(format!(
                    "unit {} is configured twice",
                    unit.unit
                )));
            }
        }
        let data = ModbusData {
            units,
            max_registers: config.max_registers.clamp(1, 125),
            max_bits: config.max_bits.clamp(1, 2000),
        };
        Ok(ModbusSim {
            state: Arc::new(Mutex::new(State {
                data,
                faults: Faults::default(),
                epoch: 0,
                requests: 0,
                recording: false,
                log: Vec::new(),
                hook: None,
            })),
        })
    }

    /// A simulator configured from JSON (see [`ModbusSimConfig`]).
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let config: ModbusSimConfig = serde_json::from_str(text)
            .map_err(|e| ConfigError::new(format!("invalid Modbus configuration: {e}")))?;
        Self::new(config)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new in-memory connection.
    pub fn link(&self, framing: Framing) -> io::Result<ModbusLink> {
        let state = self.lock();
        if state.faults.refuse_connections {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused",
            ));
        }
        Ok(ModbusLink {
            state: Arc::clone(&self.state),
            framing,
            epoch: state.epoch,
            pending: Vec::new(),
            replies: VecDeque::new(),
            timeout: Some(Duration::from_secs(1)),
            closed: false,
        })
    }

    /// A connector for `ciplink`'s `ModbusDriver` that opens in-memory links with this framing (whatever the
    /// path's host or port); refused while [`ModbusFault::RefuseConnections`] is active.
    pub fn connector(&self, framing: Framing) -> ciplink::modbus::ModbusConnector {
        let sim = self.clone();
        Box::new(move |endpoint, timeout| {
            let mut link = sim
                .link(framing)
                .map_err(|_| ciplink::Error::comm(format!("Failed to open {endpoint}")))?;
            link.set_timeout(Some(timeout));
            Ok(Box::new(link) as Box<dyn ciplink::modbus::Link>)
        })
    }

    /// Serves the device over TCP on `addr` (e.g. `"127.0.0.1:0"` for a free port) with this framing.
    pub fn serve(&self, addr: &str, framing: Framing) -> io::Result<ModbusServer> {
        ModbusServer::start(Arc::clone(&self.state), addr, framing)
    }

    /// `count` registers of `area` (`holding` or `input`) of a unit from `address`.
    pub fn registers(
        &self,
        unit: u8,
        area: &str,
        address: u16,
        count: u16,
    ) -> Result<Vec<u16>, ConfigError> {
        self.lock().data.registers(unit, area, address, count)
    }

    /// Sets registers of `area` (`holding` or `input`) of a unit from `address`.
    pub fn set_registers(
        &self,
        unit: u8,
        area: &str,
        address: u16,
        values: &[u16],
    ) -> Result<(), ConfigError> {
        self.lock().data.set_registers(unit, area, address, values)
    }

    /// `count` bits of `area` (`coil` or `discrete`) of a unit from `address`.
    pub fn bits(
        &self,
        unit: u8,
        area: &str,
        address: u16,
        count: u16,
    ) -> Result<Vec<bool>, ConfigError> {
        self.lock().data.bits(unit, area, address, count)
    }

    /// Sets bits of `area` (`coil` or `discrete`) of a unit from `address`.
    pub fn set_bits(
        &self,
        unit: u8,
        area: &str,
        address: u16,
        values: &[bool],
    ) -> Result<(), ConfigError> {
        self.lock().data.set_bits(unit, area, address, values)
    }

    /// Injects a fault.
    pub fn inject(&self, fault: ModbusFault) {
        let mut state = self.lock();
        let faults = &mut state.faults;
        match fault {
            ModbusFault::DropReplies(n) => {
                faults.drop_replies = faults.drop_replies.saturating_add(n)
            }
            ModbusFault::Delay(delay) => faults.delay = delay,
            ModbusFault::RefuseConnections => faults.refuse_connections = true,
            ModbusFault::CloseConnections => state.epoch += 1,
            ModbusFault::NoReply { unit } => faults.no_reply.push(unit),
            ModbusFault::Exception {
                unit,
                function,
                code,
            } => faults.exceptions.push((unit, function, code)),
            ModbusFault::BadCrc(n) => faults.bad_crc = faults.bad_crc.saturating_add(n),
        }
    }

    /// Removes every fault (connections closed by [`ModbusFault::CloseConnections`] stay closed).
    pub fn clear_faults(&self) {
        self.lock().faults = Faults::default();
    }

    /// The number of requests (frames) received so far.
    pub fn requests(&self) -> u64 {
        self.lock().requests
    }

    /// Starts or stops keeping every request frame received (see [`ModbusSim::take_received`]).
    pub fn record(&self, on: bool) {
        let mut state = self.lock();
        state.recording = on;
        if !on {
            state.log.clear();
        }
    }

    /// The whole request frames (ADUs) received since recording started or the last call, in order.
    pub fn take_received(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.lock().log)
    }

    /// Calls `hook` before each request with the tables and the request's index (from 0). Replaces an earlier
    /// hook. It runs with the simulator locked: it must not call this simulator's methods (that deadlocks),
    /// and every connection waits while it runs, so blocking in it holds the driver.
    pub fn on_request(&self, hook: impl FnMut(&mut ModbusData, u64) + Send + 'static) {
        self.lock().hook = Some(Box::new(hook));
    }

    /// Removes the request hook.
    pub fn clear_hook(&self) {
        self.lock().hook = None;
    }
}

/// CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF); sent low byte first.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in bytes {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// The length of the request frame at the start of `buf`: `Ok(Some(n))` once known, `Ok(None)` when more
/// bytes are needed to tell, `Err(())` when it cannot be told (a bad MBAP length, an unknown RTU function).
fn request_len(framing: Framing, buf: &[u8]) -> Result<Option<usize>, ()> {
    match framing {
        Framing::Mbap => {
            if buf.len() < 7 {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
            if !(2..=254).contains(&len) {
                return Err(());
            }
            Ok(Some(6 + len))
        }
        Framing::Rtu => {
            let Some(&function) = buf.get(1) else {
                return Ok(None);
            };
            // unit, function, the fixed fields, a byte count at `count_at` (if any), the data, the CRC
            let with_count = |count_at: usize| {
                Ok(buf
                    .get(count_at)
                    .map(|&n| count_at + 1 + usize::from(n) + 2))
            };
            match function {
                1..=6 | 8 => Ok(Some(8)),
                22 => Ok(Some(10)),
                43 => Ok(Some(7)),
                15 | 16 => with_count(6),
                23 => with_count(10),
                _ => Err(()),
            }
        }
    }
}

impl State {
    /// Handles one whole request frame from a connection opened in `epoch`.
    fn handle(&mut self, framing: Framing, epoch: u64, frame: &[u8]) -> Outcome {
        let index = self.requests;
        self.requests += 1;
        if self.recording {
            self.log.push(frame.to_vec());
        }
        if epoch < self.epoch {
            return Outcome::Close;
        }
        if let Some(hook) = self.hook.as_mut() {
            hook(&mut self.data, index);
        }
        let (unit, pdu, header) = match framing {
            Framing::Mbap => {
                if frame.len() < 8 {
                    return Outcome::Silent;
                }
                (frame[6], &frame[7..], [frame[0], frame[1]])
            }
            Framing::Rtu => {
                if frame.len() < 4 {
                    return Outcome::Silent;
                }
                let (body, crc) = frame.split_at(frame.len() - 2);
                // a real device ignores a frame with a bad CRC
                if crc16(body).to_le_bytes() != [crc[0], crc[1]] {
                    return Outcome::Silent;
                }
                (frame[0], &body[1..], [0, 0])
            }
        };
        let Some(reply) = self.answer(framing, unit, pdu) else {
            return Outcome::Silent;
        };
        if self.faults.drop_replies > 0 {
            self.faults.drop_replies -= 1;
            return Outcome::Silent;
        }
        let mut adu = Vec::with_capacity(reply.len() + 7);
        match framing {
            Framing::Mbap => {
                adu.extend_from_slice(&header);
                adu.extend_from_slice(&[0, 0]);
                // a reply PDU is at most 253 bytes, so this fits
                adu.extend_from_slice(&(reply.len() as u16 + 1).to_be_bytes());
                adu.push(unit);
                adu.extend_from_slice(&reply);
            }
            Framing::Rtu => {
                adu.push(unit);
                adu.extend_from_slice(&reply);
                let mut crc = crc16(&adu);
                if self.faults.bad_crc > 0 {
                    self.faults.bad_crc -= 1;
                    crc ^= 0xFFFF;
                }
                adu.extend_from_slice(&crc.to_le_bytes());
            }
        }
        Outcome::Reply(adu, self.faults.delay)
    }

    /// The reply PDU to `pdu` for `unit`, None for no reply.
    fn answer(&mut self, framing: Framing, unit: u8, pdu: &[u8]) -> Option<Vec<u8>> {
        let &function = pdu.first()?;
        if self.faults.no_reply.contains(&unit) {
            return None;
        }
        if unit == 0 && framing == Framing::Rtu {
            // broadcast: writes reach every unit, nobody answers
            if matches!(function, 5 | 6 | 15 | 16 | 22) {
                let (max_registers, max_bits) = (self.data.max_registers, self.data.max_bits);
                for unit in self.data.units.values_mut() {
                    let _ = execute(unit, max_registers, max_bits, pdu);
                }
            }
            return None;
        }
        if let Some(&(_, _, code)) = self
            .faults
            .exceptions
            .iter()
            .find(|&&(u, f, _)| u == unit && f.is_none_or(|f| f == function))
        {
            return Some(vec![function | 0x80, code]);
        }
        let (max_registers, max_bits) = (self.data.max_registers, self.data.max_bits);
        let Some(target) = self.data.units.get_mut(&unit) else {
            // a gateway answers "target device failed to respond"; on a bus nobody answers
            return match framing {
                Framing::Mbap => Some(vec![function | 0x80, 0x0B]),
                Framing::Rtu => None,
            };
        };
        Some(match execute(target, max_registers, max_bits, pdu) {
            Ok(reply) => reply,
            Err(code) => vec![function | 0x80, code],
        })
    }
}

const ILLEGAL_FUNCTION: u8 = 0x01;
const ILLEGAL_ADDRESS: u8 = 0x02;
const ILLEGAL_VALUE: u8 = 0x03;

fn word(pdu: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([pdu[at], pdu[at + 1]])
}

fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (i, _) in bits.iter().enumerate().filter(|(_, b)| **b) {
        bytes[i / 8] |= 1 << (i % 8);
    }
    bytes
}

/// Runs one request PDU on a unit: the reply PDU or an exception code.
fn execute(unit: &mut Unit, max_registers: u16, max_bits: u16, pdu: &[u8]) -> Result<Vec<u8>, u8> {
    let function = pdu[0];
    if unit.unsupported.contains(&function) {
        return Err(ILLEGAL_FUNCTION);
    }
    let need = |len: usize| {
        if pdu.len() == len {
            Ok(())
        } else {
            Err(ILLEGAL_VALUE)
        }
    };
    let check = |unit: &Unit, area: Area, address: u16, count: u16| {
        if unit.exists(area, address, count) {
            Ok((
                usize::from(address),
                usize::from(address) + usize::from(count),
            ))
        } else {
            Err(ILLEGAL_ADDRESS)
        }
    };
    match function {
        1 | 2 => {
            need(5)?;
            let (address, count) = (word(pdu, 1), word(pdu, 3));
            if count == 0 || count > max_bits {
                return Err(ILLEGAL_VALUE);
            }
            let area = if function == 1 {
                Area::Coil
            } else {
                Area::Discrete
            };
            let (s, e) = check(unit, area, address, count)?;
            let table = if function == 1 {
                &unit.coils
            } else {
                &unit.discrete
            };
            let bytes = pack_bits(&table[s..e]);
            let mut reply = vec![function, bytes.len() as u8];
            reply.extend_from_slice(&bytes);
            Ok(reply)
        }
        3 | 4 => {
            need(5)?;
            let (address, count) = (word(pdu, 1), word(pdu, 3));
            if count == 0 || count > max_registers {
                return Err(ILLEGAL_VALUE);
            }
            let area = if function == 3 {
                Area::Holding
            } else {
                Area::Input
            };
            let (s, e) = check(unit, area, address, count)?;
            let table = if function == 3 {
                &unit.holding
            } else {
                &unit.input
            };
            let mut reply = Vec::with_capacity(2 + 2 * usize::from(count));
            reply.extend_from_slice(&[function, (2 * count) as u8]);
            for r in &table[s..e] {
                reply.extend_from_slice(&r.to_be_bytes());
            }
            Ok(reply)
        }
        5 => {
            need(5)?;
            let value = match word(pdu, 3) {
                0xFF00 => true,
                0x0000 => false,
                _ => return Err(ILLEGAL_VALUE),
            };
            let (s, _) = check(unit, Area::Coil, word(pdu, 1), 1)?;
            unit.coils[s] = value;
            Ok(pdu.to_vec())
        }
        6 => {
            need(5)?;
            let (s, _) = check(unit, Area::Holding, word(pdu, 1), 1)?;
            unit.holding[s] = word(pdu, 3);
            Ok(pdu.to_vec())
        }
        8 => {
            // only sub-function 0000, Return Query Data: the request comes back unchanged
            if pdu.len() < 3 || word(pdu, 1) != 0 {
                return Err(ILLEGAL_FUNCTION);
            }
            Ok(pdu.to_vec())
        }
        15 => {
            if pdu.len() < 6 {
                return Err(ILLEGAL_VALUE);
            }
            let (address, count) = (word(pdu, 1), word(pdu, 3));
            if count == 0 || count > 0x7B0 || usize::from(pdu[5]) != usize::from(count).div_ceil(8)
            {
                return Err(ILLEGAL_VALUE);
            }
            need(6 + usize::from(pdu[5]))?;
            let (s, e) = check(unit, Area::Coil, address, count)?;
            for (i, coil) in unit.coils[s..e].iter_mut().enumerate() {
                *coil = pdu[6 + i / 8] & (1 << (i % 8)) != 0;
            }
            Ok(pdu[..5].to_vec())
        }
        16 => {
            if pdu.len() < 6 {
                return Err(ILLEGAL_VALUE);
            }
            let (address, count) = (word(pdu, 1), word(pdu, 3));
            if count == 0 || count > 0x7B || usize::from(pdu[5]) != 2 * usize::from(count) {
                return Err(ILLEGAL_VALUE);
            }
            need(6 + usize::from(pdu[5]))?;
            let (s, e) = check(unit, Area::Holding, address, count)?;
            for (i, r) in unit.holding[s..e].iter_mut().enumerate() {
                *r = word(pdu, 6 + 2 * i);
            }
            Ok(pdu[..5].to_vec())
        }
        22 => {
            need(7)?;
            let (s, _) = check(unit, Area::Holding, word(pdu, 1), 1)?;
            let (and, or) = (word(pdu, 3), word(pdu, 5));
            unit.holding[s] = (unit.holding[s] & and) | (or & !and);
            Ok(pdu.to_vec())
        }
        23 => {
            if pdu.len() < 10 {
                return Err(ILLEGAL_VALUE);
            }
            let (read_at, read_count) = (word(pdu, 1), word(pdu, 3));
            let (write_at, write_count) = (word(pdu, 5), word(pdu, 7));
            if read_count == 0
                || read_count > max_registers
                || write_count == 0
                || write_count > 0x79
                || usize::from(pdu[9]) != 2 * usize::from(write_count)
            {
                return Err(ILLEGAL_VALUE);
            }
            need(10 + usize::from(pdu[9]))?;
            let (rs, re) = check(unit, Area::Holding, read_at, read_count)?;
            let (ws, we) = check(unit, Area::Holding, write_at, write_count)?;
            // the write happens before the read
            for (i, r) in unit.holding[ws..we].iter_mut().enumerate() {
                *r = word(pdu, 10 + 2 * i);
            }
            let mut reply = vec![23, (2 * read_count) as u8];
            for r in &unit.holding[rs..re] {
                reply.extend_from_slice(&r.to_be_bytes());
            }
            Ok(reply)
        }
        43 => device_identification(unit, pdu),
        _ => Err(ILLEGAL_FUNCTION),
    }
}

/// Function 43, MEI type 14: Read Device Identification.
fn device_identification(unit: &Unit, pdu: &[u8]) -> Result<Vec<u8>, u8> {
    if pdu.get(1) != Some(&0x0E) {
        return Err(ILLEGAL_FUNCTION);
    }
    let Some(identity) = &unit.identity else {
        return Err(ILLEGAL_FUNCTION);
    };
    if pdu.len() != 4 {
        return Err(ILLEGAL_VALUE);
    }
    let (code, first) = (pdu[2], pdu[3]);
    let objects = identity.objects();
    let in_category = |id: u8| match code {
        1 => id <= 2,
        2 => id <= 0x7F,
        3 => true,
        _ => false,
    };
    // conformity: regular identification, stream and individual access
    let mut reply = vec![43, 0x0E, code, 0x82, 0, 0, 0];
    if code == 4 {
        let (id, value) = objects
            .iter()
            .find(|(id, _)| *id == first)
            .ok_or(ILLEGAL_ADDRESS)?;
        reply[6] = 1;
        reply.push(*id);
        reply.push(value.len().min(245) as u8);
        reply.extend_from_slice(&value[..value.len().min(245)]);
        return Ok(reply);
    }
    if !(1..=3).contains(&code) {
        return Err(ILLEGAL_VALUE);
    }
    let selected: Vec<&(u8, Vec<u8>)> = objects.iter().filter(|(id, _)| in_category(*id)).collect();
    // an object id that does not exist restarts from the first, as the specification says
    let start = selected
        .iter()
        .position(|(id, _)| *id == first)
        .unwrap_or(0);
    let page = unit.identity_page.map_or(usize::MAX, usize::from);
    let mut sent = 0u8;
    for (i, (id, value)) in selected.iter().enumerate().skip(start) {
        let len = value.len().min(245);
        if usize::from(sent) == page || reply.len() + 2 + len > 253 {
            reply[4] = 0xFF;
            reply[5] = selected[i].0;
            break;
        }
        reply.push(*id);
        reply.push(len as u8);
        reply.extend_from_slice(&value[..len]);
        sent += 1;
    }
    reply[6] = sent;
    Ok(reply)
}

/// An in-memory connection to a [`ModbusSim`]: write whole or partial request frames, read the replies.
///
/// It is synchronous: a complete frame is handled as soon as it is written and its reply queued. A read with
/// nothing queued fails with [`io::ErrorKind::TimedOut`] at once instead of waiting; a reply delayed past the
/// timeout fails the read the same way and stays queued, as a late reply on a socket would. After the
/// simulator closes the connection, reads return 0 (end of stream) and writes fail.
pub struct ModbusLink {
    state: Arc<Mutex<State>>,
    framing: Framing,
    epoch: u64,
    pending: Vec<u8>,
    replies: VecDeque<(Vec<u8>, Duration)>,
    timeout: Option<Duration>,
    closed: bool,
}

impl std::fmt::Debug for ModbusLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModbusLink")
            .field("framing", &self.framing)
            .field("closed", &self.closed)
            .finish()
    }
}

impl ModbusLink {
    /// The timeout of later reads (None: no timeout, default 1 s).
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    fn handle(&mut self, frame: &[u8]) {
        let outcome = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handle(self.framing, self.epoch, frame);
        match outcome {
            Outcome::Reply(reply, delay) => self.replies.push_back((reply, delay)),
            Outcome::Silent => {}
            Outcome::Close => {
                self.closed = true;
                self.replies.clear();
            }
        }
    }
}

impl ciplink::modbus::Link for ModbusLink {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        ModbusLink::set_timeout(self, Some(timeout));
        Ok(())
    }
}

impl Write for ModbusLink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            ));
        }
        self.pending.extend_from_slice(bytes);
        while !self.pending.is_empty() && !self.closed {
            match request_len(self.framing, &self.pending) {
                Ok(Some(n)) if self.pending.len() >= n => {
                    let frame: Vec<u8> = self.pending.drain(..n).collect();
                    self.handle(&frame);
                }
                Ok(_) => break,
                // writes carry whole frames in memory, so what is there is the frame
                Err(()) => {
                    let frame = std::mem::take(&mut self.pending);
                    if self.framing == Framing::Mbap {
                        self.closed = true;
                    } else {
                        self.handle(&frame);
                    }
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for ModbusLink {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some((mut reply, delay)) = self.replies.pop_front() else {
            if self.closed {
                return Ok(0);
            }
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        };
        if self.timeout.is_some_and(|t| delay >= t) {
            self.replies.push_front((reply, Duration::ZERO));
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        }
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let n = buf.len().min(reply.len());
        buf[..n].copy_from_slice(&reply[..n]);
        if n < reply.len() {
            reply.drain(..n);
            self.replies.push_front((reply, Duration::ZERO));
        }
        Ok(n)
    }
}

/// A running Modbus TCP server (a thread per connection); it stops accepting connections when dropped.
pub struct ModbusServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ModbusServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModbusServer")
            .field("addr", &self.addr)
            .finish()
    }
}

impl ModbusServer {
    fn start(state: Arc<Mutex<State>>, addr: &str, framing: Framing) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&state);
                std::thread::spawn(move || serve_connection(stream, &state, framing));
            }
        });
        Ok(ModbusServer {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port the server listens on (the one bound when asked for port 0).
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for ModbusServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // wakes the accept loop
        let mut wake = self.addr;
        if wake.ip().is_unspecified() {
            wake.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Reads the next request frame from the stream, None when the connection ends or is garbage.
fn read_frame(stream: &mut TcpStream, framing: Framing) -> Option<Vec<u8>> {
    let mut frame = Vec::with_capacity(260);
    let mut byte = [0u8; 1];
    loop {
        match request_len(framing, &frame) {
            Ok(Some(n)) => {
                let have = frame.len();
                if have < n {
                    frame.resize(n, 0);
                    stream.read_exact(&mut frame[have..]).ok()?;
                }
                return Some(frame);
            }
            Ok(None) => {
                stream.read_exact(&mut byte).ok()?;
                frame.push(byte[0]);
            }
            Err(()) if framing == Framing::Mbap => return None,
            Err(()) => {
                // an RTU function of unknown length: take what arrives until the line is quiet
                stream
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .ok()?;
                let mut rest = [0u8; 256];
                while frame.len() < 256 {
                    match stream.read(&mut rest) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => frame.extend_from_slice(&rest[..n]),
                    }
                }
                stream.set_read_timeout(None).ok()?;
                return Some(frame);
            }
        }
    }
}

fn serve_connection(mut stream: TcpStream, state: &Mutex<State>, framing: Framing) {
    let lock = || state.lock().unwrap_or_else(PoisonError::into_inner);
    let epoch = {
        let state = lock();
        if state.faults.refuse_connections {
            return;
        }
        state.epoch
    };
    let _ = stream.set_nodelay(true);
    while let Some(frame) = read_frame(&mut stream, framing) {
        let outcome = lock().handle(framing, epoch, &frame);
        match outcome {
            Outcome::Reply(reply, delay) => {
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                if stream.write_all(&reply).is_err() {
                    return;
                }
            }
            Outcome::Silent => {}
            Outcome::Close => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{
      "kind": "modbus",
      "units": [
        {"unit": 1, "holding": 1000, "input": 1000, "coils": 2000, "discrete": 2000,
         "holes": [{"area": "holding", "start": 500, "count": 10}],
         "identity": {"vendor_name": "ciplink", "product_code": "SIM-MB", "revision": "1.0",
                      "product_name": "ciplink-sim Modbus", "model_name": "MB-1"},
         "values": {"holding": {"0": [59769, 17142]}, "coil": {"0": [true, false, true]},
                    "input": {"10": [-1, 7]}, "discrete": {"3": [1]}}},
        {"unit": 2, "holding": 100, "coils": 100, "unsupported": [22, 43]}
      ]
    }"#;

    fn sim() -> ModbusSim {
        ModbusSim::from_json(CONFIG).expect("config")
    }

    fn mbap(unit: u8, pdu: &[u8]) -> Vec<u8> {
        let mut adu = vec![0x12, 0x34, 0, 0];
        adu.extend_from_slice(&(pdu.len() as u16 + 1).to_be_bytes());
        adu.push(unit);
        adu.extend_from_slice(pdu);
        adu
    }

    fn rtu(unit: u8, pdu: &[u8]) -> Vec<u8> {
        let mut adu = vec![unit];
        adu.extend_from_slice(pdu);
        let crc = crc16(&adu);
        adu.extend_from_slice(&crc.to_le_bytes());
        adu
    }

    /// Sends one MBAP request and returns the reply PDU (None for no reply).
    fn ask(link: &mut ModbusLink, unit: u8, pdu: &[u8]) -> Option<Vec<u8>> {
        link.write_all(&mbap(unit, pdu)).expect("write");
        let mut buf = [0u8; 300];
        let n = link.read(&mut buf).ok()?;
        assert_eq!(&buf[..2], &[0x12, 0x34], "transaction id echoed");
        assert_eq!(buf[6], unit);
        assert_eq!(usize::from(u16::from_be_bytes([buf[4], buf[5]])), n - 6);
        Some(buf[7..n].to_vec())
    }

    fn ask_rtu(link: &mut ModbusLink, unit: u8, pdu: &[u8]) -> Option<Vec<u8>> {
        link.write_all(&rtu(unit, pdu)).expect("write");
        let mut buf = [0u8; 300];
        let n = link.read(&mut buf).ok()?;
        assert_eq!(crc16(&buf[..n - 2]).to_le_bytes(), [buf[n - 2], buf[n - 1]]);
        assert_eq!(buf[0], unit);
        Some(buf[1..n - 2].to_vec())
    }

    #[test]
    fn crc_matches_the_specification_example() {
        // Modbus over serial line guide: 01 03 00 00 00 0A -> CRC C5 CD
        assert_eq!(crc16(&[1, 3, 0, 0, 0, 0x0A]).to_le_bytes(), [0xC5, 0xCD]);
    }

    #[test]
    fn reads_every_table_with_seeded_values() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        assert_eq!(
            ask(&mut link, 1, &[3, 0, 0, 0, 2]),
            Some(vec![3, 4, 0xE9, 0x79, 0x42, 0xF6])
        );
        assert_eq!(
            ask(&mut link, 1, &[4, 0, 10, 0, 2]),
            Some(vec![4, 4, 0xFF, 0xFF, 0, 7])
        );
        assert_eq!(
            ask(&mut link, 1, &[1, 0, 0, 0, 10]),
            Some(vec![1, 2, 0b101, 0])
        );
        assert_eq!(
            ask(&mut link, 1, &[2, 0, 0, 0, 4]),
            Some(vec![2, 1, 0b1000])
        );
    }

    #[test]
    fn writes_use_fc05_06_15_16_with_echo_replies() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        assert_eq!(
            ask(&mut link, 1, &[5, 0, 1, 0xFF, 0]),
            Some(vec![5, 0, 1, 0xFF, 0])
        );
        assert_eq!(
            ask(&mut link, 1, &[6, 0, 9, 0x12, 0x34]),
            Some(vec![6, 0, 9, 0x12, 0x34])
        );
        assert_eq!(
            ask(&mut link, 1, &[15, 0, 20, 0, 10, 2, 0b0000_0011, 0b10]),
            Some(vec![15, 0, 20, 0, 10])
        );
        assert_eq!(
            ask(&mut link, 1, &[16, 0, 30, 0, 2, 4, 0, 1, 0xFF, 0xFE]),
            Some(vec![16, 0, 30, 0, 2])
        );
        assert_eq!(sim.bits(1, "coil", 0, 3).expect("bits"), [true, true, true]);
        assert_eq!(sim.registers(1, "holding", 9, 1).expect("regs"), [0x1234]);
        let coils = sim.bits(1, "coil", 20, 10).expect("bits");
        assert_eq!(
            coils,
            [
                true, true, false, false, false, false, false, false, false, true
            ]
        );
        assert_eq!(sim.registers(1, "hr", 30, 2).expect("regs"), [1, 0xFFFE]);
        // a coil value other than FF00/0000
        assert_eq!(ask(&mut link, 1, &[5, 0, 1, 0x12, 0]), Some(vec![0x85, 3]));
    }

    #[test]
    fn fc22_mask_math() {
        let sim = sim();
        sim.set_registers(1, "holding", 4, &[0x0012]).expect("set");
        let mut link = sim.link(Framing::Mbap).expect("link");
        // the specification example: 0x12 AND F2 OR 25 -> 0x17
        let request = [22, 0, 4, 0, 0xF2, 0, 0x25];
        assert_eq!(ask(&mut link, 1, &request), Some(request.to_vec()));
        assert_eq!(sim.registers(1, "holding", 4, 1).expect("regs"), [0x17]);
        // set bit 4 alone: AND !(1<<4), OR 1<<4
        let request = [22, 0, 4, 0xFF, 0xEF, 0, 0x10];
        ask(&mut link, 1, &request);
        assert_eq!(sim.registers(1, "holding", 4, 1).expect("regs"), [0x17]);
        let request = [22, 0, 4, 0xFF, 0xFD, 0, 0];
        ask(&mut link, 1, &request);
        assert_eq!(sim.registers(1, "holding", 4, 1).expect("regs"), [0x15]);
    }

    #[test]
    fn fc23_writes_then_reads() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        let reply = ask(&mut link, 1, &[23, 0, 40, 0, 2, 0, 41, 0, 1, 2, 0xAB, 0xCD]);
        assert_eq!(reply, Some(vec![23, 4, 0, 0, 0xAB, 0xCD]));
    }

    #[test]
    fn fc08_echo() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        assert_eq!(
            ask(&mut link, 1, &[8, 0, 0, 0xA5, 0x37]),
            Some(vec![8, 0, 0, 0xA5, 0x37])
        );
        assert_eq!(ask(&mut link, 1, &[8, 0, 1, 0, 0]), Some(vec![0x88, 1]));
    }

    #[test]
    fn holes_and_limits_answer_exceptions() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        // into a hole, past the table
        assert_eq!(
            ask(&mut link, 1, &[3, 0x01, 0xF0, 0, 20]),
            Some(vec![0x83, 2])
        );
        assert_eq!(
            ask(&mut link, 1, &[3, 0x01, 0xF0, 0, 16]),
            Some(vec![0x83, 2])
        );
        assert_eq!(
            ask(&mut link, 1, &[3, 0x01, 0xF0, 0, 4]).map(|r| r[0]),
            Some(3)
        );
        assert_eq!(
            ask(&mut link, 1, &[3, 0x01, 0xFE, 0, 4]).map(|r| r[0]),
            Some(3)
        );
        assert_eq!(
            ask(&mut link, 1, &[3, 0x03, 0xE7, 0, 2]),
            Some(vec![0x83, 2])
        );
        assert_eq!(
            ask(&mut link, 1, &[6, 0x01, 0xF4, 0, 1]),
            Some(vec![0x86, 2])
        );
        // over the register and bit limits, zero count
        assert_eq!(ask(&mut link, 1, &[3, 0, 0, 0, 126]), Some(vec![0x83, 3]));
        assert_eq!(
            ask(&mut link, 1, &[3, 0, 0, 0, 125]).map(|r| r.len()),
            Some(252)
        );
        assert_eq!(
            ask(&mut link, 1, &[1, 0, 0, 0x07, 0xD1]),
            Some(vec![0x81, 3])
        );
        assert_eq!(ask(&mut link, 1, &[4, 0, 0, 0, 0]), Some(vec![0x84, 3]));
        // an unknown function, an unsupported one
        assert_eq!(ask(&mut link, 1, &[0x41]), Some(vec![0xC1, 1]));
        assert_eq!(
            ask(&mut link, 2, &[22, 0, 0, 0, 0, 0, 0]),
            Some(vec![0x96, 1])
        );
        assert_eq!(ask(&mut link, 2, &[43, 14, 1, 0]), Some(vec![0xAB, 1]));
    }

    #[test]
    fn configured_max_registers_for_picky_devices() {
        let sim = ModbusSim::from_json(
            r#"{"max_registers": 10, "max_bits": 16, "units": [{"unit": 1}]}"#,
        )
        .expect("config");
        let mut link = sim.link(Framing::Mbap).expect("link");
        assert_eq!(ask(&mut link, 1, &[3, 0, 0, 0, 10]).map(|r| r[1]), Some(20));
        assert_eq!(ask(&mut link, 1, &[3, 0, 0, 0, 11]), Some(vec![0x83, 3]));
        assert_eq!(ask(&mut link, 1, &[1, 0, 0, 0, 17]), Some(vec![0x81, 3]));
    }

    #[test]
    fn unknown_unit_is_0b_over_mbap_and_silent_over_rtu() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        assert_eq!(ask(&mut link, 9, &[3, 0, 0, 0, 1]), Some(vec![0x83, 0x0B]));
        let mut link = sim.link(Framing::Rtu).expect("link");
        assert_eq!(ask_rtu(&mut link, 9, &[3, 0, 0, 0, 1]), None);
        assert_eq!(
            ask_rtu(&mut link, 2, &[3, 0, 0, 0, 1]),
            Some(vec![3, 2, 0, 0])
        );
    }

    #[test]
    fn rtu_bad_crc_request_gets_no_reply_and_bad_crc_fault_spoils_replies() {
        let sim = sim();
        let mut link = sim.link(Framing::Rtu).expect("link");
        let mut frame = rtu(1, &[3, 0, 0, 0, 1]);
        frame[7] ^= 1;
        link.write_all(&frame).expect("write");
        let mut buf = [0u8; 64];
        assert_eq!(
            link.read(&mut buf).map_err(|e| e.kind()),
            Err(io::ErrorKind::TimedOut)
        );
        sim.inject(ModbusFault::BadCrc(1));
        link.write_all(&rtu(1, &[3, 0, 0, 0, 1])).expect("write");
        let n = link.read(&mut buf).expect("reply");
        assert_ne!(crc16(&buf[..n - 2]).to_le_bytes(), [buf[n - 2], buf[n - 1]]);
        assert_eq!(
            ask_rtu(&mut link, 1, &[3, 0, 0, 0, 1]),
            Some(vec![3, 2, 0xE9, 0x79])
        );
    }

    #[test]
    fn rtu_broadcast_writes_every_unit_without_reply() {
        let sim = sim();
        let mut link = sim.link(Framing::Rtu).expect("link");
        assert_eq!(ask_rtu(&mut link, 0, &[6, 0, 5, 0, 42]), None);
        assert_eq!(sim.registers(1, "holding", 5, 1).expect("regs"), [42]);
        assert_eq!(sim.registers(2, "holding", 5, 1).expect("regs"), [42]);
    }

    #[test]
    fn rtu_frames_split_across_writes_and_unknown_functions() {
        let sim = sim();
        let mut link = sim.link(Framing::Rtu).expect("link");
        let frame = rtu(1, &[16, 0, 0, 0, 1, 2, 0, 9]);
        link.write_all(&frame[..4]).expect("write");
        assert_eq!(sim.requests(), 0);
        link.write_all(&frame[4..]).expect("write");
        let mut buf = [0u8; 64];
        assert_eq!(link.read(&mut buf).expect("reply"), 8);
        assert_eq!(sim.registers(1, "holding", 0, 1).expect("regs"), [9]);
        assert_eq!(ask_rtu(&mut link, 1, &[0x41, 1, 2]), Some(vec![0xC1, 1]));
    }

    #[test]
    fn device_identification_basic_regular_individual_and_paging() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        let mut basic = vec![43, 14, 1, 0x82, 0, 0, 3];
        for (id, text) in [(0u8, "ciplink"), (1, "SIM-MB"), (2, "1.0")] {
            basic.push(id);
            basic.push(text.len() as u8);
            basic.extend_from_slice(text.as_bytes());
        }
        assert_eq!(ask(&mut link, 1, &[43, 14, 1, 0]), Some(basic));
        let regular = ask(&mut link, 1, &[43, 14, 2, 0]).expect("reply");
        assert_eq!(regular[6], 5, "objects 0, 1, 2, 4, 5");
        assert_eq!(
            ask(&mut link, 1, &[43, 14, 4, 5]),
            Some([&[43u8, 14, 4, 0x82, 0, 0, 1, 5, 4][..], b"MB-1"].concat())
        );
        assert_eq!(ask(&mut link, 1, &[43, 14, 4, 6]), Some(vec![0xAB, 2]));
        assert_eq!(ask(&mut link, 1, &[43, 14, 5, 0]), Some(vec![0xAB, 3]));
        assert_eq!(ask(&mut link, 1, &[43, 13, 1, 0]), Some(vec![0xAB, 1]));

        let paged = CONFIG.replace(
            "\"model_name\": \"MB-1\"}",
            "\"model_name\": \"MB-1\"}, \"identity_page\": 2",
        );
        let sim = ModbusSim::from_json(&paged).expect("config");
        let mut link = sim.link(Framing::Mbap).expect("link");
        let first = ask(&mut link, 1, &[43, 14, 2, 0]).expect("reply");
        assert_eq!(&first[4..7], &[0xFF, 2, 2], "more follows from object 2");
        let second = ask(&mut link, 1, &[43, 14, 2, 2]).expect("reply");
        assert_eq!(&second[4..7], &[0xFF, 5, 2]);
        let last = ask(&mut link, 1, &[43, 14, 2, 5]).expect("reply");
        assert_eq!(&last[4..8], &[0, 0, 1, 5]);
    }

    #[test]
    fn faults_drop_delay_exception_no_reply_refuse_and_close() {
        let sim = sim();
        let mut link = sim.link(Framing::Mbap).expect("link");
        let mut buf = [0u8; 64];

        sim.inject(ModbusFault::DropReplies(1));
        assert_eq!(ask(&mut link, 1, &[3, 0, 0, 0, 1]), None);
        assert!(ask(&mut link, 1, &[3, 0, 0, 0, 1]).is_some());

        sim.inject(ModbusFault::Exception {
            unit: 1,
            function: Some(3),
            code: 6,
        });
        assert_eq!(ask(&mut link, 1, &[3, 0, 0, 0, 1]), Some(vec![0x83, 6]));
        assert_eq!(ask(&mut link, 1, &[4, 0, 0, 0, 1]).map(|r| r[0]), Some(4));
        sim.inject(ModbusFault::NoReply { unit: 2 });
        assert_eq!(ask(&mut link, 2, &[3, 0, 0, 0, 1]), None);
        sim.clear_faults();
        assert_eq!(ask(&mut link, 2, &[3, 0, 0, 0, 1]), Some(vec![3, 2, 0, 0]));

        sim.inject(ModbusFault::Delay(Duration::from_millis(50)));
        link.set_timeout(Some(Duration::from_millis(10)));
        link.write_all(&mbap(1, &[3, 0, 0, 0, 1])).expect("write");
        assert_eq!(
            link.read(&mut buf).map_err(|e| e.kind()),
            Err(io::ErrorKind::TimedOut)
        );
        // the late reply answers the next read
        assert!(link.read(&mut buf).is_ok());
        sim.clear_faults();

        sim.inject(ModbusFault::RefuseConnections);
        assert!(sim.link(Framing::Mbap).is_err());
        sim.clear_faults();

        sim.inject(ModbusFault::CloseConnections);
        link.write_all(&mbap(1, &[3, 0, 0, 0, 1])).expect("write");
        assert_eq!(link.read(&mut buf).expect("eof"), 0);
        assert!(link.write_all(&mbap(1, &[3, 0, 0, 0, 1])).is_err());
        let mut fresh = sim.link(Framing::Mbap).expect("link");
        assert!(ask(&mut fresh, 1, &[3, 0, 0, 0, 1]).is_some());
    }

    #[test]
    fn records_and_hooks_see_every_request() {
        let sim = sim();
        sim.record(true);
        sim.on_request(|data, index| {
            data.set_registers(1, "input", 0, &[index as u16])
                .expect("set");
        });
        let mut link = sim.link(Framing::Mbap).expect("link");
        assert_eq!(ask(&mut link, 1, &[4, 0, 0, 0, 1]), Some(vec![4, 2, 0, 0]));
        assert_eq!(ask(&mut link, 1, &[4, 0, 0, 0, 1]), Some(vec![4, 2, 0, 1]));
        assert_eq!(
            sim.take_received(),
            [mbap(1, &[4, 0, 0, 0, 1]), mbap(1, &[4, 0, 0, 0, 1])]
        );
        assert_eq!(sim.requests(), 2);
        sim.clear_hook();
    }

    #[test]
    fn bad_configs_are_errors() {
        for bad in [
            r#"{"kind": "logix", "units": []}"#,
            r#"{"units": [{"unit": 1}, {"unit": 1}]}"#,
            r#"{"units": [{"unit": 1, "holding": 70000}]}"#,
            r#"{"units": [{"unit": 1, "values": {"holding": {"x": [1]}}}]}"#,
            r#"{"units": [{"unit": 1, "holding": 2, "values": {"holding": {"1": [1, 2]}}}]}"#,
            r#"{"units": [{"unit": 1, "values": {"coil": {"0": [2]}}}]}"#,
            r#"{"units": [{"unit": 1, "holes": [{"area": "nope", "start": 0, "count": 1}]}]}"#,
            r#"{"units": [{"unit": 1, "colis": 5}]}"#,
        ] {
            assert!(ModbusSim::from_json(bad).is_err(), "{bad}");
        }
        assert!(sim().registers(1, "coil", 0, 1).is_err());
        assert!(sim().bits(3, "coil", 0, 1).is_err());
    }
}
