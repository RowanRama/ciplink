//! Controller-side trends: the controller samples a set of tags at a fixed period into a buffer, and the
//! driver uploads the samples in batches.
//!
//! This is the trend object (class 0xB2) Studio 5000 trends use, addressed directly on a connection of its
//! own. Each pen is a tag path and a mask: the controller samples the 32-bit word at the tag's address and
//! ANDs it with the mask, so a pen can be any tag or member of up to 32 bits (BOOL, SINT, INT, DINT, USINT,
//! UINT, UDINT, REAL), a bit of an integer or a BOOL array element. 64-bit types cannot be trended this way.
//! The controller deletes the trend of a connection that closes, so a trend never outlives its driver.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cip::{CipConnection, CipOptions, GenericMessage};
use crate::epath::{LogicalValue, tag_request_path};
use crate::logix::driver::LogixDriver;
use crate::logix::types::TypeRef;
use crate::packets::INSUFFICIENT_PACKETS;
use crate::reader::Reader;
use crate::types::Elementary;
use crate::{Error, Result, Value};

const CLASS: i64 = 0xB2;
const CREATE: u8 = 0x08;
const SET_ATTRIBUTES: u8 = 0x04;
const ADD_DRIVER: u8 = 0x4E;
const START: u8 = 0x06;
const UPLOAD: u8 = 0x4C;
const STOP: u8 = 0x07;
const REMOVE_DRIVER: u8 = 0x4F;
const DELETE: u8 = 0x09;
/// The one driver (pen group) of a trend.
const DRIVER_ID: u16 = 1;
/// The controller clock of the samples counts 128 µs ticks.
const TICK_US: u64 = 128;
/// Connection size of a trend connection; an upload reply carries at most this many bytes.
const CONNECTION_SIZE: u16 = 4000;
/// The longest the driver waits between uploads.
const MAX_POLL: Duration = Duration::from_millis(50);

/// Options of a [`Trend`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrendOptions {
    /// Sample period, in whole microseconds; controllers accept 1 ms or more. Default 10 ms.
    pub period: Duration,
    /// Samples kept until [`Trend::read`]; when full the oldest are dropped. Default 4096.
    pub capacity: usize,
    /// Stop sampling after this long; None runs until [`Trend::close`]. Default None.
    pub duration: Option<Duration>,
}

impl Default for TrendOptions {
    fn default() -> Self {
        TrendOptions {
            period: Duration::from_millis(10),
            capacity: 4096,
            duration: None,
        }
    }
}

/// One sample of every pen of a trend.
#[derive(Clone, Debug, PartialEq)]
pub struct TrendSample {
    /// Controller time of the sample, microseconds since 1970 UTC.
    pub timestamp_us: u64,
    /// Time since the trend started, microseconds.
    pub elapsed_us: u64,
    /// One value per pen, in pen order: `Bool` for a BOOL or a bit, else the variant of the pen's type.
    pub values: Vec<Value>,
}

/// A pen of a trend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrendPen {
    /// The tag as requested.
    pub tag: String,
    /// The type sampled: `BOOL` for a bit or a BOOL array element.
    pub data_type: &'static str,
}

/// How a pen's masked word becomes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Bool,
    SInt,
    Int,
    DInt,
    USInt,
    UInt,
    UDInt,
    Real,
}

impl Kind {
    fn of(elementary: Elementary) -> Option<Self> {
        Some(match elementary {
            Elementary::Bool => Kind::Bool,
            Elementary::SInt => Kind::SInt,
            Elementary::Int => Kind::Int,
            Elementary::DInt => Kind::DInt,
            Elementary::USInt => Kind::USInt,
            Elementary::UInt => Kind::UInt,
            Elementary::UDInt => Kind::UDInt,
            Elementary::Real => Kind::Real,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Bool => "BOOL",
            Kind::SInt => "SINT",
            Kind::Int => "INT",
            Kind::DInt => "DINT",
            Kind::USInt => "USINT",
            Kind::UInt => "UINT",
            Kind::UDInt => "UDINT",
            Kind::Real => "REAL",
        }
    }

    /// The mask of a value of this kind; a BOOL's is its bit.
    fn mask(self, bit: u32) -> u32 {
        match self {
            Kind::Bool => 1 << bit,
            Kind::SInt | Kind::USInt => 0xFF,
            Kind::Int | Kind::UInt => 0xFFFF,
            Kind::DInt | Kind::UDInt | Kind::Real => u32::MAX,
        }
    }

    fn value(self, word: u32) -> Value {
        match self {
            Kind::Bool => Value::Bool(word != 0),
            Kind::SInt => Value::SInt(word as u8 as i8),
            Kind::Int => Value::Int(word as u16 as i16),
            Kind::DInt => Value::DInt(word as i32),
            Kind::USInt => Value::USInt(word as u8),
            Kind::UInt => Value::UInt(word as u16),
            Kind::UDInt => Value::UDInt(word),
            Kind::Real => Value::Real(f32::from_bits(word)),
        }
    }
}

/// A resolved pen: its request path, mask and decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pen {
    path: Vec<u8>,
    mask: u32,
    kind: Kind,
}

/// The pen of `tag`, addressing `plc_tag` (the tag holding a bit), of type `data_type`, with `bit` the bit of
/// a BOOL member, BOOL tag, BOOL array element or integer bit.
fn pen(tag: &str, plc_tag: &str, data_type: &TypeRef, bit: Option<u32>) -> Result<Pen> {
    let fail = |why: &str| Error::request(format!("Cannot trend {tag}: {why}"));
    let elementary = match data_type {
        TypeRef::Atomic(Some(e)) => *e,
        _ => return Err(fail("only atomic tags and members can be trended")),
    };
    let kind = match (elementary, bit) {
        // a bit of an integer or a BOOL array word
        (_, Some(_)) => Kind::Bool,
        _ => Kind::of(elementary).ok_or_else(|| {
            fail(&format!(
                "{} is not a trendable type (BOOL, SINT, INT, DINT, USINT, UINT, UDINT or REAL)",
                elementary.name()
            ))
        })?,
    };
    let bit = bit.unwrap_or(0);
    if bit >= 32 {
        return Err(fail("the bit is outside the sampled word"));
    }
    Ok(Pen {
        path: tag_request_path(plc_tag, None, false)?,
        mask: kind.mask(bit),
        kind,
    })
}

// ------------------------------------------------------------------------------------------------ requests

/// Create: attribute 8 the controller buffer size (4096 bytes) and attribute 3 = 1, as Studio 5000 sends.
fn create_request() -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    out.extend(2u16.to_le_bytes());
    out.extend(8u16.to_le_bytes());
    out.extend(4096u32.to_le_bytes());
    out.extend(3u16.to_le_bytes());
    out.push(1);
    out
}

/// Set_Attribute_List: attribute 1 the sample period in µs, attribute 5 = 0.
fn period_request(period_us: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    out.extend(2u16.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(period_us.to_le_bytes());
    out.extend(5u16.to_le_bytes());
    out.push(0);
    out
}

/// Add Driver: the driver id, the sample multiplier (1, every period), the pen count, then each pen's
/// path and mask.
fn add_driver_request(pens: &[Pen]) -> Result<Vec<u8>> {
    let count =
        u8::try_from(pens.len()).map_err(|_| Error::request("A trend has at most 255 pens"))?;
    let mut out = Vec::with_capacity(4 + pens.iter().map(|p| p.path.len() + 4).sum::<usize>());
    out.extend(DRIVER_ID.to_le_bytes());
    out.push(1);
    out.push(count);
    for pen in pens {
        out.extend(&pen.path);
        out.extend(pen.mask.to_le_bytes());
    }
    Ok(out)
}

/// The bytes of one uploaded sample: driver id, elapsed ticks and a word per pen.
fn record_size(pens: usize) -> usize {
    6 + 4 * pens
}

/// Extends the controller's 32-bit tick counter across wraps (every 6.4 days).
#[derive(Debug, Default)]
struct Ticks {
    last: u32,
    high: u64,
}

impl Ticks {
    fn elapsed_us(&mut self, ticks: u32) -> u64 {
        if ticks < self.last {
            self.high += 1 << 32;
        }
        self.last = ticks;
        (self.high | u64::from(ticks)) * TICK_US
    }
}

/// Decodes the samples of an upload reply.
fn decode(data: &[u8], pens: &[Pen], start_us: u64, ticks: &mut Ticks) -> Result<Vec<TrendSample>> {
    let size = record_size(pens.len());
    if data.len() % size != 0 {
        return Err(Error::data(format!(
            "Trend upload of {} bytes is not a whole number of {size} byte samples",
            data.len()
        )));
    }
    let mut r = Reader::new(data);
    let mut out = Vec::with_capacity(data.len() / size);
    while !r.is_empty() {
        let driver = r.u16()?;
        if driver != DRIVER_ID {
            return Err(Error::data(format!(
                "Trend sample of unknown driver {driver}"
            )));
        }
        let elapsed_us = ticks.elapsed_us(r.u32()?);
        let mut values = Vec::with_capacity(pens.len());
        for pen in pens {
            values.push(pen.kind.value(r.u32()? & pen.mask));
        }
        out.push(TrendSample {
            timestamp_us: start_us.saturating_add(elapsed_us),
            elapsed_us,
            values,
        });
    }
    Ok(out)
}

/// How long to wait between uploads: long enough to batch, short enough that a batch stays under a quarter of
/// the connection size.
fn poll_interval(period: Duration, pens: usize) -> Duration {
    let per_poll = (usize::from(CONNECTION_SIZE) / 4 / record_size(pens)).max(1);
    (period * u32::try_from(per_poll).unwrap_or(u32::MAX)).min(MAX_POLL)
}

// ------------------------------------------------------------------------------------------------ session

/// The trend's connection and its instance in the controller.
struct Session {
    conn: CipConnection,
    instance: u32,
    added: bool,
    started: bool,
    pens: Vec<Pen>,
    start_us: u64,
    ticks: Ticks,
}

impl Session {
    /// Sends a service to the trend instance (0 for the class); returns the reply data and whether the
    /// controller has more (status 0x06).
    fn send(&mut self, service: u8, instance: u32, data: &[u8]) -> Result<(Vec<u8>, bool)> {
        // a lost connection is not reopened: a new one cannot address this connection's trend
        if instance != 0 && !self.conn.target_connected() {
            return Err(Error::comm("Trend connection was lost"));
        }
        let reply = self.conn.generic_message(&GenericMessage {
            service,
            class_code: LogicalValue::Int(CLASS),
            instance: LogicalValue::Int(instance.into()),
            request_data: data.to_vec(),
            name: "trend".into(),
            ..GenericMessage::default()
        })?;
        let more = reply.reply.service_status == Some(INSUFFICIENT_PACKETS);
        if let (Some(err), false) = (&reply.tag.error, more) {
            return Err(Error::response(format!(
                "Trend service {service:#04x} failed: {}",
                err.message
            )));
        }
        Ok((reply.reply.data.unwrap_or_default(), more))
    }

    /// Opens the connection and creates, configures and starts the trend.
    fn start(&mut self, period_us: u32) -> Result<()> {
        if !self.conn.open()? {
            return Err(Error::comm("Failed to open the trend connection"));
        }
        let (created, _) = self.send(CREATE, 0, &create_request())?;
        self.instance = Reader::new(&created).u32().unwrap_or(0);
        if self.instance == 0 {
            return Err(Error::response("Create Trend replied without an instance"));
        }
        self.send(SET_ATTRIBUTES, self.instance, &period_request(period_us))?;
        // marked before sending: a lost reply still removes the driver
        self.added = true;
        self.send(ADD_DRIVER, self.instance, &add_driver_request(&self.pens)?)?;
        self.started = true;
        let (started, _) = self.send(START, self.instance, &[])?;
        self.start_us = Reader::new(&started).u64().unwrap_or(0);
        Ok(())
    }

    fn upload(&mut self) -> Result<(Vec<TrendSample>, bool)> {
        let (data, more) = self.send(UPLOAD, self.instance, &[])?;
        let samples = decode(&data, &self.pens, self.start_us, &mut self.ticks)?;
        Ok((samples, more))
    }

    /// Stops and deletes the trend and closes the connection; tries every step, returns the first error.
    fn cleanup(&mut self) -> Result<()> {
        let mut first = Ok(());
        if self.instance != 0 {
            let mut steps = Vec::with_capacity(3);
            if self.started {
                steps.push((STOP, Vec::new()));
            }
            if self.added {
                steps.push((REMOVE_DRIVER, DRIVER_ID.to_le_bytes().to_vec()));
            }
            steps.push((DELETE, Vec::new()));
            for (service, data) in steps {
                if let (Err(err), Ok(())) = (self.send(service, self.instance, &data), &first) {
                    first = Err(err);
                }
            }
            self.instance = 0;
        }
        if let (Err(err), Ok(())) = (self.conn.close(), &first) {
            first = Err(err);
        }
        first
    }
}

// ------------------------------------------------------------------------------------------------ trend

#[derive(Debug, Default)]
struct State {
    stop: bool,
    running: bool,
    samples: VecDeque<TrendSample>,
    received: u64,
    dropped: u64,
    error: Option<Error>,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A running controller-side trend (see the [module docs](self)), from [`LogixDriver::trend`].
///
/// A worker thread uploads the samples on the trend's own connection; [`read`](Self::read) takes them.
/// Closing (or dropping) the trend stops it, deletes it in the controller and closes its connection.
#[derive(Debug)]
pub struct Trend {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    pens: Vec<TrendPen>,
    period: Duration,
    start_time_us: u64,
}

impl Trend {
    /// The pens, in the order of the sample values.
    pub fn pens(&self) -> &[TrendPen] {
        &self.pens
    }

    /// Sample period.
    pub fn period(&self) -> Duration {
        self.period
    }

    /// Controller time the trend started, microseconds since 1970 UTC.
    pub fn start_time_us(&self) -> u64 {
        self.start_time_us
    }

    /// True until the trend stops: closed, its duration over, or failed.
    pub fn running(&self) -> bool {
        self.shared.lock().running
    }

    /// Samples uploaded so far, including dropped ones.
    pub fn received(&self) -> u64 {
        self.shared.lock().received
    }

    /// Samples dropped because [`TrendOptions::capacity`] was full.
    pub fn dropped(&self) -> u64 {
        self.shared.lock().dropped
    }

    /// Why the trend failed, if it did.
    pub fn error(&self) -> Option<Error> {
        self.shared.lock().error.clone()
    }

    /// Takes the samples uploaded since the last read, oldest first. Once the trend failed and every sample
    /// was taken, returns its error.
    pub fn read(&self) -> Result<Vec<TrendSample>> {
        let mut state = self.shared.lock();
        match (&state.error, state.samples.is_empty()) {
            (Some(err), true) => Err(err.clone()),
            _ => Ok(state.samples.drain(..).collect()),
        }
    }

    /// Stops the trend and waits for its cleanup; the samples uploaded until then can still be read. Returns
    /// the trend's error, if it failed.
    pub fn close(&self) -> Result<()> {
        self.signal_stop();
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            // the worker catches nothing that can panic; a panic is reported as an error below
            if worker.join().is_err() {
                self.shared
                    .lock()
                    .error
                    .get_or_insert_with(|| Error::comm("Trend worker panicked"));
            }
        }
        self.error().map_or(Ok(()), Err)
    }

    fn signal_stop(&self) {
        self.shared.lock().stop = true;
        self.shared.wake.notify_all();
    }
}

impl Drop for Trend {
    /// Stops the trend without waiting: the worker cleans up in the background.
    fn drop(&mut self) {
        self.signal_stop();
    }
}

/// The worker: uploads until stopped or the deadline, then cleans up.
fn run(
    mut session: Session,
    shared: Arc<Shared>,
    capacity: usize,
    poll: Duration,
    deadline: Option<Instant>,
) {
    let result = (|| -> Result<()> {
        let mut more = false;
        loop {
            let stopping = {
                let mut state = shared.lock();
                if !more && !state.stop {
                    let wait = deadline.map_or(poll, |d| {
                        poll.min(d.saturating_duration_since(Instant::now()))
                    });
                    state = shared
                        .wake
                        .wait_timeout_while(state, wait, |s| !s.stop)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
                state.stop || deadline.is_some_and(|d| Instant::now() >= d)
            };
            let (samples, partial) = session.upload()?;
            more = partial;
            let mut state = shared.lock();
            state.received += samples.len() as u64;
            for sample in samples {
                if state.samples.len() == capacity {
                    state.samples.pop_front();
                    state.dropped += 1;
                }
                state.samples.push_back(sample);
            }
            // the last upload drains what the controller holds
            if stopping && !more {
                return Ok(());
            }
        }
    })();
    let cleaned = session.cleanup();
    let mut state = shared.lock();
    if let Some(err) = result.err().or(cleaned.err()) {
        state.error.get_or_insert(err);
    }
    state.running = false;
}

impl LogixDriver {
    /// Starts a controller-side trend of `tags` (see [`crate::logix::trend`]) on a connection of its own.
    ///
    /// The tags are resolved with this driver's tag definitions (loaded first if `lazy_tags`); each must be
    /// an atomic tag, member or array element of up to 32 bits, or a bit (`Tag.3`). The trend keeps running
    /// while this driver is used or closed.
    pub fn trend(&self, tags: &[&str], options: TrendOptions) -> Result<Trend> {
        if tags.is_empty() {
            return Err(Error::request("A trend needs at least one tag"));
        }
        if options.capacity == 0 {
            return Err(Error::request("Trend capacity must be at least one sample"));
        }
        let period_us = u32::try_from(options.period.as_micros())
            .ok()
            .filter(|&us| us > 0)
            .ok_or_else(|| Error::request("Trend period must be between 1 µs and 71 minutes"))?;
        let (conn, pens, infos) = {
            let mut state = self.lock();
            let mut pens = Vec::with_capacity(tags.len());
            let mut infos = Vec::with_capacity(tags.len());
            for tag in tags {
                let target = state.pen_target(tag)?;
                let pen = pen(tag, &target.plc_tag, &target.data_type, target.bit)?;
                infos.push(TrendPen {
                    tag: (*tag).to_owned(),
                    data_type: pen.kind.name(),
                });
                pens.push(pen);
            }
            let options = CipOptions {
                socket_timeout: state.conn.socket_timeout(),
                connection_size: CONNECTION_SIZE,
            };
            let conn = CipConnection::new(
                state.conn.path(),
                options,
                state.conn.share_connector(),
                true,
            )?;
            (conn, pens, infos)
        };
        let poll = poll_interval(options.period, pens.len());
        let mut session = Session {
            conn,
            instance: 0,
            added: false,
            started: false,
            pens,
            start_us: 0,
            ticks: Ticks::default(),
        };
        if let Err(err) = session.start(period_us) {
            // the setup error is the one to report; cleanup is best effort
            let _ = session.cleanup();
            return Err(err);
        }
        let start_time_us = session.start_us;
        let shared = Arc::new(Shared::default());
        shared.lock().running = true;
        let deadline = options.duration.map(|d| Instant::now() + d);
        let worker = {
            let shared = Arc::clone(&shared);
            let capacity = options.capacity;
            std::thread::Builder::new()
                .name("ciplink-trend".into())
                .spawn(move || run(session, shared, capacity, poll, deadline))
                .map_err(|e| Error::comm(format!("Failed to start the trend worker: {e}")))?
        };
        Ok(Trend {
            shared,
            worker: Mutex::new(Some(worker)),
            pens: infos,
            period: options.period,
            start_time_us,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    fn atomic(e: Elementary) -> TypeRef {
        TypeRef::Atomic(Some(e))
    }

    #[test]
    fn setup_requests_match_studio_5000() {
        // the request data Studio 5000 sends for a 10 ms trend
        assert_eq!(create_request(), hex("0200080000100000030001"));
        assert_eq!(period_request(10_000), hex("0200010010270000050000"));
    }

    #[test]
    fn add_driver_lists_paths_and_masks() -> Result<()> {
        let pens = [
            pen("Tmr.ACC", "Tmr.ACC", &atomic(Elementary::DInt), None)?,
            pen("Flag", "Flag", &atomic(Elementary::Bool), Some(0))?,
        ];
        let expected = [
            "01000102", // driver 1, every sample, 2 pens
            "06",
            "9103546d7200",
            "910341434300",
            "ffffffff", // Tmr.ACC, whole word
            "03",
            "9104466c6167",
            "01000000", // Flag, bit 0
        ];
        assert_eq!(add_driver_request(&pens)?, hex(&expected.concat()));
        Ok(())
    }

    #[test]
    fn masks_follow_the_type_and_bit() -> Result<()> {
        let mask = |e, bit| pen("t", "t", &atomic(e), bit).map(|p| (p.mask, p.kind));
        assert_eq!(mask(Elementary::SInt, None)?, (0xFF, Kind::SInt));
        assert_eq!(mask(Elementary::UInt, None)?, (0xFFFF, Kind::UInt));
        assert_eq!(mask(Elementary::Real, None)?, (u32::MAX, Kind::Real));
        // a BOOL member of a UDT or TIMER: its bit in the byte the member path addresses
        assert_eq!(mask(Elementary::Bool, Some(5))?, (0x20, Kind::Bool));
        // a bit of a DINT, or element 37 of a BOOL array (bit 5 of word 1)
        assert_eq!(mask(Elementary::DInt, Some(31))?, (0x8000_0000, Kind::Bool));
        assert_eq!(mask(Elementary::DWord, Some(5))?, (0x20, Kind::Bool));
        Ok(())
    }

    #[test]
    fn rejects_types_wider_than_the_sampled_word() {
        for e in [
            Elementary::LInt,
            Elementary::LReal,
            Elementary::ULInt,
            Elementary::DWord,
        ] {
            assert!(pen("t", "t", &atomic(e), None).is_err(), "{e:?}");
        }
        assert!(pen("t", "t", &TypeRef::Atomic(None), None).is_err());
    }

    #[test]
    fn decodes_samples_in_pen_order() -> Result<()> {
        let pens = [
            pen("s", "s", &atomic(Elementary::SInt), None)?,
            pen("i", "i", &atomic(Elementary::Int), None)?,
            pen("r", "r", &atomic(Elementary::Real), None)?,
            pen("b", "w", &atomic(Elementary::DInt), Some(3))?,
        ];
        let mut data = Vec::new();
        for (ticks, word) in [(78u32, 0u32), (156, 8)] {
            data.extend(1u16.to_le_bytes());
            data.extend(ticks.to_le_bytes());
            // the controller has applied the masks
            data.extend(0xFEu32.to_le_bytes());
            data.extend(0x8000u32.to_le_bytes());
            data.extend(45.0f32.to_bits().to_le_bytes());
            data.extend(word.to_le_bytes());
        }
        let samples = decode(&data, &pens, 1_000_000, &mut Ticks::default())?;
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].elapsed_us, 78 * 128);
        assert_eq!(samples[1].timestamp_us, 1_000_000 + 156 * 128);
        assert_eq!(
            samples[0].values,
            [
                Value::SInt(-2),
                Value::Int(i16::MIN),
                Value::Real(45.0),
                Value::Bool(false)
            ]
        );
        assert_eq!(samples[1].values[3], Value::Bool(true));
        Ok(())
    }

    #[test]
    fn decodes_a_captured_upload() -> Result<()> {
        // three samples of a 10 ms DINT and BOOL trend, both values 0
        let data = hex(&[
            "01009c0000000000000000000000",
            "0100ea0000000000000000000000",
            "0100380100000000000000000000",
        ]
        .concat());
        let pens = [
            pen("a", "a", &atomic(Elementary::DInt), None)?,
            pen("b", "b", &atomic(Elementary::Bool), Some(0))?,
        ];
        let samples = decode(&data, &pens, 0, &mut Ticks::default())?;
        let ticks: Vec<u64> = samples.iter().map(|s| s.elapsed_us / TICK_US).collect();
        assert_eq!(ticks, [156, 234, 312]);
        assert!(
            samples
                .iter()
                .all(|s| s.values == [Value::DInt(0), Value::Bool(false)])
        );
        Ok(())
    }

    #[test]
    fn rejects_partial_records_and_unknown_drivers() -> Result<()> {
        let pens = [pen("a", "a", &atomic(Elementary::DInt), None)?];
        assert!(decode(&[1, 0, 0], &pens, 0, &mut Ticks::default()).is_err());
        assert!(
            decode(
                &hex("02004e00000000000000"),
                &pens,
                0,
                &mut Ticks::default()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn elapsed_time_continues_across_tick_wraps() {
        let mut ticks = Ticks::default();
        assert_eq!(ticks.elapsed_us(u32::MAX), u64::from(u32::MAX) * TICK_US);
        assert_eq!(ticks.elapsed_us(1), ((1u64 << 32) + 1) * TICK_US);
    }

    #[test]
    fn polls_keep_batches_small() {
        assert_eq!(poll_interval(Duration::from_millis(10), 2), MAX_POLL);
        // 8 pens at 1 ms: 38 byte samples, 26 per quarter connection
        assert_eq!(
            poll_interval(Duration::from_millis(1), 8),
            Duration::from_millis(26)
        );
        assert_eq!(
            poll_interval(Duration::from_millis(1), 255),
            Duration::from_millis(1)
        );
    }
}
