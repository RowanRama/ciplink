//! The adapter's state: assemblies, class 1 connections and events. Pure, with the time passed in, so the
//! connection rules are tested without sockets; the threads in `server` drive it.

use super::wire::{self, ForwardOpen, Key, NetType, Seg, Triad};
use super::{AdapterConfig, AssemblyKind, ConnectionInfo, ConnectionKind, Event, Output, Stats};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// Events kept for the application at most; older ones are dropped.
const MAX_EVENTS: usize = 1024;
/// A production this late counts as late in [`Stats`].
const LATE: Duration = Duration::from_millis(1);

/// A refused request: general status and extended status words.
pub(crate) type Refusal = (u8, Vec<u16>);

fn refuse(extended: u16) -> Refusal {
    (0x01, vec![extended])
}

pub(crate) struct AssemblyState {
    pub instance: u32,
    pub kind: AssemblyKind,
    pub data: Vec<u8>,
    /// Outputs: the run/idle header's run bit.
    pub run: bool,
    /// Outputs: an `Output` event is waiting for the application to read the data.
    notified: bool,
}

/// A class 1 connection.
#[derive(Clone, Debug)]
pub(crate) struct IoConn {
    pub kind: ConnectionKind,
    pub triad: Triad,
    pub originator: Ipv4Addr,
    pub o_t_id: u32,
    pub t_o_id: u32,
    pub o_t_rpi: Duration,
    pub t_o_rpi: Duration,
    pub input: u32,
    pub input_size: usize,
    pub output: Option<u32>,
    pub output_size: usize,
    pub dest: SocketAddrV4,
    pub multicast: bool,
    /// The local address the connection arrived on: multicast leaves from it.
    pub local: Ipv4Addr,
    timeout: Duration,
    last_rx: Instant,
    last_sequence: Option<u32>,
    last_cip_sequence: Option<u16>,
    /// This connection sends the T->O stream (a multicast stream shared by several connections is sent once).
    produces: bool,
    sequence: u32,
    cip_sequence: u16,
    next_due: Instant,
}

impl IoConn {
    fn info(&self) -> ConnectionInfo {
        ConnectionInfo {
            kind: self.kind,
            originator: self.originator,
            o_t_rpi: self.o_t_rpi,
            t_o_rpi: self.t_o_rpi,
            input: self.input,
            input_size: self.input_size,
            output: self.output,
            output_size: self.output_size,
            multicast: self.multicast,
            o_t_id: self.o_t_id,
            t_o_id: self.t_o_id,
        }
    }
}

/// Where a Forward Open came from: the originator, the local address it arrived on and its subnet mask, the
/// T->O socket address item of the request if any, and the adapter's I/O port.
pub(crate) struct Origin {
    pub peer: Ipv4Addr,
    pub local: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub t_o_sockaddr: Option<SocketAddrV4>,
    pub io_port: u16,
}

/// A class 1 packet to send.
pub(crate) struct Packet {
    pub dest: SocketAddrV4,
    pub multicast: bool,
    pub local: Ipv4Addr,
    pub frame: Vec<u8>,
}

pub(crate) struct State {
    pub config: AdapterConfig,
    pub assemblies: Vec<AssemblyState>,
    pub conns: Vec<IoConn>,
    /// An I/O connection timed out and none opened since.
    pub faulted: bool,
    pub events: VecDeque<Event>,
    pub stats: Stats,
    /// The application's status text, shown on the browser's app line.
    pub detail: String,
    next_id: u32,
}

impl State {
    pub(crate) fn new(config: AdapterConfig, seed: u32) -> Self {
        let assemblies = config
            .assemblies
            .iter()
            .map(|a| AssemblyState {
                instance: a.instance,
                kind: a.kind,
                data: vec![0; a.size],
                run: false,
                notified: false,
            })
            .collect();
        State {
            config,
            assemblies,
            conns: Vec::new(),
            faulted: false,
            events: VecDeque::new(),
            stats: Stats::default(),
            detail: String::new(),
            next_id: seed | 1,
        }
    }

    pub(crate) fn assembly(&self, instance: u32) -> Option<&AssemblyState> {
        self.assemblies.iter().find(|a| a.instance == instance)
    }

    fn assembly_mut(&mut self, instance: u32) -> Option<&mut AssemblyState> {
        self.assemblies.iter_mut().find(|a| a.instance == instance)
    }

    fn assembly_of(&self, instance: u32, kind: AssemblyKind) -> Option<&AssemblyState> {
        self.assembly(instance).filter(|a| a.kind == kind)
    }

    fn push(&mut self, event: Event) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// Replaces an input assembly's data; shorter data leaves the rest zero.
    pub(crate) fn set_input(&mut self, instance: u32, data: &[u8]) -> Result<(), String> {
        let a = self
            .assembly_mut(instance)
            .filter(|a| a.kind == AssemblyKind::Input)
            .ok_or_else(|| format!("no input assembly {instance}"))?;
        if data.len() > a.data.len() {
            return Err(format!(
                "{} bytes do not fit input assembly {instance} of {} bytes",
                data.len(),
                a.data.len()
            ));
        }
        a.data[..data.len()].copy_from_slice(data);
        a.data[data.len()..].fill(0);
        Ok(())
    }

    /// An output assembly's data and run flag; reading it re-arms its `Output` event.
    pub(crate) fn output(&mut self, instance: u32) -> Option<Output> {
        let a = self
            .assembly_mut(instance)
            .filter(|a| a.kind == AssemblyKind::Output)?;
        a.notified = false;
        Some(Output {
            data: a.data.clone(),
            run: a.run,
        })
    }

    pub(crate) fn connections(&self) -> Vec<ConnectionInfo> {
        self.conns.iter().map(IoConn::info).collect()
    }

    /// The Identity Object status word: owned (bit 0) and the extended device status (bits 4-7).
    pub(crate) fn identity_status(&self) -> u16 {
        let owned = self
            .conns
            .iter()
            .any(|c| c.kind == ConnectionKind::ExclusiveOwner);
        let running = self.conns.iter().any(|c| {
            c.output
                .and_then(|o| self.assembly(o))
                .is_some_and(|a| a.run)
        });
        let extended: u16 = if self.faulted {
            2 // at least one faulted I/O connection
        } else if self.conns.is_empty() {
            3 // no I/O connections established
        } else if running {
            6 // at least one I/O connection in run mode
        } else {
            7 // I/O connections established, all idle
        };
        u16::from(owned) | extended << 4
    }

    /// Opens a class 1 connection: the reply data and the T->O socket address item for a multicast one.
    pub(crate) fn open(
        &mut self,
        fo: &ForwardOpen,
        origin: &Origin,
        now: Instant,
    ) -> Result<(Vec<u8>, Option<SocketAddrV4>), Refusal> {
        if fo.transport & 0x0F != 1 || fo.transport & 0x80 != 0 {
            return Err(refuse(0x0103)); // transport class and trigger not supported
        }
        let segs = wire::parse_path(&fo.path).ok_or_else(|| refuse(0x0315))?;
        let mut key = None;
        let mut class = None;
        let mut numbers = Vec::new(); // config instance, then the O->T and T->O connection points
        let mut config_data = Vec::new();
        for seg in segs {
            match seg {
                Seg::Key(k) => key = Some(k),
                Seg::Class(c) => class = Some(c),
                Seg::Instance(n) | Seg::Point(n) => numbers.push(n),
                Seg::Data(d) => config_data = d,
                Seg::Port { .. } | Seg::Attribute(_) => return Err(refuse(0x0315)),
            }
        }
        if let Some(key) = key {
            self.check_key(&key)?;
        }
        let (config, o_t_point, t_o_point) = match (class, numbers.as_slice()) {
            (Some(4), [config, o_t, t_o]) => (Some(*config), *o_t, *t_o),
            (Some(4), [o_t, t_o]) => (None, *o_t, *t_o),
            _ => return Err(refuse(0x0117)), // invalid application path
        };
        let kind = if o_t_point == self.config.input_only_heartbeat {
            ConnectionKind::InputOnly
        } else if o_t_point == self.config.listen_only_heartbeat {
            ConnectionKind::ListenOnly
        } else if self.assembly_of(o_t_point, AssemblyKind::Output).is_some() {
            ConnectionKind::ExclusiveOwner
        } else {
            return Err(refuse(0x0117));
        };
        let input_size = self
            .assembly_of(t_o_point, AssemblyKind::Input)
            .ok_or_else(|| refuse(0x0117))?
            .data
            .len();
        if !config_data.is_empty() {
            let size = config
                .and_then(|c| self.assembly_of(c, AssemblyKind::Config))
                .map(|a| a.data.len())
                .ok_or_else(|| refuse(0x0118))?; // configuration data without a configuration assembly
            if size != config_data.len() {
                return Err((0x01, vec![0x0109, size as u16]));
            }
        }
        let (min, max) = (self.config.rpi_min, self.config.rpi_max);
        let rpi_ok = |us: u32| (min..=max).contains(&Duration::from_micros(u64::from(us)));
        if !rpi_ok(fo.o_t_rpi) || !rpi_ok(fo.t_o_rpi) {
            return Err(refuse(0x0111));
        }
        if fo.o_t.net != NetType::PointToPoint
            || !matches!(fo.t_o.net, NetType::PointToPoint | NetType::Multicast)
        {
            return Err(refuse(0x0108)); // invalid network connection parameter
        }
        let multicast = fo.t_o.net == NetType::Multicast;
        let size_ok = |p: &wire::NetParams, expected: usize| {
            p.size == expected || (p.variable && p.size <= expected)
        };
        let output_size = match kind {
            ConnectionKind::ExclusiveOwner => self.assembly(o_t_point).map_or(0, |a| a.data.len()),
            _ => 0,
        };
        match kind {
            ConnectionKind::ExclusiveOwner => {
                if !size_ok(&fo.o_t, output_size + 6) {
                    return Err((0x01, vec![0x0109, (output_size + 6) as u16]));
                }
            }
            // a heartbeat: nothing, the sequence count, or that and a run/idle header
            _ if ![0, 2, 6].contains(&fo.o_t.size) => return Err((0x01, vec![0x0109, 2])),
            _ => {}
        }
        if !size_ok(&fo.t_o, input_size + 2) {
            return Err((0x01, vec![0x0109, (input_size + 2) as u16]));
        }
        if self.conns.iter().any(|c| c.triad == fo.triad()) {
            return Err(refuse(0x0100)); // connection in use
        }
        if kind == ConnectionKind::ExclusiveOwner
            && self.conns.iter().any(|c| c.output == Some(o_t_point))
        {
            return Err(refuse(0x0106)); // ownership conflict
        }
        let t_o_rpi = Duration::from_micros(u64::from(fo.t_o_rpi));
        // a multicast stream of the same input at the same interval is shared; a listen-only connection only
        // joins one that a connection other than listen-only opened
        let stream = self
            .conns
            .iter()
            .find(|c| {
                c.multicast
                    && c.input == t_o_point
                    && c.kind != ConnectionKind::ListenOnly
                    && (kind == ConnectionKind::ListenOnly || c.t_o_rpi == t_o_rpi)
            })
            .filter(|_| multicast)
            .cloned();
        if kind == ConnectionKind::ListenOnly && stream.is_none() {
            return Err(refuse(if multicast { 0x0119 } else { 0x0108 }));
        }
        let o_t_id = self.new_id();
        let (t_o_id, dest, t_o_rpi) = match &stream {
            Some(s) => (s.t_o_id, s.dest, s.t_o_rpi),
            None if multicast => {
                let group = wire::multicast_address(origin.local, origin.mask);
                (
                    self.new_id(),
                    SocketAddrV4::new(group, origin.io_port),
                    t_o_rpi,
                )
            }
            None => {
                let dest = match origin.t_o_sockaddr {
                    Some(a) if !a.ip().is_unspecified() => a,
                    Some(a) => SocketAddrV4::new(origin.peer, a.port()),
                    None => SocketAddrV4::new(origin.peer, origin.io_port),
                };
                (fo.t_o_id, dest, t_o_rpi)
            }
        };
        let conn = IoConn {
            kind,
            triad: fo.triad(),
            originator: origin.peer,
            o_t_id,
            t_o_id,
            o_t_rpi: Duration::from_micros(u64::from(fo.o_t_rpi)),
            t_o_rpi,
            input: t_o_point,
            input_size,
            output: (kind == ConnectionKind::ExclusiveOwner).then_some(o_t_point),
            output_size,
            dest,
            multicast,
            local: origin.local,
            timeout: Duration::from_micros(fo.timeout_us()),
            last_rx: now,
            last_sequence: None,
            last_cip_sequence: None,
            produces: stream.is_none(),
            sequence: 0,
            cip_sequence: 0,
            next_due: now,
        };
        let reply = fo.reply(o_t_id, t_o_id, fo.o_t_rpi, t_o_rpi.as_micros() as u32);
        self.faulted = false;
        self.push(Event::Opened(conn.info()));
        self.conns.push(conn);
        if let (Some(instance), false) = (config, config_data.is_empty()) {
            if let Some(a) = self.assembly_mut(instance) {
                a.data.clone_from(&config_data);
            }
            self.push(Event::Config {
                instance,
                data: config_data,
            });
        }
        Ok((reply, multicast.then_some(dest)))
    }

    fn check_key(&self, key: &Key) -> Result<(), Refusal> {
        let id = &self.config.identity;
        if (key.vendor != 0 && key.vendor != id.vendor_id)
            || (key.product_code != 0 && key.product_code != id.product_code)
        {
            return Err(refuse(0x0114));
        }
        if key.device_type != 0 && key.device_type != id.device_type {
            return Err(refuse(0x0115));
        }
        let (major, minor) = (key.major & 0x7F, key.minor);
        let compatible = key.major & 0x80 != 0;
        let (our_major, our_minor) = id.revision;
        let ok = major == 0
            || (major == our_major
                && (minor == 0 || minor == our_minor || (compatible && minor <= our_minor)));
        if ok { Ok(()) } else { Err(refuse(0x0116)) }
    }

    /// Closes the class 1 connection of a Forward Close; false if there is none.
    pub(crate) fn close(&mut self, triad: Triad) -> bool {
        match self.conns.iter().position(|c| c.triad == triad) {
            Some(index) => {
                let conn = self.remove(index);
                self.push(Event::Closed(conn));
                true
            }
            None => false,
        }
    }

    /// Removes a connection: another connection on its multicast stream takes over sending it, its listen-only
    /// connections close when it was the last other one, its output goes idle.
    fn remove(&mut self, index: usize) -> ConnectionInfo {
        let conn = self.conns.remove(index);
        if conn.produces
            && let Some(next) = self
                .conns
                .iter_mut()
                .find(|c| c.multicast && c.t_o_id == conn.t_o_id)
        {
            next.produces = true;
            next.sequence = conn.sequence;
            next.cip_sequence = conn.cip_sequence;
            next.next_due = conn.next_due;
        }
        if conn.multicast
            && conn.kind != ConnectionKind::ListenOnly
            && !self.conns.iter().any(|c| {
                c.t_o_id == conn.t_o_id && c.multicast && c.kind != ConnectionKind::ListenOnly
            })
        {
            while let Some(i) = self
                .conns
                .iter()
                .position(|c| c.t_o_id == conn.t_o_id && c.multicast)
            {
                let listener = self.conns.remove(i);
                self.push(Event::Closed(listener.info()));
            }
        }
        if let Some(a) = conn.output.and_then(|o| self.assembly_mut(o)) {
            a.run = false;
        }
        conn.info()
    }

    /// Takes a received class 1 frame from `from`.
    pub(crate) fn receive(&mut self, frame: &[u8], from: SocketAddrV4, now: Instant) {
        let Some(io) = wire::decode_io(frame) else {
            return;
        };
        let Some(conn) = self
            .conns
            .iter_mut()
            .find(|c| c.o_t_id == io.connection && c.originator == *from.ip())
        else {
            return;
        };
        // a frame not newer than the last one is a duplicate or arrived out of order
        if conn
            .last_sequence
            .is_some_and(|last| io.sequence.wrapping_sub(last) as i32 <= 0)
        {
            return;
        }
        conn.last_sequence = Some(io.sequence);
        conn.last_rx = now;
        let Some(output) = conn.output else {
            return; // a heartbeat
        };
        let Some(cip_sequence) = wire::u16_at(io.payload, 0) else {
            return;
        };
        if conn.last_cip_sequence == Some(cip_sequence) {
            return; // the same data again
        }
        conn.last_cip_sequence = Some(cip_sequence);
        let Some(header) = wire::u32_at(io.payload, 2) else {
            return;
        };
        let data = &io.payload[6..];
        let Some(a) = self.assembly_mut(output) else {
            return;
        };
        if data.len() != a.data.len() {
            return;
        }
        let run = header & 1 == 1;
        if a.data != data || a.run != run {
            a.data.copy_from_slice(data);
            a.run = run;
            if !a.notified {
                a.notified = true;
                self.push(Event::Output { instance: output });
            }
        }
    }

    /// The T->O packets due by `now`.
    pub(crate) fn produce(&mut self, now: Instant) -> Vec<Packet> {
        let mut packets = Vec::new();
        for i in 0..self.conns.len() {
            let conn = &self.conns[i];
            if !conn.produces || conn.next_due > now {
                continue;
            }
            let late = now - conn.next_due;
            let data = self
                .assembly(conn.input)
                .map(|a| a.data.clone())
                .unwrap_or_default();
            let conn = &mut self.conns[i];
            conn.sequence = conn.sequence.wrapping_add(1);
            conn.cip_sequence = conn.cip_sequence.wrapping_add(1);
            packets.push(Packet {
                dest: conn.dest,
                multicast: conn.multicast,
                local: conn.local,
                frame: wire::encode_io(conn.t_o_id, conn.sequence, conn.cip_sequence, &data),
            });
            conn.next_due += conn.t_o_rpi;
            if conn.next_due <= now {
                conn.next_due = now + conn.t_o_rpi; // fell a whole interval behind: skip, do not burst
            }
            self.stats.produced += 1;
            if late >= LATE {
                self.stats.late += 1;
            }
            self.stats.max_late = self.stats.max_late.max(late);
        }
        packets
    }

    /// Closes the connections whose originator went quiet for their timeout.
    pub(crate) fn expire(&mut self, now: Instant) {
        while let Some(index) = self
            .conns
            .iter()
            .position(|c| now.saturating_duration_since(c.last_rx) > c.timeout)
        {
            let conn = self.remove(index);
            self.faulted = true;
            self.push(Event::TimedOut(conn));
        }
    }

    /// When the next production or timeout is due, None without connections.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.conns
            .iter()
            .flat_map(|c| {
                [
                    c.produces.then_some(c.next_due),
                    Some(c.last_rx + c.timeout),
                ]
            })
            .flatten()
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::wire::tests::logix_forward_open;
    use crate::adapter::{AdapterIdentity, Assembly};

    fn config() -> AdapterConfig {
        AdapterConfig {
            identity: AdapterIdentity {
                vendor_id: 1234,
                device_type: 0x2B,
                product_code: 7,
                revision: (1, 3),
                serial: 0x1122_3344,
                product_name: "Station".into(),
            },
            assemblies: vec![
                Assembly::input(100, 256),
                Assembly::output(150, 32),
                Assembly::config(151, 0),
                Assembly::config(152, 4),
            ],
            input_only_heartbeat: 198,
            listen_only_heartbeat: 199,
            ..AdapterConfig::default()
        }
    }

    fn origin() -> Origin {
        Origin {
            peer: Ipv4Addr::new(192, 0, 2, 5),
            local: Ipv4Addr::new(192, 0, 2, 10),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            t_o_sockaddr: None,
            io_port: 2222,
        }
    }

    fn fo() -> ForwardOpen {
        ForwardOpen::decode(&logix_forward_open(), false).expect("decode")
    }

    /// A Forward Open of `kind` with serial `serial`, T->O multicast or not, at `rpi` µs.
    fn fo_of(kind: ConnectionKind, serial: u16, multicast: bool, rpi: u32) -> ForwardOpen {
        let mut fo = fo();
        fo.serial = serial;
        fo.t_o_rpi = rpi;
        fo.o_t_rpi = rpi;
        fo.t_o.net = if multicast {
            NetType::Multicast
        } else {
            NetType::PointToPoint
        };
        let point = match kind {
            ConnectionKind::ExclusiveOwner => 0x96,
            ConnectionKind::InputOnly => 198,
            ConnectionKind::ListenOnly => 199,
        };
        if kind != ConnectionKind::ExclusiveOwner {
            fo.o_t.size = 2;
        }
        fo.path = vec![0x20, 0x04, 0x24, 0x97, 0x2C, point, 0x2C, 0x64];
        fo
    }

    fn opened(state: &mut State, fo: &ForwardOpen, now: Instant) -> (u32, u32) {
        let (reply, _) = state.open(fo, &origin(), now).expect("open");
        (
            wire::u32_at(&reply, 0).expect("o_t"),
            wire::u32_at(&reply, 4).expect("t_o"),
        )
    }

    fn refusal(state: &mut State, fo: &ForwardOpen) -> Vec<u16> {
        state
            .open(fo, &origin(), Instant::now())
            .expect_err("refused")
            .1
    }

    #[test]
    fn exclusive_owner_opens_with_a_multicast_stream() {
        let mut state = State::new(config(), 0x100);
        let now = Instant::now();
        let (reply, sockaddr) = state.open(&fo(), &origin(), now).expect("open");
        assert_eq!(reply.len(), 26);
        assert_eq!(reply[8..16], fo().refusal()[..8]); // the connection triad
        assert_eq!(wire::u32_at(&reply, 16), Some(20_000)); // O->T API
        assert_eq!(wire::u32_at(&reply, 20), Some(20_000)); // T->O API
        let group = SocketAddrV4::new(Ipv4Addr::new(239, 192, 2, 32), 2222);
        assert_eq!(sockaddr, Some(group));
        let conn = &state.conns[0];
        assert_eq!(conn.kind, ConnectionKind::ExclusiveOwner);
        assert_eq!((conn.output, conn.input), (Some(150), 100));
        assert_eq!(conn.timeout, Duration::from_millis(320));
        assert!(matches!(state.events.pop_front(), Some(Event::Opened(_))));
        assert_eq!(state.identity_status(), 0x71); // owned, established and idle
    }

    #[test]
    fn point_to_point_sends_to_the_originator_or_its_socket_address() {
        let mut state = State::new(config(), 0x100);
        let fo = fo_of(ConnectionKind::ExclusiveOwner, 1, false, 10_000);
        let (_, t_o) = opened(&mut state, &fo, Instant::now());
        assert_eq!(t_o, fo.t_o_id); // the originator chooses a point-to-point T->O id
        assert_eq!(state.conns[0].dest, "192.0.2.5:2222".parse().expect("addr"));
        let mut state = State::new(config(), 0x100);
        let origin = Origin {
            t_o_sockaddr: Some("0.0.0.0:3000".parse().expect("addr")),
            ..origin()
        };
        state.open(&fo, &origin, Instant::now()).expect("open");
        assert_eq!(state.conns[0].dest, "192.0.2.5:3000".parse().expect("addr"));
    }

    #[test]
    fn refusals_carry_the_extended_status_studio_5000_shows() {
        let mut state = State::new(config(), 0x100);
        let mut bad = fo();
        bad.o_t.size = 30;
        assert_eq!(refusal(&mut state, &bad), [0x0109, 38]);
        let mut bad = fo();
        bad.t_o.size = 100;
        assert_eq!(refusal(&mut state, &bad), [0x0109, 258]);
        let mut bad = fo();
        bad.t_o_rpi = 500;
        assert_eq!(refusal(&mut state, &bad), [0x0111]);
        let mut bad = fo();
        bad.path = vec![0x20, 0x04, 0x24, 0x97, 0x2C, 0x99, 0x2C, 0x64];
        assert_eq!(refusal(&mut state, &bad), [0x0117]);
        bad.path = vec![0x20, 0x04, 0x24, 0x97, 0x2C, 0x96, 0x2C, 0x96];
        assert_eq!(refusal(&mut state, &bad), [0x0117]);
        let mut bad = fo();
        bad.transport = 0x83;
        assert_eq!(refusal(&mut state, &bad), [0x0103]);
        let mut bad = fo();
        bad.o_t.net = NetType::Multicast;
        assert_eq!(refusal(&mut state, &bad), [0x0108]);
        assert!(state.conns.is_empty());
    }

    #[test]
    fn a_second_owner_is_an_ownership_conflict_and_a_repeat_is_in_use() {
        let mut state = State::new(config(), 0x100);
        opened(&mut state, &fo(), Instant::now());
        assert_eq!(refusal(&mut state, &fo()), [0x0100]);
        let mut other = fo();
        other.originator_serial = 99;
        assert_eq!(refusal(&mut state, &other), [0x0106]);
    }

    #[test]
    fn electronic_keys_are_checked() {
        let mut state = State::new(config(), 0x100);
        let with_key = |vendor: u16, device_type: u16, code: u16, major: u8, minor: u8| {
            let mut fo = fo();
            let mut path = vec![0x34, 0x04];
            for v in [vendor, device_type, code] {
                path.extend(v.to_le_bytes());
            }
            path.extend([major, minor]);
            path.extend(&fo.path);
            fo.path = path;
            fo
        };
        assert_eq!(refusal(&mut state, &with_key(1, 0x2B, 7, 1, 3)), [0x0114]);
        assert_eq!(
            refusal(&mut state, &with_key(1234, 0x2B, 8, 1, 3)),
            [0x0114]
        );
        assert_eq!(
            refusal(&mut state, &with_key(1234, 0x0C, 7, 1, 3)),
            [0x0115]
        );
        assert_eq!(
            refusal(&mut state, &with_key(1234, 0x2B, 7, 2, 1)),
            [0x0116]
        );
        assert_eq!(
            refusal(&mut state, &with_key(1234, 0x2B, 7, 1, 2)),
            [0x0116]
        );
        // compatible: same major, our minor at least the key's
        let fo = with_key(1234, 0x2B, 7, 0x81, 2);
        state
            .open(&fo, &origin(), Instant::now())
            .expect("compatible");
        assert!(state.close(fo.triad()));
        state
            .open(&with_key(0, 0, 0, 0, 0), &origin(), Instant::now())
            .expect("no key values");
    }

    #[test]
    fn config_data_reaches_the_application() {
        let mut state = State::new(config(), 0x100);
        let mut fo = fo();
        fo.path = vec![
            0x20, 0x04, 0x24, 152, 0x2C, 0x96, 0x2C, 0x64, 0x80, 2, 1, 2, 3, 4,
        ];
        opened(&mut state, &fo, Instant::now());
        assert_eq!(state.assembly(152).expect("config").data, [1, 2, 3, 4]);
        assert!(matches!(
            state.events.back(),
            Some(Event::Config { instance: 152, data }) if data == &[1, 2, 3, 4]
        ));
        let mut state = State::new(config(), 0x100);
        fo.path = vec![0x20, 0x04, 0x24, 152, 0x2C, 0x96, 0x2C, 0x64, 0x80, 1, 1, 2];
        assert_eq!(refusal(&mut state, &fo), [0x0109, 4]);
        fo.path = vec![0x20, 0x04, 0x24, 1, 0x2C, 0x96, 0x2C, 0x64, 0x80, 1, 1, 2];
        assert_eq!(refusal(&mut state, &fo), [0x0118]);
        // a Generic Ethernet Module's config instance 1 with no data is accepted
        fo.path = vec![0x20, 0x04, 0x24, 1, 0x2C, 0x96, 0x2C, 0x64];
        opened(&mut state, &fo, Instant::now());
    }

    #[test]
    fn input_only_and_listen_only_share_the_owners_multicast_stream() {
        let mut state = State::new(config(), 0x100);
        let now = Instant::now();
        assert_eq!(
            refusal(
                &mut state,
                &fo_of(ConnectionKind::ListenOnly, 3, true, 20_000)
            ),
            [0x0119]
        );
        let (_, owner) = opened(
            &mut state,
            &fo_of(ConnectionKind::ExclusiveOwner, 1, true, 20_000),
            now,
        );
        let (_, input_only) = opened(
            &mut state,
            &fo_of(ConnectionKind::InputOnly, 2, true, 20_000),
            now,
        );
        let (_, listener) = opened(
            &mut state,
            &fo_of(ConnectionKind::ListenOnly, 3, true, 50_000),
            now,
        );
        assert_eq!((input_only, listener), (owner, owner));
        let (_, other) = opened(
            &mut state,
            &fo_of(ConnectionKind::InputOnly, 4, true, 10_000),
            now,
        );
        assert_ne!(other, owner); // another interval is another stream
        assert_eq!(state.conns[2].t_o_rpi, Duration::from_millis(20)); // the listener gets the stream's
        assert_eq!(state.produce(now).len(), 2);
        // the owner closes: the input-only connection takes the stream over, the listener stays
        assert!(state.close((1, 1, 0x00C0_FFEE)));
        assert_eq!(state.conns.len(), 3);
        assert_eq!(state.produce(now + Duration::from_millis(20)).len(), 2);
        // the last connection other than listen-only closes: the listener closes too
        state.events.clear();
        assert!(state.close((2, 1, 0x00C0_FFEE)));
        assert_eq!(state.conns.len(), 1);
        assert_eq!(state.events.len(), 2);
    }

    #[test]
    fn production_runs_at_the_rpi_and_skips_rather_than_bursts() {
        let mut state = State::new(config(), 0x100);
        let start = Instant::now();
        let (_, t_o) = opened(&mut state, &fo(), start);
        state.set_input(100, &[9, 8, 7]).expect("input");
        let packets = state.produce(start);
        assert_eq!(packets.len(), 1);
        let io = wire::decode_io(&packets[0].frame).expect("frame");
        assert_eq!((io.connection, io.sequence), (t_o, 1));
        assert_eq!(&io.payload[..5], [1, 0, 9, 8, 7]);
        assert_eq!(io.payload.len(), 258);
        assert!(state.produce(start + Duration::from_millis(19)).is_empty());
        assert_eq!(state.produce(start + Duration::from_millis(20)).len(), 1);
        // 100 ms late: one packet, then the next one interval later
        let late = start + Duration::from_millis(140);
        assert_eq!(state.produce(late).len(), 1);
        assert!(state.produce(late + Duration::from_millis(19)).is_empty());
        assert_eq!(state.stats.produced, 3);
        assert_eq!(state.stats.late, 1);
        assert_eq!(
            state.next_deadline(),
            Some(late + Duration::from_millis(20))
        );
    }

    #[test]
    fn outputs_update_on_new_data_and_drop_duplicates() {
        let mut state = State::new(config(), 0x100);
        let now = Instant::now();
        let (o_t, _) = opened(&mut state, &fo(), now);
        state.events.clear();
        let from: SocketAddrV4 = "192.0.2.5:2222".parse().expect("addr");
        let frame = |seq: u32, cip: u16, run: u32, byte: u8| {
            let mut data = run.to_le_bytes().to_vec();
            data.extend([byte; 32]);
            wire::encode_io(o_t, seq, cip, &data)
        };
        state.receive(&frame(1, 1, 1, 5), from, now);
        state.receive(&frame(2, 2, 1, 6), from, now);
        assert_eq!(state.events.len(), 1); // coalesced until the application reads
        let out = state.output(150).expect("output");
        assert_eq!((out.data[0], out.run), (6, true));
        state.receive(&frame(2, 3, 1, 7), from, now); // a repeated sequence number
        state.receive(&frame(1, 3, 1, 7), from, now); // an old one
        assert_eq!(state.output(150).expect("output").data[0], 6);
        state.receive(&frame(3, 3, 0, 6), from, now); // idle
        assert!(!state.output(150).expect("output").run);
        assert_eq!(state.events.len(), 2);
        // wrong sender, wrong size: ignored
        state.receive(
            &frame(4, 4, 1, 9),
            "192.0.2.6:2222".parse().expect("addr"),
            now,
        );
        state.receive(&wire::encode_io(o_t, 5, 5, &[1; 10]), from, now);
        assert_eq!(state.output(150).expect("output").data[0], 6);
    }

    #[test]
    fn a_quiet_originator_times_out_and_faults_the_status() {
        let mut state = State::new(config(), 0x100);
        let now = Instant::now();
        let (o_t, _) = opened(&mut state, &fo(), now);
        let from: SocketAddrV4 = "192.0.2.5:2222".parse().expect("addr");
        let mut data = 1u32.to_le_bytes().to_vec();
        data.extend([0; 32]);
        state.receive(
            &wire::encode_io(o_t, 1, 1, &data),
            from,
            now + Duration::from_millis(300),
        );
        state.expire(now + Duration::from_millis(400));
        assert_eq!(state.conns.len(), 1); // the packet reset the watchdog
        state.expire(now + Duration::from_millis(621));
        assert!(state.conns.is_empty());
        assert!(matches!(state.events.back(), Some(Event::TimedOut(_))));
        assert!(!state.output(150).expect("output").run);
        assert_eq!(state.identity_status(), 0x20);
        opened(&mut state, &fo(), now);
        assert_eq!(state.identity_status() >> 4, 7);
    }

    #[test]
    fn every_input_and_output_pair_of_the_station_layout_opens() {
        let inputs = [(100u8, 148usize), (101, 276), (102, 500)];
        let outputs = [(150u8, 32usize), (151, 64), (152, 128)];
        let mut assemblies: Vec<Assembly> = inputs
            .iter()
            .map(|&(i, size)| Assembly::input(u32::from(i), size))
            .collect();
        assemblies.extend(
            outputs
                .iter()
                .map(|&(o, size)| Assembly::output(u32::from(o), size)),
        );
        assemblies.push(Assembly::config(199, 0));
        let config = AdapterConfig {
            assemblies,
            ..AdapterConfig::default()
        };
        config.validate().expect("valid");
        let mut state = State::new(config, 1);
        let now = Instant::now();
        let mut serial = 0;
        for &(input, input_size) in &inputs {
            for &(output, output_size) in &outputs {
                serial += 1;
                let mut fo = fo();
                fo.serial = serial;
                fo.o_t.size = output_size + 6;
                fo.t_o.size = input_size + 2; // 502 at most: a standard Forward Open carries it
                fo.path = vec![0x20, 0x04, 0x24, 199, 0x2C, output, 0x2C, input];
                state.open(&fo, &origin(), now).expect("open");
                let info = state.connections().pop().expect("connection");
                assert_eq!(
                    (info.input, info.input_size, info.output, info.output_size),
                    (
                        u32::from(input),
                        input_size,
                        Some(u32::from(output)),
                        output_size
                    )
                );
                assert!(matches!(state.events.back(), Some(Event::Opened(i)) if *i == info));
                assert!(state.close(fo.triad()));
            }
            // input only on the default heartbeat
            serial += 1;
            let mut fo = fo();
            fo.serial = serial;
            fo.o_t.size = 2;
            fo.t_o.size = input_size + 2;
            fo.path = vec![0x20, 0x04, 0x24, 199, 0x2C, 238, 0x2C, input];
            state.open(&fo, &origin(), now).expect("input only");
            let info = state.connections().pop().expect("connection");
            assert_eq!(
                (info.kind, info.output, info.output_size),
                (ConnectionKind::InputOnly, None, 0)
            );
            assert!(state.close(fo.triad()));
        }
    }

    #[test]
    fn inputs_must_fit_their_assembly() {
        let mut state = State::new(config(), 0x100);
        assert!(state.set_input(100, &[0; 257]).is_err());
        assert!(state.set_input(150, &[0; 4]).is_err());
        state.set_input(100, &[1; 256]).expect("full");
        state.set_input(100, &[2; 2]).expect("short");
        assert_eq!(state.assembly(100).expect("input").data[..3], [2, 2, 0]);
    }
}
