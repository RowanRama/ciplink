//! A class 1 scanner (originator) for testing EtherNet/IP adapters: it opens one I/O connection like a Logix
//! controller's Generic Ethernet Module, sends O->T every RPI and keeps what arrives T->O.
//!
//! Its frames are written here from the CIP layout, apart from the adapter's own codec in `ciplink`, so a test
//! of one against the other does not share a misreading. Test-only: ciplink itself ships no originator.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What to open.
#[derive(Clone, Debug)]
pub struct IoRequest {
    /// O->T connection point: an output assembly, or a heartbeat instance.
    pub o_t_point: u32,
    /// T->O connection point: an input assembly.
    pub t_o_point: u32,
    /// Configuration instance.
    pub config_point: u32,
    /// Configuration data sent in the connection path (empty for none).
    pub config_data: Vec<u8>,
    /// O->T data bytes (0 for a heartbeat).
    pub o_t_size: usize,
    /// T->O data bytes.
    pub t_o_size: usize,
    /// O->T carries the 32-bit run/idle header (an exclusive owner's does).
    pub run_idle: bool,
    /// Requested packet interval, both ways.
    pub rpi: Duration,
    /// T->O multicast instead of point-to-point.
    pub multicast: bool,
    /// Connection serial number (the triad's first part).
    pub serial: u16,
    /// Timeout multiplier code: the timeout is the RPI times 4 << code.
    pub multiplier: u8,
    /// An electronic key: vendor, device type, product code, major revision (0x80: compatible), minor.
    pub key: Option<(u16, u16, u16, u8, u8)>,
}

impl IoRequest {
    /// An exclusive owner of `output` (bytes `o_t_size`) and `input` (bytes `t_o_size`), point-to-point.
    pub fn owner(output: u32, o_t_size: usize, input: u32, t_o_size: usize, rpi: Duration) -> Self {
        IoRequest {
            o_t_point: output,
            t_o_point: input,
            config_point: 1,
            config_data: Vec::new(),
            o_t_size,
            t_o_size,
            run_idle: true,
            rpi,
            multicast: false,
            serial: 1,
            multiplier: 2,
            key: None,
        }
    }

    /// An input-only (or listen-only) connection on `heartbeat` for `input`.
    pub fn heartbeat(heartbeat: u32, input: u32, t_o_size: usize, rpi: Duration) -> Self {
        IoRequest {
            o_t_point: heartbeat,
            o_t_size: 0,
            run_idle: false,
            ..Self::owner(heartbeat, 0, input, t_o_size, rpi)
        }
    }
}

/// Why a scanner could not open its connection.
#[derive(Debug)]
pub enum ScanError {
    /// A socket error.
    Io(io::Error),
    /// The adapter refused the Forward Open with this general and extended status.
    Refused {
        /// General status.
        general: u8,
        /// Extended status words.
        extended: Vec<u16>,
    },
    /// The reply could not be read.
    BadReply(String),
}

impl From<io::Error> for ScanError {
    fn from(err: io::Error) -> Self {
        ScanError::Io(err)
    }
}

/// What the scanner has received.
#[derive(Debug, Default)]
struct Received {
    input: Option<Vec<u8>>,
    packets: u64,
    arrivals: Vec<Instant>,
    last_sequence: Option<u32>,
}

struct Shared {
    output: Mutex<(Vec<u8>, bool)>,
    received: Mutex<Received>,
    sending: AtomicBool,
    stop: AtomicBool,
}

/// An open class 1 connection.
pub struct Scanner {
    tcp: TcpStream,
    session: u32,
    request: IoRequest,
    /// The connection IDs the adapter's reply gave: O->T (used to send) and T->O (expected in its packets).
    pub o_t_id: u32,
    /// T->O connection ID.
    pub t_o_id: u32,
    /// The actual packet intervals of the reply.
    pub api: (Duration, Duration),
    /// The multicast address of the reply's T->O socket address item.
    pub multicast_group: Option<SocketAddrV4>,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("o_t_id", &self.o_t_id)
            .field("t_o_id", &self.t_o_id)
            .finish()
    }
}

fn le16(data: &[u8], at: usize) -> Result<u16, ScanError> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| ScanError::BadReply(format!("short at {at}")))
}

fn le32(data: &[u8], at: usize) -> Result<u32, ScanError> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| ScanError::BadReply(format!("short at {at}")))
}

/// Sends an encapsulation frame and reads the reply's data.
fn transact(
    tcp: &mut TcpStream,
    command: u16,
    session: u32,
    data: &[u8],
) -> Result<(u32, Vec<u8>), ScanError> {
    let mut frame = Vec::with_capacity(24 + data.len());
    frame.extend(command.to_le_bytes());
    frame.extend((data.len() as u16).to_le_bytes());
    frame.extend(session.to_le_bytes());
    frame.extend([0u8; 16]); // status, sender context, options
    frame.extend(data);
    tcp.write_all(&frame)?;
    let mut header = [0u8; 24];
    tcp.read_exact(&mut header)?;
    let mut reply = vec![0u8; usize::from(u16::from_le_bytes([header[2], header[3]]))];
    tcp.read_exact(&mut reply)?;
    let status = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if status != 0 {
        return Err(ScanError::BadReply(format!(
            "encapsulation status {status:#x}"
        )));
    }
    Ok((
        u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
        reply,
    ))
}

/// SendRRData of an unconnected message (with extra items), returning the items of the reply.
fn send_rr(
    tcp: &mut TcpStream,
    session: u32,
    message: &[u8],
    extra: &[(u16, Vec<u8>)],
) -> Result<Vec<(u16, Vec<u8>)>, ScanError> {
    let mut data = vec![0u8; 6]; // interface handle, timeout
    data.extend((2 + extra.len() as u16).to_le_bytes());
    data.extend([0, 0, 0, 0]); // null address item
    data.extend(0x00B2u16.to_le_bytes());
    data.extend((message.len() as u16).to_le_bytes());
    data.extend(message);
    for (kind, item) in extra {
        data.extend(kind.to_le_bytes());
        data.extend((item.len() as u16).to_le_bytes());
        data.extend(item);
    }
    let (_, reply) = transact(tcp, 0x6F, session, &data)?;
    let count = le16(&reply, 6)?;
    let mut items = Vec::new();
    let mut at = 8;
    for _ in 0..count {
        let kind = le16(&reply, at)?;
        let size = usize::from(le16(&reply, at + 2)?);
        let item = reply
            .get(at + 4..at + 4 + size)
            .ok_or_else(|| ScanError::BadReply("short item".into()))?;
        items.push((kind, item.to_vec()));
        at += 4 + size;
    }
    Ok(items)
}

/// A logical segment of the smallest size that holds `value`.
fn logical(kind: u8, value: u32, out: &mut Vec<u8>) {
    if value <= 0xFF {
        out.extend([kind, value as u8]);
    } else {
        out.extend([kind | 1, 0]);
        out.extend((value as u16).to_le_bytes());
    }
}

/// A Connection Manager request: service, path to class 6 instance 1, data.
fn connection_manager(service: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![service, 2, 0x20, 0x06, 0x24, 0x01];
    out.extend(data);
    out
}

fn status_of(reply: &[u8]) -> Result<(u8, Vec<u16>, &[u8]), ScanError> {
    let general = *reply
        .get(2)
        .ok_or_else(|| ScanError::BadReply("short reply".into()))?;
    let words = usize::from(
        *reply
            .get(3)
            .ok_or_else(|| ScanError::BadReply("short reply".into()))?,
    );
    let extended = (0..words)
        .map(|i| le16(reply, 4 + 2 * i))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((general, extended, &reply[4 + 2 * words..]))
}

impl Scanner {
    /// Opens the connection to the adapter at `adapter` (its TCP address); I/O goes to `io` (its UDP 2222
    /// address). The scanner receives T->O on a UDP port of its own, named in the request's T->O socket address
    /// item, on the loopback address or the address it reaches the adapter from.
    pub fn open(
        adapter: SocketAddr,
        io: SocketAddr,
        request: IoRequest,
    ) -> Result<Scanner, ScanError> {
        let mut tcp = TcpStream::connect_timeout(&adapter, Duration::from_secs(2))?;
        tcp.set_read_timeout(Some(Duration::from_secs(2)))?;
        let local_ip = tcp.local_addr()?.ip();
        let (session, _) = transact(&mut tcp, 0x65, 0, &[1, 0, 0, 0])?;
        let udp = UdpSocket::bind((local_ip, 0))?;
        udp.set_read_timeout(Some(Duration::from_millis(50)))?;
        let port = udp.local_addr()?.port();

        let large = request.o_t_size + 6 > 505 || request.t_o_size + 2 > 505;
        let rpi = request.rpi.as_micros() as u32;
        let mut data = vec![0x0A, 0x0E]; // priority/tick, timeout ticks
        data.extend(0u32.to_le_bytes()); // O->T id: the target chooses
        // a T->O ID of its own: a port freed by a scanner in another test may be bound again while that test's
        // adapter still sends to it, and those packets must not count here
        static NEXT_T_O_ID: AtomicU32 = AtomicU32::new(0x5EED_0000);
        data.extend(NEXT_T_O_ID.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        data.extend(request.serial.to_le_bytes());
        data.extend(0x0001u16.to_le_bytes()); // originator vendor
        data.extend(0x0BAD_CAFEu32.to_le_bytes()); // originator serial
        data.extend([request.multiplier, 0, 0, 0]);
        let o_t_size = request.o_t_size + 2 + if request.run_idle { 4 } else { 0 };
        let t_o_size = request.t_o_size + 2;
        let params = |net: u32, size: usize| -> Vec<u8> {
            if large {
                (net << 29 | 0x0800_0000 | size as u32)
                    .to_le_bytes()
                    .to_vec() // scheduled priority, fixed
            } else {
                ((net << 13 | 0x0800 | size as u32) as u16)
                    .to_le_bytes()
                    .to_vec()
            }
        };
        data.extend(rpi.to_le_bytes());
        data.extend(params(2, o_t_size));
        data.extend(rpi.to_le_bytes());
        data.extend(params(if request.multicast { 1 } else { 2 }, t_o_size));
        data.push(0x01); // class 1, cyclic, client
        let mut path = Vec::new();
        if let Some((vendor, device_type, code, major, minor)) = request.key {
            path.extend([0x34, 0x04]);
            for v in [vendor, device_type, code] {
                path.extend(v.to_le_bytes());
            }
            path.extend([major, minor]);
        }
        path.extend([0x20, 0x04]);
        logical(0x24, request.config_point, &mut path);
        logical(0x2C, request.o_t_point, &mut path);
        logical(0x2C, request.t_o_point, &mut path);
        if !request.config_data.is_empty() {
            path.extend([0x80, request.config_data.len().div_ceil(2) as u8]);
            path.extend(&request.config_data);
            if request.config_data.len() % 2 == 1 {
                path.push(0);
            }
        }
        data.push((path.len() / 2) as u8);
        data.extend(&path);

        // T->O socket address item: where point-to-point data goes (address 0: the address this came from)
        let mut sockaddr = vec![0, 2];
        sockaddr.extend(port.to_be_bytes());
        sockaddr.extend([0u8; 12]);
        let service = if large { 0x5B } else { 0x54 };
        let items = send_rr(
            &mut tcp,
            session,
            &connection_manager(service, &data),
            &[(0x8001, sockaddr)],
        )?;
        let reply = items
            .iter()
            .find(|(k, _)| *k == 0x00B2)
            .map(|(_, d)| d.clone())
            .ok_or_else(|| ScanError::BadReply("no unconnected data item".into()))?;
        if reply.first() != Some(&(service | 0x80)) {
            return Err(ScanError::BadReply(format!(
                "reply service {:?}",
                reply.first()
            )));
        }
        let (general, extended, body) = status_of(&reply)?;
        if general != 0 {
            return Err(ScanError::Refused { general, extended });
        }
        let o_t_id = le32(body, 0)?;
        let t_o_id = le32(body, 4)?;
        if le16(body, 8)? != request.serial {
            return Err(ScanError::BadReply(
                "the reply names another connection".into(),
            ));
        }
        let api = (
            Duration::from_micros(u64::from(le32(body, 16)?)),
            Duration::from_micros(u64::from(le32(body, 20)?)),
        );
        let multicast_group = items.iter().find(|(k, _)| *k == 0x8001).and_then(|(_, d)| {
            (d.len() == 16 && d[..2] == [0, 2]).then(|| {
                SocketAddrV4::new(
                    Ipv4Addr::new(d[4], d[5], d[6], d[7]),
                    u16::from_be_bytes([d[2], d[3]]),
                )
            })
        });

        let shared = Arc::new(Shared {
            output: Mutex::new((vec![0; request.o_t_size], true)),
            received: Mutex::new(Received::default()),
            sending: AtomicBool::new(true),
            stop: AtomicBool::new(false),
        });
        let udp = Arc::new(udp);
        let mut threads = Vec::new();
        let (s, u, r) = (Arc::clone(&shared), Arc::clone(&udp), request.clone());
        threads.push(std::thread::spawn(move || {
            send_loop(&s, &u, io, o_t_id, &r)
        }));
        let (s, u) = (Arc::clone(&shared), Arc::clone(&udp));
        threads.push(std::thread::spawn(move || receive_loop(&s, &u, t_o_id)));
        Ok(Scanner {
            tcp,
            session,
            request,
            o_t_id,
            t_o_id,
            api,
            multicast_group,
            shared,
            threads,
        })
    }

    /// Sets the O->T data and the run bit of the run/idle header.
    pub fn set_output(&self, data: &[u8], run: bool) {
        let mut output = self
            .shared
            .output
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        output.0[..data.len()].copy_from_slice(data);
        output.1 = run;
    }

    /// The latest T->O data, None before the first packet.
    pub fn input(&self) -> Option<Vec<u8>> {
        self.received().input.clone()
    }

    /// T->O packets received.
    pub fn packets(&self) -> u64 {
        self.received().packets
    }

    /// The times between T->O packets.
    pub fn intervals(&self) -> Vec<Duration> {
        let received = self.received();
        received.arrivals.windows(2).map(|w| w[1] - w[0]).collect()
    }

    fn received(&self) -> std::sync::MutexGuard<'_, Received> {
        self.shared
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Stops sending O->T without closing, as a pulled cable would; the adapter's watchdog then expires.
    pub fn go_quiet(&self) {
        self.shared.sending.store(false, Ordering::SeqCst);
    }

    /// Waits until at least `count` T->O packets arrived, or `limit` passed.
    pub fn wait_for_packets(&self, count: u64, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if self.packets() >= count {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    /// Closes the connection with a Forward Close; the reply's general and extended status.
    pub fn close(mut self) -> Result<(u8, Vec<u16>), ScanError> {
        // the Forward Close goes out while I/O still runs, as a controller sends it: stopping first could let the
        // connection time out before the close arrives
        let mut data = vec![0x0A, 0x0E];
        data.extend(self.request.serial.to_le_bytes());
        data.extend(0x0001u16.to_le_bytes());
        data.extend(0x0BAD_CAFEu32.to_le_bytes());
        data.extend([0, 0]); // path size, reserved (no path: this device)
        let items = send_rr(
            &mut self.tcp,
            self.session,
            &connection_manager(0x4E, &data),
            &[],
        )?;
        let reply = items
            .iter()
            .find(|(k, _)| *k == 0x00B2)
            .map(|(_, d)| d.clone())
            .ok_or_else(|| ScanError::BadReply("no unconnected data item".into()))?;
        self.stop_threads();
        let (general, extended, _) = status_of(&reply)?;
        Ok((general, extended))
    }

    fn stop_threads(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        self.stop_threads();
    }
}

fn send_loop(shared: &Shared, udp: &UdpSocket, io: SocketAddr, o_t_id: u32, request: &IoRequest) {
    let mut sequence = 0u32;
    let mut next = Instant::now();
    while !shared.stop.load(Ordering::SeqCst) {
        if shared.sending.load(Ordering::SeqCst) {
            sequence = sequence.wrapping_add(1);
            let (data, run) = shared
                .output
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let mut payload = (sequence as u16).to_le_bytes().to_vec();
            if request.run_idle {
                payload.extend(u32::from(run).to_le_bytes());
            }
            payload.extend(&data);
            let mut frame = vec![2, 0, 0x02, 0x80, 8, 0];
            frame.extend(o_t_id.to_le_bytes());
            frame.extend(sequence.to_le_bytes());
            frame.extend(0x00B1u16.to_le_bytes());
            frame.extend((payload.len() as u16).to_le_bytes());
            frame.extend(payload);
            let _ = udp.send_to(&frame, io);
        }
        next += request.rpi;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            next = now;
        }
    }
}

fn receive_loop(shared: &Shared, udp: &UdpSocket, t_o_id: u32) {
    let mut buffer = vec![0u8; 2048];
    while !shared.stop.load(Ordering::SeqCst) {
        let Ok(size) = udp.recv(&mut buffer) else {
            continue;
        };
        let frame = &buffer[..size];
        // item count 2, sequenced address item (8 bytes), connected data item
        if size < 20 || frame[..6] != [2, 0, 0x02, 0x80, 8, 0] || frame[14..16] != [0xB1, 0] {
            continue;
        }
        let id = u32::from_le_bytes([frame[6], frame[7], frame[8], frame[9]]);
        let sequence = u32::from_le_bytes([frame[10], frame[11], frame[12], frame[13]]);
        let length = usize::from(u16::from_le_bytes([frame[16], frame[17]]));
        if id != t_o_id || 18 + length != size || length < 2 {
            continue;
        }
        let mut received = shared
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if received
            .last_sequence
            .is_some_and(|last| sequence.wrapping_sub(last) as i32 <= 0)
        {
            continue;
        }
        received.last_sequence = Some(sequence);
        received.input = Some(frame[20..].to_vec());
        received.packets += 1;
        received.arrivals.push(Instant::now());
    }
}
