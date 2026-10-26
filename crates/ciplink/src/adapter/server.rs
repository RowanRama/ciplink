//! The adapter's threads: the TCP server (a thread per session) for explicit messages and Forward Opens, the UDP
//! ListIdentity responder, the class 1 receiver and the producer, which owns the I/O timing.

use super::objects::{self, Ctx};
use super::state::{Origin, State};
use super::wire::{
    self, CONNECTED_ADDRESS, CONNECTED_DATA, ForwardOpen, HEADER, NULL_ADDRESS, SOCKADDR_T_O, Seg,
    Triad, UNCONNECTED_DATA, reply, u16_at,
};
use super::{AdapterConfig, Event};
use crate::{Error, Result};
use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const NOP: u16 = 0x0000;
const LIST_SERVICES: u16 = 0x0004;
const LIST_IDENTITY: u16 = 0x0063;
const LIST_INTERFACES: u16 = 0x0064;
const REGISTER_SESSION: u16 = 0x0065;
const UNREGISTER_SESSION: u16 = 0x0066;
const SEND_RR_DATA: u16 = 0x006F;
const SEND_UNIT_DATA: u16 = 0x0070;

/// Encapsulation status: invalid command, bad data, invalid session, invalid length, unsupported version.
const INVALID_COMMAND: u32 = 0x01;
const BAD_DATA: u32 = 0x03;
const INVALID_SESSION: u32 = 0x64;
const INVALID_LENGTH: u32 = 0x65;
const UNSUPPORTED_VERSION: u32 = 0x69;

/// How often blocked threads look at the stop flag.
const POLL: Duration = Duration::from_millis(100);
/// The producer sleeps at most this long while connections are open, so a new one starts producing at once.
const MAX_SLEEP: Duration = Duration::from_millis(5);

/// What every thread shares.
pub(crate) struct Shared {
    state: Mutex<State>,
    /// Signalled when events may have arrived, and on stop.
    events: Condvar,
    /// Wakes the producer when a connection opens, and on stop.
    wake: Condvar,
    stop: AtomicBool,
    /// The open TCP sessions, shut down on stop.
    streams: Mutex<Vec<(u64, TcpStream)>>,
    next_stream: AtomicU64,
    next_session: AtomicU32,
    io: UdpSocket,
    bind: Ipv4Addr,
    pub addr: SocketAddr,
    pub io_addr: SocketAddr,
}

impl Shared {
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` on the state, then tells event waiters to look.
    fn update<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let result = f(&mut self.lock());
        self.events.notify_all();
        result
    }

    pub(crate) fn next_event(&self, timeout: Option<Duration>) -> Option<Event> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut state = self.lock();
        loop {
            if let Some(event) = state.events.pop_front() {
                return Some(event);
            }
            if self.stop.load(Ordering::SeqCst) {
                return None;
            }
            state = match deadline {
                None => self
                    .events
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let left = deadline.checked_duration_since(Instant::now())?;
                    self.events
                        .wait_timeout(state, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// The adapter's threads, joined by [`Threads::stop`].
pub(crate) struct Threads {
    handles: Vec<JoinHandle<()>>,
}

impl Threads {
    pub(crate) fn stop(self, shared: &Shared) {
        shared.stop.store(true, Ordering::SeqCst);
        shared.events.notify_all();
        shared.wake.notify_all();
        // wakes the accept loop, which would otherwise wait for the next connection
        let _ = TcpStream::connect_timeout(&wake_addr(shared.addr), Duration::from_secs(1));
        for (_, stream) in shared
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for handle in self.handles {
            let _ = handle.join();
        }
    }
}

fn io_error(what: &str, addr: impl std::fmt::Display, err: std::io::Error) -> Error {
    // Windows answers "access denied" for a port another program holds exclusively
    let hint = if matches!(
        err.kind(),
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
    ) {
        " (another EtherNet/IP program, e.g. FactoryTalk Linx or RSLinx, may be using it; only one can listen \
         on an IP address, see docs/adapter.md)"
    } else {
        ""
    };
    Error::comm(format!("cannot {what} {addr}: {err}{hint}"))
}

/// The TCP listener and the UDP ListIdentity socket, on the same port. For port 0 a free TCP port is tried
/// until UDP gets it too: Windows excludes port ranges per protocol.
fn bind_explicit(bind: Ipv4Addr, port: u16) -> Result<(TcpListener, UdpSocket)> {
    let mut attempt = 0;
    loop {
        let listener = TcpListener::bind((bind, port))
            .map_err(|e| io_error("listen on TCP", format!("{bind}:{port}"), e))?;
        let actual = listener
            .local_addr()
            .map_err(|e| io_error("read the address of", bind, e))?
            .port();
        match UdpSocket::bind((bind, actual)) {
            Ok(udp) => return Ok((listener, udp)),
            Err(_) if port == 0 && attempt < 20 => attempt += 1,
            Err(e) => return Err(io_error("listen on UDP", format!("{bind}:{actual}"), e)),
        }
    }
}

/// Binds the sockets and starts the threads.
pub(crate) fn start(config: AdapterConfig) -> Result<(Arc<Shared>, Threads)> {
    let bind = config.bind;
    let (listener, identity_socket) = bind_explicit(bind, config.port)?;
    let addr = listener
        .local_addr()
        .map_err(|e| io_error("read the address of", bind, e))?;
    let io = UdpSocket::bind((bind, config.io_port))
        .map_err(|e| io_error("listen on UDP", format!("{bind}:{}", config.io_port), e))?;
    let io_addr = io
        .local_addr()
        .map_err(|e| io_error("read the address of", bind, e))?;
    for socket in [&identity_socket, &io] {
        socket
            .set_read_timeout(Some(POLL))
            .map_err(|e| io_error("set a timeout on", bind, e))?;
    }
    let mut seed = [0u8; 4];
    getrandom::fill(&mut seed).map_err(|e| Error::comm(format!("no random numbers: {e}")))?;
    let seed = u32::from_le_bytes(seed);
    let shared = Arc::new(Shared {
        state: Mutex::new(State::new(config, seed)),
        events: Condvar::new(),
        wake: Condvar::new(),
        stop: AtomicBool::new(false),
        streams: Mutex::new(Vec::new()),
        next_stream: AtomicU64::new(0),
        next_session: AtomicU32::new(seed.rotate_left(16) | 1),
        io,
        bind,
        addr,
        io_addr,
    });
    let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| {
        std::thread::Builder::new()
            .name(format!("ciplink-adapter-{name}"))
            .spawn(f)
            .map_err(|e| Error::comm(format!("cannot start a thread: {e}")))
    };
    let mut handles = Vec::with_capacity(4);
    let s = Arc::clone(&shared);
    handles.push(spawn("tcp", Box::new(move || accept(&s, &listener)))?);
    let s = Arc::clone(&shared);
    handles.push(spawn(
        "identity",
        Box::new(move || answer_identity(&s, &identity_socket)),
    )?);
    let s = Arc::clone(&shared);
    handles.push(spawn("receive", Box::new(move || receive(&s)))?);
    let s = Arc::clone(&shared);
    handles.push(spawn("produce", Box::new(move || produce(&s)))?);
    log::info!("adapter listening on {addr}, I/O on {io_addr}");
    Ok((shared, Threads { handles }))
}

/// Where to connect to reach a listener on `addr`: its loopback when it listens on every address.
fn wake_addr(addr: SocketAddr) -> SocketAddr {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(Ipv4Addr::LOCALHOST.into());
    }
    addr
}

fn v4(ip: IpAddr) -> Ipv4Addr {
    match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => ip.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
    }
}

/// The subnet mask of a local address (255.255.255.0 if no adapter has it).
fn mask_of(ip: Ipv4Addr) -> Ipv4Addr {
    if ip.is_loopback() {
        return Ipv4Addr::new(255, 0, 0, 0);
    }
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .find_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) if a.ip == ip => Some(a.netmask),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::new(255, 255, 255, 0))
}

/// The local address a peer reaches this host on: the adapter's bind address, else the address of the
/// network card on the peer's subnet.
fn local_for(bind: Ipv4Addr, peer: Ipv4Addr) -> Ipv4Addr {
    if !bind.is_unspecified() {
        return bind;
    }
    if peer.is_loopback() {
        return Ipv4Addr::LOCALHOST;
    }
    let mut first = None;
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if let if_addrs::IfAddr::V4(a) = interface.addr
            && !a.ip.is_loopback()
        {
            let mask = u32::from(a.netmask);
            if u32::from(a.ip) & mask == u32::from(peer) & mask {
                return a.ip;
            }
            first.get_or_insert(a.ip);
        }
    }
    first.unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn accept(shared: &Arc<Shared>, listener: &TcpListener) {
    for stream in listener.incoming() {
        if shared.stopping() {
            break;
        }
        let Ok(stream) = stream else { continue };
        let id = shared.next_stream.fetch_add(1, Ordering::Relaxed);
        if let Ok(copy) = stream.try_clone() {
            shared
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((id, copy));
        }
        let shared = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("ciplink-adapter-session".into())
            .spawn(move || {
                serve(&shared, stream);
                shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retain(|(i, _)| *i != id);
            });
        if let Err(err) = spawned {
            log::error!("adapter cannot serve a connection: {err}");
        }
    }
}

/// A class 3 (explicit message) connection of a session.
struct Class3 {
    o_t: u32,
    t_o: u32,
    triad: Triad,
    request_size: usize,
    reply_size: usize,
    /// The sequence count and reply of the last request: a repeat is answered again without executing it.
    last: Option<(u16, Vec<u8>)>,
}

/// One TCP client.
struct Session {
    handle: u32,
    peer: Ipv4Addr,
    ctx: Ctx,
    class3: Vec<Class3>,
}

enum Outcome {
    Reply(Vec<u8>),
    Silent,
    Close,
}

fn serve(shared: &Shared, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let (Ok(peer), Ok(local)) = (stream.peer_addr(), stream.local_addr()) else {
        return;
    };
    let local = v4(local.ip());
    let mut session = Session {
        handle: 0,
        peer: v4(peer.ip()),
        ctx: Ctx::new(local, mask_of(local)),
        class3: Vec::new(),
    };
    let mut header = [0u8; HEADER];
    loop {
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let mut frame = header.to_vec();
        frame.resize(
            HEADER + usize::from(u16::from_le_bytes([header[2], header[3]])),
            0,
        );
        if stream.read_exact(&mut frame[HEADER..]).is_err() {
            return;
        }
        match handle(shared, &mut session, &frame) {
            Outcome::Reply(reply) => {
                if stream.write_all(&reply).is_err() {
                    return;
                }
            }
            Outcome::Silent => {}
            Outcome::Close => return,
        }
    }
}

fn handle(shared: &Shared, session: &mut Session, frame: &[u8]) -> Outcome {
    let command = u16::from_le_bytes([frame[0], frame[1]]);
    let length = usize::from(u16::from_le_bytes([frame[2], frame[3]]));
    let handle = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
    let context = &frame[12..20];
    let data = &frame[HEADER..];
    let answer = |status: u32, data: &[u8]| {
        Outcome::Reply(wire::encap(command, handle, status, context, data))
    };
    if data.len() != length {
        return answer(INVALID_LENGTH, &[]);
    }
    match command {
        NOP => Outcome::Silent,
        LIST_SERVICES => answer(0, &list_services()),
        LIST_IDENTITY => answer(
            0,
            &objects::list_identity(&shared.lock(), session.ctx.local, shared.addr.port()),
        ),
        LIST_INTERFACES => answer(0, &0u16.to_le_bytes()),
        REGISTER_SESSION => {
            if data.len() != 4 {
                return answer(INVALID_LENGTH, &[]);
            }
            if u16_at(data, 0) != Some(1) {
                return answer(UNSUPPORTED_VERSION, data);
            }
            if session.handle != 0 {
                return answer(INVALID_COMMAND, data);
            }
            session.handle = shared.next_session.fetch_add(1, Ordering::Relaxed).max(1);
            Outcome::Reply(wire::encap(command, session.handle, 0, context, data))
        }
        UNREGISTER_SESSION => Outcome::Close,
        SEND_RR_DATA | SEND_UNIT_DATA => {
            if session.handle == 0 || handle != session.handle {
                return answer(INVALID_SESSION, &[]);
            }
            let Some(items) = wire::cpf_items(data) else {
                return answer(BAD_DATA, &[]);
            };
            if command == SEND_RR_DATA {
                let Some(message) = items
                    .iter()
                    .find(|(kind, _)| *kind == UNCONNECTED_DATA)
                    .map(|(_, m)| *m)
                else {
                    return answer(BAD_DATA, &[]);
                };
                let t_o_sockaddr = items
                    .iter()
                    .find(|(kind, _)| *kind == SOCKADDR_T_O)
                    .and_then(|(_, d)| wire::decode_sockaddr(d));
                let (out, sockaddr) = unconnected(shared, session, message, t_o_sockaddr);
                let sockaddr = sockaddr.map(wire::sockaddr);
                let mut reply_items = vec![(NULL_ADDRESS, &[][..]), (UNCONNECTED_DATA, &out[..])];
                if let Some(item) = &sockaddr {
                    reply_items.push((SOCKADDR_T_O, item));
                }
                answer(0, &wire::cpf(&reply_items))
            } else {
                match items.as_slice() {
                    [(CONNECTED_ADDRESS, id), (CONNECTED_DATA, message)]
                        if id.len() == 4 && message.len() >= 2 =>
                    {
                        let o_t = u32::from_le_bytes([id[0], id[1], id[2], id[3]]);
                        let sequence = u16::from_le_bytes([message[0], message[1]]);
                        let (t_o, out) = connected(shared, session, o_t, sequence, &message[2..]);
                        let mut body = message[..2].to_vec(); // the sequence count is echoed
                        body.extend(out);
                        answer(
                            0,
                            &wire::cpf(&[
                                (CONNECTED_ADDRESS, &t_o.to_le_bytes()),
                                (CONNECTED_DATA, &body),
                            ]),
                        )
                    }
                    _ => answer(BAD_DATA, &[]),
                }
            }
        }
        _ => answer(INVALID_COMMAND, &[]),
    }
}

fn list_services() -> Vec<u8> {
    let mut item = 1u16.to_le_bytes().to_vec(); // version
    item.extend(0x0120u16.to_le_bytes()); // CIP over TCP, and class 0/1 over UDP
    item.extend(b"Communications\0\0");
    wire::encode_items(&[(0x0100, &item)])
}

fn connected(
    shared: &Shared,
    session: &mut Session,
    o_t: u32,
    sequence: u16,
    message: &[u8],
) -> (u32, Vec<u8>) {
    let service = message.first().copied().unwrap_or(0);
    let Some(c) = session.class3.iter_mut().find(|c| c.o_t == o_t) else {
        return (0, reply(service, 0x01, &[0x0107], &[]));
    };
    if let Some((last, out)) = &c.last
        && *last == sequence
    {
        return (c.t_o, out.clone());
    }
    let out = if message.len() + 2 > c.request_size {
        reply(service, 0x15, &[], &[]) // too much data
    } else {
        let mut out = shared.update(|s| objects::message(s, &mut session.ctx, message));
        if out.len() + 2 > c.reply_size {
            out = reply(service, 0x11, &[], &[]); // reply data too large
        }
        out
    };
    c.last = Some((sequence, out.clone()));
    (c.t_o, out)
}

/// Answers an unconnected message; the T->O socket address item to add for a multicast Forward Open.
fn unconnected(
    shared: &Shared,
    session: &mut Session,
    message: &[u8],
    t_o_sockaddr: Option<SocketAddrV4>,
) -> (Vec<u8>, Option<SocketAddrV4>) {
    let service = message.first().copied().unwrap_or(0);
    let Some(request) = wire::parse_request(message) else {
        return (reply(service, 0x04, &[], &[]), None);
    };
    if !objects::is_connection_manager(&request.path) {
        return (
            shared.update(|s| objects::message(s, &mut session.ctx, message)),
            None,
        );
    }
    match service {
        0x54 | 0x5B => forward_open(shared, session, service, request.data, t_o_sockaddr),
        0x4E => (forward_close(shared, session, request.data), None),
        // Unconnected Send: this device answers the embedded message, whatever route it names
        0x52 => match embedded(request.data) {
            Some(inner) => unconnected(shared, session, inner, t_o_sockaddr),
            None => (reply(service, 0x13, &[], &[]), None),
        },
        _ => (reply(service, 0x08, &[], &[]), None),
    }
}

/// The message embedded in an Unconnected Send's data.
fn embedded(data: &[u8]) -> Option<&[u8]> {
    let size = usize::from(u16_at(data, 2)?);
    data.get(4..4 + size)
}

fn forward_open(
    shared: &Shared,
    session: &mut Session,
    service: u8,
    data: &[u8],
    t_o_sockaddr: Option<SocketAddrV4>,
) -> (Vec<u8>, Option<SocketAddrV4>) {
    let Some(fo) = ForwardOpen::decode(data, service == 0x5B) else {
        return (reply(service, 0x13, &[], &[]), None);
    };
    if fo.transport & 0x0F == 3 {
        return (open_class3(session, service, &fo), None);
    }
    let origin = Origin {
        peer: session.peer,
        local: session.ctx.local,
        mask: session.ctx.mask,
        t_o_sockaddr,
        io_port: shared.io_addr.port(),
    };
    let result = shared.update(|s| s.open(&fo, &origin, Instant::now()));
    match result {
        Ok((data, sockaddr)) => {
            shared.wake.notify_all();
            log::info!("adapter: {} opened a connection", session.peer);
            (reply(service, 0, &[], &data), sockaddr)
        }
        Err((general, extended)) => {
            log::info!(
                "adapter: refused a Forward Open from {}: {general:#04x} {extended:04x?}",
                session.peer
            );
            (reply(service, general, &extended, &fo.refusal()), None)
        }
    }
}

/// A class 3 connection to the Message Router, kept by the session.
fn open_class3(session: &mut Session, service: u8, fo: &ForwardOpen) -> Vec<u8> {
    let to_router = matches!(
        wire::parse_path(&fo.path).as_deref(),
        Some([Seg::Class(2), Seg::Instance(1)] | [Seg::Key(_), Seg::Class(2), Seg::Instance(1)])
    );
    let refuse = |extended: &[u16]| reply(service, 0x01, extended, &fo.refusal());
    if !to_router {
        return refuse(&[0x0117]);
    }
    if session.class3.iter().any(|c| c.triad == fo.triad()) {
        return refuse(&[0x0100]);
    }
    let o_t = session.handle ^ (session.class3.len() as u32 + 1).rotate_left(24);
    session.class3.push(Class3 {
        o_t,
        t_o: fo.t_o_id,
        triad: fo.triad(),
        request_size: fo.o_t.size,
        reply_size: fo.t_o.size,
        last: None,
    });
    reply(
        service,
        0,
        &[],
        &fo.reply(o_t, fo.t_o_id, fo.o_t_rpi, fo.t_o_rpi),
    )
}

fn forward_close(shared: &Shared, session: &mut Session, data: &[u8]) -> Vec<u8> {
    let Some((triad, _)) = wire::decode_forward_close(data) else {
        return reply(0x4E, 0x13, &[], &[]);
    };
    let closed = match session.class3.iter().position(|c| c.triad == triad) {
        Some(index) => {
            session.class3.remove(index);
            true
        }
        None => shared.update(|s| s.close(triad)),
    };
    if closed {
        reply(0x4E, 0, &[], &wire::forward_close_reply(triad))
    } else {
        reply(0x4E, 0x01, &[0x0107], &wire::forward_close_reply(triad))
    }
}

/// Answers ListIdentity (and ListServices) over UDP, broadcasts included.
fn answer_identity(shared: &Shared, socket: &UdpSocket) {
    let mut buffer = [0u8; 600];
    while !shared.stopping() {
        let Ok((size, peer)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        if size < HEADER {
            continue;
        }
        let command = u16::from_le_bytes([buffer[0], buffer[1]]);
        let data = match command {
            LIST_IDENTITY => {
                let local = local_for(shared.bind, v4(peer.ip()));
                objects::list_identity(&shared.lock(), local, shared.addr.port())
            }
            LIST_SERVICES => list_services(),
            _ => continue,
        };
        let reply = wire::encap(command, 0, 0, &buffer[12..20], &data);
        let _ = socket.send_to(&reply, peer);
    }
}

/// Takes class 1 frames from scanners.
fn receive(shared: &Shared) {
    let mut buffer = vec![0u8; 65_536];
    while !shared.stopping() {
        // errors include Windows reporting an ICMP port unreachable for an earlier send: keep going
        let Ok((size, SocketAddr::V4(from))) = shared.io.recv_from(&mut buffer) else {
            continue;
        };
        shared.update(|s| s.receive(&buffer[..size], from, Instant::now()));
    }
}

/// Sends every T->O packet when due and closes connections that time out.
fn produce(shared: &Shared) {
    let mut multicast_if = None;
    while !shared.stopping() {
        let mut state = shared.lock();
        let now = Instant::now();
        let before = state.events.len();
        state.expire(now);
        let packets = state.produce(now);
        let deadline = state.next_deadline();
        if state.events.len() != before {
            shared.events.notify_all();
        }
        if packets.is_empty() && deadline.is_none() {
            // no connections: wait for one, under the lock an open takes, so its wake-up is not missed
            let _ = shared
                .wake
                .wait_timeout(state, POLL)
                .unwrap_or_else(PoisonError::into_inner);
            continue;
        }
        drop(state);
        for packet in packets {
            if packet.multicast && multicast_if != Some(packet.local) {
                let socket = socket2::SockRef::from(&shared.io);
                if let Err(err) = socket.set_multicast_if_v4(&packet.local) {
                    log::warn!(
                        "adapter: cannot send multicast from {}: {err}",
                        packet.local
                    );
                }
                multicast_if = Some(packet.local);
            }
            if let Err(err) = shared.io.send_to(&packet.frame, packet.dest) {
                log::debug!("adapter: sending to {} failed: {err}", packet.dest);
            }
        }
        // sleep until the next packet is due (thread::sleep has sub-millisecond resolution, Condvar
        // timeouts do not on Windows)
        let now = Instant::now();
        let wait = deadline.map_or(MAX_SLEEP, |d| d.saturating_duration_since(now));
        if !wait.is_zero() {
            std::thread::sleep(wait.min(MAX_SLEEP));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_on_every_address_wakes_the_loopback() {
        let any: SocketAddr = "0.0.0.0:4321".parse().expect("addr");
        assert_eq!(wake_addr(any), "127.0.0.1:4321".parse().expect("addr"));
    }

    #[test]
    fn unconnected_send_carries_the_embedded_message() {
        let data = [0x0A, 0x0E, 4, 0, 1, 2, 3, 4, 1, 0, 0x01, 0x00];
        assert_eq!(embedded(&data), Some(&[1, 2, 3, 4][..]));
        assert_eq!(embedded(&data[..5]), None);
    }

    #[test]
    fn a_bound_adapter_reports_its_own_address() {
        let bind = Ipv4Addr::new(10, 1, 2, 3);
        assert_eq!(local_for(bind, Ipv4Addr::new(8, 8, 8, 8)), bind);
        assert_eq!(
            local_for(Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST),
            Ipv4Addr::LOCALHOST
        );
    }
}
