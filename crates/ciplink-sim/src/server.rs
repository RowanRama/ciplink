//! The TCP server (a thread per connection) and the UDP ListIdentity responder.

use crate::encap::{Inner, Outcome, Session};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// A running TCP server; it stops accepting connections when dropped (connections already open are served
/// until their clients close them).
pub struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    pub(crate) fn start(inner: Arc<Mutex<Inner>>, addr: &str) -> io::Result<Self> {
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
                let inner = Arc::clone(&inner);
                std::thread::spawn(move || serve_connection(stream, &inner, addr.port()));
            }
        });
        Ok(Server {
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

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // wakes the accept loop; without that connection join would wait forever
        let _ = TcpStream::connect_timeout(&wake_addr(self.addr), Duration::from_secs(1));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Where to connect to reach a listener on `addr`: an unspecified address (`0.0.0.0`, `::`) is not one a
/// client can connect to on every OS (Windows refuses it), its loopback is.
fn wake_addr(addr: SocketAddr) -> SocketAddr {
    let mut addr = addr;
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => addr.set_ip(Ipv4Addr::LOCALHOST.into()),
        IpAddr::V6(ip) if ip.is_unspecified() => addr.set_ip(Ipv6Addr::LOCALHOST.into()),
        _ => {}
    }
    addr
}

fn serve_connection(mut stream: TcpStream, inner: &Mutex<Inner>, port: u16) {
    let lock = || inner.lock().unwrap_or_else(PoisonError::into_inner);
    if lock().faults.refuse_connections {
        return;
    }
    let _ = stream.set_nodelay(true);
    let mut session = Session::new(port);
    let mut header = [0u8; 24];
    loop {
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let mut frame = header.to_vec();
        frame.resize(
            24 + usize::from(u16::from_le_bytes([header[2], header[3]])),
            0,
        );
        if stream.read_exact(&mut frame[24..]).is_err() {
            return;
        }
        let (outcome, delay) = lock().handle(&mut session, &frame);
        match outcome {
            Outcome::Reply(reply) => {
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

/// A running UDP responder to ListIdentity broadcasts; it stops when dropped.
pub struct UdpServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UdpServer {
    pub(crate) fn start(inner: Arc<Mutex<Inner>>, addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        let addr = socket.local_addr()?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut buffer = [0u8; 600];
            while !stopping.load(Ordering::SeqCst) {
                let Ok((size, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                // only ListIdentity is answered over UDP
                if size < 24 || buffer[..2] != [0x63, 0x00] {
                    continue;
                }
                let mut session = Session::new(addr.port());
                let (outcome, _) = inner
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .handle(&mut session, &buffer[..size]);
                if let Outcome::Reply(reply) = outcome {
                    let _ = socket.send_to(&reply, peer);
                }
            }
        });
        Ok(UdpServer {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    /// The address the responder is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for UdpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_a_server_on_every_interface_connects_to_its_loopback() {
        let any: SocketAddr = "0.0.0.0:4321".parse().expect("addr");
        assert_eq!(wake_addr(any), "127.0.0.1:4321".parse().expect("addr"));
        let any6: SocketAddr = "[::]:4321".parse().expect("addr");
        assert_eq!(wake_addr(any6), "[::1]:4321".parse().expect("addr"));
        let local: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        assert_eq!(wake_addr(local), local);
    }
}
