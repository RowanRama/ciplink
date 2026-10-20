//! Moving encapsulation frames: the TCP transport and the trait a test fake implements.

use crate::{Error, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Encapsulation header size; its bytes 2..4 hold the length of the data that follows.
pub const HEADER_SIZE: usize = 24;

/// Sends request frames and receives reply frames, one encapsulation frame at a time.
///
/// The driver owns one transport per connection and never uses it from two threads at once.
pub trait Transport: Send {
    /// Sends one whole request frame.
    fn send(&mut self, frame: &[u8]) -> Result<()>;
    /// Receives one whole reply frame (header and data).
    fn receive(&mut self) -> Result<Vec<u8>>;
    /// Sets the timeout of later sends and receives, None to block forever.
    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()>;
}

/// Opens a transport to `host:port`; the driver calls it on every `open()`.
pub type Connector =
    Box<dyn Fn(&str, u16, Option<Duration>) -> Result<Box<dyn Transport>> + Send + Sync>;

/// The default connector: a TCP connection with keep-alive.
pub fn tcp_connector() -> Connector {
    Box::new(|host, port, timeout| {
        Ok(Box::new(TcpTransport::connect(host, port, timeout)?) as Box<dyn Transport>)
    })
}

/// EtherNet/IP over TCP, keeping bytes received past a frame for the next one.
pub struct TcpTransport {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl TcpTransport {
    /// Connects to `host:port` within `timeout`.
    pub fn connect(host: &str, port: u16, timeout: Option<Duration>) -> Result<Self> {
        let fail = || Error::comm(format!("Failed to open socket to {host}:{port}"));
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|_| fail())?
            .find(|a| a.is_ipv4())
            .ok_or_else(fail)?;
        let stream = match timeout {
            Some(t) => TcpStream::connect_timeout(&addr, t),
            None => TcpStream::connect(addr),
        }
        .map_err(|_| fail())?;
        stream.set_nodelay(true).map_err(|_| fail())?;
        let mut transport = TcpTransport {
            stream,
            buffer: Vec::with_capacity(4096),
        };
        transport.set_timeout(timeout)?;
        Ok(transport)
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.stream
            .write_all(frame)
            .map_err(|_| Error::comm("socket connection broken."))
    }

    fn receive(&mut self) -> Result<Vec<u8>> {
        let mut chunk = [0u8; 4096];
        loop {
            if self.buffer.len() >= HEADER_SIZE {
                let size =
                    HEADER_SIZE + usize::from(u16::from_le_bytes([self.buffer[2], self.buffer[3]]));
                if self.buffer.len() >= size {
                    let rest = self.buffer.split_off(size);
                    return Ok(std::mem::replace(&mut self.buffer, rest));
                }
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(Error::comm(
                        "socket connection closed before a complete frame was received",
                    ));
                }
                Ok(n) => self.buffer.extend_from_slice(&chunk[..n]),
                Err(_) => return Err(Error::comm("socket connection broken")),
            }
        }
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        let fail = |_| Error::comm("socket connection broken");
        self.stream.set_read_timeout(timeout).map_err(fail)?;
        self.stream.set_write_timeout(timeout).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn frame(len: u16, fill: u8) -> Vec<u8> {
        let mut f = vec![0u8; HEADER_SIZE + usize::from(len)];
        f[2..4].copy_from_slice(&len.to_le_bytes());
        f[HEADER_SIZE..].fill(fill);
        f
    }

    #[test]
    fn receive_splits_frames_that_arrive_together_and_in_pieces() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut both = frame(3, 1);
            both.extend(frame(0, 0));
            s.write_all(&both).expect("write");
            let third = frame(5000, 7);
            s.write_all(&third[..10]).expect("write");
            std::thread::sleep(Duration::from_millis(20));
            s.write_all(&third[10..]).expect("write");
        });
        let mut t = TcpTransport::connect("127.0.0.1", port, Some(Duration::from_secs(5)))
            .expect("connect");
        assert_eq!(t.receive().expect("1"), frame(3, 1));
        assert_eq!(t.receive().expect("2"), frame(0, 0));
        assert_eq!(t.receive().expect("3"), frame(5000, 7));
        server.join().expect("join");
        assert!(matches!(t.receive(), Err(Error::Comm(_))));
    }
}
