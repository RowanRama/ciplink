//! Where a driver connects (the path parser), the byte stream it talks over, and the connectors that open one.

use std::fmt;
use std::io;
use std::net::TcpStream;
use std::time::Duration;

use crate::transport::tcp_stream;
use crate::{Error, Result};

/// Parity of a serial line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Even parity (the Modbus default).
    Even,
    /// Odd parity.
    Odd,
}

/// Where a Modbus driver connects, parsed from its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Modbus TCP.
    Tcp {
        /// IPv4 address or name.
        host: String,
        /// TCP port, 502 by default.
        port: u16,
    },
    /// RTU on a serial port.
    Rtu {
        /// `COM3`, `/dev/ttyUSB0`.
        port: String,
        /// Bits per second, 19200 by default.
        baud: u32,
        /// Even by default.
        parity: Parity,
        /// 7 or 8, 8 by default.
        data_bits: u8,
        /// 1 or 2, 1 by default.
        stop_bits: u8,
    },
    /// RTU frames over TCP (serial device servers).
    RtuOverTcp {
        /// IPv4 address or name.
        host: String,
        /// TCP port, 502 by default.
        port: u16,
    },
}

const PATH_HELP: &str = "modbus path needs tcp://, rtu:// or rtu+tcp://";

fn host_port(text: &str, path: &str) -> Result<(String, u16)> {
    let bad = |why: &str| Error::request(format!("bad modbus path '{path}': {why}"));
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| bad("port is not a number"))?;
            (host, port)
        }
        None => (text, 502),
    };
    if host.is_empty() {
        return Err(bad("no host"));
    }
    if port == 0 {
        return Err(bad("port 0"));
    }
    Ok((host.to_owned(), port))
}

impl Endpoint {
    /// The endpoint and the default unit of `path`: `tcp://host[:port][?unit=N]`,
    /// `rtu://PORT[?baud=B&parity=N|E|O&data=7|8&stop=1|2&unit=N]` or `rtu+tcp://host[:port][?unit=N]`.
    pub fn parse(path: &str) -> Result<(Endpoint, u8)> {
        let bad = |why: String| Error::request(format!("bad modbus path '{path}': {why}"));
        let (scheme, rest) = path
            .split_once("://")
            .ok_or_else(|| Error::request(PATH_HELP))?;
        let (target, query) = rest.split_once('?').unwrap_or((rest, ""));
        let scheme = scheme.to_ascii_lowercase();
        let mut unit = 1u8;
        let mut baud = 19200u32;
        let mut parity = Parity::Even;
        let mut data_bits = 8u8;
        let mut stop_bits = 1u8;
        let serial = scheme == "rtu";
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = key.to_ascii_lowercase();
            let invalid = || bad(format!("{key}={value} is not valid"));
            match key.as_str() {
                "unit" => unit = value.parse().map_err(|_| invalid())?,
                "baud" if serial => {
                    baud = value.parse().map_err(|_| invalid())?;
                    if baud == 0 {
                        return Err(invalid());
                    }
                }
                "parity" if serial => {
                    parity = match value.to_ascii_uppercase().as_str() {
                        "N" => Parity::None,
                        "E" => Parity::Even,
                        "O" => Parity::Odd,
                        _ => return Err(invalid()),
                    }
                }
                "data" if serial => {
                    data_bits = match value {
                        "7" => 7,
                        "8" => 8,
                        _ => return Err(invalid()),
                    }
                }
                "stop" if serial => {
                    stop_bits = match value {
                        "1" => 1,
                        "2" => 2,
                        _ => return Err(invalid()),
                    }
                }
                _ => return Err(bad(format!("unknown option '{key}'"))),
            }
        }
        let endpoint = match scheme.as_str() {
            "tcp" => {
                let (host, port) = host_port(target, path)?;
                Endpoint::Tcp { host, port }
            }
            "rtu+tcp" => {
                let (host, port) = host_port(target, path)?;
                Endpoint::RtuOverTcp { host, port }
            }
            "rtu" => {
                if target.is_empty() {
                    return Err(bad("no serial port".into()));
                }
                Endpoint::Rtu {
                    port: target.to_owned(),
                    baud,
                    parity,
                    data_bits,
                    stop_bits,
                }
            }
            _ => return Err(Error::request(PATH_HELP)),
        };
        Ok((endpoint, unit))
    }

    /// True for RTU framing (a serial port, or RTU over TCP).
    pub fn is_rtu(&self) -> bool {
        !matches!(self, Endpoint::Tcp { .. })
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Tcp { host, port } => write!(f, "tcp://{host}:{port}"),
            Endpoint::RtuOverTcp { host, port } => write!(f, "rtu+tcp://{host}:{port}"),
            Endpoint::Rtu {
                port,
                baud,
                parity,
                data_bits,
                stop_bits,
            } => {
                let parity = match parity {
                    Parity::None => 'N',
                    Parity::Even => 'E',
                    Parity::Odd => 'O',
                };
                write!(
                    f,
                    "rtu://{port}?baud={baud}&parity={parity}&data={data_bits}&stop={stop_bits}"
                )
            }
        }
    }
}

/// A byte stream to a Modbus device: a TCP socket, a serial port, or a test fake. A read that times out returns
/// an io::Error of kind TimedOut or WouldBlock.
pub trait Link: io::Read + io::Write + Send {
    /// Timeout of later reads and writes.
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()>;

    /// Discards the input already received without waiting for more (RTU, before each request). The default
    /// reads with a 1 ms timeout until nothing is left.
    fn discard_input(&mut self) -> io::Result<()> {
        self.set_timeout(Duration::from_millis(1))?;
        discard_ready(self)
    }
}

/// Reads and drops what `link` returns until a read times out (or would block); at most 64 KiB, so a device
/// that never stops talking cannot hold the caller.
fn discard_ready(link: &mut (impl io::Read + ?Sized)) -> io::Result<()> {
    let mut sink = [0u8; 256];
    for _ in 0..256 {
        match link.read(&mut sink) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Link for TcpStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        // a zero timeout is an error for a socket
        let timeout = Some(timeout.max(Duration::from_millis(1)));
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }

    fn discard_input(&mut self) -> io::Result<()> {
        // non-blocking: a short read timeout would cost a timer tick (about 15 ms on Windows) per request
        self.set_nonblocking(true)?;
        let result = discard_ready(self);
        self.set_nonblocking(false)?;
        result
    }
}

impl Link for Box<dyn serialport::SerialPort> {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        serialport::SerialPort::set_timeout(self.as_mut(), timeout).map_err(io::Error::from)
    }

    fn discard_input(&mut self) -> io::Result<()> {
        serialport::SerialPort::clear(self.as_mut(), serialport::ClearBuffer::Input)
            .map_err(io::Error::from)
    }
}

/// Opens a link to an endpoint; the driver calls it on every open.
pub type ModbusConnector = Box<dyn Fn(&Endpoint, Duration) -> Result<Box<dyn Link>> + Send + Sync>;

/// TCP for `tcp://` and `rtu+tcp://`, `serialport` for `rtu://`.
pub fn modbus_connector() -> ModbusConnector {
    Box::new(|endpoint, timeout| match endpoint {
        Endpoint::Tcp { host, port } | Endpoint::RtuOverTcp { host, port } => {
            let mut stream = tcp_stream(host, *port, Some(timeout))?;
            Link::set_timeout(&mut stream, timeout)
                .map_err(|_| Error::comm(format!("Failed to open socket to {host}:{port}")))?;
            Ok(Box::new(stream) as Box<dyn Link>)
        }
        Endpoint::Rtu {
            port,
            baud,
            parity,
            data_bits,
            stop_bits,
        } => {
            let fail = |e: serialport::Error| {
                Error::comm(format!("Failed to open serial port {port}: {e}"))
            };
            let serial = serialport::new(port, *baud)
                .parity(match parity {
                    Parity::None => serialport::Parity::None,
                    Parity::Even => serialport::Parity::Even,
                    Parity::Odd => serialport::Parity::Odd,
                })
                .data_bits(if *data_bits == 7 {
                    serialport::DataBits::Seven
                } else {
                    serialport::DataBits::Eight
                })
                .stop_bits(if *stop_bits == 2 {
                    serialport::StopBits::Two
                } else {
                    serialport::StopBits::One
                })
                .flow_control(serialport::FlowControl::None)
                .timeout(timeout)
                .open()
                .map_err(fail)?;
            serial.clear(serialport::ClearBuffer::All).map_err(fail)?;
            Ok(Box::new(serial) as Box<dyn Link>)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(path: &str) -> (Endpoint, u8) {
        Endpoint::parse(path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn tcp(host: &str, port: u16) -> Endpoint {
        Endpoint::Tcp {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn endpoint_parse() {
        assert_eq!(parse("tcp://10.0.0.9"), (tcp("10.0.0.9", 502), 1));
        assert_eq!(
            parse("tcp://10.0.0.9:1502?unit=7"),
            (tcp("10.0.0.9", 1502), 7)
        );
        assert_eq!(parse("TCP://plc.local?UNIT=0"), (tcp("plc.local", 502), 0));
        assert_eq!(
            parse("rtu+tcp://127.0.0.1:4001?unit=3"),
            (
                Endpoint::RtuOverTcp {
                    host: "127.0.0.1".into(),
                    port: 4001
                },
                3
            )
        );
        let serial = |port: &str, baud, parity, data_bits, stop_bits| Endpoint::Rtu {
            port: port.into(),
            baud,
            parity,
            data_bits,
            stop_bits,
        };
        assert_eq!(
            parse("rtu://COM3"),
            (serial("COM3", 19200, Parity::Even, 8, 1), 1)
        );
        assert_eq!(
            parse("rtu:///dev/ttyUSB0?baud=9600&parity=n&data=7&stop=2&unit=12"),
            (serial("/dev/ttyUSB0", 9600, Parity::None, 7, 2), 12)
        );
        assert_eq!(
            parse("rtu://COM10?Parity=O").0,
            serial("COM10", 19200, Parity::Odd, 8, 1)
        );
        assert_eq!(parse("tcp://h:1").0.to_string(), "tcp://h:1");
        assert_eq!(
            parse("rtu://COM3").0.to_string(),
            "rtu://COM3?baud=19200&parity=E&data=8&stop=1"
        );
        assert!(parse("rtu+tcp://h").0.is_rtu());
        assert!(!parse("tcp://h").0.is_rtu());
    }

    #[test]
    fn bad_paths() {
        for path in [
            "10.0.0.9",
            "10.0.0.9/1",
            "udp://h",
            "tcp://",
            "tcp://h:0",
            "tcp://h:99999",
            "tcp://h:x",
            "tcp://h?unit=256",
            "tcp://h?baud=9600",
            "tcp://h?color=red",
            "rtu://",
            "rtu://COM3?parity=X",
            "rtu://COM3?data=6",
            "rtu://COM3?stop=3",
            "rtu://COM3?baud=0",
            "rtu://COM3?baud=fast",
        ] {
            assert!(
                matches!(Endpoint::parse(path), Err(Error::Request { .. })),
                "{path}"
            );
        }
        assert_eq!(
            Endpoint::parse("10.0.0.9")
                .expect_err("no scheme")
                .to_string(),
            "modbus path needs tcp://, rtu:// or rtu+tcp://"
        );
    }
}
