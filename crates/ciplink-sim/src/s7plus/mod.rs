//! A simulated S7-1500 style CPU that speaks S7comm-plus over TLS (secure PG/HMI communication), for testing
//! S7comm-plus clients without hardware. Written from the clean-room protocol notes
//! (`docs/dev/s7commplus-protocol.md`, "the spec"); every name in it is invented.
//!
//! On a TCP connection it answers COTP (CR / CC / DT, 1024-byte TPDUs), the cleartext InitSsl exchange, a TLS 1.3
//! handshake with a self-signed ECDSA P-256 certificate generated when the simulator is made, then:
//!
//! - CreateObject (the session) and the session-setup SetMultiVariables, which must write the
//!   ServerSessionVersion back unchanged;
//! - GetMultiVariables of tags (by access area and LIDs, CRC checked when non-zero), of LID 1 of each DB (its
//!   type RID) and of the system limits, at most `max_read` items;
//! - SetMultiVariables tag writes in the form a read returns, at most `max_write` items, with per-item errors;
//! - Explore of the block list (RID 3, with or without the DB filter), the type information (RID 537), a single
//!   type, a DB, the text languages (RID 114);
//! - GetVarSubStreamed of the protection level (keep-alive), PLC name, identification, engineering version,
//!   project;
//! - DeleteObject, after which the client closes.
//!
//! Sequence numbers, both integrity counters, the protocol version and the session ID are checked on every
//! request; any mismatch or malformed request closes the connection without a reply.
//!
//! Item errors: -255 (`0x814E88000962FF01`, no such LID), -61 (`0x814E8D000641FFC3`, index out of range), -17
//! (`0x8009890012C9FFEF`, CRC mismatch), and two invented ones: `0x81048800_0000FFD8` (-40, the written value
//! does not have the tag's wire form) and `0x81048800_0000FFD7` (-41, not simulated: whole arrays of structures,
//! whole BOOL-array writes).
//!
//! ```no_run
//! use ciplink_sim::s7plus::S7PlusSimulator;
//!
//! let sim = S7PlusSimulator::from_json(
//!     r#"{"s7plus": {"dbs": [{"name": "Line1", "number": 5, "members": {"Count": {"type": "DINT", "value": 7}}}]}}"#,
//! )
//! .expect("config");
//! let server = sim.serve("127.0.0.1:0").expect("bind");
//! println!("S7comm-plus on {}, certificate {}", server.addr(), sim.fingerprint());
//! ```

mod config;
mod model;
mod session;
mod wire;

pub use config::{DbConfig, MemberConfig, MemberDetail, S7PlusConfig, TypeConfig};

use crate::ConfigError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value as Json, json};
use session::{Conn, Device};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// A fault injected into an [`S7PlusSimulator`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum S7PlusFault {
    /// Every reply is sent this late.
    Delay(Duration),
    /// The replies to the next `n` requests are not sent (the connection stays open).
    DropReplies(u32),
    /// Every connection open now is closed at once (TCP shutdown, no TLS close_notify). New connections are
    /// served as usual.
    CloseConnections,
    /// New connections are refused with a COTP DR (disconnect request) instead of a CC.
    RefuseConnections,
    /// Reads and writes of this tag (a name as [`S7PlusSimulator::value`] takes it) fail with this item error.
    ItemError {
        /// Tag name.
        tag: String,
        /// The 64-bit item error, e.g. `0x814E88000962FF01`.
        code: u64,
    },
    /// The next reply is an Error PDU (function `04 B1`) with a negative return value.
    ErrorPdu,
    /// Reads and writes with failed items answer with a negative return value (low 16 bits -1) and the error
    /// list, instead of the positive `...0013` seen on a real CPU for reads (what a CPU sends for a failed
    /// write was never captured).
    NegativeItemErrors,
    /// A system-event frame (`72 fe`, no trailer) is sent before the next reply: four 4-byte zero integers,
    /// then flags `00`, datatype `17` (Struct), struct ID 0 (4 bytes), element ID 40305 (4 bytes), flags `00`,
    /// datatype `09` (LInt), this return value as 8 bytes big endian, and a 4-byte zero end of struct.
    SystemEvent {
        /// Return value; negative means the connection is dead (spec 10.7).
        return_value: i64,
    },
}

#[derive(Debug, Default)]
pub(crate) struct Faults {
    delay: Duration,
    drop_replies: u32,
    refuse_connections: bool,
    items: Vec<(String, u64)>,
    error_pdu: bool,
    system_event: Option<i64>,
    negative_item_errors: bool,
}

struct Shared {
    device: Device,
    connections: HashMap<u64, TcpStream>,
    next_connection: u64,
}

/// A simulated S7comm-plus CPU, shared by every connection to it; clones refer to the same device.
#[derive(Clone)]
pub struct S7PlusSimulator {
    shared: Arc<Mutex<Shared>>,
    tls: Arc<ServerConfig>,
    certificate: Vec<u8>,
}

impl std::fmt::Debug for S7PlusSimulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S7PlusSimulator")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl S7PlusSimulator {
    /// A simulator of this CPU, with a new self-signed certificate.
    pub fn new(config: S7PlusConfig) -> Result<Self, ConfigError> {
        let model = model::Model::new(&config)?;
        let (tls, certificate) = tls_config()?;
        Ok(S7PlusSimulator {
            shared: Arc::new(Mutex::new(Shared {
                device: Device {
                    config,
                    model,
                    faults: Faults::default(),
                    requests: 0,
                    recording: false,
                    log: Vec::new(),
                },
                connections: HashMap::new(),
                next_connection: 1,
            })),
            tls,
            certificate,
        })
    }

    /// A simulator configured from JSON (see [`S7PlusConfig`]).
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        Self::new(S7PlusConfig::from_json(text)?)
    }

    /// A simulator configured from a JSON file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new(format!("cannot read {}: {e}", path.display())))?;
        Self::from_json(&text)
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serves S7comm-plus over TCP on `addr`, e.g. `"127.0.0.1:0"` for a free port.
    pub fn serve(&self, addr: &str) -> io::Result<S7PlusServer> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let sim = self.clone();
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let sim = sim.clone();
                std::thread::spawn(move || sim.connection(stream));
            }
        });
        Ok(S7PlusServer {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    /// SHA-256 fingerprint of the server certificate, `"AB:CD:..."` (32 upper-case hex pairs).
    pub fn fingerprint(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.certificate);
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// The server certificate (DER).
    pub fn certificate_der(&self) -> Vec<u8> {
        self.certificate.clone()
    }

    /// The value of a tag as JSON: `Line1.Conveyor.Speed`, `Line1.Items[3]`, `Line1.Grid[2,5]`,
    /// `Line1.Stamp.MONTH`, a PLC tag by its bare name (`StartButton`) or as `IArea.StartButton`. Structures are
    /// objects, arrays lists, dates and times ISO 8601 strings, TIME / S5TIME milliseconds, LTIME nanoseconds.
    pub fn value(&self, name: &str) -> Result<Json, ConfigError> {
        self.lock().device.model.value(name).map_err(ConfigError)
    }

    /// Sets a tag's value from JSON (the forms [`S7PlusSimulator::value`] returns).
    pub fn set_value(&self, name: &str, value: &Json) -> Result<(), ConfigError> {
        self.lock()
            .device
            .model
            .set_value(name, value)
            .map_err(ConfigError)
    }

    /// Injects a fault; several can be active at once.
    pub fn inject(&self, fault: S7PlusFault) {
        let mut shared = self.lock();
        if fault == S7PlusFault::CloseConnections {
            for (_, stream) in shared.connections.drain() {
                let _ = stream.shutdown(Shutdown::Both);
            }
            return;
        }
        fault.apply(&mut shared.device.faults);
    }

    /// Removes every fault.
    pub fn clear_faults(&self) {
        self.lock().device.faults = Faults::default();
    }

    /// Simulates a download that changes the program: the first member of the first DB gets a new member CRC
    /// (reads and writes sending the old address CRC fail with -17) and the ServerSessionVersion of new
    /// sessions changes (project version + 1).
    pub fn change_program(&self) {
        let mut shared = self.lock();
        shared.device.model.change_program();
        shared.device.config.project_version = shared.device.config.project_version.wrapping_add(1);
    }

    /// The number of S7comm-plus requests received so far (InitSsl excluded).
    pub fn requests(&self) -> u64 {
        self.lock().device.requests
    }

    /// The number of connections open now.
    pub fn connections(&self) -> usize {
        self.lock().connections.len()
    }

    /// Starts or stops keeping every decrypted request PDU (see [`S7PlusSimulator::take_received`]).
    pub fn record(&self, on: bool) {
        let mut shared = self.lock();
        shared.device.recording = on;
        if !on {
            shared.device.log.clear();
        }
    }

    /// The request PDUs (version byte + data, without frame headers) received since recording started or the
    /// last call, in order.
    pub fn take_received(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.lock().device.log)
    }

    /// Runs one command of the `ciplink-sim` binary's standard input:
    /// `{"cmd": "value", "path": ..}`, `{"cmd": "set", "path": .., "value": ..}`, `{"cmd": "fault", "fault": ..}`
    /// (`{"delay_ms": n}`, `{"drop_replies": n}`, `{"close_connections": true}`, `{"refuse_connections": true}`,
    /// `{"item_error": {"tag": .., "code": n}}`, `{"error_pdu": true}`, `{"system_event": {"return_value": n}}`,
    /// `{"negative_item_errors": true}`),
    /// `{"cmd": "clear_faults"}`, `{"cmd": "change_program"}`, `{"cmd": "requests"}`, `{"cmd": "fingerprint"}`.
    pub fn command(&self, request: &Json) -> Result<Json, String> {
        let text = |name: &str| {
            request
                .get(name)
                .and_then(Json::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} is missing"))
        };
        match request.get("cmd").and_then(Json::as_str).unwrap_or("") {
            "value" => self.value(&text("path")?).map_err(|e| e.0),
            "set" => {
                let value = request.get("value").cloned().unwrap_or(Json::Null);
                self.set_value(&text("path")?, &value).map_err(|e| e.0)?;
                Ok(Json::Null)
            }
            "fault" => {
                self.inject(parse_fault(request.get("fault").unwrap_or(&Json::Null))?);
                Ok(Json::Null)
            }
            "clear_faults" => {
                self.clear_faults();
                Ok(Json::Null)
            }
            "change_program" => {
                self.change_program();
                Ok(Json::Null)
            }
            "requests" => Ok(json!(self.requests())),
            "fingerprint" => Ok(json!(self.fingerprint())),
            other => Err(format!("unknown command {other:?}")),
        }
    }

    fn connection(&self, stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        let id = {
            let mut shared = self.lock();
            let id = shared.next_connection;
            shared.next_connection += 1;
            if let Ok(clone) = stream.try_clone() {
                shared.connections.insert(id, clone);
            }
            id
        };
        let _ = self.serve_connection(stream, id);
        self.lock().connections.remove(&id);
    }

    fn serve_connection(&self, stream: TcpStream, id: u64) -> io::Result<()> {
        let mut cotp = Cotp::new(stream);
        let refuse = self.lock().device.faults.refuse_connections;
        if !cotp.accept(id as u16, refuse)? {
            return Ok(());
        }
        let mut conn = Conn::new();
        let Some(request) = wire::read_pdu(&mut cotp)? else {
            return Ok(());
        };
        let Some(reply) = session::init_ssl(&request, &mut conn) else {
            return Ok(());
        };
        // cleartext: the whole PDU in one DT frame
        cotp.write_all(&wire::frames(&reply, wire::FRAME_DATA).concat())?;
        let tls = ServerConnection::new(Arc::clone(&self.tls)).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(tls, cotp);
        while let Some(request) = wire::read_pdu(&mut tls)? {
            let outcome = self.lock().device.handle(&mut conn, &request);
            if outcome.close {
                break;
            }
            if !outcome.delay.is_zero() {
                std::thread::sleep(outcome.delay);
            }
            if let Some(event) = outcome.event {
                tls.write_all(&event)?;
            }
            if let Some(reply) = outcome.reply {
                wire::write_pdu(&mut tls, &reply)?;
            }
        }
        tls.sock.close();
        Ok(())
    }
}

fn parse_fault(spec: &Json) -> Result<S7PlusFault, String> {
    let number = |v: &Json, what: &str| v.as_u64().ok_or_else(|| format!("{what} is a count"));
    if let Some(ms) = spec.get("delay_ms") {
        return Ok(S7PlusFault::Delay(Duration::from_millis(number(
            ms, "delay_ms",
        )?)));
    }
    if let Some(n) = spec.get("drop_replies") {
        let n = u32::try_from(number(n, "drop_replies")?).map_err(|e| e.to_string())?;
        return Ok(S7PlusFault::DropReplies(n));
    }
    if spec.get("close_connections").is_some() {
        return Ok(S7PlusFault::CloseConnections);
    }
    if spec.get("refuse_connections").is_some() {
        return Ok(S7PlusFault::RefuseConnections);
    }
    if spec.get("error_pdu").is_some() {
        return Ok(S7PlusFault::ErrorPdu);
    }
    if spec.get("negative_item_errors").is_some() {
        return Ok(S7PlusFault::NegativeItemErrors);
    }
    if let Some(item) = spec.get("item_error") {
        return Ok(S7PlusFault::ItemError {
            tag: item
                .get("tag")
                .and_then(Json::as_str)
                .ok_or("item_error needs a tag")?
                .to_owned(),
            code: item
                .get("code")
                .and_then(Json::as_u64)
                .ok_or("item_error needs a code")?,
        });
    }
    if let Some(event) = spec.get("system_event") {
        return Ok(S7PlusFault::SystemEvent {
            return_value: event
                .get("return_value")
                .and_then(Json::as_i64)
                .unwrap_or(0),
        });
    }
    Err(format!("unknown fault {spec}"))
}

/// TLS 1.3 only, AES-GCM only, a fresh self-signed ECDSA P-256 certificate (CN `ciplink-sim/Communication-1`,
/// SAN 192.0.2.10, a documentation address, so it never matches the address connected to, as behind NAT).
fn tls_config() -> Result<(Arc<ServerConfig>, Vec<u8>), ConfigError> {
    let err = |e: &dyn std::fmt::Display| ConfigError::new(format!("TLS setup: {e}"));
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| err(&e))?;
    let mut params =
        rcgen::CertificateParams::new(vec!["192.0.2.10".to_owned()]).map_err(|e| err(&e))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "ciplink-sim");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ciplink-sim/Communication-1");
    let certificate = params.self_signed(&key).map_err(|e| err(&e))?;
    let der = certificate.der().to_vec();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| err(&e))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .map_err(|e| err(&e))?;
    // the PLC sends records of at most 1,000 bytes
    config.max_fragment_size = Some(1000);
    config.send_tls13_tickets = 2;
    Ok((Arc::new(config), der))
}

/// TPKT + COTP over a TCP stream; after CC the DT payloads are one byte stream in both directions.
struct Cotp {
    stream: TcpStream,
    buffer: Vec<u8>,
    pos: usize,
}

/// Largest DT payload with a 1024-byte TPDU.
const DT_PAYLOAD: usize = 1017;

impl Cotp {
    fn new(stream: TcpStream) -> Cotp {
        Cotp {
            stream,
            buffer: Vec::new(),
            pos: 0,
        }
    }

    /// One TPKT frame's COTP part (length indicator onwards); None at end of stream.
    fn tpdu(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut header = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            let n = self.stream.read(&mut header[got..])?;
            if n == 0 {
                return if got == 0 {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            got += n;
        }
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if header[0] != 3 || len < 7 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad TPKT header",
            ));
        }
        let mut body = vec![0u8; len - 4];
        self.stream.read_exact(&mut body)?;
        Ok(Some(body))
    }

    /// Answers the CR with a CC (echoing its parameters) or, when refusing, a DR. Ok(false): not connected.
    fn accept(&mut self, own_ref: u16, refuse: bool) -> io::Result<bool> {
        let Some(cr) = self.tpdu()? else {
            return Ok(false);
        };
        if cr.len() < 7 || cr[1] != 0xE0 {
            return Ok(false);
        }
        let own = own_ref.max(1).to_be_bytes();
        let mut tpdu = if refuse {
            vec![0x06, 0x80, cr[4], cr[5], own[0], own[1], 0x00]
        } else {
            let mut cc = vec![0, 0xD0, cr[4], cr[5], own[0], own[1], 0x00];
            cc.extend_from_slice(&cr[7..]);
            cc[0] = (cc.len() - 1) as u8;
            cc
        };
        let mut frame = vec![3, 0];
        frame.extend_from_slice(&((tpdu.len() + 4) as u16).to_be_bytes());
        frame.append(&mut tpdu);
        self.stream.write_all(&frame)?;
        Ok(!refuse)
    }

    fn close(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Read for Cotp {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buffer.len() {
            let Some(tpdu) = self.tpdu()? else {
                return Ok(0);
            };
            // DT: LI 2, F0, EOT/number; EOT is ignored (the payloads are one stream)
            if tpdu.len() < 3 || tpdu[1] != 0xF0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "COTP TPDU other than DT",
                ));
            }
            let start = usize::from(tpdu[0]) + 1;
            self.buffer = tpdu.get(start..).unwrap_or_default().to_vec();
            self.pos = 0;
        }
        let n = out.len().min(self.buffer.len() - self.pos);
        out[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for Cotp {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // as the PLC does: every DT frame has EOT set
        for chunk in data.chunks(DT_PAYLOAD) {
            let mut frame = Vec::with_capacity(chunk.len() + 7);
            frame.extend_from_slice(&[3, 0]);
            frame.extend_from_slice(&((chunk.len() + 7) as u16).to_be_bytes());
            frame.extend_from_slice(&[0x02, 0xF0, 0x80]);
            frame.extend_from_slice(chunk);
            self.stream.write_all(&frame)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// A running S7comm-plus server; it stops accepting connections when dropped (connections already open are
/// served until their clients close them or [`S7PlusFault::CloseConnections`]).
pub struct S7PlusServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl S7PlusServer {
    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port the server listens on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for S7PlusServer {
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
