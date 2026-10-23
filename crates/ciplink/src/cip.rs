//! The CIP driver: session, Forward Open/Close, generic messages, ListIdentity and discovery.
//!
//! [`CipConnection`] is the connection state and every operation on it; [`CipDriver`] wraps it in a mutex so a
//! handle can be shared between threads, one request/reply at a time. The Logix and SLC drivers build on the
//! connection, holding its lock across multi-step operations.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::browse::{Node, PortInfo};
use crate::epath::{LogicalValue, Segment, encode_epath, parse_cip_route, parse_connection_path};
use crate::identity::{ListIdentity, ModuleIdentity};
use crate::packets::{self, Encap, ForwardOpen, Reply, ReplyKind};
use crate::reader::Reader;
use crate::transport::{Connector, Transport, tcp_connector};
use crate::{Error, ErrorKind, Result, TagError, Value};

const DEFAULT_PORT: u16 = 44818;
const CONTEXT: [u8; 8] = *b"_pycomm_";
const PROTOCOL_VERSION: u16 = 1;
const VENDOR_ID: [u8; 2] = [0x09, 0x10];
const NO_SESSION: &str = "A session must be registered before a Forward Open (call open() again after a connection error)";
/// Python's `with_forward_open` reports the decorated function, a lambda for generic messages.
const GENERIC_CALLER: &str = "<lambda>";
/// The longest one discovery broadcast collects replies (Python has no limit).
const DISCOVER_LIMIT: Duration = Duration::from_secs(10);

/// Connection options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipOptions {
    /// Timeout of connecting, sends and receives; None blocks forever. Default 5 s.
    pub socket_timeout: Option<Duration>,
    /// Maximum connected message size, 1 to 65535; above 511 uses a Large Forward Open. Default 4000.
    pub connection_size: u16,
}

impl Default for CipOptions {
    fn default() -> Self {
        CipOptions {
            socket_timeout: Some(Duration::from_secs(5)),
            connection_size: 4000,
        }
    }
}

/// The route of an Unconnected Send ([`GenericMessage::route_path`]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum RoutePath {
    /// The connection path of the driver.
    #[default]
    Current,
    /// No route.
    None,
    /// A route such as `bp/2` or `1/0/2/10.1.1.1`.
    Text(String),
    /// Route segments (none means no route).
    Segments(Vec<Segment>),
    /// An encoded route path (size in words, pad byte, segments).
    Encoded(Vec<u8>),
}

/// A generic CIP message, like a Logix MSG instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericMessage {
    /// Service code.
    pub service: u8,
    /// Class of the object addressed.
    pub class_code: LogicalValue,
    /// Instance of the object, 0 for the class attributes.
    pub instance: LogicalValue,
    /// Attribute, None (or 0, or empty) for none.
    pub attribute: Option<LogicalValue>,
    /// Request data following the request path.
    pub request_data: Vec<u8>,
    /// Name returned in [`TagResult::tag`].
    pub name: String,
    /// Send over the CIP connection (Forward Open first if needed), else unconnected (UCMM).
    pub connected: bool,
    /// Unconnected only: wrap the message in an Unconnected Send along `route_path`.
    pub unconnected_send: bool,
    /// Route of the Unconnected Send; ignored unless `unconnected_send`.
    pub route_path: RoutePath,
}

impl Default for GenericMessage {
    fn default() -> Self {
        GenericMessage {
            service: 0,
            class_code: LogicalValue::Int(0),
            instance: LogicalValue::Int(0),
            attribute: None,
            request_data: Vec::new(),
            name: "generic".into(),
            connected: true,
            unconnected_send: false,
            route_path: RoutePath::Current,
        }
    }
}

/// The result of reading or writing one tag, or of a generic message (the Python `Tag`).
#[derive(Clone, Debug, PartialEq)]
pub struct TagResult {
    /// Tag name, or the name of a generic message.
    pub tag: String,
    /// Value read or written, None on error.
    pub value: Option<Value>,
    /// Data type name.
    pub data_type: Option<String>,
    /// Error, None on success.
    pub error: Option<TagError>,
}

impl TagResult {
    /// True if there is a value and no error (Python's `bool(tag)`).
    pub fn is_ok(&self) -> bool {
        self.value.is_some() && self.error.is_none()
    }

    /// The kind of the error, None without one.
    pub fn error_kind(&self) -> Option<ErrorKind> {
        self.error.as_ref().map(|e| e.kind)
    }
}

/// The reply to a generic message: the result with the raw reply data as its value, and the parsed reply.
#[derive(Clone, Debug, PartialEq)]
pub struct GenericReply {
    /// Name, reply data as [`Value::Bytes`] (None if the reply had none), and the error (of kind Other).
    pub tag: TagResult,
    /// The parsed reply.
    pub reply: Reply,
}

impl GenericReply {
    /// The reply data, None when the reply carried none.
    pub fn data(&self) -> Option<&[u8]> {
        self.reply.data.as_deref()
    }

    /// True if the message succeeded (Python's `bool(tag)`).
    pub fn is_ok(&self) -> bool {
        self.tag.is_ok()
    }
}

/// The connection state of a CIP driver and the operations on it.
///
/// Matches the Python `CIPDriver`: the same requests in the same order, the same sequence counter, the same
/// packing and fallback decisions. A transport failure in the middle of a request drops the connection.
pub struct CipConnection {
    connector: Arc<Connector>,
    transport: Option<Box<dyn Transport>>,
    path: String,
    host: String,
    port: u16,
    cip_path: Vec<Segment>,
    session: u32,
    connection_opened: bool,
    target_cid: Option<Vec<u8>>,
    target_is_connected: bool,
    next_sequence: u16,
    connection_size: u16,
    extended_forward_open: bool,
    socket_timeout: Option<Duration>,
    csn: [u8; 2],
    vsn: [u8; 4],
}

fn check_connection_size(size: u16) -> Result<()> {
    if size == 0 {
        return Err(Error::request(
            "connection_size must be an integer between 1 and 65535",
        ));
    }
    Ok(())
}

fn check_socket_timeout(timeout: Option<Duration>) -> Result<()> {
    if timeout.is_some_and(|t| t.is_zero()) {
        return Err(Error::request(
            "socket_timeout must be a positive finite number or None",
        ));
    }
    Ok(())
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::comm("failed to generate a connection ID"))?;
    Ok(out)
}

impl CipConnection {
    /// A closed connection to `path` (`ip[:port][/port/link...]`, see
    /// [`parse_connection_path`]); `auto_slot` makes a bare IP mean `bp/0` and `ip/n` slot n (Logix).
    pub fn new(
        path: &str,
        options: CipOptions,
        connector: Connector,
        auto_slot: bool,
    ) -> Result<Self> {
        let (host, port, cip_path) = parse_connection_path(path, auto_slot)?;
        check_socket_timeout(options.socket_timeout)?;
        check_connection_size(options.connection_size)?;
        Ok(CipConnection {
            connector: Arc::new(connector),
            transport: None,
            path: path.to_owned(),
            host,
            port: port.unwrap_or(DEFAULT_PORT),
            cip_path,
            session: 0,
            connection_opened: false,
            target_cid: None,
            target_is_connected: false,
            next_sequence: 1,
            connection_size: options.connection_size,
            extended_forward_open: options.connection_size > 511,
            socket_timeout: options.socket_timeout,
            csn: [0x27, 0x04],
            vsn: [0x09, 0x10, 0x19, 0x71],
        })
    }

    /// A connector opening transports like this connection's (for another connection to the same device).
    pub(crate) fn share_connector(&self) -> Connector {
        let connector = Arc::clone(&self.connector);
        Box::new(move |host, port, timeout| connector(host, port, timeout))
    }

    /// The path the connection was created with.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Host (IP address or name) of the target.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// TCP port of the target.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The route from the target to the controller.
    pub fn cip_path(&self) -> &[Segment] {
        &self.cip_path
    }

    /// The route, to change (the Logix driver drops the slot of a Micro800).
    pub fn cip_path_mut(&mut self) -> &mut Vec<Segment> {
        &mut self.cip_path
    }

    /// True while a session is registered.
    pub fn connected(&self) -> bool {
        self.connection_opened
    }

    /// True while the CIP connection (Forward Open) is open.
    pub fn target_connected(&self) -> bool {
        self.target_is_connected
    }

    /// Session handle, 0 without a session.
    pub fn session(&self) -> u32 {
        self.session
    }

    /// Connection ID the target assigned in the Forward Open reply.
    pub fn target_cid(&self) -> Option<&[u8]> {
        self.target_cid.as_deref()
    }

    /// Maximum connected message size.
    pub fn connection_size(&self) -> u16 {
        self.connection_size
    }

    /// True if the next Forward Open is a Large Forward Open.
    pub fn extended_forward_open(&self) -> bool {
        self.extended_forward_open
    }

    /// Sets the connection size (1 to 65535) used by the next Forward Open; a RequestError while connected.
    pub fn set_connection_size(&mut self, size: u16) -> Result<()> {
        check_connection_size(size)?;
        if self.target_is_connected {
            return Err(Error::request(
                "Close the connection before changing connection_size",
            ));
        }
        self.connection_size = size;
        self.extended_forward_open = size > 511;
        Ok(())
    }

    /// The socket timeout.
    pub fn socket_timeout(&self) -> Option<Duration> {
        self.socket_timeout
    }

    /// Sets the socket timeout, applying it to an open transport too; None blocks forever.
    pub fn set_socket_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        check_socket_timeout(timeout)?;
        if let Some(transport) = self.transport.as_mut() {
            transport.set_timeout(timeout)?;
        }
        self.socket_timeout = timeout;
        Ok(())
    }

    /// Takes the next sequence count: 1 to 65535, then 1 again. Every connected request takes one when it is
    /// built, sent or not.
    pub fn next_sequence(&mut self) -> u16 {
        let sequence = self.next_sequence;
        self.next_sequence = if sequence == u16::MAX {
            1
        } else {
            sequence + 1
        };
        sequence
    }

    /// The encapsulation values of the next request.
    pub fn encap(&self) -> Encap {
        Encap {
            session: self.session,
            context: CONTEXT,
            option: 0,
        }
    }

    /// Opens the transport and registers a session; Ok(false) if the target refused the session. A
    /// CommError if the connection could not be made. Does nothing if a session is registered.
    pub fn open(&mut self) -> Result<bool> {
        if self.connection_opened {
            return Ok(true);
        }
        match self.try_open() {
            Ok(true) => Ok(true),
            Ok(false) => {
                log::error!("Session not registered");
                self.drop_connection();
                Ok(false)
            }
            Err(err) => {
                log::debug!("open failed: {err}");
                self.drop_connection();
                Err(Error::comm("failed to open a connection"))
            }
        }
    }

    fn try_open(&mut self) -> Result<bool> {
        if self.transport.is_none() {
            log::debug!("Opening connection to {}", self.host);
            self.transport = Some((self.connector)(
                &self.host,
                self.port,
                self.socket_timeout,
            )?);
        }
        self.connection_opened = true;
        Ok(self.register_session()? != 0)
    }

    /// The session handle, registering one if none is (0 if refused).
    fn register_session(&mut self) -> Result<u32> {
        if self.session != 0 {
            return Ok(self.session);
        }
        let frame = packets::register_session_request(&self.encap(), PROTOCOL_VERSION, 0);
        let reply = self.request(&frame, ReplyKind::RegisterSession)?;
        match reply.session.filter(|_| reply.is_valid()) {
            Some(session) => {
                self.session = session;
                log::info!("Session={session} has been registered.");
                Ok(session)
            }
            None => {
                log::error!(
                    "Failed to register session: {}",
                    reply.error().unwrap_or_default()
                );
                Ok(0)
            }
        }
    }

    /// Closes the CIP connection and the session and drops the transport. Every step is tried; their
    /// errors are joined into one CommError.
    pub fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if self.target_is_connected {
            if let Err(err) = self.forward_close() {
                log::error!("Error closing connection with device: {err}");
                errors.push(err.to_string());
            }
        }
        // read after the Forward Close: a transport error there has already dropped the session
        if self.session != 0 {
            if let Err(err) = self.unregister_session() {
                log::error!("Error closing connection with device: {err}");
                errors.push(err.to_string());
            }
        }
        self.drop_connection();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::comm(errors.join(" - ")))
        }
    }

    fn unregister_session(&mut self) -> Result<()> {
        let frame = packets::unregister_session_request(&self.encap());
        self.transact(&frame, false)?;
        self.session = 0;
        log::info!("Session Unregistered");
        Ok(())
    }

    /// Forgets the session and CIP connection and closes the transport.
    pub fn drop_connection(&mut self) {
        self.transport = None;
        self.target_cid = None;
        self.target_is_connected = false;
        self.session = 0;
        self.connection_opened = false;
    }

    /// Opens the CIP connection unless it is open (Python's `with_forward_open`): a Large Forward Open,
    /// then a standard one of 500 bytes if that is rejected. A ResponseError naming `caller` if both are.
    pub fn ensure_forward_open(&mut self, caller: &str) -> Result<()> {
        if self.target_is_connected {
            return Ok(());
        }
        let mut opened = false;
        if self.extended_forward_open {
            log::info!("Attempting an Extended Forward Open...");
        }
        if self.forward_open()? {
            opened = true;
        } else if self.extended_forward_open {
            log::info!("Extended Forward Open failed, attempting standard Forward Open.");
            let size = self.connection_size;
            self.extended_forward_open = false;
            self.connection_size = 500;
            let result = self.forward_open();
            opened = matches!(result, Ok(true));
            if !opened {
                // no evidence the Large Forward Open is unsupported
                self.extended_forward_open = true;
                self.connection_size = size;
            }
            result?;
        }
        if !opened {
            return Err(Error::response(format!(
                "Target did not connected. {caller} will not be executed."
            )));
        }
        Ok(())
    }

    /// One (Large) Forward Open with a fresh connection triad; Ok(false) if the target rejected it.
    pub fn forward_open(&mut self) -> Result<bool> {
        if self.target_is_connected {
            return Ok(true);
        }
        if self.session == 0 {
            return Err(Error::comm(NO_SESSION));
        }
        // a fresh triad per attempt: a retry must not look like the rejected connection
        let cid = random::<4>()?;
        self.csn = random::<2>()?;
        self.vsn = random::<4>()?;
        let params = ForwardOpen {
            cid,
            csn: self.csn,
            vid: VENDOR_ID,
            vsn: self.vsn,
            connection_size: u32::from(self.connection_size),
            large: self.extended_forward_open,
        };
        let data = packets::forward_open_data(&params, &self.cip_path)?;
        let service = if self.extended_forward_open {
            packets::LARGE_FORWARD_OPEN
        } else {
            packets::FORWARD_OPEN
        };
        let reply = self.generic_message(&connection_manager(service, data, "forward_open"))?;
        if reply.is_ok() {
            let data = reply.data().unwrap_or_default();
            self.target_cid = Some(data[..data.len().min(4)].to_vec());
            self.target_is_connected = true;
            log::info!(
                "{}Forward Open succeeded. Target CID={:02x?}",
                if self.extended_forward_open {
                    "Extended "
                } else {
                    ""
                },
                self.target_cid
            );
            return Ok(true);
        }
        log::error!("forward_open failed - {}", error_text(&reply.tag));
        Ok(false)
    }

    /// Forward Close of the CIP connection; Ok(false) if the target rejected it.
    pub fn forward_close(&mut self) -> Result<bool> {
        if self.session == 0 {
            return Err(Error::comm(NO_SESSION));
        }
        let data = packets::forward_close_data(&self.csn, &VENDOR_ID, &self.vsn, &self.cip_path)?;
        let reply = self.generic_message(&connection_manager(
            packets::FORWARD_CLOSE,
            data,
            "forward_close",
        ))?;
        if reply.is_ok() {
            self.target_is_connected = false;
            log::info!("Forward Close succeeded.");
            return Ok(true);
        }
        log::error!("forward_close failed: {}", error_text(&reply.tag));
        Ok(false)
    }

    /// Sends a frame and receives its reply frame (none if `expect_reply` is false), one exchange at a
    /// time. Any transport failure drops the connection: a late reply would answer the next request.
    pub fn transact(&mut self, frame: &[u8], expect_reply: bool) -> Result<Option<Vec<u8>>> {
        let Some(transport) = self.transport.as_mut() else {
            self.drop_connection();
            return Err(Error::comm("failed to send message"));
        };
        log::trace!(">>> SEND >>> {frame:02x?}");
        if let Err(err) = transport.send(frame) {
            log::debug!("send failed: {err}");
            self.drop_connection();
            return Err(Error::comm("failed to send message"));
        }
        if !expect_reply {
            return Ok(None);
        }
        match transport.receive() {
            Ok(reply) => {
                log::trace!("<<< RECEIVE <<< {reply:02x?}");
                Ok(Some(reply))
            }
            Err(err) => {
                log::debug!("receive failed: {err}");
                self.drop_connection();
                Err(Error::comm("failed to receive reply"))
            }
        }
    }

    fn request(&mut self, frame: &[u8], kind: ReplyKind) -> Result<Reply> {
        let raw = self.transact(frame, true)?.unwrap_or_default();
        Ok(Reply::parse(kind, &raw))
    }

    /// Sends a connected CIP message (without its sequence count) with `sequence` from
    /// [`next_sequence`](Self::next_sequence) and returns the raw reply frame. Does not open the CIP
    /// connection.
    pub fn send_connected(&mut self, sequence: u16, message: &[u8]) -> Result<Vec<u8>> {
        let frame = packets::send_unit_data_request(
            &self.encap(),
            self.target_cid.as_deref().unwrap_or_default(),
            sequence,
            message,
        )?;
        Ok(self.transact(&frame, true)?.unwrap_or_default())
    }

    /// Sends an unconnected CIP message (SendRRData) and returns the raw reply frame.
    pub fn send_unconnected(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let frame = packets::send_rr_data_request(&self.encap(), message)?;
        Ok(self.transact(&frame, true)?.unwrap_or_default())
    }

    /// Sends a generic message. Its failure is in the result; Err for a connection failure, a Forward Open
    /// the target rejected, or a request that cannot be encoded.
    pub fn generic_message(&mut self, msg: &GenericMessage) -> Result<GenericReply> {
        let attribute = msg.attribute.clone();
        let reply = if msg.connected {
            self.ensure_forward_open(GENERIC_CALLER)?;
            let sequence = self.next_sequence();
            let message = packets::generic_message(
                msg.service,
                msg.class_code.clone(),
                msg.instance.clone(),
                attribute,
                &msg.request_data,
            )?;
            log::info!("Sending generic message: {}", msg.name);
            let raw = self.send_connected(sequence, &message)?;
            Reply::parse(ReplyKind::SendUnitData, &raw)
        } else {
            let route = self.route_path(&msg.route_path)?;
            let message = packets::generic_unconnected_message(
                msg.service,
                msg.class_code.clone(),
                msg.instance.clone(),
                attribute,
                &msg.request_data,
                &route,
                msg.unconnected_send,
            )?;
            log::info!("Sending generic message: {}", msg.name);
            let raw = self.send_unconnected(&message)?;
            Reply::parse(ReplyKind::SendRRData, &raw)
        };
        let error = reply.error();
        match &error {
            Some(err) => log::error!("Generic message {:?} failed: {err}", msg.name),
            None => log::info!("Generic message {:?} completed", msg.name),
        }
        Ok(GenericReply {
            tag: TagResult {
                tag: msg.name.clone(),
                value: reply.data.clone().map(Value::Bytes),
                data_type: None,
                // Python's generic message error is a plain string, its kind is OTHER
                error: error.map(|e| TagError::new(e, ErrorKind::Other)),
            },
            reply,
        })
    }

    /// The encoded route of an Unconnected Send (computed even when unused, as in Python).
    fn route_path(&self, route: &RoutePath) -> Result<Vec<u8>> {
        let encode = |segments: &[Segment]| encode_epath(segments, true, true, true);
        match route {
            RoutePath::Current => encode(&self.cip_path),
            RoutePath::None => Ok(Vec::new()),
            RoutePath::Text(text) => encode(&parse_cip_route(text, false)?),
            RoutePath::Segments(segments) if segments.is_empty() => Ok(Vec::new()),
            RoutePath::Segments(segments) => encode(segments),
            RoutePath::Encoded(bytes) => Ok(bytes.clone()),
        }
    }

    /// The target's identity by ListIdentity over the session, None if the reply was not usable.
    pub fn list_identity(&mut self) -> Result<Option<ListIdentity>> {
        let frame = packets::list_identity_request(&self.encap());
        Ok(self.request(&frame, ReplyKind::ListIdentity)?.identity)
    }

    /// The identity of the module in `slot` of the rack at the end of the connection path. CommErrors
    /// pass through; any other failure is a ResponseError "error getting module info".
    pub fn get_module_info(&mut self, slot: i64) -> Result<ModuleIdentity> {
        match self.module_info(slot) {
            Err(err @ Error::Comm(_)) => Err(err),
            Err(err) => {
                log::debug!("get_module_info failed: {err}");
                Err(Error::response("error getting module info"))
            }
            ok => ok,
        }
    }

    fn module_info(&mut self, slot: i64) -> Result<ModuleIdentity> {
        let mut route = self.cip_path[..self.cip_path.len().saturating_sub(1)].to_vec();
        route.push(Segment::port("bp", slot));
        let msg = GenericMessage {
            service: 0x01,                       // Get_Attributes_All
            class_code: LogicalValue::Int(0x01), // Identity Object
            instance: LogicalValue::Raw(vec![0x01]),
            name: "get_module_info".into(),
            connected: false,
            unconnected_send: true,
            route_path: RoutePath::Encoded(encode_epath(&route, true, true, true)?),
            ..GenericMessage::default()
        };
        let reply = self.generic_message(&msg)?;
        if !reply.is_ok() {
            return Err(Error::response(format!(
                "generic_message did not return valid data - {}",
                error_text(&reply.tag)
            )));
        }
        ModuleIdentity::decode(&mut Reader::new(reply.data().unwrap_or_default()))
    }
}

fn connection_manager(service: u8, request_data: Vec<u8>, name: &str) -> GenericMessage {
    GenericMessage {
        service,
        class_code: LogicalValue::Int(packets::CONNECTION_MANAGER.into()),
        instance: LogicalValue::Int(1), // the Connection Manager has a single instance
        request_data,
        name: name.into(),
        connected: false,
        ..GenericMessage::default()
    }
}

fn error_text(tag: &TagResult) -> String {
    tag.error
        .as_ref()
        .map_or_else(|| "None".into(), |e| e.message.clone())
}

/// A CIP driver handle that can be shared between threads.
pub struct CipDriver {
    conn: Mutex<CipConnection>,
}

impl CipDriver {
    /// A driver for `path` over TCP; not connected until [`open`](Self::open).
    pub fn new(path: &str, options: CipOptions) -> Result<Self> {
        Self::with_connector(path, options, tcp_connector())
    }

    /// A driver opening its transports with `connector` (a test fake, or a custom transport).
    pub fn with_connector(path: &str, options: CipOptions, connector: Connector) -> Result<Self> {
        Ok(Self::from_connection(CipConnection::new(
            path, options, connector, false,
        )?))
    }

    /// A driver around a connection.
    pub fn from_connection(conn: CipConnection) -> Self {
        CipDriver {
            conn: Mutex::new(conn),
        }
    }

    /// Locks the connection, for several requests that must not interleave with other threads'.
    ///
    /// If a thread panicked while holding the lock, the connection is dropped first (a reply may be left
    /// unread on the transport) and the driver stays usable: the next `open()` reconnects.
    pub fn lock(&self) -> MutexGuard<'_, CipConnection> {
        match self.conn.lock() {
            Ok(conn) => conn,
            Err(poisoned) => {
                let mut conn = poisoned.into_inner();
                conn.drop_connection();
                self.conn.clear_poison();
                conn
            }
        }
    }

    /// Opens the transport and registers a session; Ok(false) if the target refused the session.
    pub fn open(&self) -> Result<bool> {
        self.lock().open()
    }

    /// Closes the CIP connection and session; see [`CipConnection::close`].
    pub fn close(&self) -> Result<()> {
        self.lock().close()
    }

    /// True while a session is registered.
    pub fn connected(&self) -> bool {
        self.lock().connected()
    }

    /// Maximum connected message size.
    pub fn connection_size(&self) -> u16 {
        self.lock().connection_size()
    }

    /// Sets the connection size used by the next Forward Open.
    pub fn set_connection_size(&self, size: u16) -> Result<()> {
        self.lock().set_connection_size(size)
    }

    /// The socket timeout.
    pub fn socket_timeout(&self) -> Option<Duration> {
        self.lock().socket_timeout()
    }

    /// Sets the socket timeout.
    pub fn set_socket_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.lock().set_socket_timeout(timeout)
    }

    /// Sends a generic message; see [`CipConnection::generic_message`].
    pub fn generic_message(&self, msg: &GenericMessage) -> Result<GenericReply> {
        self.lock().generic_message(msg)
    }

    /// Takes the next sequence count.
    pub fn next_sequence(&self) -> u16 {
        self.lock().next_sequence()
    }

    /// Sends a connected CIP message (without sequence count) with the next sequence count and returns the
    /// raw reply frame. Does not open the CIP connection.
    pub fn send_connected_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut conn = self.lock();
        let sequence = conn.next_sequence();
        conn.send_connected(sequence, message)
    }

    /// Sends an unconnected CIP message and returns the raw reply frame.
    pub fn send_unconnected_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.lock().send_unconnected(message)
    }

    /// The identity of the module in `slot` of the rack at the end of the connection path.
    pub fn get_module_info(&self, slot: i64) -> Result<ModuleIdentity> {
        self.lock().get_module_info(slot)
    }

    /// The identity of the device at `route` (see [`crate::browse`]).
    pub fn identity_at(&self, route: &str) -> Result<ModuleIdentity> {
        self.lock().identity_at(route)
    }

    /// The ports of the device at `route` (see [`crate::browse`]).
    pub fn ports_at(&self, route: &str) -> Result<Vec<PortInfo>> {
        self.lock().ports_at(route)
    }

    /// Probes the slots, nodes or IP addresses on `port` of the device at `route` (`nodes`, by default the
    /// port's own) from `workers` connections at once; the nodes in address order (see [`crate::browse`]).
    pub fn browse_port(
        &self,
        route: &str,
        port: u16,
        nodes: Option<&[String]>,
        workers: usize,
    ) -> Result<Vec<Node>> {
        let scan = self.lock().scan(route, port, nodes)?;
        Ok(scan.collect(workers))
    }

    /// [`browse_port`](Self::browse_port), calling `found` with each node as it answers (in any order) until it
    /// returns false.
    pub fn scan_port(
        &self,
        route: &str,
        port: u16,
        nodes: Option<&[String]>,
        workers: usize,
        found: &mut dyn FnMut(Node) -> bool,
    ) -> Result<()> {
        let scan = self.lock().scan(route, port, nodes)?;
        scan.run(workers, found);
        Ok(())
    }

    /// Identifies the target at `path` with ListIdentity over a session of its own; None if the session or
    /// reply was refused.
    pub fn list_identity(path: &str) -> Result<Option<ListIdentity>> {
        Self::list_identity_with(path, CipOptions::default(), tcp_connector(), false)
    }

    /// [`list_identity`](Self::list_identity) with options, a connector and Logix path parsing.
    pub fn list_identity_with(
        path: &str,
        options: CipOptions,
        connector: Connector,
        auto_slot: bool,
    ) -> Result<Option<ListIdentity>> {
        let mut conn = CipConnection::new(path, options, connector, auto_slot)?;
        let result = conn
            .open()
            .and_then(|ok| if ok { conn.list_identity() } else { Ok(None) });
        conn.close()?; // as Python's finally: an error closing replaces the result
        result
    }

    /// Discovers EtherNet/IP devices by broadcasting ListIdentity to `broadcast` (`255.255.255.255`) from
    /// every network adapter at once, then unbound if none answered.
    pub fn discover(broadcast: &str) -> Vec<ListIdentity> {
        log::info!("Discovering devices...");
        // one broadcast per network adapter, all at once: each waits a second for its last reply
        let mut devices: Vec<ListIdentity> = std::thread::scope(|scope| {
            let broadcasts: Vec<_> = local_addresses()
                .into_iter()
                .map(|ip| {
                    scope.spawn(move || {
                        log::debug!("Broadcasting discover for IP: {ip}");
                        Self::discover_at(Some(IpAddr::V4(ip)), broadcast, DEFAULT_PORT)
                    })
                })
                .collect();
            broadcasts
                .into_iter()
                .flat_map(|b| b.join().unwrap_or_default())
                .collect()
        });
        if devices.is_empty() {
            log::debug!("No devices found so far, attempting broadcast without binding to an IP.");
            devices.extend(Self::discover_at(None, broadcast, DEFAULT_PORT));
        }
        log::info!("Discovered {} device(s)", devices.len());
        devices
    }

    /// One discovery broadcast to `broadcast:port` from `bind` (any address if None), collecting replies
    /// until none arrives for a second. Failures are logged, not returned.
    #[doc(hidden)]
    pub fn discover_at(bind: Option<IpAddr>, broadcast: &str, port: u16) -> Vec<ListIdentity> {
        let mut devices = Vec::new();
        if let Err(err) = broadcast_discover(bind, broadcast, port, DISCOVER_LIMIT, &mut devices) {
            log::error!("Error broadcasting discover request: {err}");
        }
        devices
    }
}

fn broadcast_discover(
    bind: Option<IpAddr>,
    broadcast: &str,
    port: u16,
    limit: Duration,
    devices: &mut Vec<ListIdentity>,
) -> std::io::Result<()> {
    let bind = bind.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let sock = UdpSocket::bind(SocketAddr::new(bind, 0))?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
    sock.set_broadcast(true)?;
    let message = packets::list_identity_request(&Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    });
    sock.send_to(&message, (broadcast, port))?;
    let mut buf = [0u8; 4096];
    // until the timeout (or any error) ends it, as in Python; the limit stops a sender that never pauses
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        let Ok(n) = sock.recv(&mut buf) else { break };
        let reply = Reply::parse(ReplyKind::ListIdentity, &buf[..n]);
        if reply.is_valid() {
            devices.extend(reply.identity);
        }
    }
    Ok(())
}

/// The IPv4 address of every network adapter that is up, loopback excluded, each once.
fn local_addresses() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if let if_addrs::IfAddr::V4(v4) = interface.addr
            && !v4.ip.is_loopback()
            && !out.contains(&v4.ip)
        {
            out.push(v4.ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> CipConnection {
        let connector: Connector = Box::new(|_, _, _| Err(Error::comm("no network in unit tests")));
        CipConnection::new("127.0.0.1", CipOptions::default(), connector, false).expect("path")
    }

    #[test]
    fn discover_stops_at_its_time_limit_when_replies_keep_coming() {
        // a device (or anything on the port) answering faster than the 1 s read timeout must not hold
        // discover forever
        let responder = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let port = responder.local_addr().expect("addr").port();
        let chatter = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, from) = responder.recv_from(&mut buf).expect("request");
            for _ in 0..40 {
                let _ = responder.send_to(b"not a reply", from);
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let start = std::time::Instant::now();
        let mut devices = Vec::new();
        broadcast_discover(
            None,
            "127.0.0.1",
            port,
            Duration::from_millis(300),
            &mut devices,
        )
        .expect("discover");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        assert!(devices.is_empty());
        chatter.join().expect("join");
    }

    #[test]
    fn sequence_counts_from_one_and_wraps_after_65535_to_one() {
        let mut c = conn();
        assert_eq!(c.next_sequence(), 1);
        assert_eq!(c.next_sequence(), 2);
        for _ in 3..65535 {
            c.next_sequence();
        }
        assert_eq!(c.next_sequence(), 65535);
        assert_eq!(c.next_sequence(), 1);
    }

    #[test]
    fn connection_size_selects_forward_open_format() {
        for (size, large) in [
            (100, false),
            (500, false),
            (511, false),
            (512, true),
            (4000, true),
        ] {
            let opts = CipOptions {
                connection_size: size,
                ..CipOptions::default()
            };
            let c = CipConnection::new("127.0.0.1", opts, tcp_connector(), false).expect("new");
            assert_eq!(c.connection_size(), size);
            assert_eq!(c.extended_forward_open(), large, "{size}");
        }
    }

    #[test]
    fn invalid_options_are_rejected() {
        let size = CipOptions {
            connection_size: 0,
            ..CipOptions::default()
        };
        assert!(CipConnection::new("127.0.0.1", size, tcp_connector(), false).is_err());
        let timeout = CipOptions {
            socket_timeout: Some(Duration::ZERO),
            ..CipOptions::default()
        };
        assert!(CipConnection::new("127.0.0.1", timeout, tcp_connector(), false).is_err());
        let none = CipOptions {
            socket_timeout: None,
            ..CipOptions::default()
        };
        assert!(CipConnection::new("127.0.0.1", none, tcp_connector(), false).is_ok());
    }

    #[test]
    fn unconnected_send_timeout_is_below_socket_timeout() {
        // router timeout = 2^(priority & 0x0F) ms * ticks, priority 0x0A and 4 ticks
        let router_ms = (1u64 << (0x0A & 0x0F)) * 4;
        let socket = CipOptions::default().socket_timeout.expect("default");
        assert!(Duration::from_millis(router_ms) < socket);
    }

    #[test]
    fn forward_open_and_close_need_a_session() {
        let mut c = conn();
        let want = Err(Error::comm(NO_SESSION));
        assert_eq!(c.forward_open(), want);
        assert_eq!(c.forward_close(), want);
        assert_eq!(c.ensure_forward_open("read"), Err(Error::comm(NO_SESSION)));
    }

    #[test]
    fn transact_without_transport_is_a_send_failure() {
        let mut c = conn();
        assert_eq!(
            c.transact(b"x", true),
            Err(Error::comm("failed to send message"))
        );
    }

    #[test]
    fn open_connect_failure_is_a_comm_error_and_leaves_it_closed() {
        let mut c = conn();
        assert_eq!(c.open(), Err(Error::comm("failed to open a connection")));
        assert!(!c.connected());
    }
}
