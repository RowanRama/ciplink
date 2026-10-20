//! The SLC 500 / MicroLogix driver (Python `SLCDriver`): data file reads and writes over PCCC Execute
//! messages on a CIP connection, the processor type, data log queues and the file directory.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use indexmap::IndexMap;

use crate::cip::{CipConnection, CipDriver, CipOptions, TagResult};
use crate::identity::ListIdentity;
use crate::packets::{Reply, ReplyKind};
use crate::slc::pccc::{
    self, Address, DataFile, FILE_DIRECTORY_CHUNK, Requestor, SLC_REPLY_START, Sys0Info,
};
use crate::transport::{Connector, Transport, tcp_connector};
use crate::{Error, ErrorKind, Result, TagError, Value};

/// The vendor ID the CIP driver sends in its Forward Open, and so in every PCCC requestor ID.
const VENDOR_ID: [u8; 2] = [0x09, 0x10];
/// The vendor serial number before the first Forward Open (Python's `_cfg["vsn"]` default).
const DEFAULT_VSN: [u8; 4] = [0x09, 0x10, 0x19, 0x71];

/// An EtherNet/IP driver for the data files of SLC 500 and MicroLogix processors.
///
/// Like the Python `SLCDriver`: a bare IP address routes to `bp/0` and `ip/n` to slot n of the backplane,
/// the default connection size is 500 (a standard Forward Open), and every call opens the CIP connection
/// first if it is not open. One call runs at a time; the connection is locked for its whole duration.
pub struct SlcDriver {
    cip: CipDriver,
    /// The vendor serial number of the latest Forward Open, which Python also sends as the requestor ID.
    vsn: Arc<Mutex<[u8; 4]>>,
}

impl SlcDriver {
    /// The SLC defaults: 5 s socket timeout, connection size 500.
    pub fn default_options() -> CipOptions {
        CipOptions {
            socket_timeout: Some(Duration::from_secs(5)),
            connection_size: 500,
        }
    }

    /// A driver for `path` (`ip[:port][/slot]` or `ip/port/link/...`) over TCP; not connected until
    /// [`open`](Self::open).
    pub fn new(path: &str, options: CipOptions) -> Result<Self> {
        Self::with_connector(path, options, tcp_connector())
    }

    /// A driver opening its transports with `connector`.
    pub fn with_connector(path: &str, options: CipOptions, connector: Connector) -> Result<Self> {
        let vsn = Arc::new(Mutex::new(DEFAULT_VSN));
        let conn = CipConnection::new(path, options, watch_vsn(connector, vsn.clone()), true)?;
        Ok(SlcDriver {
            cip: CipDriver::from_connection(conn),
            vsn,
        })
    }

    /// The CIP driver underneath (generic messages, connection settings, module info).
    ///
    /// Its [`lock`](CipDriver::lock) is the lock every `SlcDriver` call takes: do not call `SlcDriver`
    /// methods on the same thread while holding that guard, or the call deadlocks.
    pub fn cip(&self) -> &CipDriver {
        &self.cip
    }

    /// Opens the transport and registers a session; Ok(false) if the target refused the session.
    pub fn open(&self) -> Result<bool> {
        self.cip.open()
    }

    /// Closes the CIP connection and the session.
    pub fn close(&self) -> Result<()> {
        self.cip.close()
    }

    /// True while a session is registered.
    pub fn connected(&self) -> bool {
        self.cip.connected()
    }

    /// Identifies the target at `path` (SLC path rules) with ListIdentity over a session of its own.
    pub fn list_identity(path: &str) -> Result<Option<ListIdentity>> {
        CipDriver::list_identity_with(path, Self::default_options(), tcp_connector(), true)
    }

    fn requestor(&self) -> Requestor {
        Requestor {
            vid: VENDOR_ID,
            vsn: *self.vsn.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Reads data file addresses, one request each; add a word count in braces to read several elements
    /// (`N7:0{10}`). A PCCC or CIP error is the result's error; an invalid address is a RequestError (the
    /// addresses before it have been read), and a connection failure is a CommError.
    pub fn read(&self, addresses: &[&str]) -> Result<Vec<TagResult>> {
        let mut conn = self.cip.lock();
        conn.ensure_forward_open("read")?;
        let mut results = Vec::with_capacity(addresses.len());
        for address in addresses {
            results.push(self.read_tag(&mut conn, address)?);
        }
        Ok(results)
    }

    fn read_tag(&self, conn: &mut CipConnection, tag: &str) -> Result<TagResult> {
        let built = pccc::read_request(tag, &self.requestor(), 0);
        let (addr, message) = with_transaction(conn, built)?;
        let raw = send(conn, &message)?;
        log::debug!("SLC read_tag({tag})");
        if let Some(status) = request_status(&raw) {
            return Ok(failed(&addr, status));
        }
        Ok(
            match pccc::parse_read_reply(&addr, &raw[SLC_REPLY_START.min(raw.len())..]) {
                Ok(value) => TagResult {
                    tag: addr.tag.clone(),
                    value: Some(value),
                    data_type: Some(addr.file_type.name().into()),
                    error: None,
                },
                Err(err) => {
                    log::error!("Failed to parse read reply for {}", addr.tag);
                    failed(&addr, err.to_string())
                }
            },
        )
    }

    /// Writes values to data file addresses, one request each; a multi-element address (`N7:0{3}`) takes a
    /// list of at least that many values. Errors as [`read`](Self::read); a value that does not fit is a
    /// RequestError.
    pub fn write(&self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        let mut conn = self.cip.lock();
        conn.ensure_forward_open("write")?;
        let mut results = Vec::with_capacity(items.len());
        for (tag, value) in items {
            results.push(self.write_tag(&mut conn, tag, value)?);
        }
        Ok(results)
    }

    fn write_tag(&self, conn: &mut CipConnection, tag: &str, value: &Value) -> Result<TagResult> {
        let built = pccc::write_request(tag, value, &self.requestor(), 0);
        let (addr, message) = with_transaction(conn, built)?;
        let raw = send(conn, &message)?;
        if let Some(status) = request_status(&raw) {
            return Ok(failed(&addr, status));
        }
        Ok(TagResult {
            tag: addr.tag.clone(),
            value: Some(value.clone()),
            data_type: Some(addr.file_type.name().into()),
            error: None,
        })
    }

    /// The processor type (catalog number such as `1766-LEC`), None if the processor reported an error.
    pub fn get_processor_type(&self) -> Result<Option<String>> {
        let mut conn = self.cip.lock();
        conn.ensure_forward_open("get_processor_type")?;
        self.processor_type(&mut conn)
    }

    fn processor_type(&self, conn: &mut CipConnection) -> Result<Option<String>> {
        let transaction = conn.next_sequence();
        let message = pccc::processor_type_request(&self.requestor(), transaction);
        let raw = send(conn, &message)?;
        if let Some(status) = request_status(&raw) {
            log::error!("failed to get processor type: {status}");
            return Ok(None);
        }
        Ok(pccc::parse_processor_type(&raw))
    }

    /// Reads `num_data_logs` entries of data log queue `queue_num`, then one more to clear the queue. Each
    /// entry is text, bytes if it is not UTF-8, or None if the processor reported an error.
    pub fn get_datalog_queue(
        &self,
        num_data_logs: usize,
        queue_num: u8,
    ) -> Result<Vec<Option<Value>>> {
        let mut conn = self.cip.lock();
        conn.ensure_forward_open("get_datalog_queue")?;
        // the count comes from the caller: do not let a huge one abort on allocation before any request
        let mut data = Vec::with_capacity(num_data_logs.min(256));
        for _ in 0..num_data_logs {
            data.push(datalog(&mut conn, queue_num)?);
        }
        datalog(&mut conn, queue_num)?; // the extra read clears the queue
        Ok(data)
    }

    /// The data files of the processor from its file directory (SYS0), named like `N7`, in directory order.
    /// A ResponseError if the processor type, directory size or directory cannot be read.
    pub fn get_file_directory(&self) -> Result<IndexMap<String, DataFile>> {
        let mut conn = self.cip.lock();
        conn.ensure_forward_open("get_file_directory")?;
        let Some(plc_type) = self.processor_type(&mut conn)? else {
            return Err(Error::response("Failed to read processor type"));
        };
        let info = pccc::sys0_info(&plc_type);
        let Some(size) = self.file_directory_size(&mut conn, &info)? else {
            return Err(Error::response("Failed to read file directory size"));
        };
        let data = self.read_file_directory(&mut conn, &info, size)?;
        log::debug!("SYS0 data ({} bytes): {data:02x?}", data.len());
        pccc::parse_file_directory(info.file_position, info.row_size, &data)
    }

    fn file_directory_size(
        &self,
        conn: &mut CipConnection,
        info: &Sys0Info,
    ) -> Result<Option<i32>> {
        let transaction = conn.next_sequence();
        let message = pccc::file_directory_size_request(info, &self.requestor(), transaction);
        let raw = send(conn, &message)?;
        if let Some(status) = request_status(&raw) {
            log::error!("failed to read size of File 0: {status}");
            return Ok(None);
        }
        let size = pccc::parse_file_directory_size(&raw, info);
        match size {
            Some(size) => log::debug!("SYS 0 file size: {size}"),
            None => log::error!("failed to parse size of File 0"),
        }
        Ok(size)
    }

    fn read_file_directory(
        &self,
        conn: &mut CipConnection,
        info: &Sys0Info,
        size: i32,
    ) -> Result<Vec<u8>> {
        let size = usize::try_from(size).unwrap_or(0); // a negative size reads nothing, like Python
        let mut data = Vec::with_capacity(size);
        let mut offset = 0usize;
        while data.len() < size {
            let chunk = (size - data.len()).min(usize::from(FILE_DIRECTORY_CHUNK)) as u8; // at most 0x50
            let transaction = conn.next_sequence();
            let message = pccc::file_directory_read_request(
                info.file_type,
                offset,
                chunk,
                &self.requestor(),
                transaction,
            )?;
            let raw = send(conn, &message)?;
            if let Some(status) = request_status(&raw) {
                let msg = format!("Error reading File 0 contents: {status}");
                log::error!("{msg}");
                return Err(Error::response(msg));
            }
            let part = &raw[SLC_REPLY_START.min(raw.len())..];
            if part.is_empty() {
                // Python asks again forever; stop instead
                return Err(Error::response(
                    "Error reading File 0 contents: the reply has no data",
                ));
            }
            offset += part.len() / 2;
            data.extend_from_slice(part);
        }
        Ok(data)
    }
}

/// One data log entry (`_get_datalog`); its request has a fixed requestor ID and transaction code.
fn datalog(conn: &mut CipConnection, queue_num: u8) -> Result<Option<Value>> {
    let raw = send(conn, &pccc::datalog_request(queue_num))?;
    if let Some(status) = request_status(&raw) {
        log::error!("Failed to retrieve data log: {status}");
        return Ok(None);
    }
    let entry = pccc::parse_datalog(&raw);
    if matches!(entry, Value::Bytes(_)) {
        log::error!("Failed to decode data log");
    }
    Ok(Some(entry))
}

/// Sends a PCCC message as a connected message with the next sequence count; the raw reply frame.
fn send(conn: &mut CipConnection, message: &[u8]) -> Result<Vec<u8>> {
    let sequence = conn.next_sequence();
    conn.send_connected(sequence, message)
}

/// The error of a reply (`request_status`): the CIP or encapsulation error, else the PCCC status; None
/// for success.
fn request_status(raw: &[u8]) -> Option<String> {
    let reply = Reply::parse(ReplyKind::SendUnitData, raw);
    if !reply.is_valid() {
        return reply.error();
    }
    pccc::request_status(raw)
}

/// Offset of the transaction code in a PCCC read/write message, after the 13-byte message start, the
/// command and the status.
const TRANSACTION_AT: usize = 15;

/// Takes the transaction code of a read/write message built with code 0 the way Python does: a
/// RequestError (bad address or value) comes before Python's `next(self._sequence)`, any other error (a size
/// that does not fit a USINT) after it.
fn with_transaction(
    conn: &mut CipConnection,
    built: Result<(Address, Vec<u8>)>,
) -> Result<(Address, Vec<u8>)> {
    match built {
        Err(err @ Error::Request { .. }) => Err(err),
        Err(err) => {
            conn.next_sequence();
            Err(err)
        }
        Ok((addr, mut message)) => {
            let transaction = conn.next_sequence().to_le_bytes();
            if let Some(field) = message.get_mut(TRANSACTION_AT..TRANSACTION_AT + 2) {
                field.copy_from_slice(&transaction);
            }
            Ok((addr, message))
        }
    }
}

fn failed(addr: &Address, error: String) -> TagResult {
    TagResult {
        tag: addr.tag.clone(),
        value: None,
        data_type: Some(addr.file_type.name().into()),
        // Python's SLC errors are plain strings, their kind is OTHER
        error: Some(TagError::new(error, ErrorKind::Other)),
    }
}

/// Wraps `connector` so its transports record the vendor serial number of each Forward Open they send:
/// Python sends the driver's current vsn in every PCCC requestor ID, and the CIP connection randomises it
/// per Forward Open.
fn watch_vsn(connector: Connector, vsn: Arc<Mutex<[u8; 4]>>) -> Connector {
    Box::new(move |host, port, timeout| {
        let inner = connector(host, port, timeout)?;
        Ok(Box::new(VsnWatch {
            inner,
            vsn: vsn.clone(),
        }) as Box<dyn Transport>)
    })
}

struct VsnWatch {
    inner: Box<dyn Transport>,
    vsn: Arc<Mutex<[u8; 4]>>,
}

/// The vsn of a (Large) Forward Open request frame: SendRRData, service 0x54/0x5B to the Connection
/// Manager instance 1, then priority, ticks, two connection IDs, csn and vendor ID before it.
fn forward_open_vsn(frame: &[u8]) -> Option<[u8; 4]> {
    let header = frame.get(..46)?;
    let is_forward_open = header[0] == 0x6F
        && matches!(header[40], 0x54 | 0x5B)
        && header[41..46] == [0x02, 0x20, 0x06, 0x24, 0x01];
    if !is_forward_open {
        return None;
    }
    frame.get(60..64)?.try_into().ok()
}

impl Transport for VsnWatch {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if let Some(vsn) = forward_open_vsn(frame) {
            *self.vsn.lock().unwrap_or_else(PoisonError::into_inner) = vsn;
        }
        self.inner.send(frame)
    }

    fn receive(&mut self) -> Result<Vec<u8>> {
        self.inner.receive()
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.inner.set_timeout(timeout)
    }
}
