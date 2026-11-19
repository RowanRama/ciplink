//! The S7comm-plus protocol state on the session core (`S7Plus`) and the public driver (`S7PlusDriver`).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use indexmap::IndexMap;

use super::browse::{self, Address, SymbolTree};
use super::codec::{Cursor, Payload, Scalar, Struct, WireValue};
use super::link::Link;
use super::pdu::{Explore, ItemAddress, error_code, ids};
use super::tls::{self, Fingerprint, SeenFingerprint};
use super::types::{CpuInfo, S7Symbol, S7Tag, S7Type};
use super::values;
use crate::cip::TagResult;
use crate::session::{
    ConnectionCallback, ConnectionState, Handle, Protocol, Session, SessionOptions,
    SubscribeOptions, Subscription,
};
use crate::{Error, ErrorKind, Result, TagError, Value};

/// The S7comm-plus port.
pub const DEFAULT_PORT: u16 = 102;
/// Items per request when the system limits cannot be read (the value of every CPU seen).
const DEFAULT_LIMIT: usize = 100;
/// Encoded bytes of one write request at most (one frame holds 65,535).
const MAX_WRITE_BYTES: usize = 60_000;
/// At most one browse caused by item errors per this long (a browse of a mid-size program takes seconds).
const ERROR_BROWSE_INTERVAL: Duration = Duration::from_secs(60);

/// Options of an [`S7PlusDriver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S7PlusOptions {
    /// Timeout of the TCP connect and of each socket read and write; None blocks forever. Default 10 s (a large
    /// browse reply arrives over several seconds, but never 10 s without a byte).
    pub socket_timeout: Option<Duration>,
    /// Browse the symbol table on `open` (and on a reconnect that needs it). With false, the first request that
    /// needs a tag name browses. Default true.
    pub init_tags: bool,
    /// SHA-256 fingerprint of the PLC certificate to require, hex with or without `:`. None accepts any
    /// certificate (the default; see [`S7PlusDriver::certificate_fingerprint`]).
    pub tls_fingerprint: Option<String>,
}

impl Default for S7PlusOptions {
    fn default() -> Self {
        S7PlusOptions {
            socket_timeout: Some(Duration::from_secs(10)),
            init_tags: true,
            tls_fingerprint: None,
        }
    }
}

impl S7PlusOptions {
    /// The session options an S7 driver uses by default: [`SessionOptions::default`] with a 15 s keep-alive
    /// (the PLC's idle timeout is unknown; spec 10.7 suggests 10 to 20 s).
    pub fn default_session() -> SessionOptions {
        SessionOptions {
            keep_alive: Some(Duration::from_secs(15)),
            ..SessionOptions::default()
        }
    }
}

/// Every error on the link is a CommError (the session reconnects on those).
fn fatal(e: Error) -> Error {
    match e {
        Error::Comm(_) => e,
        other => Error::comm(other.to_string()),
    }
}

fn not_connected() -> Error {
    Error::comm("S7comm-plus not connected")
}

/// A TagError for an item error (spec 12): classified by its low 16 bits.
fn item_error(code: u64) -> TagError {
    let low = error_code(code);
    let kind = match low {
        -255 | -61 => ErrorKind::NotFound,
        -17 => ErrorKind::TableChanged,
        _ => ErrorKind::Device,
    };
    let message = match low {
        -255 => "no such LID: the program changed".to_string(),
        -61 => "array index out of range".to_string(),
        -17 => "symbol CRC mismatch: the program changed".to_string(),
        _ => String::new(),
    };
    let text = format!("S7 item error 0x{code:016X} ({low})");
    let message = if message.is_empty() {
        text
    } else {
        format!("{text}: {message}")
    };
    TagError::new(message, kind)
}

/// True for the item errors that mean the symbol table is out of date.
fn program_changed(code: u64) -> bool {
    matches!(error_code(code), -17 | -255)
}

fn wstring(v: &WireValue) -> Option<String> {
    match v.as_scalar()? {
        Scalar::WString(s) => Some(s.clone()),
        _ => None,
    }
}

fn ascii(bytes: &[u8]) -> Option<String> {
    let s: String = bytes
        .iter()
        .map(|&b| char::from(b))
        .collect::<String>()
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    (!s.is_empty()).then_some(s)
}

/// Fills order number, serial, hardware and firmware version from the identification blob (spec 13.7).
fn identification(info: &mut CpuInfo, v: &WireValue) {
    let Some(Scalar::Blob(blob)) = v.as_scalar() else {
        return;
    };
    let b = &blob.data;
    info.order_number = b.get(8..27).and_then(ascii);
    info.serial_number = b.get(28..44).and_then(ascii);
    info.hardware_version = b.get(45).copied();
    if let Some(fw) = b.get(47..50) {
        info.firmware = Some(format!("V{}.{}.{}", fw[0], fw[1], fw[2]));
    }
}

/// `"V3.1"` from ServerSessionVersion element 319 (`1;<order number>;V3.1`).
fn session_firmware(version: &[u8]) -> Option<String> {
    let v = WireValue::decode(&mut Cursor::new(version)).ok()?;
    let Some(Scalar::Struct(s)) = v.as_scalar() else {
        return None;
    };
    let Struct::Normal { elements, .. } = s.as_ref() else {
        return None;
    };
    let text = elements
        .iter()
        .find(|(id, _)| *id == 319)
        .and_then(|(_, v)| wstring(v))?;
    text.rsplit(';').next().map(str::to_string)
}

/// The S7comm-plus driver's state: the link, the symbol tree and what `open` read.
pub(crate) struct S7Plus {
    host: String,
    port: u16,
    options: S7PlusOptions,
    pin: Option<Fingerprint>,
    link: Option<Link>,
    /// `link.is_some()`, readable without the state lock.
    up: Arc<AtomicBool>,
    /// Struct 306 of the current session.
    session_version: Option<Vec<u8>>,
    /// Struct 306 of the session the tree was browsed in.
    browsed_version: Option<Vec<u8>>,
    /// The tree was browsed on the current link. Indexed names carry CRC 0, so the PLC cannot catch an index
    /// computed from an old tree: they browse first after a reconnect that kept the tree.
    checked: bool,
    tree: Option<Arc<SymbolTree>>,
    /// +1 each browse whose result differs.
    tree_generation: u64,
    /// A write saw a CRC / LID error: browse before the next request.
    stale: bool,
    last_error_browse: Option<Instant>,
    resolved: HashMap<String, std::result::Result<Address, TagError>>,
    max_read: usize,
    max_write: usize,
    info: CpuInfo,
    fingerprint: SeenFingerprint,
}

impl S7Plus {
    fn set_link(&mut self, link: Option<Link>) {
        self.up.store(link.is_some(), Ordering::SeqCst);
        self.link = link;
    }

    /// Runs `f` on the link; any error drops the link (every link error is fatal, spec 12), except a
    /// RequestError, which is raised before anything is sent (a request too large for one frame).
    fn io<R>(&mut self, f: impl FnOnce(&mut Link) -> Result<R>) -> Result<R> {
        let link = self.link.as_mut().ok_or_else(not_connected)?;
        match f(link) {
            Ok(v) => Ok(v),
            Err(e @ Error::Request { .. }) => Err(e),
            Err(e) => {
                self.set_link(None);
                Err(fatal(e))
            }
        }
    }

    /// As [`io`](Self::io) for optional information: a refused request (negative return value) keeps the link.
    fn io_optional<R>(&mut self, f: impl FnOnce(&mut Link) -> Result<R>) -> Option<R> {
        let link = self.link.as_mut()?;
        match f(link) {
            Ok(v) => Some(v),
            Err(e) => {
                log::info!("S7comm-plus optional request failed: {e}");
                if matches!(e, Error::Comm(_)) {
                    self.set_link(None);
                }
                None
            }
        }
    }

    /// Connect steps 1 to 8 (and the browse): Ok(false) if the COTP connection was refused.
    fn connect(&mut self, browse: impl FnOnce(&Self) -> bool) -> Result<bool> {
        let Some(link) = Link::connect(
            &self.host,
            self.port,
            self.options.socket_timeout,
            self.pin,
            &self.fingerprint,
        )
        .map_err(fatal)?
        else {
            return Ok(false);
        };
        self.session_version = Some(link.session_version.clone());
        self.checked = false;
        self.set_link(Some(link));
        let result = self.after_connect(browse);
        if result.is_err() {
            self.set_link(None);
        }
        result.map(|()| true)
    }

    fn after_connect(&mut self, browse: impl FnOnce(&Self) -> bool) -> Result<()> {
        self.read_limits();
        self.read_identity();
        if self.link.is_none() {
            return Err(not_connected());
        }
        if browse(self) {
            self.browse()?;
        }
        Ok(())
    }

    /// System limits (spec 10.5, optional), the five items as captured; 100 where an item fails or reads 0, and
    /// for both when the PLC refuses the request.
    fn read_limits(&mut self) {
        let items: Vec<ItemAddress> = [1000, 1001, 0, 1, 2]
            .into_iter()
            .map(|lid| ItemAddress {
                crc: 0,
                area: ids::OBJECT_ROOT,
                sub_area: ids::SYSTEM_LIMITS,
                lids: vec![lid],
            })
            .collect();
        let reply = self.io_optional(|l| l.get_multi(&items));
        let limit = |n: u32| {
            reply
                .iter()
                .flat_map(|r| &r.values)
                .find(|(i, _)| *i == n)
                .and_then(|(_, v)| v.as_scalar()?.as_i128())
                .and_then(|v| usize::try_from(v).ok())
                .filter(|&v| v > 0)
                .unwrap_or(DEFAULT_LIMIT)
        };
        self.max_read = limit(1);
        self.max_write = limit(2);
    }

    /// PLC name and identification (spec 13.7); a failure is logged and leaves them None.
    fn read_identity(&mut self) {
        let name = self.io_optional(|l| l.get_var(ids::CPU_COMMON, ids::ATTR_NAME));
        self.info.name = name.as_ref().and_then(wstring);
        let ident = self.io_optional(|l| l.get_var(ids::CPU_PROXY, ids::ATTR_IDENTIFICATION));
        if let Some(v) = ident {
            identification(&mut self.info, &v);
        }
        if self.info.firmware.is_none() {
            self.info.firmware = self.session_version.as_deref().and_then(session_firmware);
        }
    }

    /// Reads the symbol table (spec 13.2 to 13.4). Returns true if it differs from the one before.
    fn browse(&mut self) -> Result<bool> {
        let started = Instant::now();
        let blocks = self.io(|l| l.explore(&Explore::data_blocks()))?;
        let dbs = browse::data_blocks(&blocks.objects);
        let mut db_types = HashMap::new();
        let items: Vec<ItemAddress> = dbs
            .iter()
            .map(|(_, n)| ItemAddress {
                crc: 0,
                area: ids::DB_AREA_BASE + n,
                sub_area: ids::DB_VALUE_ACTUAL,
                lids: vec![1],
            })
            .collect();
        for chunk in items.chunks(self.max_read.max(1)) {
            let reply = self.io(|l| l.get_multi(chunk))?;
            for (n, v) in reply.values {
                if let (Some(item), Some(Scalar::Rid(rid))) =
                    (chunk.get(n as usize - 1), v.as_scalar())
                {
                    db_types.insert(item.area - ids::DB_AREA_BASE, *rid);
                }
            }
        }
        let info = self.io(|l| l.explore(&Explore::children(ids::TYPE_INFO_CONTAINER, &[])))?;
        let types = browse::type_infos(&info.objects);
        let tree = SymbolTree::new(dbs, &db_types, types);
        log::info!(
            "S7comm-plus browse: {} data blocks, {} types in {:.1} s",
            tree.dbs.len(),
            tree.types.len(),
            started.elapsed().as_secs_f64()
        );
        let changed = self
            .tree
            .as_ref()
            .is_none_or(|old| old.signature() != tree.signature());
        if changed {
            self.tree_generation += 1;
        }
        self.tree = Some(Arc::new(tree));
        self.browsed_version.clone_from(&self.session_version);
        self.checked = true;
        self.stale = false;
        self.resolved.clear();
        Ok(changed)
    }

    fn tree(&mut self) -> Result<Arc<SymbolTree>> {
        self.tree_for(&[])
    }

    /// The tree for resolving `names`: browsed first if there is none, it is stale, or a name has an index and
    /// the tree was not browsed on this link.
    fn tree_for(&mut self, names: &[&str]) -> Result<Arc<SymbolTree>> {
        let indexed = || names.iter().any(|n| n.contains('['));
        if self.tree.is_none() || self.stale || (!self.checked && indexed()) {
            self.browse()?;
        }
        self.tree.clone().ok_or_else(not_connected)
    }

    fn resolve(&mut self, tree: &SymbolTree, name: &str) -> std::result::Result<Address, TagError> {
        if let Some(cached) = self.resolved.get(name) {
            return cached.clone();
        }
        let resolved = tree.resolve(name);
        self.resolved.insert(name.to_string(), resolved.clone());
        resolved
    }

    /// Reads resolved items in requests of at most `max_read`; results go to `out` by position. Returns the
    /// positions whose item error means the program changed.
    fn read_items(
        &mut self,
        tree: &SymbolTree,
        tags: &[&str],
        items: &[(usize, Address)],
        out: &mut [Option<TagResult>],
    ) -> Result<Vec<usize>> {
        let mut changed = Vec::new();
        for chunk in items.chunks(self.max_read.max(1)) {
            let addresses: Vec<ItemAddress> = chunk.iter().map(|(_, a)| a.item.clone()).collect();
            let reply = self.io(|l| l.get_multi(&addresses))?;
            for (n, v) in reply.values {
                let (pos, address) = &chunk[n as usize - 1];
                let (value, data_type) = values::decode(tree, address, &v);
                out[*pos] = Some(TagResult {
                    tag: tags[*pos].to_string(),
                    value: Some(value),
                    data_type: Some(data_type),
                    error: None,
                });
            }
            for (n, code) in reply.errors {
                let (pos, address) = &chunk[n as usize - 1];
                if program_changed(code) {
                    changed.push(*pos);
                }
                out[*pos] = Some(TagResult {
                    tag: tags[*pos].to_string(),
                    value: None,
                    data_type: Some(tree.data_type(address)),
                    error: Some(item_error(code)),
                });
            }
        }
        Ok(changed)
    }

    fn read_tags(&mut self, tags: &[&str]) -> Result<Vec<TagResult>> {
        if self.link.is_none() {
            return Err(not_connected());
        }
        let tree = self.tree_for(tags)?;
        let mut out: Vec<Option<TagResult>> = vec![None; tags.len()];
        let mut items = Vec::with_capacity(tags.len());
        for (pos, tag) in tags.iter().enumerate() {
            match self.resolve(&tree, tag) {
                Ok(a) => items.push((pos, a)),
                Err(e) => out[pos] = Some(failed(tag, e)),
            }
        }
        let changed = self.read_items(&tree, tags, &items, &mut out)?;
        let due = self
            .last_error_browse
            .is_none_or(|t| t.elapsed() >= ERROR_BROWSE_INTERVAL);
        if !changed.is_empty() && due {
            log::info!(
                "S7comm-plus: {} items report a program change, browsing again",
                changed.len()
            );
            self.last_error_browse = Some(Instant::now());
            self.browse()?;
            let tree = self.tree()?;
            let mut again = Vec::with_capacity(changed.len());
            for pos in changed {
                match self.resolve(&tree, tags[pos]) {
                    Ok(a) => again.push((pos, a)),
                    Err(e) => out[pos] = Some(failed(tags[pos], e)),
                }
            }
            self.read_items(&tree, tags, &again, &mut out)?;
        }
        Ok(out
            .into_iter()
            .zip(tags)
            .map(|(r, tag)| {
                r.unwrap_or_else(|| failed(tag, TagError::new("no result", ErrorKind::Comm)))
            })
            .collect())
    }

    fn write_tags(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        if self.link.is_none() {
            return Err(not_connected());
        }
        let names: Vec<&str> = items.iter().map(|(tag, _)| *tag).collect();
        let tree = self.tree_for(&names)?;
        let mut out: Vec<TagResult> = Vec::with_capacity(items.len());
        let mut ready: Vec<(usize, ItemAddress, WireValue, usize)> = Vec::new();
        for (pos, (tag, value)) in items.iter().enumerate() {
            let encoded = self
                .resolve(&tree, tag)
                .and_then(|a| Ok((values::encode(&tree, tag, &a, value)?, a)));
            out.push(TagResult {
                tag: (*tag).to_string(),
                value: Some(value.clone()),
                data_type: None,
                error: None,
            });
            match encoded {
                Ok((wire, a)) => {
                    out[pos].data_type = Some(tree.data_type(&a));
                    let mut size = Vec::new();
                    a.item.encode(&mut size);
                    wire.encode(&mut size);
                    if size.len() + 5 > MAX_WRITE_BYTES {
                        out[pos].error = Some(TagError::new(
                            format!("{tag}: value too large for one request"),
                            ErrorKind::BadRequest,
                        ));
                        continue;
                    }
                    ready.push((pos, a.item, wire, size.len() + 5));
                }
                Err(e) => out[pos].error = Some(e),
            }
        }
        let mut start = 0;
        while start < ready.len() {
            let mut end = start;
            let mut bytes = 0;
            // every item fits alone (checked above), so each chunk takes at least one
            while end < ready.len()
                && end - start < self.max_write.max(1)
                && bytes + ready[end].3 <= MAX_WRITE_BYTES
            {
                bytes += ready[end].3;
                end += 1;
            }
            let chunk = &ready[start..end];
            let request: Vec<(ItemAddress, WireValue)> = chunk
                .iter()
                .map(|(_, a, w, _)| (a.clone(), w.clone()))
                .collect();
            let reply = self.io(|l| l.set_multi(&request))?;
            for (n, code) in reply.errors {
                let pos = chunk[n as usize - 1].0;
                if program_changed(code) {
                    self.stale = true;
                }
                out[pos].error = Some(item_error(code));
            }
            start = end;
        }
        Ok(out)
    }

    fn plc_info(&mut self) -> Result<CpuInfo> {
        if self.link.is_none() {
            return Err(not_connected());
        }
        if self.info.name.is_none() || self.info.order_number.is_none() {
            self.read_identity();
        }
        let mut info = self.info.clone();
        if let Some(v) =
            self.io_optional(|l| l.get_var(ids::AS_ROOT, ids::ATTR_ENGINEERING_VERSION))
            && let Some(items) = v.as_array()
        {
            let parts: Vec<String> = items
                .iter()
                .take(4)
                .filter_map(|s| s.as_i128().map(|n| n.to_string()))
                .collect();
            info.engineering_version = (!parts.is_empty()).then(|| parts.join("."));
        }
        if let Some(v) =
            self.io_optional(|l| l.get_var(ids::RELEASE_MANAGEMENT_ROOT, ids::ATTR_PROJECT))
            && let Payload::Array(items) = &v.payload
            && let Some(Scalar::WString(project)) = items.get(2)
        {
            info.project = Some(project.clone());
        }
        let session = self.link.as_ref().map_or(0, |l| l.session);
        if let Some(v) = self.io_optional(|l| l.get_var(session, ids::ATTR_PROTECTION_LEVEL)) {
            info.protection_level = v
                .as_scalar()
                .and_then(Scalar::as_i128)
                .and_then(|n| u32::try_from(n).ok());
        }
        if self.link.is_none() {
            return Err(not_connected());
        }
        info.max_read = self.max_read;
        info.max_write = self.max_write;
        Ok(info)
    }
}

fn failed(tag: &str, error: TagError) -> TagResult {
    TagResult {
        tag: tag.to_string(),
        value: None,
        data_type: None,
        error: Some(error),
    }
}

impl Protocol for S7Plus {
    fn open(&mut self) -> Result<bool> {
        if self.link.is_some() {
            return Ok(true);
        }
        let init = self.options.init_tags;
        self.connect(|_| init)
    }

    /// A whole new link; the symbol table is kept unless it is stale or the ServerSessionVersion changed.
    fn reopen(&mut self) -> Result<bool> {
        if self.link.is_some() {
            return Ok(true);
        }
        let init = self.options.init_tags;
        self.connect(|p| match &p.tree {
            None => init,
            Some(_) => p.stale || p.session_version != p.browsed_version,
        })
    }

    fn close(&mut self) -> Result<()> {
        match self.link.take() {
            Some(link) => {
                self.up.store(false, Ordering::SeqCst);
                link.close()
            }
            None => Ok(()),
        }
    }

    fn drop_link(&mut self) {
        self.set_link(None);
    }

    fn connected(&self) -> bool {
        self.link.is_some()
    }

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>> {
        self.read_tags(tags)
    }

    fn write(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        self.write_tags(items)
    }

    /// The protection-level read (spec 10.6); its value is ignored.
    fn keep_alive(&mut self) -> Result<()> {
        let session = self.link.as_ref().ok_or_else(not_connected)?.session;
        self.io(|l| l.get_var(session, ids::ATTR_PROTECTION_LEVEL))
            .map(|_| ())
    }
}

/// Splits `host` or `host:port`.
fn split_path(path: &str) -> Result<(String, u16)> {
    let path = path.trim();
    let bad = || {
        Error::request(format!(
            "Invalid S7comm-plus path {path:?}: expected host or host:port"
        ))
    };
    if path.is_empty() {
        return Err(bad());
    }
    match path.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            Ok((host.to_string(), port.parse().map_err(|_| bad())?))
        }
        Some(_) => Err(bad()),
        None => Ok((path.to_string(), DEFAULT_PORT)),
    }
}

/// A driver for Siemens S7-1500 / S7-1200 CPUs over S7comm-plus with TLS (secure PG/HMI communication,
/// firmware 2.9 and later).
///
/// Every call runs on the driver's [session](crate::session) thread, in queue order; concurrent reads are
/// merged into one request list. A driver from [`new`](Self::new) reconnects in the background and keeps the
/// link alive. Tag names are TIA style: `Line1.Conveyor.Speed`, `Line1.Items[3]`, PLC tags by their bare name;
/// quotes around a segment are accepted. Multi-dimensional arrays are read and written whole only.
pub struct S7PlusDriver {
    session: Session<S7Plus>,
    up: Arc<AtomicBool>,
    fingerprint: SeenFingerprint,
    host: String,
    port: u16,
}

impl S7PlusDriver {
    /// A driver for `path` (`host` or `host:port`, default port 102); not connected until
    /// [`open`](Self::open). Reconnects and keeps alive ([`S7PlusOptions::default_session`]). A malformed
    /// `tls_fingerprint` is a RequestError.
    pub fn new(path: &str, options: S7PlusOptions) -> Result<Self> {
        Self::with_session(path, options, S7PlusOptions::default_session())
    }

    /// A driver with explicit session options.
    pub fn with_session(
        path: &str,
        options: S7PlusOptions,
        session: SessionOptions,
    ) -> Result<Self> {
        let (host, port) = split_path(path)?;
        let pin = options
            .tls_fingerprint
            .as_deref()
            .map(tls::parse_fingerprint)
            .transpose()?;
        let up = Arc::new(AtomicBool::new(false));
        let fingerprint: SeenFingerprint = Arc::new(Mutex::new(None));
        let state = S7Plus {
            host: host.clone(),
            port,
            options,
            pin,
            link: None,
            up: Arc::clone(&up),
            session_version: None,
            browsed_version: None,
            checked: false,
            tree: None,
            tree_generation: 0,
            stale: false,
            last_error_browse: None,
            resolved: HashMap::new(),
            max_read: DEFAULT_LIMIT,
            max_write: DEFAULT_LIMIT,
            info: CpuInfo::default(),
            fingerprint: Arc::clone(&fingerprint),
        };
        Ok(S7PlusDriver {
            session: Session::new(state, session),
            up,
            fingerprint,
            host,
            port,
        })
    }

    fn run<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut S7Plus) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        self.session.call(f).wait()
    }

    /// Connects, creates a session, reads the limits and the CPU name and browses (unless `init_tags` is
    /// false). Ok(false): the target refused the COTP connection.
    pub fn open(&self) -> Result<bool> {
        self.session.open().wait()
    }

    /// Deletes the session and closes the connection. Queued requests fail with `CommError("driver closed")`,
    /// subscriptions end and reconnecting stops.
    pub fn close(&self) -> Result<()> {
        self.session.close()
    }

    /// Stops the session and callback threads and fails pending requests without closing the connection (what
    /// drop does). The next request starts the session thread again.
    pub fn stop(&self) {
        self.session.stop();
    }

    /// True while a session is open. Never waits.
    pub fn connected(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }

    /// Where the link is: closed, connected, or reconnecting in the background. Never waits.
    pub fn connection_state(&self) -> ConnectionState {
        self.session.state()
    }

    /// Sets (or with None removes) the connection callback; see
    /// [`LogixDriver::set_connection_callback`](crate::logix::driver::LogixDriver::set_connection_callback).
    pub fn set_connection_callback(&self, callback: Option<ConnectionCallback>) {
        self.session.set_connection_callback(callback);
    }

    /// Reads tags; one result per tag in order. A name that does not resolve or an item the PLC refuses is
    /// that tag's error; a lost connection is a CommError.
    pub fn read(&self, tags: &[&str]) -> Result<Vec<TagResult>> {
        self.read_async(tags).wait()
    }

    /// [`read`](Self::read) without waiting.
    pub fn read_async(&self, tags: &[&str]) -> Handle<Vec<TagResult>> {
        self.session.read(tags)
    }

    /// Writes tags; one result per item, carrying the value as given. A value that does not fit is that item's
    /// `BadValue`; whole structures (except DTL) and whole BOOL arrays are refused (`BadRequest`).
    pub fn write(&self, items: &[(&str, Value)]) -> Result<Vec<TagResult>> {
        self.write_async(items).wait()
    }

    /// [`write`](Self::write) without waiting.
    pub fn write_async(&self, items: &[(&str, Value)]) -> Handle<Vec<TagResult>> {
        self.session.write(items)
    }

    /// Reads `tags` every `options.interval` and delivers those that changed (see [`Subscription`]).
    pub fn subscribe(&self, tags: &[&str], options: SubscribeOptions) -> Result<Subscription> {
        self.session.subscribe(tags, options)
    }

    /// Top-level tags: every data block and every PLC tag of the I, Q and M areas, in browse order. Empty
    /// before the first browse. Waits for the request in flight; no I/O.
    pub fn tags(&self) -> IndexMap<String, S7Tag> {
        self.session
            .lock()
            .tree
            .as_ref()
            .map(|t| t.tags())
            .unwrap_or_default()
    }

    /// The structure types the tags use (UDTs, STRUCT members, FB interfaces, system types), by type name.
    pub fn data_types(&self) -> IndexMap<String, S7Type> {
        self.session
            .lock()
            .tree
            .as_ref()
            .map(|t| t.data_types())
            .unwrap_or_default()
    }

    /// Every symbol as a flat list: members of structures and arrays of structures expanded, elementary arrays
    /// and system types (DTL, IEC timers) as one entry. Browses first if needed.
    pub fn tag_list(&self) -> Result<Vec<S7Symbol>> {
        self.run(|p| Ok(p.tree()?.symbols()))
    }

    /// One name resolved: type, dims, access sequence, CRC, HMI flags. Browses first if needed.
    pub fn get_tag_info(&self, name: &str) -> Result<S7Symbol> {
        let name = name.to_string();
        self.run(move |p| {
            let tree = p.tree_for(&[&name])?;
            let a = p
                .resolve(&tree, &name)
                .map_err(|e| Error::request_kind(e.message, e.kind))?;
            Ok(tree.symbol(&name, &a))
        })
    }

    /// Browses again now and returns whether the table changed.
    pub fn refresh_tags(&self) -> Result<bool> {
        self.run(|p| {
            if p.link.is_none() {
                return Err(not_connected());
            }
            p.browse()
        })
    }

    /// The number of browses whose result differed (0 before the first browse); a change means the tags or
    /// types changed. No I/O.
    pub fn tags_version(&self) -> u64 {
        self.session.lock().tree_generation
    }

    /// CPU name, order number, serial number, hardware and firmware versions, TIA version, project name and
    /// protection level.
    pub fn get_plc_info(&self) -> Result<CpuInfo> {
        self.run(S7Plus::plc_info)
    }

    /// The PLC (station) name read at open; None before.
    pub fn name(&self) -> Option<String> {
        self.session.lock().info.name.clone()
    }

    /// `"AB:CD:..."` of the certificate presented at the latest handshake (accepted or refused by the pin),
    /// None before one.
    pub fn certificate_fingerprint(&self) -> Option<String> {
        self.fingerprint
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(tls::format_fingerprint)
    }

    /// The socket timeout.
    pub fn socket_timeout(&self) -> Option<Duration> {
        self.session.lock().options.socket_timeout
    }

    /// Sets the socket timeout, of the open link too.
    pub fn set_socket_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.run(move |p| {
            p.options.socket_timeout = timeout;
            match &p.link {
                Some(link) => link.set_timeout(timeout),
                None => Ok(()),
            }
        })
    }
}

impl fmt::Display for S7PlusDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.session.lock();
        write!(
            f,
            "S7PlusDriver({}:{}, {}, {})",
            self.host,
            self.port,
            state.info.name.as_deref().unwrap_or("None"),
            state.info.firmware.as_deref().unwrap_or("None")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_host_and_port() {
        assert_eq!(
            split_path("10.0.0.5").expect("host"),
            ("10.0.0.5".into(), 102)
        );
        assert_eq!(split_path("plc:1102").expect("port"), ("plc".into(), 1102));
        assert!(split_path("").is_err());
        assert!(split_path(":102").is_err());
        assert!(split_path("plc:x").is_err());
    }

    #[test]
    fn item_errors_classify_by_their_low_16_bits() {
        assert_eq!(item_error(0x814E_8800_0962_FF01).kind, ErrorKind::NotFound);
        assert_eq!(item_error(0x814E_8D00_0641_FFC3).kind, ErrorKind::NotFound);
        assert_eq!(
            item_error(0x8009_8900_12C9_FFEF).kind,
            ErrorKind::TableChanged
        );
        let other = item_error(0x8000_0000_0000_FFFE);
        assert_eq!(other.kind, ErrorKind::Device);
        assert!(other.message.contains("0x800000000000FFFE"));
        assert!(program_changed(0x8009_8900_12C9_FFEF) && !program_changed(0x814E_8D00_0641_FFC3));
    }

    #[test]
    fn a_malformed_pin_fails_new() {
        let options = S7PlusOptions {
            tls_fingerprint: Some("AB:CD".into()),
            ..S7PlusOptions::default()
        };
        assert!(matches!(
            S7PlusDriver::new("127.0.0.1", options),
            Err(Error::Request { .. })
        ));
    }

    #[test]
    fn firmware_from_the_session_version() {
        let version: Vec<u8> = {
            let s = "0017 0000013a 823f 0015 1a 313b36455337203558582d58585858582d584142303b56332e31 00";
            let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect()
        };
        assert_eq!(session_firmware(&version).as_deref(), Some("V3.1"));
    }

    use super::super::fake::{FakePlc, LID_MISSING};
    use super::super::pdu::function;
    use crate::session::ConnectionEvent;

    fn driver(plc: &FakePlc, session: SessionOptions, pin: Option<String>) -> S7PlusDriver {
        let options = S7PlusOptions {
            socket_timeout: Some(Duration::from_secs(5)),
            init_tags: true,
            tls_fingerprint: pin,
        };
        S7PlusDriver::with_session(&format!("127.0.0.1:{}", plc.port), options, session)
            .expect("driver")
    }

    fn count(plc: &FakePlc, f: u16) -> usize {
        plc.lock().functions.iter().filter(|&&x| x == f).count()
    }

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    fn open_browse_read_write_and_close() {
        let plc = FakePlc::start();
        let d = driver(&plc, SessionOptions::off(), None);
        assert!(d.open().expect("open"));
        assert!(d.connected());
        assert_eq!(d.name().as_deref(), Some("PLC_Line1"));
        assert_eq!(
            d.certificate_fingerprint(),
            Some(tls::format_fingerprint(&plc.fingerprint))
        );
        let r = d
            .read(&[
                "Line1.Conveyor.Speed",
                "Line1.Count",
                "StartButton",
                "Nope",
                "Line1.Items[5]",
            ])
            .expect("read");
        assert_eq!(r[0].value, Some(Value::Real(1.5)));
        assert_eq!(r[0].data_type.as_deref(), Some("REAL"));
        assert_eq!(r[1].value, Some(Value::DInt(-300)));
        assert_eq!(r[2].value, Some(Value::Bool(false)));
        assert_eq!(r[3].error_kind(), Some(ErrorKind::NotFound));
        assert_eq!(r[4].value, Some(Value::UInt(5)));
        let w = d
            .write(&[
                ("Line1.Count", Value::DInt(42)),
                ("Line1.Count", Value::Real(1.0)),
            ])
            .expect("write");
        assert!(w[0].is_ok());
        assert_eq!(w[1].error_kind(), Some(ErrorKind::BadValue));
        assert_eq!(
            d.read(&["Line1.Count"]).expect("read")[0].value,
            Some(Value::DInt(42))
        );
        assert_eq!(
            count(&plc, function::SET_MULTI_VARIABLES),
            2,
            "setup + one write"
        );
        let tags = d.tags();
        assert_eq!(
            tags.keys().collect::<Vec<_>>(),
            vec!["Line1", "StartButton"]
        );
        assert!(d.data_types().contains_key("DTL"));
        let list = d.tag_list().expect("tag list");
        assert!(
            list.iter()
                .any(|s| s.name == "Line1.Conveyor.Speed" && s.access == "8A0E0005.A.B")
        );
        let info = d.get_tag_info("Line1.Conveyor.Speed").expect("info");
        assert_eq!(info.crc, 0x6E44_A73A);
        assert!(matches!(
            d.get_tag_info("Nope"),
            Err(Error::Request {
                kind: Some(ErrorKind::NotFound),
                ..
            })
        ));
        let cpu = d.get_plc_info().expect("cpu");
        assert_eq!(cpu.order_number.as_deref(), Some("6ES7 5XX-XXXXX-XAB0"));
        assert_eq!(cpu.serial_number.as_deref(), Some("SVPX0000000000AB"));
        assert_eq!(cpu.hardware_version, Some(4));
        assert_eq!(cpu.firmware.as_deref(), Some("V3.1.3"));
        assert_eq!(cpu.engineering_version.as_deref(), Some("19.0.0.0"));
        assert_eq!(cpu.project.as_deref(), Some("Demo line"));
        assert_eq!(cpu.protection_level, Some(0));
        assert_eq!((cpu.max_read, cpu.max_write), (100, 100));
        assert!(d.to_string().contains("PLC_Line1"));
        assert!(!d.refresh_tags().expect("refresh"), "unchanged");
        assert_eq!(d.tags_version(), 1);
        d.close().expect("close");
        assert!(!d.connected());
        wait_for("DeleteObject", || count(&plc, function::DELETE_OBJECT) == 1);
    }

    #[test]
    fn reads_are_split_by_the_read_limit() {
        let plc = FakePlc::start();
        let d = driver(&plc, SessionOptions::off(), None);
        d.open().expect("open");
        plc.lock().read_sizes.clear();
        let names: Vec<String> = (0..250).map(|i| format!("Line1.Items[{i}]")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let r = d.read(&refs).expect("read");
        assert_eq!(r.len(), 250);
        assert_eq!(r[249].value, Some(Value::UInt(249)));
        assert_eq!(plc.lock().read_sizes, vec![100, 100, 50]);
    }

    #[test]
    fn the_pin_must_match_and_the_fingerprint_is_exposed_either_way() {
        let plc = FakePlc::start();
        let right = tls::format_fingerprint(&plc.fingerprint)
            .to_lowercase()
            .replace(':', " ");
        let d = driver(&plc, SessionOptions::off(), Some(right));
        assert!(d.open().expect("pinned open"));
        d.close().expect("close");
        let d = driver(&plc, SessionOptions::off(), Some("00".repeat(32)));
        let err = d.open().expect_err("wrong pin");
        assert!(
            matches!(&err, Error::Comm(m) if m.contains("does not match")),
            "{err}"
        );
        assert_eq!(
            d.certificate_fingerprint(),
            Some(tls::format_fingerprint(&plc.fingerprint))
        );
        assert!(!d.connected());
    }

    #[test]
    fn a_refused_connection_opens_false() {
        let plc = FakePlc::start();
        plc.lock().refuse = true;
        let d = driver(&plc, SessionOptions::off(), None);
        assert!(!d.open().expect("open"));
        assert!(!d.connected());
    }

    #[test]
    fn a_program_change_heals_a_read_with_one_browse() {
        let plc = FakePlc::start();
        let d = driver(&plc, SessionOptions::off(), None);
        d.open().expect("open");
        let explores = count(&plc, function::EXPLORE);
        plc.lock().change_crc("Count");
        let r = d
            .read(&["Line1.Count", "Line1.Conveyor.Speed"])
            .expect("read");
        assert_eq!(r[0].value, Some(Value::DInt(-300)), "{:?}", r[0].error);
        assert_eq!(count(&plc, function::EXPLORE), explores + 2, "one browse");
        assert_eq!(d.tags_version(), 2);
        // a second change within a minute is not browsed again: the item reports it
        plc.lock().change_crc("Count");
        let r = d.read(&["Line1.Count"]).expect("read");
        assert_eq!(r[0].error_kind(), Some(ErrorKind::TableChanged));
    }

    #[test]
    fn a_write_after_a_program_change_fails_once_and_the_next_request_browses() {
        let plc = FakePlc::start();
        let d = driver(&plc, SessionOptions::off(), None);
        d.open().expect("open");
        plc.lock().change_crc("Count");
        let w = d.write(&[("Line1.Count", Value::DInt(1))]).expect("write");
        assert_eq!(w[0].error_kind(), Some(ErrorKind::TableChanged));
        let explores = count(&plc, function::EXPLORE);
        let w = d.write(&[("Line1.Count", Value::DInt(1))]).expect("write");
        assert!(w[0].is_ok(), "{:?}", w[0].error);
        assert_eq!(count(&plc, function::EXPLORE), explores + 2);
        plc.lock().values.remove("8A0E0005.C");
        let r = d.read(&["Line1.Count"]).expect("read");
        let message = r[0]
            .error
            .as_ref()
            .map(|e| e.message.clone())
            .unwrap_or_default();
        assert!(
            message.contains(&format!("{LID_MISSING:016X}")),
            "{message}"
        );
    }

    #[test]
    fn a_lost_link_reconnects_without_browsing_again() {
        let plc = FakePlc::start();
        let session = SessionOptions {
            keep_alive: None,
            ..S7PlusOptions::default_session()
        };
        let d = driver(&plc, session, None);
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        d.set_connection_callback(Some(Box::new(move |ev: &ConnectionEvent| {
            e.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(ev.clone());
        })));
        d.open().expect("open");
        let explores = count(&plc, function::EXPLORE);
        plc.lock().drop_after = Some(0);
        let err = d.read(&["Line1.Count"]).expect_err("lost");
        assert!(matches!(err, Error::Comm(_)));
        wait_for("reconnect", || {
            d.connection_state() == ConnectionState::Connected && d.connected()
        });
        let r = d.read(&["Line1.Count"]).expect("read after reconnect");
        assert_eq!(r[0].value, Some(Value::DInt(-300)));
        assert_eq!(
            count(&plc, function::EXPLORE),
            explores,
            "the tree was kept"
        );
        assert_eq!(plc.lock().connections, 2);
        wait_for("events", || {
            let ev = events.lock().unwrap_or_else(PoisonError::into_inner);
            ev.iter()
                .any(|e| matches!(e, ConnectionEvent::Disconnected { .. }))
                && ev.last() == Some(&ConnectionEvent::Connected)
        });
        d.close().expect("close");
    }

    /// Sets the lower bound of the fake's `Items` array (a download that changes its declaration).
    fn set_items_lower_bound(plc: &FakePlc, lower: i32) {
        let mut s = plc.lock();
        for o in &mut s.types {
            let names = o.varnames.clone().unwrap_or_default();
            if let Some(list) = o.vartypes.as_mut() {
                for (e, n) in list.elements.iter_mut().zip(&names) {
                    if n == "Items" {
                        e.offset_info[12..16].copy_from_slice(&lower.to_le_bytes());
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_names_browse_again_after_a_reconnect_that_kept_the_tree() {
        let plc = FakePlc::start();
        let session = SessionOptions {
            keep_alive: None,
            ..S7PlusOptions::default_session()
        };
        let d = driver(&plc, session, None);
        d.open().expect("open");
        assert_eq!(
            d.read(&["Line1.Items[5]"]).expect("read")[0].value,
            Some(Value::UInt(5))
        );
        // ARRAY[0..299] becomes ARRAY[1..300] and the link drops; the session version stays the same
        set_items_lower_bound(&plc, 1);
        plc.lock().drop_after = Some(0);
        assert!(d.read(&["Line1.Count"]).is_err());
        wait_for("reconnect", || d.connected());
        let explores = count(&plc, function::EXPLORE);
        assert_eq!(
            d.read(&["Line1.Count"]).expect("scalar")[0].value,
            Some(Value::DInt(-300))
        );
        assert_eq!(count(&plc, function::EXPLORE), explores, "CRC-protected");
        let r = d.read(&["Line1.Items[5]"]).expect("indexed");
        assert_eq!(r[0].value, Some(Value::UInt(4)), "LID 4 of the new tree");
        assert_eq!(count(&plc, function::EXPLORE), explores + 2, "one browse");
        d.read(&["Line1.Items[6]"]).expect("again");
        assert_eq!(count(&plc, function::EXPLORE), explores + 2, "only once");
        d.close().expect("close");
    }

    #[test]
    fn a_value_too_large_for_one_request_fails_alone() {
        let plc = FakePlc::start();
        let d = driver(&plc, SessionOptions::off(), None);
        d.open().expect("open");
        let big = Value::Array(vec![Value::LReal(1.0); 10_000]);
        let w = d
            .write(&[("Line1.Big", big), ("Line1.Count", Value::DInt(7))])
            .expect("write");
        assert_eq!(w[0].error_kind(), Some(ErrorKind::BadRequest));
        assert!(w[1].is_ok(), "{:?}", w[1].error);
        assert!(d.connected());
        assert_eq!(
            d.read(&["Line1.Count"]).expect("read")[0].value,
            Some(Value::DInt(7))
        );
        assert_eq!(plc.lock().connections, 1, "the link was kept");
    }

    #[test]
    fn refused_system_limits_fall_back_to_100() {
        let plc = FakePlc::start();
        plc.lock().refuse_limits = true;
        plc.lock().max_read = 7;
        let d = driver(&plc, SessionOptions::off(), None);
        assert!(d.open().expect("open"));
        let cpu = d.get_plc_info().expect("cpu");
        assert_eq!((cpu.max_read, cpu.max_write), (100, 100));
        assert_eq!(
            d.read(&["Line1.Count"]).expect("read")[0].value,
            Some(Value::DInt(-300))
        );
        assert_eq!(plc.lock().connections, 1);
    }

    #[test]
    fn keep_alive_requests_go_out_when_idle() {
        let plc = FakePlc::start();
        let session = SessionOptions {
            keep_alive: Some(Duration::from_millis(50)),
            ..SessionOptions::off()
        };
        let d = driver(&plc, session, None);
        d.open().expect("open");
        let before = count(&plc, function::GET_VAR_SUB_STREAMED);
        wait_for("keep-alive", || {
            count(&plc, function::GET_VAR_SUB_STREAMED) >= before + 3
        });
        assert!(d.connected());
    }

    #[test]
    fn requests_before_open_fail_and_lazy_browse_waits_for_the_first_name() {
        let plc = FakePlc::start();
        let d = driver(&plc, SessionOptions::off(), None);
        assert!(matches!(d.read(&["Line1.Count"]), Err(Error::Comm(_))));
        let options = S7PlusOptions {
            init_tags: false,
            ..S7PlusOptions::default()
        };
        let d = S7PlusDriver::with_session(
            &format!("127.0.0.1:{}", plc.port),
            options,
            SessionOptions::off(),
        )
        .expect("driver");
        let explores = count(&plc, function::EXPLORE);
        d.open().expect("open");
        assert_eq!(count(&plc, function::EXPLORE), explores);
        assert!(d.tags().is_empty());
        assert_eq!(
            d.read(&["Line1.Count"]).expect("read")[0].value,
            Some(Value::DInt(-300))
        );
        assert_eq!(count(&plc, function::EXPLORE), explores + 2);
    }
}
