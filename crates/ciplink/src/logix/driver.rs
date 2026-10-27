//! The Logix driver: connection setup, controller info, the tag list upload (symbol lists, structure makeups and
//! templates, batched in multi-service packets), the tag cache file, the AOI probe, lazy tag definitions and the
//! tag table version checks, as the Python `LogixDriver` does them.
//!
//! [`LogixDriver`] is the thread-safe handle; `Logix` is its state behind one mutex, the connection included,
//! so every multi-step operation (an upload, a read with its checks) holds one lock.  The read/write engine
//! (`logix/rw.rs`) and the descriptions (`logix/descriptions.rs`) add `impl` blocks on `Logix` and
//! [`LogixDriver`] using the `pub(crate)` fields and helpers documented here.
//!
//! Parity: the same requests in the same order as the Python driver, with the same sequence counts (a request
//! takes its count when it is built, sent or not, see `Request`), the same packing and the same retries.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;

use crate::cip::{CipConnection, CipOptions, GenericMessage, GenericReply, TagResult};
use crate::epath::{DataValue, LogicalType, LogicalValue, Segment, encode_epath, tag_request_path};
use crate::identity::{ListIdentity, ModuleIdentity};
use crate::logix::tag_cache::{TagCacheError, TagCacheFile, write_atomic};
use crate::logix::types::{
    DataType, MIN_VER_EXTERNAL_ACCESS, MemberInfo, PyObj, ScopeInfo, Symbol, TagDef, TagInfo,
    TemplateMakeup, TypeRef, create_tag, is_aoi, nested_template_ids, parse_structure_makeup,
    parse_symbol_list, parse_template, read_reply_size, split_tag_name, tag_info, tag_key,
    template_read_request, user_symbols,
};
use crate::packets::{
    self, Reply, ReplyKind, TAG_TABLE_VERSION_REPLY_SIZE, TAG_TABLE_VERSION_REQUEST_SIZE,
    TAG_TABLE_VERSION_SERVICE, TagTableVersion, parse_multi_service_reply, parse_tag_table_version,
};
use crate::reader::Reader;
use crate::status;
use crate::transport::{Connector, tcp_connector};
use crate::types::Elementary;
use crate::value::{py_bytes_repr, py_str_repr};
use crate::{Error, ErrorKind, Result, TagError, Value};

/// First major revision whose tags are requested by symbol instance ID.
pub const MIN_VER_INSTANCE_IDS: u32 = 21;
/// Catalog number prefix of Micro800 controllers.
pub const MICRO800_PREFIX: &str = "2080";
/// Seconds without tag table reloads after one failed or the controller was busy.
pub const RELOAD_BACKOFF: Duration = Duration::from_secs(2);
/// The error of a read or write of an AOI's local tag (refused by the AOI probe).
pub const AOI_LOCAL: &str = "AOI local tag, not externally accessible";

/// Bytes of a multi-service packet request besides its services (used to estimate the packet size).
pub(crate) const MULTISERVICE_READ_OVERHEAD: usize = 10;
/// Bytes of a multi-service reply besides its services: sequence, reply header and service count.
pub(crate) const MULTISERVICE_REPLY_OVERHEAD: usize = 8;
/// General statuses a controller answers the reads of an AOI's locals with: IOI syntax error, permission denied.
pub(crate) const AOI_REFUSED: [u8; 2] = [0x04, 0x0F];

const TAG_TABLE_UPLOAD_TRIES: usize = 3;
const SYMBOL_PAGE_REPLY: usize = 1000; // reply bytes budgeted for a symbol list page, about 20 tags
const MAKEUP_REPLY: usize = 36; // offset, header, count and 4 attributes
const MAKEUP_ATTRIBUTES: [u8; 10] = [0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00];
const GET_ATTRIBUTES_ALL: u8 = 0x01;
const GET_ATTRIBUTE_LIST: u8 = 0x03;
const SET_ATTRIBUTE_LIST: u8 = 0x04;
const GET_INSTANCE_ATTRIBUTE_LIST: u8 = 0x55;
const READ_TAG: u8 = 0x4C;
const IDENTITY_CLASS: i64 = 0x01;
const PROGRAM_NAME_CLASS: i64 = 0x64;
const SYMBOL_CLASS: i64 = 0x6B;
const TEMPLATE_CLASS: i64 = 0x6C;
const WALL_CLOCK_CLASS: i64 = 0x8B;
/// Nesting of structure templates followed before giving up (Python stops at its recursion limit).
const MAX_TEMPLATE_DEPTH: usize = 200;
/// Bytes of a member info at the start of a raw template.
const TEMPLATE_MEMBER_INFO_LEN: usize = 8;
const SCOPE_KEYS: [&str; 3] = ["programs", "tasks", "modules"];

/// Symbol lists by scope: the controller (None) or a program.
type SymbolLists = Vec<(Option<String>, Vec<Symbol>)>;

// ------------------------------------------------------------------------------------------------ options

/// Options of a [`LogixDriver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogixOptions {
    /// Upload the tag definitions on connect (ignored with `lazy_tags`). Default true.
    pub init_tags: bool,
    /// With `init_tags`, upload the program-scoped tags too. Default true.
    pub init_program_tags: bool,
    /// Only tags whose name (without `Program:X.`) starts with this prefix are kept. Default empty.
    pub tag_namespace_filter: String,
    /// Skip the upload on connect and resolve tag definitions at their first use. Default false.
    pub lazy_tags: bool,
    /// File keeping the tag list between connections (see [`tag_cache`](crate::logix::tag_cache)): a connect
    /// at an unchanged tag table version uploads nothing, and the templates of an unchanged symbol list are not
    /// read again.
    pub tag_cache_file: Option<PathBuf>,
    /// Connection options.
    pub cip: CipOptions,
}

impl Default for LogixOptions {
    fn default() -> Self {
        LogixOptions {
            init_tags: true,
            init_program_tags: true,
            tag_namespace_filter: String::new(),
            lazy_tags: false,
            tag_cache_file: None,
            cip: CipOptions::default(),
        }
    }
}

// ------------------------------------------------------------------------------------------------ public types

/// The result of probing an AOI type: whether a whole instance can be read, and which members can.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AoiProbe {
    /// The read of a whole instance was not refused.
    pub whole_read: bool,
    /// Members whose read was not refused, in template order.
    pub readable: Vec<String>,
    /// Members refused (0x04 IOI syntax error or 0x0F permission denied): local tags.
    pub refused: Vec<String>,
}

impl AoiProbe {
    /// The probe as the Python driver's dict (`data_type['aoi']`).
    pub fn to_py(&self) -> PyObj {
        let list =
            |items: &[String]| PyObj::List(items.iter().map(|s| PyObj::Str(s.clone())).collect());
        PyObj::Dict(vec![
            (
                PyObj::Str("whole_read".into()),
                PyObj::Bool(self.whole_read),
            ),
            (PyObj::Str("readable".into()), list(&self.readable)),
            (PyObj::Str("refused".into()), list(&self.refused)),
        ])
    }
}

/// The identity read by [`LogixDriver::get_plc_info`] and its keyswitch position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlcInfo {
    /// The Identity Object attributes.
    pub identity: ModuleIdentity,
    /// Keyswitch position decoded from the status word, e.g. `"REMOTE RUN"`.
    pub keyswitch: String,
}

/// The tag definitions of a [`LogixDriver`] at one moment (see [`LogixDriver::definitions`]).
#[derive(Clone, Debug)]
pub struct Definitions {
    /// The [`LogixDriver::definitions_version`] they were taken at.
    pub version: u64,
    /// Changes when the tag definitions are replaced (an upload, shared tags), not when tags are added to them
    /// (lazy loads, which only append).
    pub tags_generation: u64,
    /// Where `tags` starts in the driver's tag definitions: 0, or the count of tags a binding already has
    /// (see [`LogixDriver::definitions_since`]).
    pub tags_from: usize,
    /// Tag definitions by name, in upload order (from `tags_from` on).
    pub tags: IndexMap<String, TagDef>,
    /// Structure data types by name.
    pub data_types: IndexMap<Option<String>, Arc<DataType>>,
    /// The AOI probes applied to data type objects (Python's `data_type['aoi']`): a probe belongs to the very
    /// `Arc` it is paired with (compare with [`Arc::ptr_eq`]), not to every type of that name.
    pub probes: Vec<(Arc<DataType>, AoiProbe)>,
}

/// A tag's or a member's definition returned by [`LogixDriver::get_tag_info`].
#[derive(Clone, Debug, PartialEq)]
pub enum TagDefinition {
    /// A whole tag.
    Tag(TagDef),
    /// A structure member.
    Member(MemberInfo),
}

// ------------------------------------------------------------------------------------------------ requests

/// A connected service the driver built, taking its sequence count when it was built (as the Python packets
/// do), sent alone or embedded in a multi-service packet.  `key` names the request to its sender (the read and
/// write engine uses its own key type); a tag table version check has none.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Request<K> {
    /// The sequence count taken when the request was built.
    pub(crate) sequence: u16,
    /// The service message without its sequence count (what is embedded in a multi-service packet).
    pub(crate) message: Vec<u8>,
    /// A fragmented read or write: always sent alone.
    pub(crate) fragmented: bool,
    /// The sender's name for the request, None for a tag table version check.
    pub(crate) key: Option<K>,
}

impl<K> Request<K> {
    /// A request built now, taking the next sequence count.
    pub(crate) fn new(conn: &mut CipConnection, message: Vec<u8>, key: K) -> Self {
        Request {
            sequence: conn.next_sequence(),
            message,
            fragmented: false,
            key: Some(key),
        }
    }

    /// A tag table version check built now, taking the next sequence count.
    pub(crate) fn version_check(conn: &mut CipConnection) -> Self {
        Request {
            sequence: conn.next_sequence(),
            message: TAG_TABLE_VERSION_SERVICE.to_vec(),
            fragmented: false,
            key: None,
        }
    }

    /// True for a tag table version check.
    pub(crate) fn is_version_check(&self) -> bool {
        self.key.is_none()
    }

    /// The size Python counts for packing: the message with its 2-byte sequence count (embedded, the count
    /// becomes a 2-byte offset).
    fn packed_size(&self) -> usize {
        2 + self.message.len()
    }
}

/// A packet to send: one request alone, or several in a multi-service packet with its own sequence count.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Packet<K> {
    /// A request sent alone.
    Single(Request<K>),
    /// A multi-service packet.
    Multi {
        /// The packet's sequence count.
        sequence: u16,
        /// The embedded requests, in order.
        requests: Vec<Request<K>>,
    },
}

impl<K> Packet<K> {
    /// The CIP message of the packet (without its sequence count).
    pub(crate) fn message(&self) -> Result<Vec<u8>> {
        match self {
            Packet::Single(r) => Ok(r.message.clone()),
            Packet::Multi { requests, .. } => {
                let messages: Vec<&[u8]> = requests.iter().map(|r| r.message.as_slice()).collect();
                packets::multi_service_message(&messages)
            }
        }
    }

    /// The packet's sequence count.
    pub(crate) fn sequence(&self) -> u16 {
        match self {
            Packet::Single(r) => r.sequence,
            Packet::Multi { sequence, .. } => *sequence,
        }
    }
}

// ------------------------------------------------------------------------------------------------ state

/// The controller info (the Python driver's `info` dict): its entries in the order they were set, with the
/// `programs`, `tasks` and `modules` entries (None placeholders in `items`) kept in `scope`.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Info {
    /// Entries in insertion order; `programs`, `tasks` and `modules` are placeholders rendered from `scope`.
    pub(crate) items: IndexMap<String, PyObj>,
    /// The programs, tasks and modules found by the tag list uploads.
    pub(crate) scope: ScopeInfo,
}

fn dict_get<'a>(obj: &'a PyObj, key: &str) -> Option<&'a PyObj> {
    match obj {
        PyObj::Dict(items) => items.iter().find_map(|(k, v)| match k {
            PyObj::Str(s) if s == key => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

impl Info {
    fn str(&self, key: &str) -> Option<&str> {
        match self.items.get(key) {
            Some(PyObj::Str(s)) => Some(s),
            _ => None,
        }
    }

    fn revision(&self, part: &str) -> Option<i128> {
        match self.items.get("revision").and_then(|r| dict_get(r, part)) {
            Some(PyObj::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// The serial number, None before `get_plc_info`.
    pub(crate) fn serial(&self) -> Option<&str> {
        self.str("serial")
    }

    /// Makes sure `programs`, `tasks` and `modules` exist, emptying them all if `reset`.
    fn ensure_scope(&mut self, reset: bool) {
        for key in SCOPE_KEYS {
            if reset || !self.items.contains_key(key) {
                self.items.insert(key.to_owned(), PyObj::None);
                match key {
                    "programs" => self.scope.programs.clear(),
                    "tasks" => self.scope.tasks.clear(),
                    _ => self.scope.modules.clear(),
                }
            }
        }
    }

    fn to_py(&self) -> PyObj {
        let scope = self.scope.to_py();
        PyObj::Dict(
            self.items
                .iter()
                .map(|(k, v)| {
                    let value = if SCOPE_KEYS.contains(&k.as_str()) {
                        dict_get(&scope, k).cloned().unwrap_or(PyObj::None)
                    } else {
                        v.clone()
                    };
                    (PyObj::Str(k.clone()), value)
                })
                .collect(),
        )
    }
}

/// A template's raw definition and where it came from (a tag cache file load, or 0 when read).
#[derive(Clone, Debug)]
pub(crate) struct CachedTemplate {
    makeup: TemplateMakeup,
    data: Arc<Vec<u8>>,
    origin: u64,
}

/// The per-connection template caches of the Python driver's `_cache`.
#[derive(Clone, Debug, Default)]
pub(crate) struct TemplateCache {
    /// `id:struct`: structure makeups read since the last upload started.
    pub(crate) structs: HashMap<u16, TemplateMakeup>,
    /// `id:template`: raw templates, kept over online edits.
    pub(crate) templates: HashMap<u16, CachedTemplate>,
    /// `id:udt`: parsed data types of the current upload, in the order they were parsed.
    pub(crate) udts: IndexMap<u16, Arc<DataType>>,
    /// `id:aoi`: AOI probes and the makeup they were made at.
    pub(crate) aois: HashMap<u16, (TemplateMakeup, AoiProbe)>,
    /// `descriptions`: program references, member identifiers and Description indexes.
    pub(crate) descriptions: crate::logix::descriptions::DescriptionCache,
}

impl TemplateCache {
    fn clear(&mut self) {
        self.structs.clear();
        self.templates.clear();
        self.udts.clear();
        self.aois.clear();
        self.descriptions = Default::default();
    }
}

/// The options kept from [`LogixOptions`] (Python's `_init_args` and friends).
#[derive(Clone, Debug)]
pub(crate) struct InitArgs {
    /// Upload on connect (`init_tags` and not `lazy_tags`).
    pub(crate) init_tags: bool,
    /// The startup upload includes the programs.
    pub(crate) init_program_tags: bool,
    /// Tag name prefix filter.
    pub(crate) tag_namespace_filter: String,
    /// Tag definitions are resolved at their first use.
    pub(crate) lazy_tags: bool,
    /// The tag cache file.
    pub(crate) tag_cache_file: Option<PathBuf>,
}

/// The state of a Logix driver: the connection and everything the Python `LogixDriver` keeps.
pub(crate) struct Logix {
    /// The CIP connection.
    pub(crate) conn: CipConnection,
    /// Options.
    pub(crate) args: InitArgs,
    /// Controller info.
    pub(crate) info: Info,
    /// The target is a Micro800: no multi-service packets, no program name, no instance IDs.
    pub(crate) micro800: bool,
    /// Tags are requested by symbol instance ID (Python's `_cfg["use_instance_ids"]`).
    pub(crate) use_instance_ids: bool,
    /// The controller reports its tag table version.
    pub(crate) tag_table_detection: bool,
    /// The tag table version `tags` was loaded at, None if unknown.
    pub(crate) tag_table_version: Option<TagTableVersion>,
    /// Download and project timestamps of the kept templates.
    templates_read_at: Option<(i32, i32, i32)>,
    /// Until when reloads are backed off, and the error refused requests get meanwhile.
    reload_backoff: Option<(Instant, String)>,
    /// Tag definitions by name, in upload order.
    pub(crate) tags: IndexMap<String, TagDef>,
    /// Incremented whenever `tags` is replaced (not when a lazy load adds to it): a memo of parsed requests
    /// is valid for one generation, as Python's memo is for one `_tags` dict.
    pub(crate) tags_generation: u64,
    /// Structure data types by name (None for a template without one).
    pub(crate) data_types: IndexMap<Option<String>, Arc<DataType>>,
    /// Lazy tags: each scope's symbol list, read once.
    pub(crate) lazy_tag_lists: HashMap<Option<String>, IndexMap<String, Symbol>>,
    /// Template caches.
    pub(crate) cache: TemplateCache,
    /// The AOI probes applied to data type objects (Python's `data_type['aoi']`).
    pub(crate) aoi_applied: AppliedProbes,
    /// Incremented whenever `tags`, `data_types` or `aoi_applied` change (see [`LogixDriver::definitions`]).
    pub(crate) definitions: Arc<AtomicU64>,
    clock_offset: Duration,
}

static FILE_ORIGIN: AtomicU64 = AtomicU64::new(1);

/// The result of a reply that may fail: Python's `TagError` from `response.error` of a generic message.
fn generic_error(reply: &GenericReply) -> String {
    reply
        .tag
        .error
        .as_ref()
        .map_or_else(|| "None".into(), |e| e.message.clone())
}

/// Wraps a failure other than a CommError as a ResponseError with `message` (Python's `raise ... from err`).
fn wrap(err: Error, message: &str) -> Error {
    match err {
        Error::Comm(_) => err,
        _ => Error::response(message),
    }
}

impl Logix {
    /// A closed driver state for `path` (Logix path parsing: a bare IP means slot 0).
    pub(crate) fn new(path: &str, options: LogixOptions, connector: Connector) -> Result<Self> {
        let conn = CipConnection::new(path, options.cip, connector, true)?;
        Ok(Logix {
            conn,
            args: InitArgs {
                init_tags: options.init_tags && !options.lazy_tags,
                init_program_tags: options.init_program_tags,
                tag_namespace_filter: options.tag_namespace_filter,
                lazy_tags: options.lazy_tags,
                tag_cache_file: options.tag_cache_file,
            },
            info: Info::default(),
            micro800: false,
            use_instance_ids: true,
            tag_table_detection: false,
            tag_table_version: None,
            templates_read_at: None,
            reload_backoff: None,
            tags: IndexMap::new(),
            tags_generation: 0,
            data_types: IndexMap::new(),
            lazy_tag_lists: HashMap::new(),
            cache: TemplateCache::default(),
            aoi_applied: AppliedProbes::default(),
            definitions: Arc::new(AtomicU64::new(0)),
            clock_offset: Duration::ZERO,
        })
    }

    /// Marks the tag definitions changed, for the bindings rendering them.
    pub(crate) fn definitions_changed(&self) {
        self.definitions.fetch_add(1, Ordering::Release);
    }

    /// The driver's clock: now, moved by `advance_clock` (a test clock moved past the range of `Instant` stays
    /// at now instead of panicking).
    fn now(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(self.clock_offset).unwrap_or(now)
    }

    // -------------------------------------------------------------------------------------------- open/close

    /// Registers a session and initializes the driver; on an initialization failure the connection is closed
    /// (its CommError ignored) and the failure returned, so the next `open()` reconnects.
    pub(crate) fn open(&mut self) -> Result<bool> {
        if self.conn.connected() {
            return Ok(true);
        }
        let opened = self.conn.open()?;
        if opened {
            if self.args.lazy_tags {
                self.reset_lazy_tags();
            }
            if let Err(err) = self.initialize_driver() {
                if let Err(close) = self.conn.close() {
                    log::debug!("close after a failed initialization: {close}");
                }
                return Err(err);
            }
        }
        Ok(opened)
    }

    fn initialize_driver(&mut self) -> Result<()> {
        log::info!("Initializing driver...");
        let identity = self.conn.list_identity()?;
        log::debug!("Identified target: {identity:?}");
        self.micro800 = identity
            .as_ref()
            .is_some_and(|i| i.identity.product_name.starts_with(MICRO800_PREFIX));
        let serial = self.info.serial().map(str::to_owned);
        let items = self.plc_info()?.1;
        self.info = Info {
            items,
            scope: ScopeInfo::default(),
        };
        if self.info.serial() != serial.as_deref() {
            // template instance ids are the controller's
            self.cache.templates.clear();
            self.cache.aois.clear();
        }
        self.reload_backoff = None;

        self.use_instance_ids = self.revision_major() >= MIN_VER_INSTANCE_IDS && !self.micro800;
        if !self.micro800 {
            self.get_plc_name()?;
        }
        if self.micro800 && matches!(self.conn.cip_path().last(), Some(Segment::Port { .. })) {
            self.conn.cip_path_mut().pop(); // the backplane segment is not used by these controllers
        }

        // an ID can name another tag after an online edit, IDs are only used if the version shows edits
        self.tag_table_detection = false;
        let mut version = None;
        if self.use_instance_ids {
            version = self.read_tag_table_version()?;
            self.tag_table_detection = version.is_some();
            if self.tags.is_empty() {
                self.tag_table_version = version;
            }
            if !self.tag_table_detection {
                log::warn!(
                    "The controller does not report its tag table version, tag table change detection is \
                     unavailable: tags are requested by name instead of by instance ID"
                );
                self.use_instance_ids = false;
            }
        }
        if self.args.init_tags {
            let scope = self.startup_scope();
            let filter = self.args.tag_namespace_filter.clone();
            self.load_tag_list(scope.as_deref(), true, &filter, version)?;
        }
        log::info!("Initialization complete.");
        Ok(())
    }

    fn startup_scope(&self) -> Option<String> {
        self.args.init_program_tags.then(|| "*".to_owned())
    }

    /// Forgets the tag definitions and every cache (lazy tags, on connect and after a tag table change).
    pub(crate) fn reset_lazy_tags(&mut self) {
        self.tags = IndexMap::new();
        self.tags_generation += 1;
        self.data_types = IndexMap::new();
        self.definitions_changed();
        self.lazy_tag_lists.clear();
        self.cache.clear();
        self.aoi_applied.clear();
    }

    // -------------------------------------------------------------------------------------------- info

    /// The major revision of the controller, 0 if unknown.
    pub(crate) fn revision_major(&self) -> u32 {
        self.info
            .revision("major")
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0)
    }

    /// Reads the identity; returns it and the info entries (identity and keyswitch), merged into `info`.
    fn plc_info(&mut self) -> Result<(PlcInfo, IndexMap<String, PyObj>)> {
        let msg = GenericMessage {
            service: GET_ATTRIBUTES_ALL,
            class_code: LogicalValue::Int(IDENTITY_CLASS),
            instance: LogicalValue::Raw(vec![0x01]),
            connected: false,
            unconnected_send: !self.micro800,
            name: "get_plc_info".into(),
            ..GenericMessage::default()
        };
        let read = |conn: &mut CipConnection| -> Result<ModuleIdentity> {
            let reply = conn.generic_message(&msg)?;
            if !reply.is_ok() {
                return Err(Error::response(format!(
                    "get_plc_info did not return valid data - {}",
                    generic_error(&reply)
                )));
            }
            ModuleIdentity::decode(&mut Reader::new(reply.data().unwrap_or_default()))
        };
        let identity = read(&mut self.conn).map_err(|e| wrap(e, "Failed to get PLC info"))?;
        let keyswitch = status::keyswitch(identity.status[0], identity.status[1]).to_owned();
        let items = identity_items(&identity, &keyswitch);
        for (k, v) in &items {
            self.info.items.insert(k.clone(), v.clone());
        }
        Ok((
            PlcInfo {
                identity,
                keyswitch,
            },
            items,
        ))
    }

    /// Reads the program name (KB 23341) into `info["name"]`.
    pub(crate) fn get_plc_name(&mut self) -> Result<String> {
        self.conn.ensure_forward_open("get_plc_name")?;
        let msg = GenericMessage {
            service: GET_ATTRIBUTES_ALL,
            class_code: LogicalValue::Int(PROGRAM_NAME_CLASS),
            instance: LogicalValue::Int(1),
            name: "get_plc_name".into(),
            ..GenericMessage::default()
        };
        let read = |conn: &mut CipConnection| -> Result<String> {
            let reply = conn.generic_message(&msg)?;
            if !reply.is_ok() {
                return Err(Error::response(format!(
                    "response did not return valid data - {}",
                    generic_error(&reply)
                )));
            }
            let data = reply.data().unwrap_or_default();
            if data.is_empty() {
                return Ok(String::new()); // Python keeps the empty reply data as the name
            }
            match Elementary::String.decode(&mut Reader::new(data))? {
                Value::String(s) => Ok(s),
                _ => Err(Error::data("program name is not a string")),
            }
        };
        let name = read(&mut self.conn).map_err(|e| wrap(e, "failed to get the plc name"))?;
        self.info
            .items
            .insert("name".into(), PyObj::Str(name.clone()));
        Ok(name)
    }

    // -------------------------------------------------------------------------------------------- versions

    /// Requests by instance ID are checked against the tag table version.
    pub(crate) fn version_checks(&self) -> bool {
        self.use_instance_ids && self.tag_table_detection
    }

    /// Reads the tag table version (1756-PM020 step 5), None if the controller did not return it.
    pub(crate) fn read_tag_table_version(&mut self) -> Result<Option<TagTableVersion>> {
        let request = Request::<()>::version_check(&mut self.conn);
        let raw = self
            .conn
            .send_connected(request.sequence, &request.message)?;
        let mut reply = Reply::parse(ReplyKind::SendUnitData, &raw);
        let version = parse_tag_table_version(&mut reply);
        if version.is_none() {
            log::info!(
                "Tag table version not read - {}",
                reply.error().unwrap_or_else(|| "None".into())
            );
        }
        Ok(version)
    }

    /// True if a version read differs from `loaded_at` or failed (None).
    #[allow(dead_code)] // for the read/write engine (logix/rw.rs)
    pub(crate) fn tag_table_changed(
        versions: &[Option<TagTableVersion>],
        loaded_at: Option<TagTableVersion>,
    ) -> bool {
        versions.iter().any(|v| v.is_none() || *v != loaded_at)
    }

    /// Loads the tag definitions again as `open()` did after the tag table version changed; if that fails
    /// (e.g. a download in progress) reloads are backed off and false is returned. CommErrors pass through.
    pub(crate) fn refresh_tag_table(&mut self) -> Result<bool> {
        log::info!("Tag table changed on the controller, loading the tag definitions again");
        if self.backoff_error().is_some() {
            return Ok(false);
        }
        let result = if self.args.lazy_tags {
            match self.read_tag_table_version() {
                Ok(Some(version)) => {
                    self.reset_lazy_tags();
                    self.tag_table_version = Some(version);
                    Ok(())
                }
                Ok(None) => Err(Error::response("the tag table version was not read")),
                Err(err) => Err(err),
            }
        } else {
            let scope = self.startup_scope();
            let filter = self.args.tag_namespace_filter.clone();
            self.load_tag_list(scope.as_deref(), true, &filter, None)
                .map(|_| ())
        };
        match result {
            Ok(()) => Ok(true),
            Err(err @ Error::Comm(_)) => Err(err),
            Err(err) => {
                self.back_off(&format!("reload failed - {err}"));
                Ok(false)
            }
        }
    }

    /// No reload is attempted for the next [`RELOAD_BACKOFF`]: reads and writes get an error instead.
    pub(crate) fn back_off(&mut self, reason: &str) {
        let secs = RELOAD_BACKOFF.as_secs_f64();
        log::warn!("Tag table not reloaded, {reason}, next attempt in {secs:?} s");
        let error = format!(
            "Tag table is being reloaded, controller busy ({reason}), next attempt in {secs:?} s"
        );
        let now = self.now();
        self.reload_backoff = Some((now.checked_add(RELOAD_BACKOFF).unwrap_or(now), error));
    }

    /// The error of the requests refused while reloads are backed off, None if they are not.
    pub(crate) fn backoff_error(&self) -> Option<String> {
        match &self.reload_backoff {
            Some((until, error)) if self.now() < *until => Some(error.clone()),
            _ => None,
        }
    }

    /// The error refused requests get: the backoff error, kind Refused.
    #[allow(dead_code)] // for the read/write engine (logix/rw.rs)
    pub(crate) fn refused_error(&self) -> TagError {
        let message = self
            .reload_backoff
            .as_ref()
            .map(|(_, e)| e.clone())
            .unwrap_or_default();
        TagError::new(message, ErrorKind::Refused)
    }

    /// Loads the definitions again if the controller's tag table changed since they were loaded.
    pub(crate) fn check_tag_table(&mut self) -> Result<bool> {
        self.conn.ensure_forward_open("check_tag_table")?;
        if !self.version_checks() || self.backoff_error().is_some() {
            return Ok(false);
        }
        let Some(version) = self.read_tag_table_version()? else {
            self.back_off("the tag table version was not read");
            return Ok(false);
        };
        if Some(version) == self.tag_table_version {
            return Ok(false);
        }
        self.refresh_tag_table()
    }

    // -------------------------------------------------------------------------------------------- packing

    /// Groups consecutive requests into multi-service packets, in call order, bounding both the request and the
    /// reply size by the connection size. Fragmented requests, requests too big for a multi-service packet,
    /// and groups of one are sent alone; a Micro800 gets every request alone.
    ///
    /// With `version_checks` (reads only) every multi-service packet starts with a tag table version check, so
    /// a group of one is a packet of two, and a request sent alone gets a standalone check before and after it.
    /// Packets and checks take their sequence counts here, in Python's order.
    pub(crate) fn pack_multi_requests<K>(
        &mut self,
        sized_requests: Vec<(Request<K>, usize)>,
        version_checks: bool,
    ) -> Vec<Packet<K>> {
        if self.micro800 {
            return sized_requests
                .into_iter()
                .map(|(r, _)| Packet::Single(r))
                .collect();
        }
        let connection_size = usize::from(self.conn.connection_size());
        let mut empty_request = MULTISERVICE_READ_OVERHEAD;
        let mut empty_response = MULTISERVICE_REPLY_OVERHEAD;
        if version_checks {
            empty_request += TAG_TABLE_VERSION_REQUEST_SIZE;
            empty_response += TAG_TABLE_VERSION_REPLY_SIZE;
        }
        let mut packets: Vec<Packet<K>> = Vec::new();
        let mut group: Vec<Request<K>> = Vec::new();
        let (mut request_size, mut response_size) = (empty_request, empty_response);

        let flush = |conn: &mut CipConnection,
                     packets: &mut Vec<Packet<K>>,
                     group: &mut Vec<Request<K>>| {
            if version_checks && !group.is_empty() {
                // the check is built before the packet, as Python evaluates its arguments
                let check = Request::version_check(conn);
                let sequence = conn.next_sequence();
                let mut requests = Vec::with_capacity(group.len() + 1);
                requests.push(check);
                requests.append(group);
                packets.push(Packet::Multi { sequence, requests });
            } else if group.len() == 1 {
                packets.extend(group.drain(..).map(Packet::Single));
            } else if !group.is_empty() {
                let sequence = conn.next_sequence();
                packets.push(Packet::Multi {
                    sequence,
                    requests: std::mem::take(group),
                });
            }
        };

        for (request, reply_size) in sized_requests {
            let message_size = request.packed_size();
            if request.fragmented
                || empty_request + message_size > connection_size
                || empty_response + reply_size > connection_size
            {
                flush(&mut self.conn, &mut packets, &mut group);
                let last_is_check =
                    matches!(packets.last(), Some(Packet::Single(r)) if r.is_version_check());
                if version_checks && !last_is_check {
                    packets.push(Packet::Single(Request::version_check(&mut self.conn)));
                }
                packets.push(Packet::Single(request));
                if version_checks {
                    packets.push(Packet::Single(Request::version_check(&mut self.conn)));
                }
                (request_size, response_size) = (empty_request, empty_response);
                continue;
            }
            if request_size + message_size > connection_size
                || response_size + reply_size > connection_size
            {
                flush(&mut self.conn, &mut packets, &mut group);
                (request_size, response_size) = (empty_request, empty_response);
            }
            group.push(request);
            request_size += message_size;
            response_size += reply_size;
        }
        flush(&mut self.conn, &mut packets, &mut group);
        packets
    }

    /// Sends a packet as built, returning the reply of a request sent alone, or the reply of a multi-service
    /// packet and its services' replies.
    pub(crate) fn send_packet<K>(&mut self, packet: &Packet<K>) -> Result<(Reply, Vec<Reply>)> {
        let raw = self
            .conn
            .send_connected(packet.sequence(), &packet.message()?)?;
        Ok(match packet {
            Packet::Single(_) => (Reply::parse(ReplyKind::SendUnitData, &raw), Vec::new()),
            Packet::Multi { requests, .. } => {
                let multi = parse_multi_service_reply(&raw, requests.len());
                (multi.reply, multi.replies)
            }
        })
    }

    /// Sends the requests in multi-service packets and returns (key, reply) of each request answered in one
    /// with a valid reply. The others (sent alone, or a packet that was not answered) are left to the caller.
    pub(crate) fn send_batched<K>(
        &mut self,
        sized_requests: Vec<(Request<K>, usize)>,
    ) -> Result<Vec<(K, Reply)>> {
        let mut answered = Vec::new();
        for packet in self.pack_multi_requests(sized_requests, false) {
            if let Packet::Multi { .. } = &packet {
                let (reply, replies) = self.send_packet(&packet)?;
                if replies.is_empty() {
                    log::info!(
                        "Multi-service request not answered, sending its requests alone - {}",
                        reply.error().unwrap_or_else(|| "None".into())
                    );
                }
                let Packet::Multi { requests, .. } = packet else {
                    continue;
                };
                for (request, reply) in requests.into_iter().zip(replies) {
                    if let (Some(key), true) = (request.key, reply.is_valid()) {
                        answered.push((key, reply));
                    }
                }
            }
        }
        Ok(answered)
    }

    // -------------------------------------------------------------------------------------------- tag lists

    /// `get_tag_list`; `version` (with checks) is a tag table version just read, the read before the upload.
    pub(crate) fn load_tag_list(
        &mut self,
        program: Option<&str>,
        cache: bool,
        namespace_filter: &str,
        mut version: Option<TagTableVersion>,
    ) -> Result<Vec<TagDef>> {
        let program = program.map(|p| p.strip_prefix("Program:").unwrap_or(p).to_owned());
        let checks = cache && self.version_checks();
        let mut tags = Vec::new();
        let mut settled = false;
        for attempt in 1..=TAG_TABLE_UPLOAD_TRIES {
            if !checks {
                version = None;
            } else if version.is_none() || attempt > 1 {
                version = self.read_tag_table_version()?;
                if version.is_none() {
                    return Err(Error::response(
                        "Tag table version not read, the tag list was not uploaded",
                    ));
                }
            }
            tags = self.upload_tag_list(program.as_deref(), cache, namespace_filter, version)?;
            if !checks {
                settled = true;
                break;
            }
            let after = self.read_tag_table_version()?;
            if after == version {
                settled = true;
                break;
            }
            if after.is_none() {
                self.back_off("the tag table version was not read after the upload");
                version = None; // the first read or write after the backoff loads it again
                settled = true;
                break;
            }
            log::info!("Tag table changed during upload {attempt} of {TAG_TABLE_UPLOAD_TRIES}");
        }
        if !settled {
            log::warn!("Tag table kept changing during the upload, keeping the last one");
        }
        if cache {
            let mut by_name = IndexMap::with_capacity(tags.len());
            for tag in &tags {
                by_name.insert(tag.tag_name.clone(), tag.clone());
            }
            self.tags = by_name;
            self.tags_generation += 1;
            self.definitions_changed();
            self.lazy_tag_lists.clear();
            self.tag_table_version = version;
        }
        log::info!(
            "Completed tag list upload. Uploaded {} tags.",
            self.tags.len()
        );
        Ok(tags)
    }

    fn upload_tag_list(
        &mut self,
        program: Option<&str>,
        cache: bool,
        namespace_filter: &str,
        version: Option<TagTableVersion>,
    ) -> Result<Vec<TagDef>> {
        self.cache.structs.clear(); // the raw templates are kept, their makeups are read again
        // only across online edits: a download can reorder a template's members and keep its makeup
        let read_at = version.map(|v| (v.2, v.3, v.4));
        if read_at.is_none() || read_at != self.templates_read_at {
            self.cache.templates.clear();
            self.cache.aois.clear();
        }
        self.templates_read_at = read_at;
        self.cache.udts.clear();
        let all_scopes = program.is_none() || program == Some("*");
        self.info.ensure_scope(all_scopes);

        log::info!("Starting tag list upload...");
        let startup_scope = self.startup_scope();
        if cache
            && self.args.tag_cache_file.is_some()
            && !self.args.lazy_tags
            && program == startup_scope.as_deref()
        {
            return self.tag_list_with_cache_file(program, namespace_filter, version);
        }
        let symbols = self.get_symbol_lists(program)?;
        let tags = self.isolate_scopes(&symbols, namespace_filter)?;
        if !self.args.lazy_tags {
            self.probe_aois(&tags)?;
        }
        Ok(tags)
    }

    /// Uploads the symbol list of each scope of a `get_tag_list` program as (scope, symbols): the controller
    /// (None) or a program; for `*` the controller then every program in it, their pages batched.
    fn get_symbol_lists(&mut self, program: Option<&str>) -> Result<SymbolLists> {
        let scope = program.filter(|p| *p != "*").map(str::to_owned);
        let symbols = self.get_symbol_list(scope.as_deref())?;
        let programs: Vec<String> = if program == Some("*") {
            symbols
                .iter()
                .filter(|s| s.tag_name.starts_with("Program:"))
                .map(|s| s.tag_name.replace("Program:", ""))
                .collect()
        } else {
            Vec::new()
        };
        let mut lists = vec![(scope, symbols)];
        if program == Some("*") {
            let mut uploaded = self.get_program_symbol_lists(&programs)?;
            for p in programs {
                let list = uploaded.get(&p).cloned().unwrap_or_default();
                lists.push((Some(p.clone()), list));
            }
            uploaded.clear();
        }
        Ok(lists)
    }

    fn get_symbol_list(&mut self, program: Option<&str>) -> Result<Vec<Symbol>> {
        let name = program.unwrap_or("controller");
        log::info!("Beginning upload of {name} tags...");
        let tags = self.get_instance_attribute_list_service(program, 0)?;
        log::info!("Completed upload of {name} tags");
        Ok(tags)
    }

    /// Uploads the symbol lists of these programs: every round asks each unfinished program for its next page,
    /// several programs per multi-service packet; a program whose page is not answered in a packet (or made no
    /// progress, or was sent alone) is uploaded from that page on by itself.
    fn get_program_symbol_lists(
        &mut self,
        programs: &[String],
    ) -> Result<IndexMap<String, Vec<Symbol>>> {
        log::info!(
            "Beginning upload of the tags of {} programs...",
            programs.len()
        );
        let revision = self.revision_major();
        let mut lists: IndexMap<String, Vec<Symbol>> =
            programs.iter().map(|p| (p.clone(), Vec::new())).collect();
        let mut starts: IndexMap<String, u64> = programs.iter().map(|p| (p.clone(), 0)).collect();
        while !starts.is_empty() {
            let mut requests = Vec::with_capacity(starts.len());
            for (program, start) in &starts {
                let request = self.symbol_list_request(Some(program), *start, program.clone())?;
                requests.push((request, SYMBOL_PAGE_REPLY));
            }
            let mut next_starts: IndexMap<String, u64> = IndexMap::new();
            let mut finished: Vec<String> = Vec::new();
            for (program, reply) in self.send_batched(requests)? {
                let mut page = Vec::new();
                let next = parse_symbol_list(
                    reply.data.as_deref().unwrap_or_default(),
                    reply.service_status.unwrap_or_default(),
                    revision,
                    &mut page,
                )?;
                let start = starts.get(&program).copied().unwrap_or_default();
                let progressed = match next {
                    None => true,
                    Some(n) => !page.is_empty() && n > start,
                };
                if progressed {
                    lists.entry(program.clone()).or_default().extend(page);
                    match next {
                        Some(n) => {
                            next_starts.insert(program, n);
                        }
                        None => {
                            finished.push(program.clone());
                            next_starts.insert(program, u64::MAX);
                        }
                    }
                }
            }
            for (program, start) in &starts {
                if !next_starts.contains_key(program) {
                    let rest = self.get_instance_attribute_list_service(Some(program), *start)?;
                    lists.entry(program.clone()).or_default().extend(rest);
                }
            }
            starts = next_starts
                .into_iter()
                .filter(|(p, _)| !finished.contains(p))
                .collect();
        }
        log::info!(
            "Completed upload of the tags of {} programs",
            programs.len()
        );
        Ok(lists)
    }

    /// The request for a page of the symbol list of `program` (None for the controller) from `instance`.
    fn symbol_list_request<K>(
        &mut self,
        program: Option<&str>,
        instance: u64,
        key: K,
    ) -> Result<Request<K>> {
        let mut segments = Vec::with_capacity(3);
        if let Some(program) = program.filter(|p| !p.is_empty()) {
            let name = if program.starts_with("Program:") {
                program.to_owned()
            } else {
                format!("Program:{program}")
            };
            segments.push(Segment::Data(DataValue::Symbol(name)));
        }
        let instance = i64::try_from(instance)
            .map_err(|_| Error::data(format!("Error packing {instance} as UDINT")))?;
        segments.push(Segment::logical(
            LogicalType::ClassId,
            LogicalValue::Int(SYMBOL_CLASS),
        ));
        segments.push(Segment::logical(
            LogicalType::InstanceId,
            LogicalValue::Int(instance),
        ));
        let path = encode_epath(&segments, true, true, false)?;
        let mut attributes: Vec<u16> = vec![1, 2, 3, 5, 6, 8];
        if self.revision_major() >= MIN_VER_EXTERNAL_ACCESS {
            attributes.push(10);
        }
        let mut message = Vec::with_capacity(path.len() + 3 + 2 * attributes.len());
        message.push(GET_INSTANCE_ATTRIBUTE_LIST);
        message.extend(path);
        message.extend((attributes.len() as u16).to_le_bytes());
        for a in attributes {
            message.extend(a.to_le_bytes());
        }
        Ok(Request::new(&mut self.conn, message, key))
    }

    /// Uploads the symbol list of `program` (None for the controller) from instance `start` on, one page per
    /// request. CommErrors pass through, other failures are `ResponseError("failed to get attribute list")`.
    pub(crate) fn get_instance_attribute_list_service(
        &mut self,
        program: Option<&str>,
        start: u64,
    ) -> Result<Vec<Symbol>> {
        let revision = self.revision_major();
        let mut upload = || -> Result<Vec<Symbol>> {
            let mut last = Some(start);
            let mut tags = Vec::new();
            while let Some(instance) = last {
                log::debug!("Getting tags starting with instance {instance}");
                let request = self.symbol_list_request(program, instance, ())?;
                let raw = self
                    .conn
                    .send_connected(request.sequence, &request.message)?;
                let reply = Reply::parse(ReplyKind::SendUnitData, &raw);
                if !reply.is_valid() {
                    return Err(Error::response(format!(
                        "send_unit_data returned not valid data - {}",
                        reply.error().unwrap_or_else(|| "None".into())
                    )));
                }
                let before = tags.len();
                last = parse_symbol_list(
                    reply.data.as_deref().unwrap_or_default(),
                    reply.service_status.unwrap_or_default(),
                    revision,
                    &mut tags,
                )?;
                if last.is_some_and(|next| next <= instance) {
                    return Err(Error::response(
                        "Tag list upload did not advance the instance cursor",
                    ));
                }
                log::debug!(
                    "Uploaded {} tags, last instance: {last:?}",
                    tags.len() - before
                );
            }
            Ok(tags)
        };
        upload().map_err(|e| wrap(e, "failed to get attribute list"))
    }

    /// The user tags of each (scope, symbol list), in order, with their definitions; the structure makeups of
    /// their templates are read first, batched.
    pub(crate) fn isolate_scopes(
        &mut self,
        symbol_lists: &[(Option<String>, Vec<Symbol>)],
        namespace_filter: &str,
    ) -> Result<Vec<TagDef>> {
        let mut scope = std::mem::take(&mut self.info.scope);
        let user: Vec<(String, Symbol)> = symbol_lists
            .iter()
            .flat_map(|(program, symbols)| {
                user_symbols(&mut scope, symbols, program.as_deref(), namespace_filter)
                    .into_iter()
                    .map(|(name, symbol)| (name, symbol.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        self.info.scope = scope;
        let mut run = || -> Result<Vec<TagDef>> {
            let ids: BTreeSet<u16> = user
                .iter()
                .filter(|(_, s)| s.symbol_type & 0x8000 != 0)
                .map(|(_, s)| s.symbol_type & 0x0FFF)
                .collect();
            self.prefetch_templates(ids)?;
            user.iter()
                .map(|(name, symbol)| self.create_tag(name, symbol))
                .collect()
        };
        run().map_err(|e| wrap(e, "failed isolating user tags"))
    }

    /// A tag's definition, reading its data type if it is a structure.
    pub(crate) fn create_tag(&mut self, name: &str, symbol: &Symbol) -> Result<TagDef> {
        create_tag(name, symbol, &mut |id, st| self.get_data_type(id, st))
    }

    // -------------------------------------------------------------------------------------------- templates

    /// Reads the structure makeups of these templates, then of the templates nested in them, level by level in
    /// multi-service packets, and the templates not read yet or whose makeup changed.
    fn prefetch_templates(&mut self, ids: BTreeSet<u16>) -> Result<()> {
        let mut pending = ids;
        while !pending.is_empty() {
            let unread: Vec<u16> = pending
                .iter()
                .copied()
                .filter(|id| !self.cache.structs.contains_key(id))
                .collect();
            self.read_structure_makeups(&unread)?;
            let mut nested = BTreeSet::new();
            for &id in &pending {
                let makeup = self.get_structure_makeup(id)?; // read alone if not answered in a batch
                let data = self.template_data(id, makeup)?;
                nested.extend(nested_template_ids(&data, &makeup)?);
            }
            pending = nested
                .into_iter()
                .filter(|id| !self.cache.structs.contains_key(id))
                .collect();
        }
        Ok(())
    }

    /// Reads the structure makeups of these templates into the cache in multi-service packets; those not
    /// answered there are left to `get_structure_makeup`.
    fn read_structure_makeups(&mut self, ids: &[u16]) -> Result<()> {
        let mut requests = Vec::with_capacity(ids.len());
        for &id in ids {
            let message = packets::generic_message(
                GET_ATTRIBUTE_LIST,
                LogicalValue::Int(TEMPLATE_CLASS),
                LogicalValue::Int(id.into()),
                None,
                &MAKEUP_ATTRIBUTES,
            )?;
            requests.push((Request::new(&mut self.conn, message, id), MAKEUP_REPLY));
        }
        for (id, reply) in self.send_batched(requests)? {
            let data = reply.data.unwrap_or_default();
            if data.is_empty() {
                // Python keeps the empty reply as the value and fails parsing it
                return Err(Error::response("failed to parse structure attributes"));
            }
            // a reply Python fails to decode is not answered, it is read alone
            if let Ok(makeup) = parse_structure_makeup(&data) {
                self.cache.structs.insert(id, makeup);
            }
        }
        Ok(())
    }

    /// The structure makeup of a template, read alone if not cached.
    pub(crate) fn get_structure_makeup(&mut self, id: u16) -> Result<TemplateMakeup> {
        if let Some(makeup) = self.cache.structs.get(&id) {
            return Ok(*makeup);
        }
        let reply = self.conn.generic_message(&GenericMessage {
            service: GET_ATTRIBUTE_LIST,
            class_code: LogicalValue::Int(TEMPLATE_CLASS),
            instance: LogicalValue::Int(id.into()),
            request_data: MAKEUP_ATTRIBUTES.to_vec(),
            name: format!("_get_structure_makeup(instance_id={id})"),
            ..GenericMessage::default()
        })?;
        let not_valid = |error: String| {
            Error::response(format!(
                "('send_unit_data returned not valid data', {})",
                py_str_repr(&error)
            ))
        };
        if !reply.is_ok() {
            return Err(not_valid(generic_error(&reply)));
        }
        let data = reply.data().unwrap_or_default();
        if data.is_empty() {
            return Err(Error::response("failed to parse structure attributes"));
        }
        let makeup = parse_structure_makeup(data)
            .map_err(|e| not_valid(format!("Failed to parse reply - {e}")))?;
        self.cache.structs.insert(id, makeup);
        Ok(makeup)
    }

    /// The raw template, read again only if its makeup changed since it was read or loaded from the file.
    fn template_data(&mut self, id: u16, makeup: TemplateMakeup) -> Result<Arc<Vec<u8>>> {
        if let Some(cached) = self.cache.templates.get(&id) {
            if cached.makeup == makeup {
                return Ok(Arc::clone(&cached.data));
            }
        }
        let data = Arc::new(self.read_template(id, makeup.object_definition_size)?);
        self.cache.templates.insert(
            id,
            CachedTemplate {
                makeup,
                data: Arc::clone(&data),
                origin: 0,
            },
        );
        Ok(data)
    }

    /// Reads a template in pieces until the controller says it is complete.
    fn read_template(&mut self, id: u16, object_definition_size: u32) -> Result<Vec<u8>> {
        let mut read = || -> Result<Vec<u8>> {
            let mut offset: u32 = 0;
            let mut raw = Vec::new();
            loop {
                let request_data = template_read_request(object_definition_size, offset)?;
                let reply = self.conn.generic_message(&GenericMessage {
                    service: READ_TAG,
                    class_code: LogicalValue::Int(TEMPLATE_CLASS),
                    instance: LogicalValue::Int(id.into()),
                    request_data,
                    name: format!(
                        "_read_template(instance_id={id}, object_definition_size={object_definition_size}, \
                         offset={offset})"
                    ),
                    ..GenericMessage::default()
                })?;
                let status = reply.reply.service_status;
                if !matches!(
                    status,
                    Some(packets::SUCCESS | packets::INSUFFICIENT_PACKETS)
                ) {
                    return Err(Error::response("Error reading template"));
                }
                let data = reply.reply.data.unwrap_or_default();
                raw.extend_from_slice(&data);
                if status == Some(packets::SUCCESS) {
                    return Ok(raw);
                }
                if data.is_empty() {
                    return Err(Error::response("Template read made no progress"));
                }
                offset = u32::try_from(data.len())
                    .ok()
                    .and_then(|n| offset.checked_add(n))
                    .ok_or_else(|| Error::data("template offset out of range"))?;
            }
        };
        read().map_err(|e| wrap(e, "Failed to read template"))
    }

    /// The data type of template `id`, read and parsed once per upload.
    pub(crate) fn get_data_type(&mut self, id: u16, symbol_type: u16) -> Result<Arc<DataType>> {
        if let Some(dt) = self.cache.udts.get(&id) {
            return Ok(Arc::clone(dt));
        }
        self.load_data_type(id, symbol_type).map_err(|err| {
            wrap(
                err,
                &format!("Failed to get data type information for {id}"),
            )
        })
    }

    /// Python's recursive `_get_data_type`, walked with an explicit stack so that nesting from the controller
    /// cannot overflow the caller's stack: a template's struct members not loaded yet are loaded first, in
    /// member order (the requests Python's recursion makes, in its order), then the template is parsed with
    /// them all cached. A truncated member info stops the walk where Python's parse fails.
    fn load_data_type(&mut self, id: u16, symbol_type: u16) -> Result<Arc<DataType>> {
        struct Pending {
            id: u16,
            symbol_type: u16,
            makeup: TemplateMakeup,
            data: Arc<Vec<u8>>,
            next_member: usize,
        }
        let read = |this: &mut Self, id: u16, symbol_type: u16| -> Result<Pending> {
            log::debug!("Getting data type for id {id}");
            let makeup = this.get_structure_makeup(id)?;
            let data = this.template_data(id, makeup)?;
            Ok(Pending {
                id,
                symbol_type,
                makeup,
                data,
                next_member: 0,
            })
        };
        let mut stack = vec![read(self, id, symbol_type)?];
        while let Some(top) = stack.last_mut() {
            let mut child = None;
            while child.is_none() && top.next_member < usize::from(top.makeup.member_count) {
                let start = top.next_member * TEMPLATE_MEMBER_INFO_LEN;
                top.next_member += 1;
                let Some(info) = top.data.get(start..start + TEMPLATE_MEMBER_INFO_LEN) else {
                    top.next_member = usize::MAX; // the parse fails at this member
                    break;
                };
                let one = TemplateMakeup {
                    member_count: 1,
                    ..top.makeup
                };
                let typ = u16::from_le_bytes([info[2], info[3]]);
                child = nested_template_ids(info, &one)?
                    .into_iter()
                    .next()
                    .filter(|i| !self.cache.udts.contains_key(i))
                    .map(|i| (i, typ));
            }
            if let Some((child_id, child_type)) = child {
                if stack.len() >= MAX_TEMPLATE_DEPTH {
                    return Err(Error::response(format!(
                        "Failed to get data type information for {child_id}"
                    )));
                }
                let pending = read(self, child_id, child_type)?;
                stack.push(pending);
                continue;
            }
            let Some(done) = stack.pop() else { break };
            let udts = &self.cache.udts;
            let dt = parse_template(&done.data, &done.makeup, done.symbol_type, &mut |i, _| {
                // loaded by the walk above, or a template holding itself (cut off by the depth cap)
                udts.get(&i).cloned().ok_or_else(|| {
                    Error::response(format!("Failed to get data type information for {i}"))
                })
            })?;
            let dt = Arc::new(dt);
            self.cache.udts.insert(done.id, Arc::clone(&dt));
            self.data_types.insert(dt.name.clone(), Arc::clone(&dt));
            self.definitions_changed();
            log::debug!("Got data type {:?} for id {}", dt.name, done.id);
            if stack.is_empty() {
                return Ok(dt);
            }
        }
        // the loop returns when it pops the last template
        Err(Error::response(format!(
            "Failed to get data type information for {id}"
        )))
    }

    // -------------------------------------------------------------------------------------------- AOI probe

    /// True if the AOI template was probed at its current structure makeup.
    fn aoi_probed(&self, id: u16) -> bool {
        match (self.cache.aois.get(&id), self.cache.structs.get(&id)) {
            (Some((makeup, _)), Some(current)) => makeup == current,
            _ => false,
        }
    }

    /// The probe of an AOI data type, None if not an AOI or not probed.
    #[allow(dead_code)] // for the read/write engine (logix/rw.rs)
    pub(crate) fn aoi_probe(&self, data_type: &DataType) -> Option<&AoiProbe> {
        self.aoi_applied.get(data_type)
    }

    /// The probe of a tag's or member's data type (Python's `_aoi_probe`).
    #[allow(dead_code)] // for the read/write engine (logix/rw.rs)
    pub(crate) fn aoi_probe_of(&self, info: TagInfo<'_>) -> Option<&AoiProbe> {
        match info.data_type() {
            TypeRef::Struct(dt) => self.aoi_probe(dt),
            TypeRef::Atomic(_) => None,
        }
    }

    /// Finds which members of each AOI data type are readable: for each AOI type not probed at its current
    /// makeup, one instance reachable from `tags` is read whole and member by member (Read Tag only, in
    /// multi-service packets). 0x04 and 0x0F refuse a read, any other reply (or none) leaves it readable.
    pub(crate) fn probe_aois(&mut self, tags: &[TagDef]) -> Result<()> {
        let mut wanted: IndexMap<Option<String>, u16> = IndexMap::new();
        for (&id, dt) in &self.cache.udts {
            if is_aoi(dt) && !self.aoi_probed(id) {
                wanted.insert(dt.name.clone(), id);
            }
        }
        let instances = if wanted.is_empty() {
            IndexMap::new()
        } else {
            aoi_instances(tags, &wanted)
        };
        let use_ids = self.use_instance_ids;
        let mut names: Vec<(Option<String>, Option<String>)> = Vec::new(); // (AOI, member or None)
        let mut sized = Vec::new();
        for (name, (path, base_id)) in &instances {
            let Some(dt) = wanted
                .get(name)
                .and_then(|id| self.cache.udts.get(id))
                .cloned()
            else {
                continue;
            };
            let whole = dt.template.structure_size as usize + 10;
            let mut reads: Vec<(Option<String>, String, usize)> = vec![(None, path.clone(), whole)];
            for member in &dt.attributes {
                let Some(info) = dt.internal_tags.get(member) else {
                    continue;
                };
                let size = read_reply_size(TagInfo::Member(info), 1)?;
                reads.push((Some(member.clone()), format!("{path}.{member}"), size));
            }
            for (member, tag, size) in reads {
                let request_path = tag_request_path(&tag, Some(*base_id), use_ids)?;
                let message = packets::read_tag_message(&request_path, 1);
                let request = Request::new(&mut self.conn, message, names.len());
                names.push((name.clone(), member));
                sized.push((request, size));
            }
        }
        // smallest replies first so they share packets, a whole AOI too big for one is sent alone
        sized.sort_by_key(|(_, size)| *size);
        let packets = self.pack_multi_requests(sized, false);
        let mut refused = vec![false; names.len()];
        for packet in &packets {
            let (reply, replies) = self.send_packet(packet)?;
            let pairs: Vec<(&Request<usize>, &Reply)> = match packet {
                Packet::Single(r) => vec![(r, &reply)],
                Packet::Multi { requests, .. } => requests.iter().zip(&replies).collect(),
            };
            for (request, reply) in pairs {
                let is_refused = reply
                    .service_status
                    .is_some_and(|s| AOI_REFUSED.contains(&s));
                if let (Some(index), true) = (request.key, is_refused) {
                    if let Some(flag) = refused.get_mut(index) {
                        *flag = true;
                    }
                }
            }
        }
        let mut probes: IndexMap<Option<String>, AoiProbe> = instances
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    AoiProbe {
                        whole_read: true,
                        ..AoiProbe::default()
                    },
                )
            })
            .collect();
        for ((name, member), refused) in names.iter().zip(refused) {
            let Some(probe) = probes.get_mut(name) else {
                continue;
            };
            match member {
                None => probe.whole_read = !refused,
                Some(m) if refused => probe.refused.push(m.clone()),
                Some(m) => probe.readable.push(m.clone()),
            }
        }
        for (name, probe) in &probes {
            let Some(&id) = wanted.get(name) else {
                continue;
            };
            if let Some(makeup) = self.cache.structs.get(&id) {
                self.cache.aois.insert(id, (*makeup, probe.clone()));
            }
        }
        if !probes.is_empty() {
            log::info!(
                "Probed the member access of {} AOI types in {} packets",
                probes.len(),
                packets.len()
            );
        }
        // on the data type objects of this upload: tags kept from an earlier one keep theirs
        let applied: Vec<(Arc<DataType>, AoiProbe)> = self
            .cache
            .udts
            .iter()
            .filter(|(id, _)| self.aoi_probed(**id))
            .filter_map(|(id, dt)| {
                self.cache
                    .aois
                    .get(id)
                    .map(|(_, probe)| (Arc::clone(dt), probe.clone()))
            })
            .collect();
        for (dt, probe) in applied {
            self.aoi_applied.set(&dt, probe);
        }
        self.aoi_applied.prune();
        self.definitions_changed();
        Ok(())
    }

    // -------------------------------------------------------------------------------------------- tag cache file

    /// The tag list upload through the tag cache file (Python's `_get_tag_list_with_cache_file`).
    fn tag_list_with_cache_file(
        &mut self,
        program: Option<&str>,
        namespace_filter: &str,
        version: Option<TagTableVersion>,
    ) -> Result<Vec<TagDef>> {
        let path = self.args.tag_cache_file.clone().unwrap_or_default();
        let cached = load_tag_cache_file(&path);
        let mut current = match (&cached, version) {
            (Some((c, _)), Some(v)) => {
                c.scope.as_deref() == program
                    && c.serial.as_deref() == self.info.serial()
                    && c.table_version == Some(v)
            }
            _ => false,
        };

        let mut symbols = match (&cached, current) {
            (Some((c, _)), true) => c.symbols.clone(),
            _ => self.get_symbol_lists(program)?,
        };
        let mut templates: HashMap<u16, (TemplateMakeup, Arc<Vec<u8>>)> = HashMap::new();
        let origin = FILE_ORIGIN.fetch_add(1, Ordering::Relaxed);
        if let Some((c, _)) = &cached {
            if c.symbols == symbols {
                templates = c
                    .templates
                    .iter()
                    .map(|(id, makeup, data)| (*id, (*makeup, Arc::new(data.clone()))))
                    .collect();
                self.cache.aois.extend(
                    c.probes
                        .iter()
                        .map(|(id, makeup, probe)| (*id, (*makeup, probe.clone()))),
                );
            } else {
                log::info!(
                    "Tag cache file {} not used, it is out of date",
                    path.display()
                );
            }
        }
        if current {
            // the tag table is unchanged, so are the makeups
            self.cache
                .structs
                .extend(templates.iter().map(|(id, (makeup, _))| (*id, *makeup)));
        }
        // the makeups decide which ones are used (template_data)
        self.cache
            .templates
            .extend(templates.iter().map(|(id, (makeup, data))| {
                (
                    *id,
                    CachedTemplate {
                        makeup: *makeup,
                        data: Arc::clone(data),
                        origin,
                    },
                )
            }));

        let tags = match self.isolate_scopes(&symbols, namespace_filter) {
            Ok(tags) => tags,
            Err(err @ Error::Comm(_)) => return Err(err),
            Err(err) => {
                // e.g. a damaged template in the file, upload everything instead
                if templates.is_empty() && !current {
                    return Err(err);
                }
                log::warn!(
                    "Ignoring tag cache file {}, its contents failed: {err:?}",
                    path.display()
                );
                self.cache.clear();
                self.info.ensure_scope(true); // only the startup scope ('*' or None) gets here
                templates.clear();
                if current {
                    // the symbol lists came from the file too
                    symbols = self.get_symbol_lists(program)?;
                    current = false;
                }
                self.isolate_scopes(&symbols, namespace_filter)?
            }
        };

        if current {
            log::info!(
                "Tag table unchanged since tag cache file {} was written, loaded the tag list from it",
                path.display()
            );
        } else if !templates.is_empty() {
            let saved = self
                .cache
                .udts
                .keys()
                .filter(|id| {
                    self.cache
                        .templates
                        .get(id)
                        .is_some_and(|t| t.origin == origin)
                })
                .count();
            log::info!(
                "Used tag cache file {}, saved the reads of {saved} templates",
                path.display()
            );
        }
        self.probe_aois(&tags)?;
        let contents = self.tag_cache_contents(program, symbols, version);
        let previous = cached.as_ref().map(|(_, bytes)| bytes.as_slice());
        save_tag_cache_file(&path, &contents, previous);
        Ok(tags)
    }

    /// The contents of the tag cache file for these symbol lists: every template used by them with the probes
    /// of its AOIs, and the controller serial and tag table version they were uploaded at (read before the
    /// upload, so a version still current means nothing changed).
    fn tag_cache_contents(
        &self,
        program: Option<&str>,
        symbols: SymbolLists,
        version: Option<TagTableVersion>,
    ) -> TagCacheFile {
        let templates = self
            .cache
            .udts
            .keys()
            .filter_map(|id| {
                self.cache
                    .templates
                    .get(id)
                    .map(|t| (*id, t.makeup, t.data.to_vec()))
            })
            .collect();
        let probes = self
            .cache
            .udts
            .keys()
            .filter(|id| self.aoi_probed(**id))
            .filter_map(|id| {
                self.cache
                    .aois
                    .get(id)
                    .map(|(makeup, probe)| (*id, *makeup, probe.clone()))
            })
            .collect();
        TagCacheFile {
            scope: program.map(str::to_owned),
            serial: self.info.serial().map(str::to_owned),
            table_version: version,
            symbols,
            templates,
            probes,
        }
    }

    // -------------------------------------------------------------------------------------------- tag info

    /// Resolves a tag's definition, the lazy tags way: read the scope's symbol list once and only the
    /// templates this tag needs. Returns the tag's name in `tags`.
    pub(crate) fn load_tag_definition(&mut self, name: &str) -> Result<String> {
        self.conn.ensure_forward_open("_load_tag_definition")?;
        let (program, symbol_name) = match name.strip_prefix("Program:") {
            Some(_) => match name.split_once('.') {
                Some((scope, symbol)) => (
                    Some(scope["Program:".len()..].to_owned()),
                    symbol.to_owned(),
                ),
                None => {
                    return Err(Error::data(
                        "not enough values to unpack (expected 2, got 1)",
                    ));
                }
            },
            None => (None, name.to_owned()),
        };
        if !self.lazy_tag_lists.contains_key(&program) {
            let raw = self.get_instance_attribute_list_service(program.as_deref(), 0)?;
            let mut by_name = IndexMap::with_capacity(raw.len());
            for symbol in raw {
                by_name.insert(symbol.tag_name.clone(), symbol);
            }
            self.lazy_tag_lists.insert(program.clone(), by_name);
        }
        // only the one symbol is copied: a scope's list can hold thousands
        let empty = IndexMap::new();
        let list = self.lazy_tag_lists.get(&program).unwrap_or(&empty);
        let symbol_name = tag_key(list, &symbol_name);
        let symbol = list
            .get(&symbol_name)
            .filter(|s| {
                !symbol_name.starts_with("__")
                    && s.symbol_type & 0x1000 == 0
                    && symbol_name.starts_with(self.args.tag_namespace_filter.as_str())
            })
            .cloned();
        let Some(symbol) = symbol else {
            return Err(Error::request_kind(
                format!("Tag doesn't exist - {name}"),
                ErrorKind::NotFound,
            ));
        };
        let name = match &program {
            Some(p) => format!("Program:{p}.{symbol_name}"),
            None => symbol_name,
        };
        let tag = self.create_tag(&name, &symbol)?;
        self.tags.insert(name.clone(), tag);
        self.definitions_changed();
        Ok(name)
    }

    /// The definition of `base` or of its member `attrs`; with lazy tags an unknown tag is resolved from the
    /// controller first. Errors are RequestErrors (NotFound for a missing name) or CommErrors.
    pub(crate) fn resolve_tag_info(&mut self, base: &str, attrs: &[String]) -> Result<TagInfo<'_>> {
        let name = tag_key(&self.tags, base);
        if !self.tags.contains_key(&name) && self.args.lazy_tags {
            if let Err(err) = self.load_tag_definition(&name) {
                return Err(match err {
                    Error::Request { .. } | Error::Comm(_) => err,
                    other => {
                        let attrs: Vec<String> = attrs.iter().map(|a| py_str_repr(a)).collect();
                        let kind = match other {
                            Error::Response { .. } => ErrorKind::Comm,
                            _ => ErrorKind::BadRequest,
                        };
                        log::error!("failed to get tag data for: {base}: {other}");
                        Error::request_kind(
                            format!("failed to get tag data for: {base}, [{}]", attrs.join(", ")),
                            kind,
                        )
                    }
                });
            }
        }
        tag_info(&self.tags, base, attrs)
    }

    // -------------------------------------------------------------------------------------------- renderings

    /// A tag's dict, its data types with their AOI probes.
    pub(crate) fn tag_py(&self, tag: &TagDef) -> PyObj {
        let mut obj = tag.to_py();
        add_aoi_under(&mut obj, &tag.data_type, &self.aoi_applied);
        obj
    }

    /// A member's dict, its data types with their AOI probes.
    pub(crate) fn member_py(&self, member: &MemberInfo) -> PyObj {
        let mut obj = member.to_py();
        add_aoi_under(&mut obj, &member.data_type, &self.aoi_applied);
        obj
    }

    fn tags_py(&self) -> PyObj {
        PyObj::Dict(
            self.tags
                .iter()
                .map(|(name, tag)| (PyObj::Str(name.clone()), self.tag_py(tag)))
                .collect(),
        )
    }

    fn data_types_py(&self) -> PyObj {
        PyObj::Dict(
            self.data_types
                .iter()
                .map(|(name, dt)| {
                    let mut obj = dt.to_py();
                    add_aoi(&mut obj, dt, &self.aoi_applied);
                    (name.clone().map_or(PyObj::None, PyObj::Str), obj)
                })
                .collect(),
        )
    }
}

/// The identity entries of `info`, as Python's `ModuleIdentityObject` dict plus the keyswitch.
fn identity_items(identity: &ModuleIdentity, keyswitch: &str) -> IndexMap<String, PyObj> {
    let s = |text: &str| PyObj::Str(text.to_owned());
    let mut items = IndexMap::new();
    items.insert("vendor".into(), s(&identity.vendor));
    items.insert("product_type".into(), s(&identity.product_type));
    items.insert(
        "product_code".into(),
        PyObj::Int(identity.product_code.into()),
    );
    items.insert(
        "revision".into(),
        PyObj::Dict(vec![
            (s("major"), PyObj::Int(identity.revision.major.into())),
            (s("minor"), PyObj::Int(identity.revision.minor.into())),
        ]),
    );
    // PyObj has no bytes: the status word is rendered as a list of its two byte values
    items.insert(
        "status".into(),
        PyObj::List(
            identity
                .status
                .iter()
                .map(|b| PyObj::Int((*b).into()))
                .collect(),
        ),
    );
    items.insert("serial".into(), s(&identity.serial));
    items.insert("product_name".into(), s(&identity.product_name));
    items.insert("keyswitch".into(), s(keyswitch));
    items
}

/// {AOI name: (tag path, base tag instance id)} of an instance of each wanted AOI type in `tags`: a tag of that
/// type, else element 0 of an array tag of it, else a member of a struct tag (not through an AOI: its struct
/// members are locals); the first one found in `tags` order.
fn aoi_instances(
    tags: &[TagDef],
    wanted: &IndexMap<Option<String>, u16>,
) -> IndexMap<Option<String>, (String, u32)> {
    type Found = IndexMap<Option<String>, String>;
    fn members(dt: &DataType, memo: &mut HashMap<Option<String>, Found>) -> Found {
        if let Some(found) = memo.get(&dt.name) {
            return found.clone();
        }
        memo.insert(dt.name.clone(), Found::new()); // a template nesting itself finds nothing more
        let mut found = Found::new();
        for attr in &dt.attributes {
            let Some(info) = dt.internal_tags.get(attr) else {
                continue;
            };
            let TypeRef::Struct(member_type) = &info.data_type else {
                continue;
            };
            let path = if info.array.is_some_and(|n| n > 0) {
                format!(".{attr}[0]")
            } else {
                format!(".{attr}")
            };
            if is_aoi(member_type) {
                found.entry(member_type.name.clone()).or_insert(path);
            } else {
                for (name, sub_path) in members(member_type, memo) {
                    found
                        .entry(name)
                        .or_insert_with(|| format!("{path}{sub_path}"));
                }
            }
        }
        memo.insert(dt.name.clone(), found.clone());
        found
    }

    let mut memo = HashMap::new();
    let mut best: IndexMap<Option<String>, (u8, String, u32)> = IndexMap::new();
    for tag in tags {
        let TypeRef::Struct(dt) = &tag.data_type else {
            continue;
        };
        if tag.external_access == "None" {
            continue;
        }
        let mut path = tag.tag_name.clone();
        if tag.dim > 0 {
            path.push('[');
            path.push_str(&vec!["0"; usize::from(tag.dim)].join(","));
            path.push(']');
        }
        let found: Vec<(Option<String>, u8, String)> = if is_aoi(dt) {
            vec![(dt.name.clone(), u8::from(tag.dim > 0), path)]
        } else {
            members(dt, &mut memo)
                .into_iter()
                .map(|(name, sub)| (name, 2, format!("{path}{sub}")))
                .collect()
        };
        for (name, rank, tag_path) in found {
            let better = best.get(&name).is_none_or(|(r, _, _)| rank < *r);
            if wanted.contains_key(&name) && better {
                best.insert(name, (rank, tag_path, tag.instance_id));
            }
        }
    }
    best.into_iter()
        .map(|(name, (_, path, id))| (name, (path, id)))
        .collect()
}

/// AOI probes applied to data type objects, as Python sets `data_type['aoi']` on one dict: a data type parsed
/// again (a new object) has none until probed, tags kept from an earlier upload keep their types' probes, and
/// tags shared with another connection bring theirs. Keyed by the data type's address; each entry holds its
/// `Arc`, so the address is not reused while the entry exists.
#[derive(Clone, Debug, Default)]
pub(crate) struct AppliedProbes(HashMap<usize, (Arc<DataType>, AoiProbe)>);

impl AppliedProbes {
    fn key(data_type: &DataType) -> usize {
        std::ptr::from_ref(data_type) as usize
    }

    /// The probe applied to this data type object.
    pub(crate) fn get(&self, data_type: &DataType) -> Option<&AoiProbe> {
        self.0.get(&Self::key(data_type)).map(|(_, probe)| probe)
    }

    fn set(&mut self, data_type: &Arc<DataType>, probe: AoiProbe) {
        self.0
            .insert(Self::key(data_type), (Arc::clone(data_type), probe));
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    /// Forgets the probes of data types nothing else refers to any more.
    fn prune(&mut self) {
        self.0.retain(|_, (dt, _)| Arc::strong_count(dt) > 1);
    }

    /// The probes of `data_type` and of the structures nested in it, from `self` into `out`.
    fn copy_reachable(
        &self,
        data_type: &TypeRef,
        out: &mut AppliedProbes,
        seen: &mut BTreeSet<usize>,
    ) {
        let TypeRef::Struct(dt) = data_type else {
            return;
        };
        if !seen.insert(Self::key(dt)) {
            return;
        }
        if let Some(probe) = self.get(dt) {
            out.set(dt, probe.clone());
        }
        for member in dt.internal_tags.values() {
            self.copy_reachable(&member.data_type, out, seen);
        }
    }
}

/// Adds the probes to the data type dict `obj` of `data_type` and to those of its struct members.
fn add_aoi(obj: &mut PyObj, data_type: &DataType, applied: &AppliedProbes) {
    let PyObj::Dict(items) = obj else {
        return;
    };
    for (key, value) in items.iter_mut() {
        let (PyObj::Str(key), PyObj::Dict(members)) = (key, value) else {
            continue;
        };
        if key != "internal_tags" {
            continue;
        }
        for (name, member) in members.iter_mut() {
            let PyObj::Str(name) = name else { continue };
            if let Some(info) = data_type.internal_tags.get(name) {
                add_aoi_under(member, &info.data_type, applied);
            }
        }
    }
    if let Some(probe) = applied.get(data_type) {
        items.push((PyObj::Str("aoi".into()), probe.to_py()));
    }
}

/// Adds the probes under the `data_type` entry of a tag or member dict `obj`.
fn add_aoi_under(obj: &mut PyObj, data_type: &TypeRef, applied: &AppliedProbes) {
    let (TypeRef::Struct(dt), PyObj::Dict(items)) = (data_type, obj) else {
        return;
    };
    for (key, value) in items.iter_mut() {
        if matches!(key, PyObj::Str(k) if k == "data_type") {
            add_aoi(value, dt, applied);
        }
    }
}

// ------------------------------------------------------------------------------------------------ cache file

/// The tag cache file's contents and bytes, None if it is missing, unreadable or of another format (logged).
fn load_tag_cache_file(path: &Path) -> Option<(TagCacheFile, Vec<u8>)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log::info!(
                "Tag cache file {} not found, it will be created",
                path.display()
            );
            return None;
        }
        Err(err) => {
            log::warn!(
                "Ignoring unreadable tag cache file {}: {err}",
                path.display()
            );
            return None;
        }
    };
    match TagCacheFile::decode(&bytes) {
        Ok(file) => Some((file, bytes)),
        Err(TagCacheError::OtherVersion(_)) => {
            log::info!(
                "Tag cache file {} not used, it is out of date",
                path.display()
            );
            None
        }
        Err(err) => {
            log::warn!(
                "Ignoring unreadable tag cache file {}: {err}",
                path.display()
            );
            None
        }
    }
}

/// Atomically writes the tag cache file, unless it holds these contents already. A failure is logged.
fn save_tag_cache_file(path: &Path, contents: &TagCacheFile, previous: Option<&[u8]>) {
    let bytes = contents.encode();
    if previous == Some(bytes.as_slice()) {
        return;
    }
    if let Err(err) = write_atomic(path, &bytes) {
        log::warn!("Could not write tag cache file {}: {err}", path.display());
    }
}

// ------------------------------------------------------------------------------------------------ time

/// The PLC time in microseconds since 1970-01-01 UTC formatted as the Python driver's default
/// (`"%A, %B %d, %Y %I:%M:%S%p"`), in UTC.
pub fn format_plc_time_utc(microseconds: u64) -> String {
    const DAYS: [&str; 7] = [
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let secs = microseconds / 1_000_000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // civil from days (Howard Hinnant), days since 1970-01-01
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let hour12 = match hour % 12 {
        0 => 12,
        h => h,
    };
    format!(
        "{}, {} {day:02}, {year} {hour12:02}:{minute:02}:{second:02}{}",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        if hour < 12 { "AM" } else { "PM" }
    )
}

// ------------------------------------------------------------------------------------------------ driver

/// An EtherNet/IP driver for ControlLogix, CompactLogix and Micro800 controllers (the Python
/// `LogixDriver`): its tag definitions are uploaded on connect (or resolved lazily) and checked against the
/// controller's tag table version.
///
/// Thread-safe: every call holds the driver's one lock for its requests and replies.
pub struct LogixDriver {
    state: Mutex<Logix>,
    definitions: Arc<AtomicU64>,
}

impl LogixDriver {
    /// A driver for `path` (`ip`, `ip/slot` or a CIP route) over TCP; not connected until [`open`](Self::open).
    pub fn new(path: &str, options: LogixOptions) -> Result<Self> {
        Self::with_connector(path, options, tcp_connector())
    }

    /// A driver opening its transports with `connector`.
    pub fn with_connector(path: &str, options: LogixOptions, connector: Connector) -> Result<Self> {
        let state = Logix::new(path, options, connector)?;
        Ok(LogixDriver {
            definitions: Arc::clone(&state.definitions),
            state: Mutex::new(state),
        })
    }

    /// Locks the state. If a thread panicked holding the lock, the connection is dropped first (a reply may be
    /// left unread) and the driver stays usable.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Logix> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.conn.drop_connection();
                self.state.clear_poison();
                state
            }
        }
    }

    /// Opens the connection and initializes the driver (identity, program name, tag table version, tag list).
    /// Ok(false) if the session was refused; a failed initialization closes the connection and is returned.
    pub fn open(&self) -> Result<bool> {
        self.lock().open()
    }

    /// Closes the CIP connection and the session.
    pub fn close(&self) -> Result<()> {
        self.lock().conn.close()
    }

    /// True while a session is registered.
    pub fn connected(&self) -> bool {
        self.lock().conn.connected()
    }

    /// Maximum connected message size.
    pub fn connection_size(&self) -> u16 {
        self.lock().conn.connection_size()
    }

    /// Sets the connection size used by the next Forward Open.
    pub fn set_connection_size(&self, size: u16) -> Result<()> {
        self.lock().conn.set_connection_size(size)
    }

    /// The socket timeout.
    pub fn socket_timeout(&self) -> Option<Duration> {
        self.lock().conn.socket_timeout()
    }

    /// Sets the socket timeout.
    pub fn set_socket_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.lock().conn.set_socket_timeout(timeout)
    }

    /// Sends a generic CIP message.
    pub fn generic_message(&self, msg: &GenericMessage) -> Result<GenericReply> {
        self.lock().conn.generic_message(msg)
    }

    /// Sends a connected CIP message (without sequence count) with the next sequence count and returns the
    /// raw reply frame. Does not open the CIP connection.
    pub fn send_connected_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut state = self.lock();
        let sequence = state.conn.next_sequence();
        state.conn.send_connected(sequence, message)
    }

    /// Sends an unconnected CIP message and returns the raw reply frame.
    pub fn send_unconnected_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.lock().conn.send_unconnected(message)
    }

    /// The identity of the module in `slot` of the rack at the end of the connection path.
    pub fn get_module_info(&self, slot: i64) -> Result<ModuleIdentity> {
        self.lock().conn.get_module_info(slot)
    }

    /// The identity of the device at `route` (see [`crate::browse`]).
    pub fn identity_at(&self, route: &str) -> Result<ModuleIdentity> {
        self.lock().conn.identity_at(route)
    }

    /// What the ciplink device at `route` runs, None for any other device (see [`crate::browse::AppInfo`]).
    pub fn app_at(&self, route: &str) -> Result<Option<crate::browse::AppInfo>> {
        self.lock().conn.app_at(route)
    }

    /// The ports of the device at `route` (see [`crate::browse`]).
    pub fn ports_at(&self, route: &str) -> Result<Vec<crate::browse::PortInfo>> {
        self.lock().conn.ports_at(route)
    }

    /// Probes the slots, nodes or IP addresses on `port` of the device at `route` (`nodes`, by default the
    /// port's own) from `workers` connections at once; the nodes in address order (see [`crate::browse`]).
    pub fn browse_port(
        &self,
        route: &str,
        port: u16,
        nodes: Option<&[String]>,
        workers: usize,
    ) -> Result<Vec<crate::browse::Node>> {
        let scan = self.lock().conn.scan(route, port, nodes)?;
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
        found: &mut dyn FnMut(crate::browse::Node) -> bool,
    ) -> Result<()> {
        let scan = self.lock().conn.scan(route, port, nodes)?;
        scan.run(workers, found);
        Ok(())
    }

    /// Identifies the target at `path` (Logix path parsing) with ListIdentity over a session of its own.
    pub fn list_identity(path: &str) -> Result<Option<ListIdentity>> {
        crate::cip::CipDriver::list_identity_with(
            path,
            CipOptions::default(),
            tcp_connector(),
            true,
        )
    }

    /// Discovers EtherNet/IP devices by broadcasting ListIdentity.
    pub fn discover(broadcast: &str) -> Vec<ListIdentity> {
        crate::cip::CipDriver::discover(broadcast)
    }

    /// Reads the controller's identity and keyswitch position and stores them in [`info`](Self::info_py).
    pub fn get_plc_info(&self) -> Result<PlcInfo> {
        Ok(self.lock().plc_info()?.0)
    }

    /// Reads the name of the program running in the controller and stores it in the info.
    pub fn get_plc_name(&self) -> Result<String> {
        self.lock().get_plc_name()
    }

    /// The program name read on connect, None before.
    pub fn name(&self) -> Option<String> {
        self.lock().info.str("name").map(str::to_owned)
    }

    /// The controller's major revision, 0 if not known.
    pub fn revision_major(&self) -> u32 {
        self.lock().revision_major()
    }

    /// True if the target is a Micro800.
    pub fn micro800(&self) -> bool {
        self.lock().micro800
    }

    /// True if tags are requested by symbol instance ID.
    pub fn use_instance_ids(&self) -> bool {
        self.lock().use_instance_ids
    }

    /// Turns requests by instance ID on or off (Python's `_cfg["use_instance_ids"]`, for tests and tools).
    #[doc(hidden)]
    pub fn set_use_instance_ids(&self, on: bool) {
        self.lock().use_instance_ids = on;
    }

    /// The tag table version the tag definitions were loaded at, None if unknown.
    pub fn tag_table_version(&self) -> Option<TagTableVersion> {
        self.lock().tag_table_version
    }

    /// Reads the PLC clock: the value is `{"microseconds": us since 1970 UTC}` (see
    /// [`format_plc_time_utc`]); a failed reply is the result's error.
    pub fn get_plc_time(&self) -> Result<TagResult> {
        let reply = self.lock().conn.generic_message(&GenericMessage {
            service: GET_ATTRIBUTE_LIST,
            class_code: LogicalValue::Int(WALL_CLOCK_CLASS),
            instance: LogicalValue::Raw(vec![0x01]),
            request_data: vec![0x01, 0x00, 0x06, 0x00],
            ..GenericMessage::default()
        })?;
        let mut error = reply.tag.error.clone();
        let mut value = None;
        if error.is_none() {
            match reply.data().and_then(|d| d.get(6..14)) {
                Some(us) => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(us);
                    let mut map = IndexMap::new();
                    map.insert(
                        "microseconds".into(),
                        Value::ULInt(u64::from_le_bytes(bytes)),
                    );
                    value = Some(Value::Struct(map));
                }
                None => {
                    // Python's Struct(n_bytes(6), ULINT) decode failure; with no data at all Python raises a
                    // TypeError (indexing b''), reported here as the 0- and 6-byte case: an empty message
                    let data = reply.data().unwrap_or_default();
                    let reason = match data.len() {
                        0 | 6 => String::new(), // BufferEmptyError
                        _ => format!("Error unpacking {} as Struct", py_bytes_repr(data)),
                    };
                    error = Some(TagError::new(
                        format!("Failed to parse reply - {reason}"),
                        ErrorKind::Other,
                    ));
                }
            }
        }
        Ok(TagResult {
            tag: "get_plc_time".into(),
            value,
            data_type: None,
            error,
        })
    }

    /// Sets the PLC clock to `microseconds` since 1970 UTC, or to this computer's clock if None.
    pub fn set_plc_time(&self, microseconds: Option<u64>) -> Result<TagResult> {
        let us = microseconds.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_micros() as u64)
        });
        let mut data = Vec::with_capacity(12);
        data.extend(1u16.to_le_bytes()); // one attribute
        data.extend(6u16.to_le_bytes()); // attribute 6, the time
        data.extend(us.to_le_bytes());
        let reply = self.lock().conn.generic_message(&GenericMessage {
            service: SET_ATTRIBUTE_LIST,
            class_code: LogicalValue::Int(WALL_CLOCK_CLASS),
            instance: LogicalValue::Raw(vec![0x01]),
            request_data: data,
            name: "set_plc_time".into(),
            ..GenericMessage::default()
        })?;
        Ok(reply.tag)
    }

    /// Uploads the tag list of `program`: None for the controller's tags, `"*"` for all, else a program name.
    /// With `cache` the result replaces [`tags`](Self::tags); `tag_namespace_filter` keeps only the tags whose
    /// name (without `Program:X.`) starts with it.
    pub fn get_tag_list(
        &self,
        program: Option<&str>,
        cache: bool,
        tag_namespace_filter: &str,
    ) -> Result<Vec<TagDef>> {
        let mut state = self.lock();
        state.conn.ensure_forward_open("get_tag_list")?;
        state.load_tag_list(program, cache, tag_namespace_filter, None)
    }

    /// Loads the tag definitions again if the controller's tag table changed since they were loaded; true if
    /// they were. Without instance IDs, or while reloads are backed off, nothing is read and false returned.
    pub fn check_tag_table(&self) -> Result<bool> {
        self.lock().check_tag_table()
    }

    /// The definition of a tag or member, e.g. `"MyUdt.Member"`; with lazy tags an unknown tag is resolved
    /// from the controller.
    pub fn get_tag_info(&self, tag_name: &str) -> Result<TagDefinition> {
        let (_, base, attrs) = split_tag_name(tag_name)?;
        let mut state = self.lock();
        Ok(match state.resolve_tag_info(&base, &attrs)? {
            TagInfo::Tag(t) => TagDefinition::Tag(t.clone()),
            TagInfo::Member(m) => TagDefinition::Member(m.clone()),
        })
    }

    /// [`get_tag_info`](Self::get_tag_info) as the Python driver's dict.
    pub fn get_tag_info_py(&self, tag_name: &str) -> Result<PyObj> {
        let (_, base, attrs) = split_tag_name(tag_name)?;
        let mut state = self.lock();
        let info = match state.resolve_tag_info(&base, &attrs)? {
            TagInfo::Tag(t) => TagDefinition::Tag(t.clone()),
            TagInfo::Member(m) => TagDefinition::Member(m.clone()),
        };
        Ok(match &info {
            TagDefinition::Tag(t) => state.tag_py(t),
            TagDefinition::Member(m) => state.member_py(m),
        })
    }

    /// The tag definitions by name.
    pub fn tags(&self) -> IndexMap<String, TagDef> {
        self.lock().tags.clone()
    }

    /// Replaces the tag definitions, e.g. with another connection's to the same controller (their version is
    /// unknown, so the next checked read or write loads them again).
    pub fn set_tags(&self, tags: IndexMap<String, TagDef>) {
        let mut state = self.lock();
        state.tags = tags;
        state.tags_generation += 1;
        state.definitions_changed();
    }

    /// Shares the tag definitions of another connection to the same controller (Python's
    /// `plc2._tags = plc1.tags`), with the AOI probes of their data types, which Python keeps on the shared
    /// data type dicts. Their version is this connection's, as in Python: unknown if this one has not
    /// connected yet, so the next check or checked read loads them again.
    pub fn share_tags_from(&self, other: &LogixDriver) {
        if std::ptr::eq(self, other) {
            return;
        }
        let (tags, probes) = {
            let from = other.lock();
            let mut probes = AppliedProbes::default();
            let mut seen = BTreeSet::new();
            for tag in from.tags.values() {
                from.aoi_applied
                    .copy_reachable(&tag.data_type, &mut probes, &mut seen);
            }
            (from.tags.clone(), probes)
        };
        let mut state = self.lock();
        state.tags = tags;
        state.tags_generation += 1;
        state.aoi_applied.0.extend(probes.0);
        state.aoi_applied.prune();
        state.definitions_changed();
    }

    /// A number that changes whenever the tag definitions, the data types or their AOI probes change (an
    /// upload, a lazy load, shared tags), read without taking the driver's lock: a binding keeps what it built
    /// from [`definitions`](Self::definitions) while this is unchanged.
    pub fn definitions_version(&self) -> u64 {
        self.definitions.load(Ordering::Acquire)
    }

    /// The tag definitions, data types and AOI probes as they are now, with their
    /// [`definitions_version`](Self::definitions_version).
    pub fn definitions(&self) -> Definitions {
        self.definitions_since(u64::MAX, 0)
    }

    /// [`definitions`](Self::definitions) with only the tags after the first `count`, when the tag definitions
    /// are still those of `tags_generation` (lazy loads only add tags at the end); else all of them.
    pub fn definitions_since(&self, tags_generation: u64, count: usize) -> Definitions {
        let state = self.lock();
        let from = if state.tags_generation == tags_generation && count <= state.tags.len() {
            count
        } else {
            0
        };
        let tags = state
            .tags
            .get_range(from..)
            .map_or_else(IndexMap::new, |new| {
                new.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            });
        Definitions {
            version: state.definitions.load(Ordering::Acquire),
            tags_generation: state.tags_generation,
            tags_from: from,
            tags,
            data_types: state.data_types.clone(),
            probes: state
                .aoi_applied
                .0
                .values()
                .map(|(dt, probe)| (Arc::clone(dt), probe.clone()))
                .collect(),
        }
    }

    /// The structure data types by name.
    pub fn data_types(&self) -> IndexMap<Option<String>, Arc<DataType>> {
        self.lock().data_types.clone()
    }

    /// The AOI probe of a data type, None if it is not an AOI or was not probed.
    pub fn aoi_probe(&self, data_type_name: &str) -> Option<AoiProbe> {
        let state = self.lock();
        let data_type = state.data_types.get(&Some(data_type_name.to_owned()))?;
        state.aoi_applied.get(data_type).cloned()
    }

    /// `tags` (and `tags_json`) as the Python driver's dict, without type classes, AOI probes included.
    pub fn tags_py(&self) -> PyObj {
        self.lock().tags_py()
    }

    /// `data_types` as the Python driver's dict, without type classes, AOI probes included.
    pub fn data_types_py(&self) -> PyObj {
        self.lock().data_types_py()
    }

    /// A tag list (from [`get_tag_list`](Self::get_tag_list)) as the Python driver's list of dicts.
    pub fn tag_list_py(&self, tags: &[TagDef]) -> PyObj {
        let state = self.lock();
        PyObj::List(tags.iter().map(|tag| state.tag_py(tag)).collect())
    }

    /// `info` as the Python driver's dict (`status` as a list of its two bytes).
    pub fn info_py(&self) -> PyObj {
        self.lock().info.to_py()
    }

    /// Moves the driver's clock (the reload backoff) forward, for tests.
    #[doc(hidden)]
    pub fn advance_clock(&self, by: Duration) {
        let mut state = self.lock();
        state.clock_offset = state.clock_offset.saturating_add(by);
    }
}

impl fmt::Display for LogixDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        let info = &state.info;
        let revision = |part| info.revision(part).unwrap_or(-1);
        write!(
            f,
            "Program Name: {}, Device: {}, Revision: {}.{}",
            info.str("name").unwrap_or("None"),
            info.str("product_name").unwrap_or("None"),
            revision("major"),
            revision("minor")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> CipConnection {
        let connector: Connector = Box::new(|_, _, _| Err(Error::comm("no network in unit tests")));
        CipConnection::new("127.0.0.1", CipOptions::default(), connector, true).expect("path")
    }

    fn logix(size: u16) -> Logix {
        let connector: Connector = Box::new(|_, _, _| Err(Error::comm("no network in unit tests")));
        let options = LogixOptions {
            cip: CipOptions {
                connection_size: size,
                ..CipOptions::default()
            },
            ..LogixOptions::default()
        };
        Logix::new("127.0.0.1", options, connector).expect("new")
    }

    fn request(l: &mut Logix, len: usize, key: u32) -> Request<u32> {
        Request::new(&mut l.conn, vec![0x4C; len], key)
    }

    fn shape(packets: &[Packet<u32>]) -> Vec<String> {
        packets
            .iter()
            .map(|p| match p {
                Packet::Single(r) => match r.key {
                    Some(k) => format!("{k}@{}", r.sequence),
                    None => format!("check@{}", r.sequence),
                },
                Packet::Multi { sequence, requests } => {
                    let inner: Vec<String> = requests
                        .iter()
                        .map(|r| r.key.map_or("check".into(), |k| k.to_string()))
                        .collect();
                    format!("multi@{sequence}[{}]", inner.join(","))
                }
            })
            .collect()
    }

    #[test]
    fn packing_groups_requests_up_to_the_connection_size() {
        let mut l = logix(100);
        let sized: Vec<_> = (0..5).map(|k| (request(&mut l, 20, k), 10)).collect();
        // 10 + 3 x 22 = 76 fits, a fourth (98) too, the fifth would be 120
        let packets = l.pack_multi_requests(sized, false);
        assert_eq!(shape(&packets), ["multi@6[0,1,2,3]", "4@5"]);
    }

    #[test]
    fn packing_with_checks_starts_each_packet_with_one_and_surrounds_requests_sent_alone() {
        let mut l = logix(200);
        let mut sized = vec![(request(&mut l, 10, 0), 10)];
        let mut big = request(&mut l, 10, 1);
        big.fragmented = true;
        sized.push((big, 10));
        sized.push((request(&mut l, 10, 2), 10));
        let packets = l.pack_multi_requests(sized, true);
        // the check of a packet takes its count before the packet's own
        assert_eq!(
            shape(&packets),
            [
                "multi@5[check,0]",
                "check@6",
                "1@2",
                "check@7",
                "multi@9[check,2]"
            ]
        );
    }

    #[test]
    fn micro800_gets_every_request_alone() {
        let mut l = logix(4000);
        l.micro800 = true;
        let sized: Vec<_> = (0..3).map(|k| (request(&mut l, 4, k), 4)).collect();
        assert_eq!(
            shape(&l.pack_multi_requests(sized, true)),
            ["0@1", "1@2", "2@3"]
        );
    }

    #[test]
    fn version_check_takes_a_sequence_count() {
        let mut c = conn();
        let r = Request::<u8>::version_check(&mut c);
        assert_eq!((r.sequence, r.is_version_check()), (1, true));
        assert_eq!(c.next_sequence(), 2);
    }

    #[test]
    fn plc_time_formats_like_strftime_in_utc() {
        assert_eq!(
            format_plc_time_utc(0),
            "Thursday, January 01, 1970 12:00:00AM"
        );
        // 2024-02-29 13:05:09 UTC
        assert_eq!(
            format_plc_time_utc(1_709_211_909_000_000),
            "Thursday, February 29, 2024 01:05:09PM"
        );
    }

    #[test]
    fn backoff_survives_a_clock_moved_past_its_range() {
        let mut l = logix(4000);
        l.clock_offset = Duration::MAX;
        l.back_off("busy");
        assert!(l.backoff_error().is_some_and(|e| e.contains("busy")));
        assert!(!format_plc_time_utc(u64::MAX).is_empty());
    }
}
