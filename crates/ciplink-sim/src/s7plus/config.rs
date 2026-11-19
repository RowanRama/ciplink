//! The S7comm-plus device configuration (JSON or Rust). Every name in it is invented by its author.

use crate::ConfigError;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// An S7-1500 style CPU: identity, limits, structure types, data blocks and the I / Q / M areas.
///
/// JSON form (the top-level key `"s7plus"` picks this device in the `ciplink-sim` binary):
///
/// ```json
/// {"s7plus": {
///   "name": "PLC_Line1", "firmware": [3, 1, 3], "max_read": 100,
///   "types": {"Recipe": {"members": {"Speed": "REAL", "Name": "STRING[10]"}}},
///   "dbs": [{"name": "Line1", "number": 5, "members": {
///       "Conveyor": {"type": "STRUCT", "members": {"Speed": {"type": "REAL", "value": 1.5}}},
///       "Items": "ARRAY[1..50] OF UINT", "Recipe": "Recipe", "Stamp": "DTL"}}],
///   "areas": {"I": {"StartButton": "BOOL"}, "M": {"Mode": "INT"}}
/// }}
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S7PlusConfig {
    /// PLC (station) name, RID 50 attribute 233.
    pub name: String,
    /// Order number (MLFB), at most 19 characters.
    pub order_number: String,
    /// Serial number, at most 16 characters.
    pub serial_number: String,
    /// Firmware major, minor, patch.
    pub firmware: [u8; 3],
    /// Hardware version.
    pub hardware_version: u8,
    /// Engineering (TIA) version, four parts.
    pub engineering_version: [u8; 4],
    /// Project name (release management root, attribute 8342).
    pub project: String,
    /// Project version number in the ServerSessionVersion; `change_program` increments it.
    pub project_version: u32,
    /// Session ID handed out by CreateObject.
    pub session_id: u32,
    /// Session name (CreateObject attribute 233).
    pub session_name: String,
    /// Server version text (CreateObject attribute 301).
    pub server_version: String,
    /// Max items per GetMultiVariables (system limit LID 1000).
    pub max_read: u32,
    /// Max items per SetMultiVariables (system limit LID 1001).
    pub max_write: u32,
    /// Effective protection level (session attribute 1842).
    pub protection_level: u32,
    /// PLC data types (UDTs) by name, in declaration order.
    pub types: IndexMap<String, TypeConfig>,
    /// Data blocks.
    pub dbs: Vec<DbConfig>,
    /// PLC tags of the `I`, `Q` and `M` areas, by area letter then tag name.
    pub areas: IndexMap<String, IndexMap<String, MemberConfig>>,
}

impl Default for S7PlusConfig {
    fn default() -> Self {
        S7PlusConfig {
            name: "PLC_1".to_owned(),
            order_number: "6ES7 5XX-XXXXX-XAB0".to_owned(),
            serial_number: "S C-X0SIM0000001".to_owned(),
            firmware: [3, 1, 3],
            hardware_version: 4,
            engineering_version: [19, 0, 0, 0],
            project: "Demo_Line".to_owned(),
            project_version: 12_345_678,
            session_id: 0x7000_0A10,
            session_name: "00:0123456789ABCDEF".to_owned(),
            server_version: "Server: OMSP_14.00.00.03_66.03.00.01".to_owned(),
            max_read: 100,
            max_write: 100,
            protection_level: 0,
            types: IndexMap::new(),
            dbs: Vec::new(),
            areas: IndexMap::new(),
        }
    }
}

impl S7PlusConfig {
    /// Reads `{"s7plus": {...}}` (or the inner object alone) from JSON text. Parsed from the text (not
    /// through a `serde_json::Value`, whose objects are sorted) so members keep their declared order.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        #[derive(Deserialize)]
        struct Wrapper {
            s7plus: S7PlusConfig,
        }
        let json: Json = serde_json::from_str(text)
            .map_err(|e| ConfigError::new(format!("invalid JSON: {e}")))?;
        let parsed = if json.get("s7plus").is_some() {
            serde_json::from_str::<Wrapper>(text).map(|w| w.s7plus)
        } else {
            serde_json::from_str(text)
        };
        parsed.map_err(|e| ConfigError::new(format!("invalid configuration: {e}")))
    }
}

/// A structure type (UDT).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TypeConfig {
    /// Members in declaration order.
    pub members: IndexMap<String, MemberConfig>,
}

/// A data block.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    /// Block name.
    pub name: String,
    /// Block number (1 to 65535).
    pub number: u16,
    /// Optimized block access (BOOLs are BBOOL); default true.
    #[serde(default = "yes")]
    pub optimized: bool,
    /// Members in declaration order.
    #[serde(default)]
    pub members: IndexMap<String, MemberConfig>,
}

fn yes() -> bool {
    true
}

/// A member: a type string (`"REAL"`, `"STRING[10]"`, `"ARRAY[1..50] OF UINT"`, `"DTL"`, a UDT name) or the
/// full form.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MemberConfig {
    /// Just the type.
    Type(String),
    /// Type with options.
    Full(MemberDetail),
}

/// A member with options.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDetail {
    /// Type string; `"STRUCT"` takes `members`.
    #[serde(rename = "type")]
    pub data_type: String,
    /// Initial value (JSON as `S7PlusSimulator::set_value` takes it).
    #[serde(default)]
    pub value: Option<Json>,
    /// Members of a `STRUCT` (or `ARRAY[..] OF STRUCT`).
    #[serde(default)]
    pub members: IndexMap<String, MemberConfig>,
    /// LID; default: the next free one (from 0xA in blocks and areas, from 9 in structures).
    #[serde(default)]
    pub lid: Option<u32>,
    /// Visible in HMI engineering (default true).
    #[serde(default = "yes")]
    pub hmi_visible: bool,
    /// Accessible from HMI / OPC UA / web server (default true).
    #[serde(default = "yes")]
    pub hmi_accessible: bool,
    /// Read-only for HMI (default false).
    #[serde(default)]
    pub hmi_read_only: bool,
}

impl MemberConfig {
    pub(crate) fn detail(&self) -> MemberDetail {
        match self {
            MemberConfig::Type(data_type) => MemberDetail {
                data_type: data_type.clone(),
                value: None,
                members: IndexMap::new(),
                lid: None,
                hmi_visible: true,
                hmi_accessible: true,
                hmi_read_only: false,
            },
            MemberConfig::Full(detail) => detail.clone(),
        }
    }
}
