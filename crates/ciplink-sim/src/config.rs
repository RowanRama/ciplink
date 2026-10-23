//! Controller configuration, read from JSON or built in Rust.
//!
//! The same structs serve both: every field has a default, so a JSON file only names what it needs and Rust
//! code starts from `Default` or a constructor and chains the `with_*` / builder methods.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::collections::BTreeMap;

/// A configuration error: an unknown type, a bad value, a duplicate name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        ConfigError(message.into())
    }
}

/// A simulated device: a Logix controller or an SLC 500 / MicroLogix.
#[derive(Clone, Debug)]
pub enum Config {
    /// ControlLogix / CompactLogix / Micro800.
    Logix(Box<LogixConfig>),
    /// SLC 500 / MicroLogix answering PCCC.
    Slc(Box<SlcConfig>),
}

impl Config {
    /// Reads a configuration from JSON: an object whose `"kind"` is `"logix"` (the default) or `"slc"`.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let mut json: Json = serde_json::from_str(text)
            .map_err(|e| ConfigError::new(format!("invalid JSON: {e}")))?;
        let kind = match json.as_object_mut() {
            Some(object) => match object.remove("kind") {
                None => "logix".to_owned(),
                Some(Json::String(kind)) => kind,
                Some(other) => return Err(ConfigError::new(format!("invalid kind {other}"))),
            },
            None => return Err(ConfigError::new("the configuration must be a JSON object")),
        };
        let parse_error =
            |e: serde_json::Error| ConfigError::new(format!("invalid configuration: {e}"));
        match kind.as_str() {
            "logix" => Ok(Config::Logix(Box::new(
                serde_json::from_value(json).map_err(parse_error)?,
            ))),
            "slc" => Ok(Config::Slc(Box::new(
                serde_json::from_value(json).map_err(parse_error)?,
            ))),
            other => Err(ConfigError::new(format!(
                "unknown kind {other:?}, expected \"logix\" or \"slc\""
            ))),
        }
    }

    /// Reads a JSON configuration file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new(format!("cannot read {}: {e}", path.display())))?;
        Self::from_json(&text)
    }
}

impl From<LogixConfig> for Config {
    fn from(config: LogixConfig) -> Self {
        Config::Logix(Box::new(config))
    }
}

impl From<SlcConfig> for Config {
    fn from(config: SlcConfig) -> Self {
        Config::Slc(Box::new(config))
    }
}

/// The identity object (class 0x01) and ListIdentity reply of a device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// Vendor ID, 1 = Rockwell Automation/Allen-Bradley.
    pub vendor: u16,
    /// Device type, 14 = Programmable Logic Controller.
    pub product_type: u16,
    /// Product code.
    pub product_code: u16,
    /// Major and minor revision.
    pub revision: [u8; 2],
    /// Serial number as 8 hex digits, e.g. `"c0ffee01"`.
    pub serial: String,
    /// Product name, e.g. `"1756-SIM/A"`.
    pub product_name: String,
    /// `"RUN"`, `"REMOTE RUN"`, `"PROG"` or `"REMOTE PROG"`; sets the status word unless `status` is given.
    pub keyswitch: String,
    /// The raw identity status word, overrides `keyswitch`.
    pub status: Option<u16>,
    /// The state byte of the ListIdentity reply.
    pub state: u8,
    /// The IP address in the ListIdentity reply.
    pub ip_address: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        IdentityConfig {
            vendor: 1,
            product_type: 14,
            product_code: 166,
            revision: [33, 11],
            serial: "c0ffee01".into(),
            product_name: "1756-SIM/A".into(),
            keyswitch: "REMOTE RUN".into(),
            status: None,
            state: 3,
            ip_address: "127.0.0.1".into(),
        }
    }
}

/// A Logix controller.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogixConfig {
    /// Identity of the controller.
    pub identity: IdentityConfig,
    /// Backplane slot of the controller: Unconnected Send and Forward Open routes must name it.
    pub slot: u8,
    /// Slots in the chassis, the node range of the backplane port in the Port Object (class 0xF4).
    pub chassis_size: u8,
    /// IP address and subnet mask of the EtherNet/IP port (its TCP/IP Interface Object, class 0xF5).
    pub ip: String,
    /// Subnet mask of the EtherNet/IP port.
    pub netmask: String,
    /// Devices on the EtherNet/IP network, answering Get_Attributes_All of their identity through Unconnected
    /// Send on port 2; other addresses time out (0x01/0x0204).
    pub network: Vec<NetworkDeviceConfig>,
    /// Name of the project (class 0x64).
    pub program_name: String,
    /// Largest connection size a Forward Open may ask for.
    pub max_connection_size: u16,
    /// Large Forward Open (0x5B) is supported; if not it answers 0x08 and drivers fall back.
    pub large_forward_open: bool,
    /// Multiple Service Packet (0x0A) is supported.
    pub multi_service: bool,
    /// Tags can be addressed by symbol instance ID.
    pub instance_ids: bool,
    /// The tag table version (class 0xAC) can be read.
    pub tag_table_version: bool,
    /// Reads of an AOI's local tags are refused (0x04) and so are reads of a whole AOI that has any (0x0F).
    pub aoi_locals_refused: bool,
    /// A Micro800: no Multiple Service Packet, no instance IDs, no Large Forward Open, no tag table version.
    pub micro800: bool,
    /// The controller clock in microseconds since 1970 (UTC) at start, None for the host clock.
    pub clock_us: Option<u64>,
    /// User data types (UDTs, AOIs, custom strings); TIMER, COUNTER, CONTROL and STRING are predefined.
    pub types: Vec<TypeConfig>,
    /// Controller-scoped tags.
    pub tags: Vec<TagConfig>,
    /// Programs and their tags.
    pub programs: Vec<ProgramConfig>,
    /// Tasks.
    pub tasks: Vec<NamedConfig>,
    /// System symbols in the controller symbol list (`__x`, `Map:Local`, `Cxn:...`), never readable.
    pub system_tags: Vec<SystemTagConfig>,
    /// Other modules in the chassis, answering Get_Attributes_All of their identity through Unconnected Send.
    pub modules: Vec<ModuleConfig>,
    /// Description reads are refused (0x0F) on a connection until it passes the metadata authentication
    /// handshake (services 0x4B and 0x4C of class 0x64), as on controllers that restrict metadata access.
    pub metadata_auth: bool,
}

impl Default for LogixConfig {
    fn default() -> Self {
        LogixConfig {
            identity: IdentityConfig::default(),
            slot: 0,
            chassis_size: 10,
            ip: "192.168.1.10".into(),
            netmask: "255.255.255.0".into(),
            network: Vec::new(),
            program_name: "SimController".into(),
            max_connection_size: 4002,
            large_forward_open: true,
            multi_service: true,
            instance_ids: true,
            tag_table_version: true,
            aoi_locals_refused: true,
            micro800: false,
            clock_us: None,
            types: Vec::new(),
            tags: Vec::new(),
            programs: Vec::new(),
            tasks: Vec::new(),
            system_tags: Vec::new(),
            modules: Vec::new(),
            metadata_auth: false,
        }
    }
}

impl LogixConfig {
    /// A Micro800 (2080-LC50-48QWB) with its limits.
    pub fn micro800() -> Self {
        LogixConfig {
            identity: IdentityConfig {
                product_code: 191,
                revision: [12, 11],
                product_name: "2080-LC50-48QWB".into(),
                ..IdentityConfig::default()
            },
            micro800: true,
            ..LogixConfig::default()
        }
    }

    /// Adds a data type.
    pub fn with_type(mut self, data_type: TypeConfig) -> Self {
        self.types.push(data_type);
        self
    }

    /// Adds a controller-scoped tag.
    pub fn with_tag(mut self, tag: TagConfig) -> Self {
        self.tags.push(tag);
        self
    }

    /// Adds a program.
    pub fn with_program(mut self, program: ProgramConfig) -> Self {
        self.programs.push(program);
        self
    }
}

/// A user data type: a UDT, an Add-On Instruction or a custom string type.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TypeConfig {
    /// Type name.
    pub name: String,
    /// Members in declaration order (an AOI's EnableIn and EnableOut are added first).
    pub members: Vec<MemberConfig>,
    /// An Add-On Instruction.
    pub aoi: bool,
    /// A custom string type of this many characters (members are then LEN and DATA).
    pub string: Option<u32>,
    /// Template instance ID, else the next free one from 0x100.
    pub template_id: Option<u16>,
}

impl TypeConfig {
    /// A UDT.
    pub fn udt(name: &str, members: impl IntoIterator<Item = MemberConfig>) -> Self {
        TypeConfig {
            name: name.into(),
            members: members.into_iter().collect(),
            ..TypeConfig::default()
        }
    }

    /// An Add-On Instruction, its members after EnableIn and EnableOut.
    pub fn aoi(name: &str, members: impl IntoIterator<Item = MemberConfig>) -> Self {
        TypeConfig {
            aoi: true,
            ..TypeConfig::udt(name, members)
        }
    }

    /// A custom string type, e.g. `STRING20`.
    pub fn string(name: &str, length: u32) -> Self {
        TypeConfig {
            name: name.into(),
            string: Some(length),
            ..TypeConfig::default()
        }
    }
}

/// A member of a data type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemberConfig {
    /// Member name.
    pub name: String,
    /// Type name: an atomic type, a predefined type or a type in `types`.
    #[serde(rename = "type")]
    pub data_type: String,
    /// Array length, 0 for a scalar (a BOOL array is rounded up to whole DWORDs).
    pub dim: u32,
    /// An AOI local tag: not externally accessible.
    pub local: bool,
    /// `"Read/Write"`, `"Read Only"` or `"None"` (an AOI's EnableIn and EnableOut are Read Only).
    pub external_access: String,
    /// The member's default Description (language 0x007F), in the controller's Description index.
    pub description: Option<String>,
}

impl MemberConfig {
    /// A scalar member.
    pub fn new(name: &str, data_type: &str) -> Self {
        MemberConfig {
            name: name.into(),
            data_type: data_type.into(),
            dim: 0,
            local: false,
            external_access: "Read/Write".into(),
            description: None,
        }
    }

    /// An array member.
    pub fn array(name: &str, data_type: &str, dim: u32) -> Self {
        MemberConfig {
            dim,
            ..MemberConfig::new(name, data_type)
        }
    }

    /// Marks an AOI member as a local tag.
    pub fn local(mut self) -> Self {
        self.local = true;
        self
    }

    /// Sets the external access.
    pub fn access(mut self, external_access: &str) -> Self {
        self.external_access = external_access.into();
        self
    }

    /// Sets the default Description.
    pub fn description(mut self, text: &str) -> Self {
        self.description = Some(text.into());
        self
    }
}

impl Default for MemberConfig {
    fn default() -> Self {
        MemberConfig::new("", "DINT")
    }
}

/// A tag.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TagConfig {
    /// Tag name (an I/O tag may contain colons, e.g. `Local:1:I`).
    pub name: String,
    /// Type name.
    #[serde(rename = "type")]
    pub data_type: String,
    /// Array dimensions, up to 3 (a BOOL array has one, a multiple of 32).
    pub dims: Vec<u32>,
    /// Initial value: a number, bool, string, list (flattened row-major) or object of members.
    pub value: Json,
    /// Initial value as the controller's memory image in hex (spaces allowed), e.g. the `<Data>` of an L5X
    /// export; applied before `value`.
    pub raw: Option<String>,
    /// `"Read/Write"`, `"Read Only"` or `"None"`.
    pub external_access: String,
    /// An alias tag (the software control word has no base tag bit).
    pub alias: bool,
    /// Symbol instance ID, else the next free one in its scope.
    pub instance_id: Option<u32>,
    /// Descriptions (language 0x007F) by path below the tag: `""` the tag, `"[1]"` an element, `"[1].Member"`
    /// a member, `"[1].3"` a bit (any case).
    pub descriptions: BTreeMap<String, String>,
}

impl TagConfig {
    /// A tag of this type with a zero value.
    pub fn new(name: &str, data_type: &str) -> Self {
        TagConfig {
            name: name.into(),
            data_type: data_type.into(),
            ..TagConfig::default()
        }
    }

    /// Sets the array dimensions.
    pub fn dims(mut self, dims: &[u32]) -> Self {
        self.dims = dims.to_vec();
        self
    }

    /// Sets the initial value.
    pub fn value(mut self, value: Json) -> Self {
        self.value = value;
        self
    }

    /// Sets the external access.
    pub fn access(mut self, external_access: &str) -> Self {
        self.external_access = external_access.into();
        self
    }

    /// Sets the symbol instance ID.
    pub fn instance_id(mut self, id: u32) -> Self {
        self.instance_id = Some(id);
        self
    }

    /// Adds a Description: `path` below the tag, `""` for the tag itself.
    pub fn description(mut self, path: &str, text: &str) -> Self {
        self.descriptions.insert(path.into(), text.into());
        self
    }
}

impl Default for TagConfig {
    fn default() -> Self {
        TagConfig {
            name: String::new(),
            data_type: "DINT".into(),
            dims: Vec::new(),
            value: Json::Null,
            raw: None,
            external_access: "Read/Write".into(),
            alias: false,
            instance_id: None,
            descriptions: BTreeMap::new(),
        }
    }
}

/// A program: its routines and program-scoped tags.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProgramConfig {
    /// Program name.
    pub name: String,
    /// Routine names.
    pub routines: Vec<String>,
    /// Program-scoped tags.
    pub tags: Vec<TagConfig>,
    /// Instance ID of the program's symbol in the controller scope.
    pub instance_id: Option<u32>,
}

impl ProgramConfig {
    /// A program with one routine, `MainRoutine`.
    pub fn new(name: &str) -> Self {
        ProgramConfig {
            name: name.into(),
            routines: vec!["MainRoutine".into()],
            ..ProgramConfig::default()
        }
    }

    /// Adds a program-scoped tag.
    pub fn with_tag(mut self, tag: TagConfig) -> Self {
        self.tags.push(tag);
        self
    }
}

/// A named symbol with an optional instance ID (a task).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NamedConfig {
    /// Name.
    pub name: String,
    /// Instance ID.
    pub instance_id: Option<u32>,
}

/// A system symbol of the controller symbol list.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SystemTagConfig {
    /// Name, e.g. `__SYSTEM`, `Map:Local` or `Cxn:Standard:1`.
    pub name: String,
    /// Symbol type, by default 0x10C4 (system bit, DINT).
    pub symbol_type: Option<u16>,
    /// Instance ID.
    pub instance_id: Option<u32>,
}

/// Another module in the chassis.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModuleConfig {
    /// Backplane slot.
    pub slot: u8,
    /// Its identity.
    pub identity: IdentityConfig,
}

/// A device on the EtherNet/IP network of a Logix.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkDeviceConfig {
    /// IP address.
    pub ip: String,
    /// Its identity.
    pub identity: IdentityConfig,
}

/// An SLC 500 or MicroLogix processor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SlcConfig {
    /// Identity of the processor.
    pub identity: IdentityConfig,
    /// The catalog number the diagnostic status reply carries, e.g. `"1747-L552"`; its prefix picks the layout
    /// of the file directory (1747 SLC 5/05, 1761 MicroLogix 1000, 1762/1763/1764 MicroLogix 1100-1500, 1766
    /// MicroLogix 1400).
    pub processor_type: String,
    /// Data files, by default O0 I1 S2 B3 T4 C5 R6 N7 F8.
    pub files: Vec<FileConfig>,
    /// Entries of the data log queue, returned one per read.
    pub datalog: Vec<String>,
}

impl Default for SlcConfig {
    fn default() -> Self {
        SlcConfig {
            identity: IdentityConfig {
                product_type: 14,
                product_code: 0x59,
                revision: [3, 1],
                product_name: "1747-L552/C D/16".into(),
                ..IdentityConfig::default()
            },
            processor_type: "1747-L552".into(),
            files: Vec::new(),
            datalog: Vec::new(),
        }
    }
}

/// A data file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// File number.
    pub number: u16,
    /// File type: O, I, S, B, T, C, R, N, F, ST, A or L.
    #[serde(rename = "type")]
    pub file_type: String,
    /// Number of elements.
    pub elements: u32,
    /// Initial values, one per element: a number, a string (ST, A), or for T/C/R an object of PRE/ACC/LEN/POS
    /// and status bits or a list of the 3 words.
    pub values: Vec<Json>,
}

impl FileConfig {
    /// A data file of zeros.
    pub fn new(number: u16, file_type: &str, elements: u32) -> Self {
        FileConfig {
            number,
            file_type: file_type.into(),
            elements,
            values: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_defaults_to_logix_and_rejects_unknown_fields() {
        let Ok(Config::Logix(config)) =
            Config::from_json(r#"{"tags": [{"name": "a", "type": "INT"}]}"#)
        else {
            panic!("not a logix config")
        };
        assert_eq!(config.tags[0].data_type, "INT");
        assert_eq!(config.max_connection_size, 4002);
        assert!(Config::from_json(r#"{"tagz": []}"#).is_err());
        assert!(Config::from_json(r#"{"kind": "plc5"}"#).is_err());
        assert!(matches!(
            Config::from_json(r#"{"kind": "slc"}"#),
            Ok(Config::Slc(_))
        ));
    }
}
