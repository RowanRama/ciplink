//! Public data of the S7comm-plus driver: tags, structure types, symbols and CPU information.

use indexmap::IndexMap;

/// What a tag or member is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum S7Kind {
    /// An elementary value or an array of them.
    Elementary,
    /// STRING or WSTRING (or an array of them).
    String,
    /// A structure, UDT, FB instance or system type (or an array of them).
    Struct,
    /// A data block (top-level tag).
    DataBlock,
    /// An I, Q or M area (never returned as a tag; its PLC tags are).
    Area,
}

/// A top-level tag (a data block or a PLC tag of the I, Q or M area) or a structure member.
#[derive(Clone, Debug, PartialEq)]
pub struct S7Tag {
    /// The name.
    pub name: String,
    /// S7 type name: `"REAL"`, `"STRING"`, `"DTL"`, `"IEC_TIMER"`, or a structure type's name (see
    /// [`S7Type::name`]).
    pub type_name: String,
    /// What it is.
    pub kind: S7Kind,
    /// The PLC type number (spec 13.5); 0 for a data block.
    pub softdatatype: u8,
    /// Element counts in declared order; empty for a scalar.
    pub dims: Vec<u32>,
    /// Declared lower bounds, same length as `dims`.
    pub lower_bounds: Vec<i32>,
    /// Maximum length of a STRING / WSTRING.
    pub string_length: Option<u16>,
    /// A member's LID; a data block's number for a data block.
    pub lid: u32,
    /// Member CRC from the type information (0 for a data block).
    pub member_crc: u32,
    /// Visible in HMI engineering.
    pub hmi_visible: bool,
    /// Accessible from HMI / OPC UA / web server.
    pub hmi_accessible: bool,
    /// Read-only for HMI.
    pub hmi_read_only: bool,
}

/// A structure type from the type information (spec 13.4).
#[derive(Clone, Debug, PartialEq)]
pub struct S7Type {
    /// The type-info name when the PLC gives one, else `"DTL"`, `"IEC_TIMER"` ... for known system types, else
    /// the type RID as `"0x91000005"`. The PLC does not send UDT names.
    pub name: String,
    /// The type RID.
    pub rid: u32,
    /// Interface timestamp (attribute 529); packed struct values carry it.
    pub interface_timestamp: u64,
    /// The members in declaration order.
    pub members: IndexMap<String, S7Tag>,
}

/// A resolved symbol, as [`tag_list`](super::S7PlusDriver::tag_list) and
/// [`get_tag_info`](super::S7PlusDriver::get_tag_info) return it.
#[derive(Clone, Debug, PartialEq)]
pub struct S7Symbol {
    /// The full name (`Line1.Conveyor.Speed`, `Line1.Items[3]`).
    pub name: String,
    /// S7 type name of the value.
    pub type_name: String,
    /// Element counts of a whole array; empty otherwise.
    pub dims: Vec<u32>,
    /// Area and LIDs in hex, as in the spec: `"8A0E0005.A.B"`.
    pub access: String,
    /// The address CRC sent with reads and writes; 0 when the path has an index.
    pub crc: u32,
    /// Visible in HMI engineering (AND of the path).
    pub hmi_visible: bool,
    /// Accessible from HMI (AND of the path).
    pub hmi_accessible: bool,
    /// Read-only for HMI (OR of the path).
    pub hmi_read_only: bool,
}

/// CPU information (spec 13.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuInfo {
    /// PLC (station) name.
    pub name: Option<String>,
    /// Order number (MLFB).
    pub order_number: Option<String>,
    /// Serial number.
    pub serial_number: Option<String>,
    /// Hardware version.
    pub hardware_version: Option<u8>,
    /// Firmware version, `"V3.1.3"`.
    pub firmware: Option<String>,
    /// TIA Portal version of the project, `"19.0.0.0"`.
    pub engineering_version: Option<String>,
    /// Project name.
    pub project: Option<String>,
    /// Effective protection level (0: full access).
    pub protection_level: Option<u32>,
    /// Most items per read request.
    pub max_read: usize,
    /// Most items per write request.
    pub max_write: usize,
}

/// The S7 name of a softdatatype (spec 11.5); `"SDT_<n>"` for one the driver does not know.
pub fn softdatatype_name(sdt: u8) -> String {
    let name = match sdt {
        1 | 40 => "BOOL",
        2 => "BYTE",
        3 => "CHAR",
        4 => "WORD",
        5 => "INT",
        6 => "DWORD",
        7 => "DINT",
        8 => "REAL",
        9 => "DATE",
        10 => "TIME_OF_DAY",
        11 => "TIME",
        12 => "S5TIME",
        14 => "DATE_AND_TIME",
        17 => "STRUCT",
        19 => "STRING",
        31 => "IEC_TIMER",
        48 => "LREAL",
        49 => "ULINT",
        50 => "LINT",
        51 => "LWORD",
        52 => "USINT",
        53 => "UINT",
        54 => "UDINT",
        55 => "SINT",
        61 => "WCHAR",
        62 => "WSTRING",
        64 => "LTIME",
        65 => "LTOD",
        66 => "LDT",
        67 => "DTL",
        96 => "ANY",
        144 => "HW_ANY",
        145..=156 => "HW_ID",
        208 => "DB_ANY",
        _ => return format!("SDT_{sdt}"),
    };
    name.to_string()
}

/// The name of a known system type RID.
pub(crate) fn system_type_name(rid: u32) -> Option<&'static str> {
    match rid {
        0x0200_0043 => Some("DTL"),
        0x0200_001F => Some("IEC_TIMER"),
        _ => None,
    }
}
