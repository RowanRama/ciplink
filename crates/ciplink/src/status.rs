//! CIP status text, error classification and lookup tables.

use crate::ErrorKind;
use crate::tables;

pub use crate::tables::{product_type, state, vendor};

/// Text of a CIP general status, e.g. `"Permission denied"`.
pub fn service_status_text(status: u8) -> String {
    tables::service_status(status)
        .map_or_else(|| format!("Unknown Error ({status:02x})"), str::to_owned)
}

/// Text of the extended status following the general status at `msg[start]`, None if there is none.
pub fn extended_status_text(msg: &[u8], start: usize) -> Option<String> {
    let status = *msg.get(start)?;
    if *msg.get(start + 1)? == 0 {
        return None;
    }
    let ext = extended_status_code(msg, start)?;
    let text = tables::extend_code(status, ext).unwrap_or("Extended status");
    Some(format!("{text}  ({status:02x}, {ext:02x})"))
}

/// The first extended status word after the general status at `msg[start]`, None if there is none.
pub fn extended_status_code(msg: &[u8], start: usize) -> Option<u16> {
    if *msg.get(start + 1)? == 0 {
        return None;
    }
    let bytes = msg.get(start + 2..start + 4)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// The [`ErrorKind`] of a CIP general status and its first extended status word.
pub fn status_kind(status: u8, ext: Option<u16>) -> ErrorKind {
    if status == 0xFF {
        return match ext {
            Some(0x2104 | 0x2105 | 0x210B) => ErrorKind::NotFound,
            Some(0x2107 | 0x2109 | 0x7) => ErrorKind::BadValue,
            Some(0x2100..=0x2103) => ErrorKind::Access,
            Some(0x2108 | 0x2106) => ErrorKind::Refused,
            Some(0x210A) => ErrorKind::BadRequest,
            _ => ErrorKind::Device,
        };
    }
    match status {
        0x04 | 0x05 | 0x16 => ErrorKind::NotFound,
        0x0F => ErrorKind::Access,
        0x0C | 0x10 | 0x02 => ErrorKind::Refused,
        0x03 | 0x09 | 0x13 | 0x15 | 0x20 => ErrorKind::BadValue,
        0x08 | 0x26 => ErrorKind::BadRequest,
        _ => ErrorKind::Device,
    }
}

/// Text of an encapsulation status.
pub fn encap_status_text(status: u32) -> String {
    tables::encap_status(status).map_or_else(
        || format!("Unknown encapsulation status ({status:#06x})"),
        str::to_owned,
    )
}

/// Keyswitch position from the two Identity status bytes, `"UNKNOWN"` if not recognised.
pub fn keyswitch(a: u8, b: u8) -> &'static str {
    tables::keyswitch(a, b).unwrap_or("UNKNOWN")
}

/// External Access text of a symbol's access attribute, `"Unknown"` when absent (before v18) or unknown.
pub fn external_access(access: Option<u8>) -> &'static str {
    access
        .and_then(tables::external_access)
        .unwrap_or("Unknown")
}

/// Text of a PCCC status.
pub fn pccc_error_text(code: i32) -> Option<&'static str> {
    tables::pccc_error(code)
}
