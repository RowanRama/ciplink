//! CIP Identity Object replies: Get_Attributes_All of the Identity Object and the ListIdentity reply.

use crate::reader::Reader;
use crate::types::Elementary;
use crate::{Result, Value, status};
use indexmap::IndexMap;

/// Major and minor revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision {
    /// Major revision.
    pub major: u8,
    /// Minor revision.
    pub minor: u8,
}

/// Identity Object attributes (Get_Attributes_All).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleIdentity {
    /// Vendor name, `"UNKNOWN"` if not listed.
    pub vendor: String,
    /// Product (device) type name, `"UNKNOWN"` if not listed.
    pub product_type: String,
    /// Product code.
    pub product_code: u16,
    /// Firmware revision.
    pub revision: Revision,
    /// Raw status word (attribute 5).
    pub status: [u8; 2],
    /// Serial number as 8 hex digits.
    pub serial: String,
    /// Product name, e.g. `"1756-SIM/A"`.
    pub product_name: String,
}

fn short_string(r: &mut Reader<'_>) -> Result<String> {
    match Elementary::ShortString.decode(r)? {
        Value::String(s) => Ok(s),
        _ => Ok(String::new()),
    }
}

impl ModuleIdentity {
    /// Decodes the Get_Attributes_All reply data.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let vendor = r.u16()?;
        let product_type = r.u16()?;
        let product_code = r.u16()?;
        let revision = Revision {
            major: r.u8()?,
            minor: r.u8()?,
        };
        let s = r.take(2)?;
        let status = [s[0], s[1]];
        let serial = r.u32()?;
        let product_name = short_string(r)?;
        Ok(ModuleIdentity {
            vendor: status::vendor(vendor).unwrap_or("UNKNOWN").to_owned(),
            product_type: status::product_type(product_type)
                .unwrap_or("UNKNOWN")
                .to_owned(),
            product_code,
            revision,
            status,
            serial: format!("{serial:08x}"),
            product_name,
        })
    }

    fn fields(&self, map: &mut IndexMap<String, Value>) {
        map.insert("vendor".into(), Value::String(self.vendor.clone()));
        map.insert(
            "product_type".into(),
            Value::String(self.product_type.clone()),
        );
        map.insert("product_code".into(), Value::UInt(self.product_code));
        let revision = IndexMap::from([
            ("major".to_owned(), Value::USInt(self.revision.major)),
            ("minor".to_owned(), Value::USInt(self.revision.minor)),
        ]);
        map.insert("revision".into(), Value::Struct(revision));
        map.insert("status".into(), Value::Bytes(self.status.to_vec()));
        map.insert("serial".into(), Value::String(self.serial.clone()));
        map.insert(
            "product_name".into(),
            Value::String(self.product_name.clone()),
        );
    }

    /// The identity as the Python driver's dict.
    pub fn to_value(&self) -> Value {
        let mut map = IndexMap::new();
        self.fields(&mut map);
        Value::Struct(map)
    }
}

/// A ListIdentity reply item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListIdentity {
    /// Encapsulation protocol version.
    pub encap_protocol_version: u16,
    /// IP address the device reports.
    pub ip_address: String,
    /// Identity attributes.
    pub identity: ModuleIdentity,
    /// Device state.
    pub state: u8,
}

impl ListIdentity {
    /// Decodes a ListIdentity item (from its item type code on).
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        r.u16()?; // item type
        r.u16()?; // item length
        let encap_protocol_version = r.u16()?;
        r.i16()?; // sin_family
        r.u16()?; // sin_port
        let ip = r.take(4)?;
        let ip_address = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        r.u64()?; // sin_zero
        let identity = ModuleIdentity::decode(r)?;
        let state = r.u8()?;
        Ok(ListIdentity {
            encap_protocol_version,
            ip_address,
            identity,
            state,
        })
    }

    /// The identity as the Python driver's dict.
    pub fn to_value(&self) -> Value {
        let mut map = IndexMap::new();
        map.insert(
            "encap_protocol_version".into(),
            Value::UInt(self.encap_protocol_version),
        );
        map.insert("ip_address".into(), Value::String(self.ip_address.clone()));
        self.identity.fields(&mut map);
        map.insert("state".into(), Value::USInt(self.state));
        Value::Struct(map)
    }
}
