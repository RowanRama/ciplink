//! S7comm-plus driver for Siemens S7-1500 / S7-1200 CPUs with secure PG/HMI communication (TLS 1.3,
//! firmware 2.9 and later): browse, batched symbolic reads and writes, CPU information, keep-alive and
//! reconnect on the [session core](crate::session).
//!
//! Names are TIA style: `Line1.Conveyor.Speed`, `Line1.Items[3].Weight`, PLC tags of the I, Q and M areas by
//! their bare name. Double quotes around a segment are accepted and stripped; an exact match is tried first,
//! then a case-insensitive one. A multi-dimensional array (`Line1.Grid`) is read and written whole; its
//! elements (`Line1.Grid[2,5]`) are refused (`BadRequest`) until their order is verified on a CPU.
//!
//! Values map onto [`Value`](crate::Value): BYTE / WORD / DWORD / LWORD as `USInt` / `UInt` / `UDInt` /
//! `ULInt`, TIME and S5TIME as `DInt` milliseconds, LTIME as `LInt` nanoseconds, the date and time types as
//! ISO 8601 strings in the PLC's clock (`"2026-11-18T16:34:46.100000000"`), STRING / WSTRING / CHAR / WCHAR as
//! `String`, structures as `Struct`, arrays as `Array`. A result's `data_type` is the S7 type name (`"WORD"`,
//! `"DTL"`, `"REAL[50]"`).
//!
//! Not supported: the legacy non-TLS login, password login, tag comments (descriptions), hardware trends,
//! alarms and CPU start / stop.

mod browse;
mod codec;
mod cotp;
mod driver;
#[cfg(test)]
mod fake;
mod link;
mod pdu;
mod tls;
mod types;
mod values;

pub use driver::{DEFAULT_PORT, S7PlusDriver, S7PlusOptions};
pub use types::{CpuInfo, S7Kind, S7Symbol, S7Tag, S7Type};

/// The codec and PDU builders, for the simulator and the tests. Not a stable API.
#[doc(hidden)]
pub mod wire {
    pub use super::codec::*;
    pub use super::cotp::*;
    pub use super::pdu::*;
    pub use super::tls::{fingerprint, format_fingerprint, parse_fingerprint};

    use std::collections::HashMap;

    use super::browse::{self, SymbolTree};
    use super::types::S7Symbol;
    use crate::{TagError, Value};

    /// A symbol tree built from explored objects, for the capture tests.
    pub struct Tree(SymbolTree);

    impl Tree {
        /// The data blocks and type-info objects found anywhere in `explored`, with each DB's type RID by
        /// DB number.
        pub fn new(explored: &[Object], db_types: &HashMap<u32, u32>) -> Self {
            Tree(SymbolTree::new(
                browse::data_blocks(explored),
                db_types,
                browse::type_infos(explored),
            ))
        }

        /// The name of the I, Q or M area type (attribute 233), if browsed.
        pub fn area_name(&self, area: u32) -> Option<String> {
            let (_, rid) = browse::AREAS.iter().find(|(a, _)| *a == area)?;
            Some(self.0.types.get(rid)?.name.clone())
        }

        /// The symbol of one name.
        pub fn resolve(&self, name: &str) -> Result<S7Symbol, TagError> {
            let a = self.0.resolve(name)?;
            Ok(self.0.symbol(name, &a))
        }

        /// The softdatatype and offset-info type of the member a name ends at.
        pub fn leaf(&self, name: &str) -> Result<(u8, u8), TagError> {
            let a = self.0.resolve(name)?;
            Ok((a.leaf.softdatatype, a.leaf.layout.kind))
        }

        /// Every symbol.
        pub fn symbols(&self) -> Vec<S7Symbol> {
            self.0.symbols()
        }

        /// A read value of `name` decoded: the value and its data type name.
        pub fn decode(&self, name: &str, value: &WireValue) -> Result<(Value, String), TagError> {
            let a = self.0.resolve(name)?;
            Ok(super::values::decode(&self.0, &a, value))
        }

        /// A write of `value` to `name`: the item address and the wire value.
        pub fn encode(
            &self,
            name: &str,
            value: &Value,
        ) -> Result<(ItemAddress, WireValue), TagError> {
            let a = self.0.resolve(name)?;
            let wire = super::values::encode(&self.0, name, &a, value)?;
            Ok((a.item, wire))
        }
    }
}
