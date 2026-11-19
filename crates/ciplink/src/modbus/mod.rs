//! Modbus TCP, RTU on a serial port, and RTU framed over TCP, on the [session](crate::session) core.
//!
//! Tag names come from a map file ([`TagMap`], CSV, one row per tag). Without a map, or for anything not in
//! it, a name is a plain address:
//!
//! ```text
//! address = area offset ["." bit] [":" type [":" order]] ["{" count "}"] ["@" unit]
//! area    = co | di | hr | ir     coil, discrete input, holding register, input register
//! ```
//!
//! Addresses are 0-based protocol addresses everywhere: Modicon holding register 40001 is `hr0`. Examples:
//! `hr100:float32`, `hr100:float32:cdab`, `hr200:int16{10}`, `hr300:string{20}`, `hr10.4`, `co0{16}`, `di7@3`.

mod address;
mod driver;
mod frame;
mod link;
mod map;
mod pdu;
mod plan;
mod value;

pub use address::{Address, Area, DataType, WordOrder};
pub use driver::{DeviceInfo, ModbusDriver, ModbusOptions};
pub use link::{Endpoint, Link, ModbusConnector, Parity, modbus_connector};
pub use map::{MapTag, TagMap};
