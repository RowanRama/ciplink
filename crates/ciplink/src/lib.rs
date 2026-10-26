//! EtherNet/IP (CIP) driver for Allen-Bradley Logix, Micro800 and SLC/MicroLogix PLCs.
//!
//! The Rust core of the ciplink package (a pycomm3 fork). The same driver is bound to Python, C/C++ and C#.
#![warn(missing_docs)]

pub mod adapter;
pub mod browse;
pub mod cip;
pub mod epath;
mod error;
pub mod identity;
pub mod logix;
pub mod packets;
pub mod reader;
pub mod slc;
pub mod status;
#[allow(missing_docs, unreachable_patterns)]
mod tables;
pub mod transport;
pub mod types;
mod value;

pub use error::{Error, ErrorKind, Result, TagError};
pub use value::Value;
