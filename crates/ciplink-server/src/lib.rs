//! A tag server on the ciplink core: one process per site owns the PLC connections and serves tag values to web
//! apps over a WebSocket (the protocol of ciplink-tagserver and `@ciplink/react`).
#![warn(missing_docs)]

use std::path::Path;

pub mod cli;
pub mod codegen;
pub mod config;
pub mod hub;
pub mod logging;
pub mod mock;
pub mod modbus;
pub mod planner;
pub mod plc;
pub mod rules;
pub mod server;
pub mod service;
pub mod values;
pub mod worker;

#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod testing;

pub use config::{Config, load_config};
pub use server::ServerHandle;

/// The driver factory: simulated PLCs from their `mock_tags` files with `mock`, else real controllers.
pub fn factory(mock: bool) -> plc::Factory {
    if mock {
        mock::factory().0
    } else {
        std::sync::Arc::new(real_plc)
    }
}

/// The (not yet opened) driver of a real controller, by the PLC's `protocol`.
pub fn real_plc(cfg: &config::PlcConfig) -> Result<Box<dyn plc::Plc>, String> {
    match cfg.protocol.as_str() {
        "modbus" => Ok(Box::new(modbus::ModbusPlc::new(cfg)?)),
        _ => Ok(Box::new(plc::LogixPlc::new(cfg)?)),
    }
}

/// Serves the config file until Ctrl+C.
pub fn run(config_path: &Path, mock: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(server::run(config, factory(mock)))
}
