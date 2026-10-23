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
pub mod planner;
pub mod plc;
pub mod rules;
pub mod server;
pub mod service;
pub mod values;
pub mod worker;

pub use config::{Config, load_config};
pub use server::ServerHandle;

/// The driver factory: simulated PLCs from their `mock_tags` files with `mock`, else real controllers.
pub fn factory(mock: bool) -> plc::Factory {
    if mock {
        mock::factory().0
    } else {
        plc::LogixPlc::factory()
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
