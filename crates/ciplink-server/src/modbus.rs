//! Modbus PLCs (`protocol = "modbus"`): ciplink's [`ModbusDriver`] with the tags, types and descriptions of the
//! PLC's map file.

use std::time::Duration;

use ciplink::Value;
use ciplink::cip::TagResult;
use ciplink::modbus::{DataType, ModbusDriver, ModbusOptions, TagMap, WordOrder, modbus_connector};
use indexmap::IndexMap;
use serde_json::{Map, Value as Json};

use crate::config::PlcConfig;
use crate::plc::{Catalog, Kind, Node, Plc};

/// A Modbus device (or gateway) through ciplink's [`ModbusDriver`].
pub struct ModbusPlc {
    driver: ModbusDriver,
}

impl ModbusPlc {
    /// The driver of a configured PLC, not yet opened; loads its map file.
    pub fn new(cfg: &PlcConfig) -> Result<Self, String> {
        let map_file = cfg
            .map_file
            .as_ref()
            .ok_or_else(|| format!("plc.{} needs a map_file", cfg.name))?;
        let mut options =
            options(&cfg.modbus).map_err(|e| format!("plc.{}.modbus: {e}", cfg.name))?;
        options.map = Some(TagMap::load(map_file).map_err(|e| e.to_string())?);
        // the worker reconnects (and Plc::read returns Err on a lost link); the scheme's keep-alive stays on
        let mut session = ModbusDriver::default_session(&cfg.path).map_err(|e| e.to_string())?;
        session.reconnect = false;
        if let Some(keep_alive) = cfg.modbus.get("keep_alive") {
            session.keep_alive = match keep_alive.as_f64() {
                Some(s) if s > 0.0 && s.is_finite() => Some(Duration::from_secs_f64(s)),
                Some(_) => None,
                None => {
                    return Err(format!(
                        "plc.{}.modbus.keep_alive must be seconds (0: off)",
                        cfg.name
                    ));
                }
            };
        }
        let driver = ModbusDriver::with_session(&cfg.path, options, session, modbus_connector())
            .map_err(|e| e.to_string())?;
        Ok(ModbusPlc { driver })
    }
}

/// The driver options of a `[plc.X.modbus]` table (`keep_alive` is a session option, read by `new`).
fn options(table: &Map<String, Json>) -> Result<ModbusOptions, String> {
    let mut options = ModbusOptions::default();
    for (key, value) in table {
        let int = || {
            value
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| format!("{key} must be an integer 0..65535"))
        };
        match key.as_str() {
            "socket_timeout" => {
                let s = value
                    .as_f64()
                    .filter(|s| *s > 0.0 && s.is_finite())
                    .ok_or("socket_timeout must be seconds > 0")?;
                options.socket_timeout = Duration::from_secs_f64(s);
            }
            "max_registers" => options.max_registers = int()?,
            "max_bits" => options.max_bits = int()?,
            "max_gap" => options.max_gap = int()?,
            "word_order" => {
                options.word_order = value
                    .as_str()
                    .and_then(WordOrder::parse)
                    .ok_or("word_order must be ABCD, CDAB, BADC or DCBA")?;
            }
            "write_multiple" => {
                options.write_multiple = value
                    .as_bool()
                    .ok_or("write_multiple must be true or false")?;
            }
            "keep_alive_address" => {
                options.keep_alive_address = Some(
                    value
                        .as_str()
                        .ok_or("keep_alive_address must be a string")?
                        .to_owned(),
                );
            }
            "keep_alive" => {}
            other => return Err(format!("unknown key {other}")),
        }
    }
    Ok(options)
}

/// `base[start]{count}` (a run the planner merged) or `base{count}`: (base, start, count).
fn run(name: &str) -> Option<(&str, usize, usize)> {
    let head = name.strip_suffix('}')?;
    let (head, count) = head.rsplit_once('{')?;
    let count = count.parse().ok()?;
    match head.strip_suffix(']').and_then(|h| h.rsplit_once('[')) {
        Some((base, start)) => Some((base, start.parse().ok()?, count)),
        None => Some((head, 0, count)),
    }
}

impl Plc for ModbusPlc {
    fn open(&mut self) -> Result<(), String> {
        self.driver.open().map(|_| ()).map_err(|e| e.to_string())
    }

    fn close(&mut self) {
        let _ = self.driver.close();
    }

    /// Runs of array elements (`Totals[1]{3}`) are read as their elements, which the driver merges into the
    /// fewest requests, and put back together as one array.
    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String> {
        let mut names = Vec::with_capacity(tags.len());
        let mut spans = Vec::with_capacity(tags.len());
        for tag in tags {
            let first = names.len();
            match run(tag) {
                Some((base, start, count)) => {
                    names.extend((start..start + count).map(|i| format!("{base}[{i}]")));
                }
                None => names.push((*tag).to_owned()),
            }
            spans.push(first..names.len());
        }
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut results = self.driver.read(&refs).map_err(|e| e.to_string())?;
        if names.len() == tags.len() {
            return Ok(results);
        }
        let mut out = Vec::with_capacity(tags.len());
        for (tag, span) in tags.iter().zip(spans) {
            let parts: Vec<TagResult> = results.drain(..span.len()).collect();
            if run(tag).is_none() {
                out.extend(parts);
                continue;
            }
            let mut merged = TagResult {
                tag: (*tag).to_owned(),
                value: None,
                data_type: parts.first().and_then(|p| p.data_type.clone()),
                error: parts.iter().find_map(|p| p.error.clone()),
            };
            if merged.error.is_none() {
                merged.value = parts
                    .into_iter()
                    .map(|p| p.value)
                    .collect::<Option<Vec<Value>>>()
                    .map(Value::Array);
            }
            out.push(merged);
        }
        Ok(out)
    }

    fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String> {
        let mut results = self
            .driver
            .write(&[(tag, value.clone())])
            .map_err(|e| e.to_string())?;
        results.pop().ok_or_else(|| "no write result".to_owned())
    }

    /// One atomic or string tag per map row.
    fn catalog(&mut self) -> Catalog {
        let tags: IndexMap<String, Node> = self
            .driver
            .map()
            .tags()
            .map(|row| {
                let string = row.data_type == DataType::String;
                let node = Node {
                    type_name: row.type_name().to_owned(),
                    kind: if string { Kind::String } else { Kind::Atomic },
                    dims: if !string && row.count > 1 {
                        vec![u64::from(row.count)]
                    } else {
                        Vec::new()
                    },
                    member: false,
                    instance_id: None,
                    structure_size: string.then_some(u64::from(row.count)),
                };
                (row.name.clone(), node)
            })
            .collect();
        Catalog::new(Json::Null, tags, IndexMap::new())
    }

    fn version(&mut self) -> Json {
        Json::Null // a map does not change while serving
    }

    fn connection_size(&self) -> usize {
        0
    }

    fn describes(&self) -> bool {
        true
    }

    fn descriptions(&mut self, tags: &[&str]) -> Result<Vec<Option<String>>, String> {
        let map = self.driver.map();
        Ok(tags
            .iter()
            .map(|t| {
                // an element (`Totals[2]`) has its array's description
                map.get(t)
                    .or_else(|| map.get(t.split('[').next().unwrap_or(t)))
                    .map(|row| row.description.clone())
                    .filter(|d| !d.is_empty())
            })
            .collect())
    }
}

#[cfg(test)]
#[path = "modbus_tests.rs"]
mod tests;
