//! `ciplink-sim`: serves a simulated controller over TCP for tests in any language.
//!
//! ```text
//! ciplink-sim [--config controller.json] [--host 127.0.0.1] [--port 44818] [--udp 127.0.0.1:44818]
//!             [--framing mbap|rtu] [--exit-on-eof]
//! ```
//!
//! Prints `listening on HOST:PORT` once ready (with `--port 0` the port is a free one), then serves until killed.
//! Without `--config` it simulates a Logix controller with no tags.
//!
//! Standard input takes one JSON command per line and each gets one JSON line on standard output,
//! `{"ok": result}` or `{"error": message}`, so a test in any language can change the controller between
//! requests:
//!
//! ```text
//! {"cmd": "value", "path": "Program:Main.tag[1]"}         the value of a tag path (SLC: "N7:0")
//! {"cmd": "set", "path": "tag", "value": 5}                sets it
//! {"cmd": "add_tag", "program": null, "tag": {...}}       online edit, returns the instance ID
//! {"cmd": "remove_tag", "program": null, "name": "tag"}  online edit
//! {"cmd": "add_type", "type": {...}}                      online edit
//! {"cmd": "bump"}                                          bumps the tag table edit counter
//! {"cmd": "download", "config": {...}}                    replaces the project
//! {"cmd": "tag_table_version"}                             [counter, attr 2, download, download 2, project]
//! {"cmd": "fault", "fault": {...}}                        {"drop_replies": n}, {"delay_ms": n},
//!                                                          {"refuse_connections": true},
//!                                                          {"close_connections": true},
//!                                                          {"tag_status": {"tag", "status", "ext"}},
//!                                                          {"service_status": {"service", "class", "status", "ext"}}
//! {"cmd": "clear_faults"}
//! {"cmd": "requests"}                                      requests received so far
//! ```
//!
//! A config whose `"kind"` is `"modbus"` serves a Modbus device instead (port 502 when `--port` is not given):
//! `--framing mbap` (default, Modbus TCP) or `--framing rtu` (RTU frames over TCP, as a serial gateway). Its
//! commands:
//!
//! ```text
//! {"cmd": "registers", "unit": 1, "area": "holding", "address": 0, "count": 2}   [59769, 17142]
//! {"cmd": "set_registers", "unit": 1, "area": "holding", "address": 0, "values": [1, 2]}
//! {"cmd": "bits", "unit": 1, "area": "coil", "address": 0, "count": 3}           [true, false, true]
//! {"cmd": "set_bits", "unit": 1, "area": "coil", "address": 0, "values": [true]}
//! {"cmd": "fault", "fault": {...}}   {"drop_replies": n}, {"delay_ms": n}, {"refuse_connections": true},
//!                                    {"close_connections": true}, {"no_reply": unit},
//!                                    {"exception": {"unit", "function", "code"}}, {"bad_crc": n}
//! {"cmd": "clear_faults"}
//! {"cmd": "requests"}
//! ```
//!
//! With `--exit-on-eof` it exits when standard input closes, else it keeps serving.

use ciplink_sim::{
    Fault, Framing, LogixConfig, ModbusFault, ModbusSim, Simulator, TagConfig, TypeConfig,
};
use serde_json::{Value as Json, json};
use std::io::{BufRead, Write};
use std::time::Duration;

const USAGE: &str = "usage: ciplink-sim [--config FILE] [--host HOST] [--port PORT] [--udp ADDR] \
                     [--framing mbap|rtu] [--exit-on-eof]";

fn main() {
    if let Err(message) = run() {
        eprintln!("ciplink-sim: {message}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut config = None;
    let mut host = "127.0.0.1".to_owned();
    let mut port = None;
    let mut framing = Framing::Mbap;
    let mut udp = None;
    let mut exit_on_eof = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("{arg} needs a value\n{USAGE}"))
        };
        match arg.as_str() {
            "--config" => config = Some(value()?),
            "--host" => host = value()?,
            "--port" => port = Some(value()?),
            "--framing" => {
                framing = match value()?.as_str() {
                    "mbap" => Framing::Mbap,
                    "rtu" => Framing::Rtu,
                    other => return Err(format!("unknown framing {other} (mbap, rtu)")),
                }
            }
            "--udp" => udp = Some(value()?),
            "--exit-on-eof" => exit_on_eof = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let text = match &config {
        Some(path) => {
            Some(std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?)
        }
        None => None,
    };
    let kind = text
        .as_deref()
        .and_then(|text| serde_json::from_str::<Json>(text).ok())
        .and_then(|json| json.get("kind").and_then(Json::as_str).map(str::to_owned));
    if kind.as_deref() == Some("modbus") {
        let sim = ModbusSim::from_json(text.as_deref().unwrap_or_default()).map_err(|e| e.0)?;
        let port = port.unwrap_or_else(|| "502".to_owned());
        let server = sim
            .serve(&format!("{host}:{port}"), framing)
            .map_err(|e| format!("cannot listen on {host}:{port}: {e}"))?;
        println!("listening on {}", server.addr());
        return serve_stdin(exit_on_eof, |line| modbus_command(&sim, line));
    }
    let port = port.unwrap_or_else(|| "44818".to_owned());
    let sim = match &text {
        Some(text) => Simulator::from_json(text),
        None => Simulator::new(LogixConfig::default()),
    }
    .map_err(|e| e.to_string())?;
    let server = sim
        .serve(&format!("{host}:{port}"))
        .map_err(|e| format!("cannot listen on {host}:{port}: {e}"))?;
    let _udp = match udp {
        Some(addr) => match sim.serve_udp(&addr) {
            Ok(responder) => Some(responder),
            Err(e) => {
                eprintln!("ciplink-sim: no UDP ListIdentity on {addr}: {e}");
                None
            }
        },
        None => None,
    };
    println!("listening on {}", server.addr());
    serve_stdin(exit_on_eof, |line| command(&sim, line))
}

/// Answers one JSON command per line of standard input until it closes, then exits or keeps serving.
fn serve_stdin(
    exit_on_eof: bool,
    mut command: impl FnMut(&str) -> Result<Json, String>,
) -> Result<(), String> {
    let mut out = std::io::stdout();
    let _ = out.flush();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let answer = match command(&line) {
            Ok(result) => json!({ "ok": result }),
            Err(message) => json!({ "error": message }),
        };
        let _ = writeln!(out, "{answer}");
        let _ = out.flush();
    }
    if exit_on_eof {
        return Ok(());
    }
    loop {
        std::thread::park();
    }
}

fn field<T: serde::de::DeserializeOwned>(request: &Json, name: &str) -> Result<T, String> {
    serde_json::from_value(request.get(name).cloned().unwrap_or(Json::Null))
        .map_err(|e| format!("{name}: {e}"))
}

fn logix<R>(sim: &Simulator, f: impl FnOnce(&mut ciplink_sim::Logix) -> R) -> Result<R, String> {
    sim.with_logix(f)
        .ok_or_else(|| "not a Logix controller".to_owned())
}

fn command(sim: &Simulator, line: &str) -> Result<Json, String> {
    let request: Json = serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    let cmd: String = field(&request, "cmd")?;
    let program: Option<String> = field(&request, "program").unwrap_or(None);
    let program = program.as_deref();
    match cmd.as_str() {
        "value" => sim
            .value(&field::<String>(&request, "path")?)
            .map_err(|e| e.0),
        "set" => {
            let value: Json = request.get("value").cloned().unwrap_or(Json::Null);
            sim.set_value(&field::<String>(&request, "path")?, &value)
                .map_err(|e| e.0)?;
            Ok(Json::Null)
        }
        "add_tag" => {
            let tag: TagConfig = field(&request, "tag")?;
            logix(sim, |plc| plc.add_tag(program, &tag))?
                .map(Json::from)
                .map_err(|e| e.0)
        }
        "remove_tag" => {
            let name: String = field(&request, "name")?;
            logix(sim, |plc| plc.remove_tag(program, &name))?.map_err(|e| e.0)?;
            Ok(Json::Null)
        }
        "add_type" => {
            let data_type: TypeConfig = field(&request, "type")?;
            logix(sim, |plc| plc.add_type(&data_type))?.map_err(|e| e.0)?;
            Ok(Json::Null)
        }
        "bump" => logix(sim, |plc| plc.bump_tag_table()).map(|()| Json::Null),
        "download" => {
            let config: LogixConfig = field(&request, "config")?;
            logix(sim, |plc| plc.download(&config))?.map_err(|e| e.0)?;
            Ok(Json::Null)
        }
        "tag_table_version" => {
            logix(sim, |plc| plc.tag_table_version()).map(|v| json!([v.0, v.1, v.2, v.3, v.4]))
        }
        "fault" => {
            sim.inject(fault(request.get("fault").unwrap_or(&Json::Null))?);
            Ok(Json::Null)
        }
        "clear_faults" => {
            sim.clear_faults();
            Ok(Json::Null)
        }
        "requests" => Ok(Json::from(sim.requests())),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn fault(spec: &Json) -> Result<Fault, String> {
    let status = |spec: &Json| -> Result<(u8, Option<u16>), String> {
        Ok((field(spec, "status")?, field::<Option<u16>>(spec, "ext")?))
    };
    if let Some(n) = spec.get("drop_replies") {
        return Ok(Fault::DropReplies(
            n.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("drop_replies is a count")?,
        ));
    }
    if let Some(ms) = spec.get("delay_ms") {
        return Ok(Fault::Delay(Duration::from_millis(
            ms.as_u64().ok_or("delay_ms is a count")?,
        )));
    }
    if spec.get("refuse_connections").is_some() {
        return Ok(Fault::RefuseConnections);
    }
    if spec.get("close_connections").is_some() {
        return Ok(Fault::CloseConnections);
    }
    if let Some(t) = spec.get("tag_status") {
        let (status, ext) = status(t)?;
        return Ok(Fault::TagStatus {
            tag: field(t, "tag")?,
            status,
            ext,
        });
    }
    if let Some(s) = spec.get("service_status") {
        let (status, ext) = status(s)?;
        return Ok(Fault::ServiceStatus {
            service: field(s, "service")?,
            class: field(s, "class")?,
            status,
            ext,
        });
    }
    Err(format!("unknown fault {spec}"))
}

fn modbus_command(sim: &ModbusSim, line: &str) -> Result<Json, String> {
    let request: Json = serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    let cmd: String = field(&request, "cmd")?;
    let at = || -> Result<(u8, String, u16), String> {
        Ok((
            field(&request, "unit")?,
            field(&request, "area")?,
            field(&request, "address")?,
        ))
    };
    match cmd.as_str() {
        "registers" => {
            let (unit, area, address) = at()?;
            sim.registers(unit, &area, address, field(&request, "count")?)
                .map(|v| json!(v))
                .map_err(|e| e.0)
        }
        "set_registers" => {
            let (unit, area, address) = at()?;
            let values: Vec<u16> = field(&request, "values")?;
            sim.set_registers(unit, &area, address, &values)
                .map(|()| Json::Null)
                .map_err(|e| e.0)
        }
        "bits" => {
            let (unit, area, address) = at()?;
            sim.bits(unit, &area, address, field(&request, "count")?)
                .map(|v| json!(v))
                .map_err(|e| e.0)
        }
        "set_bits" => {
            let (unit, area, address) = at()?;
            let values: Vec<bool> = field(&request, "values")?;
            sim.set_bits(unit, &area, address, &values)
                .map(|()| Json::Null)
                .map_err(|e| e.0)
        }
        "fault" => {
            sim.inject(modbus_fault(request.get("fault").unwrap_or(&Json::Null))?);
            Ok(Json::Null)
        }
        "clear_faults" => {
            sim.clear_faults();
            Ok(Json::Null)
        }
        "requests" => Ok(Json::from(sim.requests())),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn modbus_fault(spec: &Json) -> Result<ModbusFault, String> {
    if spec.get("drop_replies").is_some() {
        return Ok(ModbusFault::DropReplies(field(spec, "drop_replies")?));
    }
    if spec.get("delay_ms").is_some() {
        return Ok(ModbusFault::Delay(Duration::from_millis(field(
            spec, "delay_ms",
        )?)));
    }
    if spec.get("refuse_connections").is_some() {
        return Ok(ModbusFault::RefuseConnections);
    }
    if spec.get("close_connections").is_some() {
        return Ok(ModbusFault::CloseConnections);
    }
    if spec.get("no_reply").is_some() {
        return Ok(ModbusFault::NoReply {
            unit: field(spec, "no_reply")?,
        });
    }
    if let Some(e) = spec.get("exception") {
        return Ok(ModbusFault::Exception {
            unit: field(e, "unit")?,
            function: field(e, "function")?,
            code: field(e, "code")?,
        });
    }
    if spec.get("bad_crc").is_some() {
        return Ok(ModbusFault::BadCrc(field(spec, "bad_crc")?));
    }
    Err(format!("unknown fault {spec}"))
}
