#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ciplink_sim::{Framing, ModbusServer, ModbusSim};
use serde_json::json;

use super::*;
use crate::config::{load_config, parse_config};
use crate::server::ServerHandle;
use crate::testing::{TempDir, Ws, vq};

fn repo_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sim")
        .join(name)
}

fn parse(text: &str) -> Result<crate::config::Config, String> {
    parse_config(
        &toml::from_str(text).map_err(|e| e.to_string())?,
        Path::new("base"),
    )
}

fn sim() -> (ModbusSim, ModbusServer) {
    let text = std::fs::read_to_string(repo_file("example_modbus.json")).unwrap();
    let sim = ModbusSim::from_json(&text).unwrap();
    let server = sim.serve("127.0.0.1:0", Framing::Mbap).unwrap();
    (sim, server)
}

fn cfg(path: &str, modbus: Json) -> PlcConfig {
    PlcConfig {
        name: "Skid".into(),
        path: path.into(),
        protocol: "modbus".into(),
        map_file: Some(repo_file("example_modbus_map.csv")),
        modbus: modbus.as_object().cloned().unwrap_or_default(),
        ..PlcConfig::default()
    }
}

#[test]
fn config_protocol_map_file_and_options() {
    let config = parse(
        "[plc.Skid]\nprotocol = \"modbus\"\npath = \"tcp://10.0.0.9?unit=1\"\nmap_file = \"maps/skid.csv\"\n\
         [plc.Skid.modbus]\nmax_gap = 0\nword_order = \"CDAB\"\nsocket_timeout = 2.0\n\
         [plc.Line]\npath = \"10.0.0.5\"\n",
    )
    .unwrap();
    let skid = &config.plcs["Skid"];
    assert_eq!(skid.protocol, "modbus");
    assert_eq!(skid.map_file, Some(Path::new("base").join("maps/skid.csv")));
    let parsed = options(&skid.modbus).unwrap();
    assert_eq!(parsed.max_gap, 0);
    assert_eq!(parsed.word_order, WordOrder::Cdab);
    assert_eq!(parsed.socket_timeout, Duration::from_secs(2));
    assert_eq!(config.plcs["Line"].protocol, "logix");
    assert!(options(json!({"max_gapp": 1}).as_object().unwrap()).is_err());
    assert!(options(json!({"word_order": "XYZW"}).as_object().unwrap()).is_err());
}

#[test]
fn modbus_without_map_file_is_an_error() {
    let err = parse("[plc.Skid]\nprotocol = \"modbus\"\npath = \"tcp://10.0.0.9\"\n").unwrap_err();
    assert!(err.contains("map_file"), "{err}");
}

#[test]
fn unknown_protocol_is_an_error() {
    let err = parse("[plc.Skid]\nprotocol = \"s5\"\npath = \"x\"\n").unwrap_err();
    assert!(err.contains("protocol"), "{err}");
}

#[test]
fn bad_map_file_or_path_fails_the_driver() {
    let mut bad = cfg("tcp://127.0.0.1", json!({}));
    bad.map_file = Some(repo_file("no_such_map.csv"));
    assert!(ModbusPlc::new(&bad).is_err());
    assert!(ModbusPlc::new(&cfg("10.0.0.5", json!({}))).is_err()); // no scheme
}

#[test]
fn catalog_from_the_map() {
    let mut plc = ModbusPlc::new(&cfg("tcp://127.0.0.1:1", json!({}))).unwrap();
    let catalog = plc.catalog();
    assert_eq!(
        catalog.tag_list(),
        vec![
            json!({"name": "Pump1_Speed", "type": "REAL"}),
            json!({"name": "Pump1_Run", "type": "BOOL"}),
            json!({"name": "Pump1_Fault", "type": "BOOL"}),
            json!({"name": "Tank_Level", "type": "LREAL"}),
            json!({"name": "Tank_Temp", "type": "LREAL"}),
            json!({"name": "Totals", "type": "UDINT", "dims": [4]}),
            json!({"name": "Recipe", "type": "STRING"}),
            json!({"name": "Drive_Status", "type": "UINT"}),
            json!({"name": "Horn", "type": "BOOL"}),
            json!({"name": "Valve2_Open", "type": "BOOL"}),
        ]
    );
    let recipe = catalog.tag("recipe").unwrap();
    assert_eq!(
        (recipe.kind, recipe.structure_size),
        (Kind::String, Some(16))
    );
    assert!(catalog.types.is_empty());
    assert_eq!(plc.version(), Json::Null);
}

#[test]
fn descriptions_from_the_map() {
    let mut plc = ModbusPlc::new(&cfg("tcp://127.0.0.1:1", json!({}))).unwrap();
    assert!(plc.describes());
    assert_eq!(
        plc.descriptions(&["Pump1_Fault", "Totals[2]", "Drive_Status.5", "hr0", "Nope"])
            .unwrap(),
        vec![
            Some("Pump 1 fault, any cause".to_owned()),
            Some("Daily totals of the last 4 days".to_owned()),
            None, // bits get no description (the worker never asks)
            None,
            None,
        ]
    );
}

#[test]
fn runs_of_elements_read_as_one_array() {
    let (_sim, server) = sim();
    let path = format!("tcp://127.0.0.1:{}", server.port());
    let mut plc = ModbusPlc::new(&cfg(&path, json!({"keep_alive": 0}))).unwrap();
    plc.open().unwrap();
    let results = plc
        .read(&["Totals[1]{3}", "Tank_Level", "Totals{2}", "Nope[0]{2}"])
        .unwrap();
    assert_eq!(results[0].tag, "Totals[1]{3}");
    assert_eq!(
        results[0].value,
        Some(Value::Array(vec![
            Value::UDInt(135),
            Value::UDInt(99),
            Value::UDInt(140)
        ]))
    );
    assert_eq!(results[0].data_type.as_deref(), Some("UDINT"));
    assert_eq!(results[1].value, Some(Value::LReal(52.300000000000004)));
    assert_eq!(
        results[2].value,
        Some(Value::Array(vec![Value::UDInt(120), Value::UDInt(135)]))
    );
    assert!(results[3].error.is_some() && results[3].value.is_none());
    plc.close();
}

async fn wait_for(mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "condition not met");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_and_writes_through_the_hub() {
    let (sim, server) = sim();
    let dir = TempDir::new();
    let text = format!(
        "[server]\nport = 0\ncycle_ms = 20\ngrace_s = 0\naudit_log = \"audit.log\"\n\
         [plc.Skid]\nprotocol = \"modbus\"\npath = \"tcp://127.0.0.1:{}\"\nmap_file = '{}'\n\
         [plc.Skid.modbus]\nmax_gap = 4\n\
         [[plc.Skid.rule]]\nmatch = \"*\"\nwritable = true\n\
         [token.hmi]\nsecret = \"s3cret\"\nwrite = [\"Skid/*\"]\n",
        server.port(),
        repo_file("example_modbus_map.csv").display()
    );
    let path = dir.path().join("tagserver.toml");
    std::fs::write(&path, text).unwrap();
    let config = load_config(&path).unwrap();
    let handle = ServerHandle::start(config, crate::factory(false)).unwrap();
    let mut ws = Ws::connect(handle.addr()).await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Tank_Level", "Totals", "Horn", "Recipe"]}))
        .await;
    // the values and the info with the map's description, in either order
    let (mut value, mut description) = (Json::Null, Json::Null);
    while value.is_null() || description.is_null() {
        let m = ws.recv().await.unwrap();
        if m["op"] == "values" && m["d"]["Tank_Level"].is_array() {
            value = vq(&m["d"]["Tank_Level"]);
        }
        if m["op"] == "info" && m["d"]["Tank_Level"]["description"].is_string() {
            description = m["d"]["Tank_Level"]["description"].clone();
        }
    }
    assert!((value[0].as_f64().unwrap() - 52.3).abs() < 1e-9, "{value}"); // 523 * 0.1
    assert_eq!(value[1], "good");
    assert_eq!(description, "Tank level (0.1 % per count)");
    // a bit of a holding register goes out as FC22
    sim.record(true);
    let ack = ws.write(2, "Horn", json!(true)).await;
    assert_eq!(ack["ok"], true, "{ack}");
    assert_eq!(sim.registers(1, "holding", 301, 1).unwrap(), vec![1 << 4]);
    assert!(
        sim.take_received()
            .iter()
            .any(|adu| adu.get(7) == Some(&22))
    );
    let ack = ws.write(3, "Drive_Status", json!(3)).await;
    assert_eq!(ack["kind"], "access", "{ack}"); // read-only in the map: the driver refuses it
    sim.set_registers(1, "input", 10, &[600]).unwrap();
    wait_for(|| {
        handle.shared().workers["Skid"]
            .snapshot("Tank_Level")
            .is_some_and(|e| {
                vq(&e.to_json())[0]
                    .as_f64()
                    .is_some_and(|v| (v - 60.0).abs() < 1e-9)
            })
    })
    .await;
    ws.close().await;
    handle.stop().unwrap();
}
