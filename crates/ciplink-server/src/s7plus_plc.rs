//! A Siemens S7-1500 / S7-1200 through ciplink's [`S7PlusDriver`] (config `protocol = "s7plus"`).

use ciplink::Value;
use ciplink::cip::TagResult;
use ciplink::s7plus::{S7Kind, S7PlusDriver, S7PlusOptions, S7Tag};
use ciplink::session::SessionOptions;
use indexmap::IndexMap;
use serde_json::{Value as Json, json};

use crate::config::PlcConfig;
use crate::plc::{Catalog, Kind, Node, Plc, TypeDef};

/// A real S7 CPU over S7comm-plus with TLS. Tag comments are not read (`describes()` is false).
pub struct S7PlusPlc {
    driver: S7PlusDriver,
}

impl S7PlusPlc {
    /// The driver of a configured PLC, not yet opened.
    pub fn new(cfg: &PlcConfig) -> Result<Self, String> {
        let options = S7PlusOptions {
            tls_fingerprint: cfg.tls_fingerprint.clone(),
            ..S7PlusOptions::default()
        };
        // the worker reconnects, as for Logix; keep-alive stays on so a link lost while idle is found
        let session = SessionOptions {
            reconnect: false,
            ..S7PlusOptions::default_session()
        };
        let driver =
            S7PlusDriver::with_session(&cfg.path, options, session).map_err(|e| e.to_string())?;
        Ok(S7PlusPlc { driver })
    }
}

fn node_of(tag: &S7Tag, member: bool) -> Node {
    let kind = match tag.kind {
        S7Kind::String => Kind::String,
        S7Kind::Struct | S7Kind::DataBlock | S7Kind::Area => Kind::Struct,
        S7Kind::Elementary => Kind::Atomic,
    };
    Node {
        type_name: tag.type_name.clone(),
        kind,
        dims: tag.dims.iter().map(|&d| u64::from(d)).collect(),
        member,
        instance_id: None,
        structure_size: None,
    }
}

impl Plc for S7PlusPlc {
    fn open(&mut self) -> Result<(), String> {
        match self.driver.open() {
            Ok(true) => Ok(()),
            Ok(false) => Err("the PLC refused the connection".to_owned()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn close(&mut self) {
        let _ = self.driver.close();
    }

    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String> {
        self.driver.read(tags).map_err(|e| e.to_string())
    }

    fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String> {
        let mut results = self
            .driver
            .write(&[(tag, value.clone())])
            .map_err(|e| e.to_string())?;
        results.pop().ok_or_else(|| "no write result".to_owned())
    }

    fn catalog(&mut self) -> Catalog {
        let tags = self
            .driver
            .tags()
            .iter()
            .map(|(name, t)| (name.clone(), node_of(t, false)))
            .collect();
        let types: IndexMap<String, TypeDef> = self
            .driver
            .data_types()
            .into_iter()
            .map(|(name, t)| {
                let members: IndexMap<String, Node> = t
                    .members
                    .iter()
                    .map(|(m, tag)| (m.clone(), node_of(tag, true)))
                    .collect();
                let public = members.keys().cloned().collect();
                let def = TypeDef {
                    members,
                    public,
                    ..TypeDef::default()
                };
                (name, def)
            })
            .collect();
        Catalog::new(self.version(), tags, types)
    }

    fn version(&mut self) -> Json {
        json!(self.driver.tags_version())
    }

    fn connection_size(&self) -> usize {
        0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ciplink_sim::s7plus::{S7PlusFault, S7PlusSimulator};

    /// Invented names only.
    const CONFIG: &str = r#"{"s7plus": {
      "name": "PLC_Line1",
      "types": {"Recipe": {"members": {"Speed": "REAL", "Name": "STRING[10]"}}},
      "dbs": [{"name": "Line1", "number": 5, "members": {
        "Speed": {"type": "REAL", "value": 1.5},
        "Items": "ARRAY[1..10] OF INT",
        "Recipe": "Recipe"}}],
      "areas": {"M": {"Mode": {"type": "INT", "value": 3}}}
    }}"#;

    fn cfg(path: String, pin: Option<String>) -> PlcConfig {
        PlcConfig {
            name: "S7".into(),
            path,
            protocol: "s7plus".into(),
            tls_fingerprint: pin,
            ..PlcConfig::default()
        }
    }

    #[test]
    fn serves_catalog_reads_and_writes_from_the_simulator() {
        let sim = S7PlusSimulator::from_json(CONFIG).unwrap();
        let server = sim.serve("127.0.0.1:0").unwrap();
        let cfg = cfg(format!("127.0.0.1:{}", server.port()), None);
        let mut plc = crate::factory(false)(&cfg).unwrap();
        plc.open().unwrap();
        assert!(!plc.describes());
        assert_eq!(plc.connection_size(), 0);

        let catalog = plc.catalog();
        let names: Vec<&String> = catalog.tags.keys().collect();
        assert_eq!(names, ["Line1", "Mode"]);
        assert_eq!(catalog.info("Mode").unwrap().type_name, "INT");
        assert_eq!(catalog.info("Line1.Speed").unwrap().kind, Kind::Atomic);
        assert_eq!(catalog.info("Line1.Items[3]").unwrap().dims, vec![10]);
        assert_eq!(catalog.info("Line1.Recipe").unwrap().kind, Kind::Struct);
        assert_eq!(
            catalog.info("Line1.Recipe.Name").unwrap().kind,
            Kind::String
        );
        assert_eq!(
            catalog.tag_list()[1],
            json!({"name": "Mode", "type": "INT"})
        );

        let r = plc.read(&["Line1.Speed", "Mode", "Line1.Nope"]).unwrap();
        assert_eq!(r[0].value, Some(Value::Real(1.5)));
        assert_eq!(r[1].value, Some(Value::Int(3)));
        assert!(r[2].error.is_some());
        let w = plc.write("Mode", &Value::LInt(-7)).unwrap();
        assert!(w.error.is_none(), "{:?}", w.error);
        assert_eq!(sim.value("Mode").unwrap(), json!(-7));

        // a dropped link is an Err for the worker, and the version survives a reconnect to the same program
        let version = plc.version();
        sim.inject(S7PlusFault::CloseConnections);
        sim.clear_faults();
        let mut lost = false;
        for _ in 0..100 {
            if plc.read(&["Mode"]).is_err() {
                lost = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(lost);
        plc.close();
        plc.open().unwrap();
        assert_eq!(plc.version(), version);
        assert_eq!(plc.read(&["Mode"]).unwrap()[0].value, Some(Value::Int(-7)));
        plc.close();
    }

    #[test]
    fn a_wrong_pin_fails_open() {
        let sim = S7PlusSimulator::from_json(CONFIG).unwrap();
        let server = sim.serve("127.0.0.1:0").unwrap();
        let cfg = cfg(
            format!("127.0.0.1:{}", server.port()),
            Some("00".repeat(32)),
        );
        let mut plc = S7PlusPlc::new(&cfg).unwrap();
        assert!(plc.open().unwrap_err().contains("does not match"));
    }
}
