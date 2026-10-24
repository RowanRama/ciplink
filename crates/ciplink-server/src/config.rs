//! Reads the TOML config file (the same format as the Python ciplink-tagserver).

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde_json::{Map, Value as Json};

use crate::rules::Resolver;

/// One `[plc.NAME]` table.
#[derive(Clone, Debug, Default)]
pub struct PlcConfig {
    /// The PLC's name in the config, the `<plc>` of qualified tag names.
    pub name: String,
    /// A ciplink path, e.g. `"10.0.0.5"` or `"10.0.0.5/1/3"`.
    pub path: String,
    /// Optional tag cache file for fast restarts.
    pub tag_cache_file: Option<PathBuf>,
    /// Optional mock tags file, used only with `--mock`.
    pub mock_tags: Option<PathBuf>,
    /// `[[plc.X.rule]]` tables in file order.
    pub rules: Vec<Map<String, Json>>,
    /// `[[plc.X.group]]` tables: name, rate_ms, match.
    pub groups: Vec<Map<String, Json>>,
    /// `[plc.X.udt.UDT]` tables: member -> entry.
    pub udt: Map<String, Json>,
    /// `[plc.X.tags]`: tag path -> entry.
    pub tags: Map<String, Json>,
}

/// One `[token.NAME]` table.
#[derive(Clone, Debug, Default)]
pub struct TokenConfig {
    /// The table name, written to the audit log.
    pub name: String,
    /// The secret a client sends in `hello` or as a Bearer token.
    pub secret: String,
    /// Match patterns on qualified names this token may write.
    pub write: Vec<String>,
}

/// The whole config.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address the server binds to.
    pub host: String,
    /// Port the server binds to.
    pub port: u16,
    /// Poll period per PLC.
    pub cycle_ms: u64,
    /// JSON lines of every write attempt, None for none.
    pub audit_log: Option<PathBuf>,
    /// Each tier-2 tag is read about this often.
    pub tier2_period_s: f64,
    /// A tag leaving tier 1 stays at tier 2 this long.
    pub grace_s: f64,
    /// Learned page -> tags, None to keep them in memory only.
    pub pages_file: Option<PathBuf>,
    /// Read structs whole when that saves reads.
    pub planner: bool,
    /// Largest struct the planner reads whole.
    pub whole_max_bytes: u64,
    /// A pressed momentary tag with no hold this long is released.
    pub momentary_timeout_ms: u64,
    /// The PLCs in file order.
    pub plcs: IndexMap<String, PlcConfig>,
    /// The tokens in file order.
    pub tokens: IndexMap<String, TokenConfig>,
    /// `[decorator.NAME]` tables.
    pub decorators: Map<String, Json>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: "127.0.0.1".into(),
            port: 8765,
            cycle_ms: 250,
            audit_log: Some("audit.log".into()),
            tier2_period_s: 3.0,
            grace_s: 10.0,
            pages_file: Some("pages.json".into()),
            planner: true,
            whole_max_bytes: 1500,
            momentary_timeout_ms: 1000,
            plcs: IndexMap::new(),
            tokens: IndexMap::new(),
            decorators: Map::new(),
        }
    }
}

impl Config {
    /// Splits `<plc>/<tag>` into (plc, tag); an unqualified name means the only PLC, if there is one.
    pub fn qualify<'a>(&'a self, name: &'a str) -> Result<(&'a str, &'a str), String> {
        let (plc, tag) = if let Some((plc, tag)) = name.split_once('/') {
            if !self.plcs.contains_key(plc) {
                return Err(format!("unknown PLC {}", py_repr(plc)));
            }
            (plc, tag)
        } else if self.plcs.len() == 1 {
            (self.plcs.keys().next().map_or("", String::as_str), name)
        } else {
            return Err(format!(
                "tag {} must be qualified as <plc>/<tag>",
                py_repr(name)
            ));
        };
        if tag.is_empty() {
            return Err(format!("empty tag name in {}", py_repr(name)));
        }
        Ok((plc, tag))
    }
}

/// A string as Python's `repr()` shows it in error messages: in single quotes.
pub fn py_repr(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

/// Reads and checks a config file; errors name the file.
pub fn load_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let data: Json = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    parse_config(&data, base).map_err(|e| format!("{}: {e}", path.display()))
}

/// Builds a Config from the parsed TOML; relative file paths are relative to `base_dir`.
pub fn parse_config(data: &Json, base_dir: &Path) -> Result<Config, String> {
    let resolve = |value: Option<&Json>| -> Option<PathBuf> {
        match value.and_then(Json::as_str) {
            Some(s) if !s.is_empty() => Some(base_dir.join(s)),
            _ => None,
        }
    };
    let empty = Map::new();
    let server = data
        .get("server")
        .and_then(Json::as_object)
        .unwrap_or(&empty);
    let defaults = Config::default();
    let int = |key: &str, default: u64| -> Result<u64, String> {
        match server.get(key) {
            None => Ok(default),
            Some(v) => v
                .as_u64()
                .ok_or_else(|| format!("server.{key} must be a non-negative integer")),
        }
    };
    let float = |key: &str, default: f64| -> Result<f64, String> {
        match server.get(key) {
            None => Ok(default),
            Some(v) => v
                .as_f64()
                .ok_or_else(|| format!("server.{key} must be a number")),
        }
    };
    let audit_default = Json::String("audit.log".into());
    let pages_default = Json::String("pages.json".into());
    let mut config = Config {
        host: server
            .get("host")
            .and_then(Json::as_str)
            .unwrap_or(&defaults.host)
            .to_owned(),
        port: u16::try_from(int("port", 8765)?).map_err(|_| "server.port is out of range")?,
        cycle_ms: int("cycle_ms", defaults.cycle_ms)?,
        audit_log: resolve(Some(server.get("audit_log").unwrap_or(&audit_default))),
        tier2_period_s: float("tier2_period_s", defaults.tier2_period_s)?,
        grace_s: float("grace_s", defaults.grace_s)?,
        pages_file: resolve(Some(server.get("pages_file").unwrap_or(&pages_default))),
        planner: server
            .get("planner")
            .and_then(Json::as_bool)
            .unwrap_or(true),
        whole_max_bytes: int("whole_max_bytes", defaults.whole_max_bytes)?,
        momentary_timeout_ms: int("momentary_timeout_ms", defaults.momentary_timeout_ms)?,
        decorators: object(data.get("decorator"), "decorator")?,
        ..defaults
    };
    if config.cycle_ms == 0 {
        return Err("server.cycle_ms must be > 0".into());
    }
    for (name, plc) in object(data.get("plc"), "plc")? {
        let where_ = format!("plc.{name}");
        let path = plc
            .get("path")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("{where_} needs a path"))?;
        let list = |key: &str| -> Result<Vec<Map<String, Json>>, String> {
            match plc.get(key) {
                None => Ok(Vec::new()),
                Some(Json::Array(items)) => items
                    .iter()
                    .map(|t| {
                        t.as_object()
                            .cloned()
                            .ok_or_else(|| format!("{where_}.{key} entries must be tables"))
                    })
                    .collect(),
                Some(_) => Err(format!("{where_}.{key} must be an array of tables")),
            }
        };
        let cfg = PlcConfig {
            name: name.clone(),
            path: path.to_owned(),
            tag_cache_file: resolve(plc.get("tag_cache_file")),
            mock_tags: resolve(plc.get("mock_tags")),
            rules: list("rule")?,
            groups: list("group")?,
            udt: object(plc.get("udt"), &format!("{where_}.udt"))?,
            tags: object(plc.get("tags"), &format!("{where_}.tags"))?,
        };
        // unknown decorators, bad entries
        Resolver::new(
            &config.decorators,
            &cfg.udt,
            &cfg.tags,
            Vec::new(),
            Vec::new(),
            &where_,
        )?;
        for group in &cfg.groups {
            let rate_ok = group
                .get("rate_ms")
                .is_some_and(|r| r.as_u64().is_some_and(|r| r > 0));
            if !rate_ok || !group.contains_key("name") {
                return Err(format!(
                    "{where_}.group needs a name and an integer rate_ms > 0: {}",
                    Json::Object(group.clone())
                ));
            }
        }
        config.plcs.insert(name.clone(), cfg);
    }
    for (name, token) in object(data.get("token"), "token")? {
        let secret = token
            .get("secret")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("token.{name} needs a secret"))?;
        let write = match token.get("write") {
            None => Vec::new(),
            Some(Json::Array(items)) => items
                .iter()
                .map(|p| {
                    p.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("token.{name}.write must be a list of strings"))
                })
                .collect::<Result<_, _>>()?,
            Some(Json::String(p)) => vec![p.clone()],
            Some(_) => return Err(format!("token.{name}.write must be a list of strings")),
        };
        config.tokens.insert(
            name.clone(),
            TokenConfig {
                name: name.clone(),
                secret: secret.to_owned(),
                write,
            },
        );
    }
    Ok(config)
}

fn object(value: Option<&Json>, what: &str) -> Result<Map<String, Json>, String> {
    match value {
        None => Ok(Map::new()),
        Some(Json::Object(map)) => Ok(map.clone()),
        Some(_) => Err(format!("{what} must be a table")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, String> {
        parse_config(
            &toml::from_str(text).map_err(|e| e.to_string())?,
            Path::new("base"),
        )
    }

    #[test]
    fn defaults_and_relative_paths() {
        let config = parse("[plc.P]\npath = \"1.2.3.4\"\nmock_tags = \"m.json\"\n").unwrap();
        assert_eq!(config.port, 8765);
        assert_eq!(config.cycle_ms, 250);
        assert_eq!(config.audit_log, Some(Path::new("base").join("audit.log")));
        assert_eq!(
            config.pages_file,
            Some(Path::new("base").join("pages.json"))
        );
        assert_eq!(
            config.plcs["P"].mock_tags,
            Some(Path::new("base").join("m.json"))
        );
        assert_eq!(config.plcs["P"].tag_cache_file, None);
    }

    #[test]
    fn empty_paths_turn_files_off() {
        let config = parse("[server]\naudit_log = \"\"\npages_file = \"\"\n").unwrap();
        assert_eq!(config.audit_log, None);
        assert_eq!(config.pages_file, None);
    }

    #[test]
    fn qualify_names() {
        let config = parse("[plc.P]\npath = \"x\"\n").unwrap();
        assert_eq!(config.qualify("Tag").unwrap(), ("P", "Tag"));
        assert_eq!(config.qualify("P/Tag").unwrap(), ("P", "Tag"));
        assert_eq!(config.qualify("Q/Tag").unwrap_err(), "unknown PLC 'Q'");
        assert_eq!(config.qualify("P/").unwrap_err(), "empty tag name in 'P/'");
        let two = parse("[plc.P]\npath = \"x\"\n[plc.Q]\npath = \"y\"\n").unwrap();
        assert_eq!(
            two.qualify("Tag").unwrap_err(),
            "tag 'Tag' must be qualified as <plc>/<tag>"
        );
    }

    #[test]
    fn bad_groups_and_decorators_are_errors() {
        let bad_group =
            "[plc.P]\npath = \"x\"\n[[plc.P.group]]\nname = \"g\"\nrate_ms = 0\nmatch = \"A\"\n";
        assert!(parse(bad_group).unwrap_err().contains("rate_ms > 0"));
        let unknown = "[plc.P]\npath = \"x\"\n[plc.P.tags]\nA = \"nope\"\n";
        assert_eq!(
            parse(unknown).unwrap_err(),
            "plc.P.tags.A: unknown decorator 'nope'"
        );
    }

    #[test]
    fn tokens() {
        let config =
            parse("[token.hmi]\nsecret = \"s\"\nwrite = [\"P/A*\"]\n[token.v]\nsecret = \"t\"\n")
                .unwrap();
        assert_eq!(config.tokens["hmi"].write, vec!["P/A*"]);
        assert!(config.tokens["v"].write.is_empty());
    }

    // ---- ports of ciplink-tagserver's tests/test_config_values.py

    #[test]
    fn load_config_file() {
        let dir = crate::testing::TempDir::new();
        let path = dir.path().join("tagserver.toml");
        std::fs::write(
            &path,
            r#"
[server]
host = "0.0.0.0"
port = 9000
cycle_ms = 100

[plc.PLC1]
path = "10.0.0.1"
tag_cache_file = "cache/PLC1.json"

[plc.Other]
path = "10.0.0.2/1/3"

[[plc.PLC1.rule]]
match = "Bench.SpeedSP"
writable = true
max = 1800

[[plc.PLC1.rule]]
match = ["Bench.Speed", "Bench.Rpm"]
deadband = 0.5

[[plc.PLC1.group]]
name = "fast"
rate_ms = 50
match = ["Bench.Axis.*"]

[token.hmi1]
secret = "change-me"
write = ["PLC1/Line1.*.SpeedSP"]

[token.viewer]
secret = "v"
"#,
        )
        .unwrap();
        let config = load_config(&path).unwrap();
        assert_eq!(
            (config.host.as_str(), config.port, config.cycle_ms),
            ("0.0.0.0", 9000, 100)
        );
        assert_eq!(config.audit_log, Some(dir.path().join("audit.log")));
        assert_eq!(config.plcs["PLC1"].path, "10.0.0.1");
        assert_eq!(
            config.plcs["PLC1"].tag_cache_file,
            Some(dir.path().join("cache/PLC1.json"))
        );
        assert_eq!(config.plcs["Other"].tag_cache_file, None);
        assert_eq!(config.tokens["hmi1"].write, ["PLC1/Line1.*.SpeedSP"]);
        assert!(config.tokens["viewer"].write.is_empty());
        let rows = |tables: &[Map<String, Json>]| -> Vec<Json> {
            tables.iter().cloned().map(Json::Object).collect()
        };
        assert_eq!(
            rows(&config.plcs["PLC1"].rules),
            [
                serde_json::json!({"match": "Bench.SpeedSP", "writable": true, "max": 1800}),
                serde_json::json!({"match": ["Bench.Speed", "Bench.Rpm"], "deadband": 0.5}),
            ]
        );
        assert_eq!(
            rows(&config.plcs["PLC1"].groups),
            [serde_json::json!({"name": "fast", "rate_ms": 50, "match": ["Bench.Axis.*"]})]
        );
        assert!(config.plcs["Other"].rules.is_empty() && config.plcs["Other"].groups.is_empty());
        assert_eq!(config.momentary_timeout_ms, 1000);
    }

    #[test]
    fn bad_group() {
        for group in [
            serde_json::json!({"name": "g", "rate_ms": 0}),
            serde_json::json!({"name": "g", "rate_ms": 1.5}),
            serde_json::json!({"rate_ms": 10}),
        ] {
            let data = serde_json::json!({"plc": {"A": {"path": "x", "group": [group]}}});
            assert!(
                parse_config(&data, Path::new("."))
                    .unwrap_err()
                    .contains("rate_ms")
            );
        }
    }

    #[test]
    fn defaults() {
        let config = parse_config(
            &serde_json::json!({"plc": {"A": {"path": "1.2.3.4"}}}),
            Path::new("."),
        )
        .unwrap();
        assert_eq!(
            (config.host.as_str(), config.port, config.cycle_ms),
            ("127.0.0.1", 8765, 250)
        );
        assert!(config.tokens.is_empty());
        let config = parse_config(
            &serde_json::json!({"server": {"momentary_timeout_ms": 300}}),
            Path::new("."),
        )
        .unwrap();
        assert_eq!(config.momentary_timeout_ms, 300);
    }

    #[test]
    fn qualify_one_plc() {
        let config = parse("[plc.A]\npath = \"x\"\n").unwrap();
        assert_eq!(config.qualify("Speed").unwrap(), ("A", "Speed"));
        assert_eq!(
            config.qualify("A/Program:Main.Speed").unwrap(),
            ("A", "Program:Main.Speed")
        );
        assert!(config.qualify("B/Speed").is_err());
    }

    #[test]
    fn qualify_several_plcs() {
        let config = parse("[plc.A]\npath = \"x\"\n[plc.B]\npath = \"y\"\n").unwrap();
        assert_eq!(config.qualify("B/Speed").unwrap(), ("B", "Speed"));
        assert!(config.qualify("Speed").unwrap_err().contains("qualified"));
        assert!(config.qualify("A/").is_err());
    }
}
