//! The `types` subcommand: a TypeScript module typing the tags of a running server (`GET /tags`), as a typed tag
//! tree (`tagTree<PLC1Tags>`) or the 0.2 union of tag names.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value as Json};

use crate::rules::{Resolver, truthy};

/// Plain integers, typed `IntRef` (a number with `.bit(n)`). Unlike ciplink-tagserver, BYTE, WORD and LWORD are
/// not here: ciplink reads every bit string as a list of bools, so they are typed like DWORD (see `BIT_STRINGS`).
const INTS: [&str; 8] = [
    "SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT",
];
/// Bit strings: values are lists of bools (least significant first) and `X.n` is a bit.
const BIT_STRINGS: [&str; 4] = ["BYTE", "WORD", "DWORD", "LWORD"];
/// Names the tree proxy answers itself (amendment 31).
const RESERVED: [&str; 5] = ["bit", "length", "then", "toString", "toJSON"];

/// GET `<url>/tags[?plc=NAME]` with a Bearer token; the whole body (plc, version, tags, types, rules, groups,
/// decorators, udt, tag_settings). `http://` only; a non-200 status is an error with the status line and body.
pub fn fetch_tags(url: &str, token: &str, plc: Option<&str>) -> Result<Json, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url}: only http:// URLs are supported"))?;
    let (authority, base) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if authority.is_empty() {
        return Err(format!("{url}: no host"));
    }
    let has_port = !authority.ends_with(']')
        && authority
            .rsplit_once(':')
            .is_some_and(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let addr = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let query = match plc {
        Some(plc) => format!("/tags?plc={}", quote(plc)),
        None => "/tags".to_owned(),
    };
    let path = format!("{}{query}", base.trim_end_matches('/'));
    let err = |e: std::io::Error| format!("{url}: {e}");
    let mut stream = TcpStream::connect(&addr).map_err(err)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(err)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\
         Accept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).map_err(err)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(err)?;
    let (status, body) = parse_response(&raw).map_err(|e| format!("{url}: {e}"))?;
    let code = status.split_whitespace().nth(1);
    if code != Some("200") {
        return Err(format!(
            "{url}{path}: {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    serde_json::from_slice(&body).map_err(|e| format!("{url}{path}: {e}"))
}

/// Percent-encodes like Python's `urllib.parse.quote` (unreserved characters and `/` kept).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~/".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// (status line, body) of a whole HTTP/1.1 response: Content-Length, chunked, or up to the end.
fn parse_response(raw: &[u8]) -> Result<(String, Vec<u8>), String> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let rest = &raw[end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default().to_owned();
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| format!("bad Content-Length {value}"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(n) = length {
        rest.get(..n)
            .ok_or("HTTP body shorter than its Content-Length")?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok((status, body))
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let eol = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated chunked body")?;
        let line = String::from_utf8_lossy(&data[..eol]);
        let size = line.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size, 16).map_err(|_| format!("bad chunk size {size:?}"))?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(body); // trailers ignored
        }
        body.extend_from_slice(data.get(..size).ok_or("truncated chunk")?);
        data = data.get(size + 2..).ok_or("truncated chunk")?;
    }
}

/// Readable names: each tag, but for an AOI its readable members (Inst.Member) instead of the instance.
pub fn tag_names(tags: &[Json]) -> Vec<String> {
    let mut names = Vec::new();
    for tag in tags {
        let name = py_str(tag.get("name").unwrap_or(&Json::Null));
        match tag.get("aoi_readable") {
            Some(members) => {
                let members = members.as_array().map(Vec::as_slice).unwrap_or_default();
                names.extend(members.iter().map(|m| format!("{name}.{}", py_str(m))));
            }
            None => names.push(name),
        }
    }
    names
}

/// The 0.2 `--format names` module: `export type TagName = "..." | ...;`. `plcs` are as passed on the command line
/// (one body each); names are qualified as `PLC/tag` when there is more than one.
pub fn names_module(bodies: &[Json], plcs: &[Option<String>]) -> String {
    let mut names: Vec<String> = Vec::new();
    for (plc, body) in plcs.iter().zip(bodies) {
        let prefix = if plcs.len() > 1 {
            format!("{}/", plc.as_deref().unwrap_or("None"))
        } else {
            String::new()
        };
        let tags = body
            .get("tags")
            .and_then(Json::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for name in tag_names(tags) {
            let name = format!("{prefix}{name}");
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    let lines: String = names
        .iter()
        .map(|n| format!("\n  | {}", py_json_str(n)))
        .collect();
    let lines = if lines.is_empty() {
        " never".to_owned()
    } else {
        lines
    };
    format!("// Generated by ciplink-server types. Do not edit.\nexport type TagName ={lines};\n")
}

/// The generated module: UDT interfaces, a tags interface and a tagTree const per PLC; `qualified` passes each
/// PLC name to its tagTree (several PLCs).
pub fn tree_module(bodies: &[Json], qualified: bool) -> Result<String, String> {
    let mut parts = Vec::new();
    let mut consts = String::new();
    for body in bodies {
        let mut tree = TreeGen::new(body)?;
        parts.extend(tree.interfaces());
        parts.push(tree.tags());
        let plc = if qualified {
            py_json_str(&tree.plc)
        } else {
            "null".to_owned()
        };
        let prefix = &tree.prefix;
        consts.push_str(&format!(
            "export const {prefix} = tagTree<{prefix}Tags>({plc}, {});\n",
            tree.meta()
        ));
    }
    let code = format!("{}\n{consts}", parts.join("\n"));
    let mut imports = vec!["tagTree".to_owned()];
    for t in ["TagRef", "IntRef", "TagArray"] {
        let re = Regex::new(&format!(r"\b{t}<")).map_err(|e| e.to_string())?;
        if re.is_match(&code) {
            imports.push(format!("type {t}"));
        }
    }
    let versions: Vec<String> = bodies
        .iter()
        .map(|b| {
            let plc = py_str(b.get("plc").unwrap_or(&Json::Null));
            let version = py_str(b.get("version").unwrap_or(&Json::Null));
            format!("{plc} tag table version {version}")
        })
        .collect();
    Ok(format!(
        "// Generated by ciplink-server types ({}). Do not edit.\nimport {{ {} }} from \"@ciplink/react\";\n\n{code}",
        versions.join(", "),
        imports.join(", ")
    ))
}

/// A TS identifier (`^[A-Za-z_$][A-Za-z0-9_$]*$`).
fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// A TS identifier from a PLC or UDT name: other characters become `_`.
fn ident(name: &str) -> String {
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if is_ident(&name) {
        name
    } else {
        format!("_{name}")
    }
}

/// A TS object type; on one line when `indent` is None.
fn obj(fields: &[(String, String)], indent: Option<usize>) -> String {
    let key = |k: &str| {
        if is_ident(k) {
            k.to_owned()
        } else {
            py_json_str(k)
        }
    };
    match indent {
        None if fields.is_empty() => "{}".to_owned(),
        None => {
            let inner: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("{}: {v};", key(k)))
                .collect();
            format!("{{ {} }}", inner.join(" "))
        }
        Some(indent) => {
            let pad = " ".repeat(indent + 2);
            let inner: String = fields
                .iter()
                .map(|(k, v)| format!("{pad}{}: {v};\n", key(k)))
                .collect();
            format!("{{\n{inner}{}}}", " ".repeat(indent))
        }
    }
}

fn ts_bool(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

/// A value as Python's `str()` formats it in an f-string (strings bare, null as None).
fn py_str(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        Json::Null => "None".to_owned(),
        Json::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        other => py_json(other),
    }
}

/// A string as Python's `json.dumps` writes it (`ensure_ascii`: non-ASCII as `\uXXXX`).
fn py_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

/// A value as Python's `json.dumps` writes it (`", "` and `": "` separators, ASCII only).
fn py_json(value: &Json) -> String {
    match value {
        Json::String(s) => py_json_str(s),
        Json::Array(items) => {
            let items: Vec<String> = items.iter().map(py_json).collect();
            format!("[{}]", items.join(", "))
        }
        Json::Object(map) => {
            let items: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", py_json_str(k), py_json(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        other => other.to_string(),
    }
}

/// Tags under a dotted prefix (`Program:X`), or a tag.
enum Item<'a> {
    Scope(IndexMap<String, Item<'a>>),
    Tag(&'a Json),
}

/// TS types for one PLC's /tags body. Paths go two ways: `path` with each index as `[0]` (what settings are
/// resolved for, amendment 36; None inside a shared interface) and `meta` with each index group as `[]`.
struct TreeGen<'a> {
    body: &'a Json,
    types: Map<String, Json>,
    resolver: Resolver,
    plc: String,
    prefix: String,
    dims: Map<String, Json>,
    bits: Map<String, Json>,
}

fn str_of<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).unwrap_or_default()
}

/// Python's `x.get("dims")` used as a truthy list.
fn dims_of(value: &Json) -> &[Json] {
    value
        .get("dims")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn members_of(udt: &Json) -> impl Iterator<Item = (&String, &Json)> {
    udt.get("members")
        .and_then(Json::as_object)
        .into_iter()
        .flatten()
}

impl<'a> TreeGen<'a> {
    fn new(body: &'a Json) -> Result<Self, String> {
        let plc = body
            .get("plc")
            .and_then(Json::as_str)
            .ok_or("a /tags body without its plc")?
            .to_owned();
        Ok(TreeGen {
            body,
            types: body
                .get("types")
                .and_then(Json::as_object)
                .cloned()
                .unwrap_or_default(),
            resolver: Resolver::from_body(body)?, // the server's resolution: decorators, then rules
            prefix: ident(&plc),
            plc,
            dims: Map::new(),
            bits: Map::new(),
        })
    }

    /// The path's effective setting of the field (a JSON null counts as unset).
    fn rule(&self, path: Option<&str>, field: &str) -> Option<Json> {
        self.resolver
            .effective(path?)
            .remove(field)
            .filter(|v| !v.is_null())
    }

    fn writable(&self, path: Option<&str>) -> bool {
        truthy(self.rule(path, "writable").as_ref())
    }

    /// (TS type, path specific) of an atomic, STRING or unknown leaf.
    fn leaf(&mut self, type_: &str, path: Option<&str>, meta: Option<&str>) -> (String, bool) {
        let w = self.writable(path);
        let text = if INTS.contains(&type_) {
            format!("IntRef<{}>", ts_bool(w))
        } else if BIT_STRINGS.contains(&type_) {
            format!(
                "TagRef<boolean[], {0}> & {{ bit(n: number): TagRef<boolean, {0}> }}",
                ts_bool(w)
            )
        } else {
            let value = match type_ {
                "BOOL" => "boolean",
                "STRING" => "string",
                "REAL" | "LREAL" => "number",
                _ => "unknown",
            };
            return (format!("TagRef<{value}, {}>", ts_bool(w)), w);
        };
        let bits = match self.rule(path, "bits") {
            Some(Json::Object(bits)) if !bits.is_empty() => bits,
            _ => return (text, w),
        };
        if let Some(meta) = meta {
            self.bits
                .insert(meta.to_owned(), Json::Object(bits.clone()));
        }
        let mut aliases = Vec::with_capacity(bits.len());
        for (name, n) in &bits {
            // a bit's own settings first, else its word's writable
            let bit = path.map(|p| format!("{p}.{}", py_str(n)));
            let bw = self
                .rule(bit.as_deref(), "writable")
                .map_or(w, |v| truthy(Some(&v)));
            aliases.push((name.clone(), format!("TagRef<boolean, {}>", ts_bool(bw))));
        }
        (format!("{text} & {}", obj(&aliases, None)), true)
    }

    /// (TS type, path specific) of a tag or member. Path specific (a writable path or bit names somewhere below)
    /// means it is typed inline; otherwise a UDT uses its shared interface.
    fn node(
        &mut self,
        type_: &str,
        dims: &[Json],
        path: Option<&str>,
        meta: Option<&str>,
        indent: usize,
    ) -> (String, bool) {
        if let Some((first, rest)) = dims.split_first() {
            if let Some(meta) = meta {
                self.dims
                    .insert(meta.to_owned(), Json::Array(dims.to_vec()));
            }
            let zeros = vec!["0"; dims.len()].join(",");
            let sub = path.map(|p| format!("{p}[{zeros}]"));
            let sub_meta = meta.map(|m| format!("{m}[]"));
            let (mut inner, special) =
                self.node(type_, &[], sub.as_deref(), sub_meta.as_deref(), indent);
            for n in rest.iter().rev() {
                inner = format!("TagArray<{inner}, {}>", py_str(n));
            }
            // not a ref: a bare array name reads and writes its first element only (ciplink and the mock)
            return (format!("TagArray<{inner}, {}>", py_str(first)), special);
        }
        let Some(udt) = self.types.get(type_).cloned() else {
            return self.leaf(type_, path, meta);
        };
        let mut fields = Vec::new();
        let mut special = false;
        for (name, member) in members_of(&udt) {
            if RESERVED.contains(&name.as_str()) {
                continue;
            }
            let sub = path.map(|p| format!("{p}.{name}"));
            let sub_meta = meta.map(|m| format!("{m}.{name}"));
            let (text, s) = self.node(
                str_of(member, "type"),
                dims_of(member),
                sub.as_deref(),
                sub_meta.as_deref(),
                indent + 2,
            );
            fields.push((name.clone(), text));
            special |= s;
        }
        let w = self.writable(path);
        if !(special || w) {
            return (format!("{}_{}", self.prefix, ident(type_)), false);
        }
        // an AOI is never read whole
        let head = if truthy(udt.get("aoi")) {
            String::new()
        } else {
            format!("TagRef<Record<string, unknown>, {}> & ", ts_bool(w))
        };
        (head + &obj(&fields, Some(indent)), true)
    }

    fn interfaces(&mut self) -> Vec<String> {
        let types = self.types.clone();
        let mut out = Vec::with_capacity(types.len());
        for (name, udt) in &types {
            let mut fields = Vec::new();
            for (m, info) in members_of(udt) {
                if !RESERVED.contains(&m.as_str()) {
                    let text = self
                        .node(str_of(info, "type"), dims_of(info), None, None, 0)
                        .0;
                    fields.push((m.clone(), text));
                }
            }
            let base = if truthy(udt.get("aoi")) {
                ""
            } else {
                " extends TagRef<Record<string, unknown>, false>"
            };
            out.push(format!(
                "export interface {}_{}{base} {}\n",
                self.prefix,
                ident(name),
                obj(&fields, Some(0))
            ));
        }
        out
    }

    /// The `<PLC>Tags` interface; a dotted tag name (`Program:X.Tag`) nests under its prefix.
    fn tags(&mut self) -> String {
        let mut root: IndexMap<String, Item> = IndexMap::new();
        let tags = self
            .body
            .get("tags")
            .and_then(Json::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        'tags: for tag in tags {
            let name = str_of(tag, "name");
            let mut scopes: Vec<&str> = name.split('.').collect();
            let last = scopes.pop().unwrap_or_default(); // split yields at least one part
            let mut level = &mut root;
            for scope in scopes {
                match level
                    .entry(scope.to_owned())
                    .or_insert_with(|| Item::Scope(IndexMap::new()))
                {
                    Item::Scope(inner) => level = inner,
                    Item::Tag(_) => continue 'tags,
                }
            }
            level.entry(last.to_owned()).or_insert(Item::Tag(tag));
        }
        let tree = self.emit(&root, "", 0);
        format!("export interface {}Tags {tree}\n", self.prefix)
    }

    fn emit(&mut self, level: &IndexMap<String, Item>, prefix: &str, indent: usize) -> String {
        let mut fields = Vec::new();
        for (name, item) in level {
            if RESERVED.contains(&name.as_str()) {
                continue;
            }
            let path = format!("{prefix}{name}");
            let text = match item {
                Item::Scope(inner) => self.emit(inner, &format!("{path}."), indent + 2),
                Item::Tag(tag) => {
                    let type_ = str_of(tag, "type");
                    let listed = tag
                        .get("type")
                        .and_then(Json::as_str)
                        .is_some_and(|t| self.types.contains_key(t));
                    match tag.get("aoi_readable") {
                        Some(readable) if !listed => {
                            // AOI type not listed
                            let members =
                                readable.as_array().map(Vec::as_slice).unwrap_or_default();
                            let mut leaves = Vec::with_capacity(members.len());
                            for m in members {
                                let m = py_str(m);
                                let text = self.leaf("", Some(&format!("{path}.{m}")), None).0;
                                leaves.push((m, text));
                            }
                            obj(&leaves, Some(indent + 2))
                        }
                        _ => {
                            self.node(type_, dims_of(tag), Some(&path), Some(&path), indent + 2)
                                .0
                        }
                    }
                }
            };
            fields.push((name.clone(), text));
        }
        obj(&fields, Some(indent))
    }

    /// tagTree meta: dims of every array path, bit names of integer paths. Call after `tags()`.
    fn meta(&self) -> String {
        let mut meta = Map::new();
        if !self.dims.is_empty() {
            meta.insert("dims".into(), Json::Object(self.dims.clone()));
        }
        if !self.bits.is_empty() {
            meta.insert("bits".into(), Json::Object(self.bits.clone()));
        }
        py_json(&Json::Object(meta))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::Command;
    use std::thread;

    use serde_json::json;

    use super::*;

    /// A /tags body with every shape codegen handles (tests/test_types.py BODY).
    fn body() -> Json {
        json!({
            "plc": "PLC1", "state": "connected", "version": 1234,
            "tags": [
                {"name": "Bench", "type": "BenchData"},
                {"name": "Tank", "type": "Tank", "dims": [4]},
                {"name": "Trend", "type": "REAL", "dims": [16]},
                {"name": "Grid", "type": "DINT", "dims": [3, 4]},
                {"name": "Flags", "type": "BOOL", "dims": [32]},
                {"name": "Message", "type": "STRING"},
                {"name": "Valve1", "type": "MyAOI", "aoi_readable": ["Open", "Cmd"]},
                {"name": "Pump-2", "type": "REAL"},
                {"name": "Program:Bench.Mode", "type": "DINT"},
                {"name": "Program:Bench.Cell", "type": "Tank", "dims": [2]},
                {"name": "Old", "type": "OldAOI", "aoi_readable": ["Done"]},
            ],
            "types": {
                "BenchData": {"members": {
                    "Running": {"type": "BOOL"}, "StartPB": {"type": "BOOL"}, "SpeedSP": {"type": "REAL"},
                    "Speed": {"type": "REAL"}, "StatusWord": {"type": "DINT"}, "Count": {"type": "DINT"},
                    "Message": {"type": "STRING"}, "Axis": {"type": "Axis"}, "Recipe": {"type": "Recipe"},
                    "length": {"type": "DINT"}}},
                "Axis": {"members": {"Position": {"type": "REAL"}, "Velocity": {"type": "REAL"}}},
                "Recipe": {"members": {"Name": {"type": "STRING"}, "Setpoints": {"type": "REAL", "dims": [4]}}},
                "Tank": {"members": {"Level": {"type": "REAL"}, "Temp": {"type": "REAL"}, "Valve": {"type": "BOOL"},
                                     "Status": {"type": "INT"}}},
                "MyAOI": {"members": {"Open": {"type": "BOOL"}, "Cmd": {"type": "DINT"}}, "aoi": true},
            },
            "rules": [
                {"match": "Bench.SpeedSP", "writable": true, "min": 0, "max": 1800},
                {"match": ["Bench.StartPB", "Tank[*].Valve"], "writable": true},
                {"match": "Bench.StatusWord.1", "writable": true},
                {"match": "Bench.StatusWord", "always": true, "bits": {"EStop": 0, "DoorOpen": 1}},
                {"match": "Tank[*].Status", "bits": {"Alarm": 3}},
                {"match": "Grid*", "writable": true},
            ],
            "groups": [],
        })
    }

    fn between<'t>(text: &'t str, start: &str, end: &str) -> &'t str {
        let rest = &text[text.find(start).expect(start) + start.len()..];
        &rest[..rest.rfind(end).expect(end)]
    }

    // The server-backed tests of test_types.py (one PLC, several PLCs, the mock server) use the bodies the
    // Python server returns for them; the server itself is tested elsewhere.

    #[test]
    fn names_of_one_plc_list_aoi_readable_members() {
        let body = json!({"plc": "PLC1", "tags": [
            {"name": "Line1.Speed", "type": "REAL"},
            {"name": "Valve1", "type": "MyAOI", "aoi_readable": ["Open", "Cmd"]}]});
        let text = names_module(&[body], &[Some("PLC1".into())]);
        assert!(text.starts_with("// Generated by ciplink-server types. Do not edit.\n"));
        assert!(text.contains(
            "export type TagName =\n  | \"Line1.Speed\"\n  | \"Valve1.Open\"\n  | \"Valve1.Cmd\";\n"
        ));
        assert!(!text.contains("Local1"));
    }

    #[test]
    fn names_are_qualified_with_several_plcs() {
        let one = json!({"plc": "PLC1", "tags": [{"name": "Line1.Speed", "type": "REAL"}]});
        let two = json!({"plc": "PLC2", "tags": [
            {"name": "Program:Station1.DoorOpen", "type": "REAL"},
            {"name": "Valve1", "type": "MyAOI", "aoi_readable": ["Open", "Cmd"]}]});
        let text = names_module(&[one, two], &[Some("PLC1".into()), Some("PLC2".into())]);
        assert!(text.ends_with(
            "  | \"PLC1/Line1.Speed\"\n  | \"PLC2/Program:Station1.DoorOpen\"\n  | \"PLC2/Valve1.Open\"\n  | \"PLC2/Valve1.Cmd\";\n"
        ));
    }

    #[test]
    fn names_without_tags_are_never_and_deduplicated() {
        let empty = names_module(&[json!({"plc": "P", "tags": []})], &[None]);
        assert!(empty.ends_with("export type TagName = never;\n"));
        let body = json!({"plc": "P", "tags": [{"name": "A"}, {"name": "A"}, {"name": "Ü"}]});
        assert!(
            names_module(&[body], &[None]).ends_with("TagName =\n  | \"A\"\n  | \"\\u00dc\";\n")
        );
    }

    #[test]
    fn tree_shapes() {
        let text = tree_module(&[body()], false).unwrap();
        assert!(text.starts_with(
            "// Generated by ciplink-server types (PLC1 tag table version 1234). Do not edit.\n"
        ));
        assert!(text.contains(
            "import { tagTree, type TagRef, type IntRef, type TagArray } from \"@ciplink/react\";"
        ));
        assert!(text.contains(
            "export interface PLC1_Axis extends TagRef<Record<string, unknown>, false> {\n  Position: TagRef<number, false>;\n  Velocity: TagRef<number, false>;\n}"
        ));
        assert!(text.contains(
            "export interface PLC1_MyAOI {\n  Open: TagRef<boolean, false>;\n  Cmd: IntRef<false>;\n}"
        ));
        assert!(text.contains("  Setpoints: TagArray<TagRef<number, false>, 4>;\n"));
        let bench = text
            .split("export interface PLC1_BenchData")
            .nth(1)
            .unwrap();
        assert!(!bench.split('}').next().unwrap().contains("length")); // a proxy name
        let tags = text.split("export interface PLC1Tags ").nth(1).unwrap();
        assert!(
            tags.contains(
                "    SpeedSP: TagRef<number, true>;\n    Speed: TagRef<number, false>;\n"
            )
        );
        assert!(tags.contains("    StartPB: TagRef<boolean, true>;\n"));
        assert!(tags.contains(
            "    StatusWord: IntRef<false> & { EStop: TagRef<boolean, false>; DoorOpen: TagRef<boolean, true>; };\n"
        ));
        // nothing writable below: shared interfaces
        assert!(tags.contains("    Axis: PLC1_Axis;\n    Recipe: PLC1_Recipe;\n"));
        // Valve writable: inline
        assert!(tags.contains("  Tank: TagArray<TagRef<Record<string, unknown>, false> & {\n"));
        assert!(tags.contains(
            "    Valve: TagRef<boolean, true>;\n    Status: IntRef<false> & { Alarm: TagRef<boolean, false>; };\n"
        ));
        assert!(tags.contains("  Grid: TagArray<TagArray<IntRef<true>, 4>, 3>;\n"));
        assert!(tags.contains("  Flags: TagArray<TagRef<boolean, false>, 32>;\n"));
        assert!(tags.contains("  Message: TagRef<string, false>;\n  Valve1: PLC1_MyAOI;\n"));
        assert!(tags.contains(
            "  \"Pump-2\": TagRef<number, false>;\n  \"Program:Bench\": {\n    Mode: IntRef<false>;\n"
        ));
        // AOI type not listed
        assert!(tags.contains("  Old: {\n    Done: TagRef<unknown, false>;\n  };\n"));
        let meta = between(&text, "tagTree<PLC1Tags>(null, ", ");");
        assert_eq!(
            meta,
            "{\"dims\": {\"Bench.Recipe.Setpoints\": [4], \"Tank\": [4], \"Trend\": [16], \"Grid\": [3, 4], \
             \"Flags\": [32], \"Program:Bench.Cell\": [2]}, \"bits\": {\"Bench.StatusWord\": {\"EStop\": 0, \
             \"DoorOpen\": 1}, \"Tank[].Status\": {\"Alarm\": 3}}}"
        );
    }

    #[test]
    fn tree_qualified_with_several_plcs() {
        let mut two = body();
        two["plc"] = json!("Line 2");
        two["version"] = json!(7);
        let text = tree_module(&[body(), two], true).unwrap();
        let first = text.lines().next().unwrap();
        assert!(first.contains("PLC1 tag table version 1234, Line 2 tag table version 7"));
        assert!(text.contains("export const PLC1 = tagTree<PLC1Tags>(\"PLC1\", {"));
        assert!(text.contains("export const Line_2 = tagTree<Line_2Tags>(\"Line 2\", {"));
        assert!(text.contains("export interface Line_2_Axis "));
    }

    #[test]
    fn tree_from_mock_server_body() {
        let body = json!({
            "plc": "PLC1", "version": 1,
            "tags": [
                {"name": "Tank", "type": "Tank", "dims": [4]},
                {"name": "Trend", "type": "REAL", "dims": [16]},
                {"name": "Program:Bench.Mode", "type": "DINT"}],
            "types": {"Tank": {"members": {"Level": {"type": "REAL"}, "Valve": {"type": "BOOL"}}}},
            "rules": [{"match": "Tank[*].Valve", "writable": true}],
            "groups": [], "decorators": {}, "udt": {}, "tag_settings": {},
        });
        let text = tree_module(&[body], false).unwrap();
        assert!(text.contains(
            "export interface PLC1_Tank extends TagRef<Record<string, unknown>, false> {"
        ));
        assert!(text.contains("    Valve: TagRef<boolean, true>;\n"));
        assert!(text.contains("  Trend: TagArray<TagRef<number, false>, 16>;\n"));
        assert!(text.contains("  \"Program:Bench\": {\n    Mode: IntRef<false>;\n  };\n"));
        assert!(text.contains(
            "export const PLC1 = tagTree<PLC1Tags>(null, {\"dims\": {\"Tank\": [4], \"Trend\": [16]}});"
        ));
    }

    #[test]
    fn bit_strings_are_bool_lists_with_bit_names() {
        let body = json!({
            "plc": "P", "version": 1,
            "tags": [{"name": "B", "type": "BYTE"}, {"name": "W", "type": "WORD"}, {"name": "D", "type": "DWORD"},
                     {"name": "L", "type": "LWORD"}],
            "rules": [{"match": "W", "writable": true, "bits": {"Run": 2}}],
        });
        let text = tree_module(&[body], false).unwrap();
        let bits = "TagRef<boolean[], false> & { bit(n: number): TagRef<boolean, false> }";
        for name in ["B", "D", "L"] {
            assert!(text.contains(&format!("  {name}: {bits};\n")), "{name}");
        }
        assert!(text.contains(
            "  W: TagRef<boolean[], true> & { bit(n: number): TagRef<boolean, true> } & { Run: TagRef<boolean, true>; };\n"
        ));
        assert!(!text.contains("IntRef"));
        assert!(text.contains("import { tagTree, type TagRef } from"));
        assert!(text.contains("{\"bits\": {\"W\": {\"Run\": 2}}}"));
    }

    #[test]
    fn non_ascii_names_are_escaped_like_json_dumps() {
        let body = json!({"plc": "Zürich", "version": null,
                          "tags": [{"name": "Grüße", "type": "REAL", "dims": [2]}]});
        let text = tree_module(&[body], true).unwrap();
        assert!(
            text.starts_with(
                "// Generated by ciplink-server types (Zürich tag table version None)."
            )
        );
        assert!(text.contains("  \"Gr\\u00fc\\u00dfe\": TagArray<TagRef<number, false>, 2>;\n"));
        assert!(text.contains(
            "export const Z_rich = tagTree<Z_richTags>(\"Z\\u00fcrich\", {\"dims\": {\"Gr\\u00fc\\u00dfe\": [2]}});"
        ));
        assert_eq!(
            py_json_str("a\"\\\n\u{1}\u{7f}\u{1F600}"),
            "\"a\\\"\\\\\\n\\u0001\\u007f\\ud83d\\ude00\""
        );
    }

    #[test]
    fn idents_replace_other_characters() {
        assert_eq!(ident("Line 2"), "Line_2");
        assert_eq!(ident("2nd"), "_2nd");
        assert_eq!(ident("$ok_1"), "$ok_1");
        assert_eq!(obj(&[], None), "{}");
        assert_eq!(
            obj(&[("a-b".into(), "X".into())], Some(2)),
            "{\n    \"a-b\": X;\n  }"
        );
    }

    /// Serves one canned response; the handle returns the request it read.
    fn serve(response: &'static [u8]) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "request cut short");
                request.extend_from_slice(&buf[..n]);
            }
            stream.write_all(response).unwrap();
            String::from_utf8(request).unwrap()
        });
        (url, handle)
    }

    #[test]
    fn fetch_tags_reads_a_content_length_body() {
        let (url, server) = serve(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-length: 13\r\n\r\n{\"plc\": \"P\"}\nextra",
        );
        let body = fetch_tags(&url, "view", Some("Line 2/\u{fc}")).unwrap();
        assert_eq!(body, json!({"plc": "P"}));
        let request = server.join().unwrap();
        assert!(
            request.starts_with("GET /tags?plc=Line%202/%C3%BC HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("\r\nAuthorization: Bearer view\r\n"));
        assert!(request.contains("\r\nConnection: close\r\n"));
    }

    #[test]
    fn fetch_tags_reads_a_chunked_body() {
        let (url, server) = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"plc\r\n7;x=1\r\n\": \"P\"}\r\n0\r\n\r\n",
        );
        let body = fetch_tags(url.trim_end_matches('/'), "t", None).unwrap();
        assert_eq!(body, json!({"plc": "P"}));
        assert!(server.join().unwrap().starts_with("GET /tags HTTP/1.1\r\n"));
    }

    #[test]
    fn fetch_tags_fails_on_an_error_status() {
        let (url, server) =
            serve(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 9\r\n\r\nbad token");
        let err = fetch_tags(&url, "x", None).unwrap_err();
        assert!(
            err.contains("HTTP/1.1 401 Unauthorized") && err.contains("bad token"),
            "{err}"
        );
        server.join().unwrap();
        assert!(fetch_tags("https://example.com", "x", None).is_err());
    }

    const CHECKS: &str = r#"import { useMomentary, useTag, useTags, useWriteTag } from "@ciplink/react";
import { PLC1, type PLC1_Tank } from "./plc";

export function checks(tank: PLC1_Tank) {
  useWriteTag(PLC1.Bench.SpeedSP)(5);
  useWriteTag(PLC1.Tank[2].Valve)(true);
  useWriteTag(PLC1.Grid[1][2])(3);
  useMomentary(PLC1.Bench.StartPB);
  // @ts-expect-error a read-only leaf
  useWriteTag(PLC1.Bench.Speed);
  // @ts-expect-error read-only through a shared interface
  useWriteTag(PLC1.Bench.Axis.Position);
  // @ts-expect-error not writable
  useWriteTag(PLC1.Tank[1].Level);
  // @ts-expect-error not writable
  useMomentary(PLC1.Bench.Running);
  // @ts-expect-error a REAL takes a number
  useWriteTag(PLC1.Bench.SpeedSP)("fast");
  // @ts-expect-error the word is read-only
  useWriteTag(PLC1.Bench.StatusWord);
  useWriteTag(PLC1.Bench.StatusWord.DoorOpen)(true);
  // @ts-expect-error EStop is read-only
  useWriteTag(PLC1.Bench.StatusWord.EStop);
  const estop: boolean | null = useTag(PLC1.Bench.StatusWord.EStop).value;
  const bit: boolean | null = useTag(PLC1.Bench.Count.bit(3)).value;
  const alarm: boolean | null = useTag(PLC1.Tank[0].Status.Alarm).value;
  const grid: number | null = useTag(PLC1.Grid[1][2]).value;
  const n: 4 = PLC1.Tank.length;
  const m: 16 = PLC1.Trend.length;
  const mode: number | null = useTag(PLC1["Program:Bench"].Mode).value;
  const cell: number | null = useTag(PLC1["Program:Bench"].Cell[1].Level).value;
  const text: string | null = useTag(PLC1.Message).value;
  const name: string | null = useTag(PLC1.Bench.Recipe.Name).value;
  const sp: number | null = useTag(PLC1.Bench.Recipe.Setpoints[3]).value;
  const flag: boolean | null = useTag(PLC1.Flags[31]).value;
  const open: boolean | null = useTag(PLC1.Valve1.Open).value;
  const pump: number | null = useTag(PLC1["Pump-2"]).value;
  useTag(PLC1.Old.Done);
  useTags([PLC1.Bench.Recipe, PLC1.Trend[0], tank.Level]);
  // @ts-expect-error a bare array name is its first element, not the array
  useTag(PLC1.Trend);
  // @ts-expect-error AOI members are not readable whole
  useTag(PLC1.Valve1);
  return [estop, bit, alarm, grid, n, m, mode, cell, text, name, sp, flag, open, pump];
}
"#;

    /// Type-checks the module against `@ciplink/react`: needs node and the client with its node_modules, at
    /// `CIPLINK_REACT_CLIENT` or in a ciplink-tagserver checkout next to this repository; skipped otherwise.
    #[test]
    fn tree_compiles() {
        let client = std::env::var_os("CIPLINK_REACT_CLIENT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ciplink-tagserver/client")
            });
        let tsc = client.join("node_modules/typescript/bin/tsc");
        if !tsc.exists() || Command::new("node").arg("--version").output().is_err() {
            eprintln!("skipped: needs node and {}", tsc.display());
            return;
        }
        let dir = std::env::temp_dir().join(format!("ciplink-codegen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plc.ts"), tree_module(&[body()], false).unwrap()).unwrap();
        std::fs::write(dir.join("checks.ts"), CHECKS).unwrap();
        let index = client
            .join("src/index.ts")
            .to_string_lossy()
            .replace('\\', "/");
        let config = json!({
            "compilerOptions": {"target": "ES2020", "module": "ESNext", "moduleResolution": "Bundler",
                                "strict": true, "jsx": "react-jsx", "lib": ["ES2020", "DOM", "DOM.Iterable"],
                                "skipLibCheck": true, "noEmit": true, "noUnusedLocals": true, "types": [],
                                "paths": {"@ciplink/react": [index]}},
            "files": ["plc.ts", "checks.ts"]});
        std::fs::write(dir.join("tsconfig.json"), config.to_string()).unwrap();
        let out = Command::new("node")
            .arg(&tsc)
            .arg("-p")
            .arg(dir.join("tsconfig.json"))
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
