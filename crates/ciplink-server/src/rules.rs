//! Tag settings: decorators attached by UDT member or tag path, then the match-pattern rules and poll groups.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, PoisonError, RwLock};

use indexmap::IndexMap;
use serde_json::{Map, Value as Json};

use crate::config::{Config, py_repr};

/// Settings of a tag path: `writable`, `min`, `max`, `units`, `description`, `deadband`, `always`, `bits`,
/// `together`, `rate_ms` (with `group`, the name that set it).
pub type Settings = Map<String, Json>;

const RULE_KEYS: [&str; 9] = [
    "writable",
    "min",
    "max",
    "units",
    "description",
    "deadband",
    "always",
    "bits",
    "together",
];
/// The only fields a struct or array passes down to its members.
const INHERITED: [&str; 2] = ["rate_ms", "together"];
const NOT_FOR_BITS: [&str; 6] = ["min", "max", "deadband", "units", "bits", "together"];

fn is_decorator_key(key: &str) -> bool {
    RULE_KEYS.contains(&key) || key == "rate_ms"
}

/// Python truthiness of a setting.
pub fn truthy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Array(a)) => !a.is_empty(),
        Some(Json::Object(o)) => !o.is_empty(),
    }
}

/// `X.<n>` as (`X`, `n`): Logix member names never start with a digit.
pub fn split_bit(tag: &str) -> Option<(&str, &str)> {
    let (word, bit) = tag.rsplit_once('.')?;
    (!word.is_empty() && !bit.is_empty() && bit.bytes().all(|b| b.is_ascii_digit()))
        .then_some((word, bit))
}

/// Replaces each `[...]` of `path` with `f(inside)`.
fn map_indexes(path: &str, f: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(open) = rest.find('[') {
        let Some(close) = rest[open..].find(']').map(|c| open + c) else {
            break;
        };
        out.push_str(&rest[..open]);
        match f(&rest[open + 1..close]) {
            Some(text) => out.push_str(&text),
            None => out.push_str(&rest[open..=close]),
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// `[02]` and `[ 2]` address element 2 in ciplink and the mock, so settings must see `[2]`.
pub fn canonical(path: &str) -> String {
    map_indexes(path, |inside| {
        let numbers: Option<Vec<String>> = inside
            .split(',')
            .map(|i| i.trim().parse::<i64>().ok().map(|n| n.to_string()))
            .collect();
        numbers.map(|n| format!("[{}]", n.join(",")))
    })
}

/// A path without its indexes.
fn strip_indexes(path: &str) -> String {
    map_indexes(path, |_| Some(String::new()))
}

/// Canonical indexes, lowercase.
pub fn normalize(path: &str) -> String {
    canonical(path).to_lowercase()
}

/// Case-insensitive; `*` any run of characters (`.` and `[]` included), `?` one, the rest literal.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || (p[pi] != '*' && p[pi] == n[ni])) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// The `match` of a rule or group table as a list.
pub fn patterns(table: &Map<String, Json>) -> Vec<&str> {
    match table.get("match") {
        Some(Json::String(s)) => vec![s.as_str()],
        Some(Json::Array(items)) => items.iter().filter_map(Json::as_str).collect(),
        _ => Vec::new(),
    }
}

fn matches(table: &Map<String, Json>, name: &str) -> bool {
    patterns(table).iter().any(|p| glob_match(p, name))
}

/// The tag path tokens of `rest`: `[...]` groups and names (Python's `\[[^\]]*\]|[^.\[\]]+`).
fn parts(rest: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    let bytes = rest.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'[' => match rest[i..].find(']') {
                Some(close) => {
                    out.push(&rest[i..=i + close]);
                    i += close + 1;
                }
                None => i += 1,
            },
            b'.' | b']' => i += 1,
            _ => {
                let end = rest[i..]
                    .find(['.', '[', ']'])
                    .map_or(rest.len(), |e| i + e);
                out.push(&rest[i..end]);
                i = end;
            }
        }
    }
    out
}

/// (`Program:X.`, rest) of a program-scoped path, ("", path) otherwise.
fn program_split(tag: &str) -> (String, &str) {
    if tag.len() >= 8 && tag.is_char_boundary(8) && tag[..8].eq_ignore_ascii_case("program:") {
        match tag.find('.') {
            None => (format!("{tag}."), ""),
            Some(dot) => (tag[..=dot].to_owned(), &tag[dot + 1..]),
        }
    } else {
        (String::new(), tag)
    }
}

static WARNED: Mutex<Option<HashSet<(String, String)>>> = Mutex::new(None);

/// The decorator fields of a table; unknown keys are logged and dropped, a bad rate_ms is an error.
fn fields(table: &Map<String, Json>, where_: &str) -> Result<Settings, String> {
    for key in table.keys() {
        if !is_decorator_key(key) {
            let mut warned = WARNED.lock().unwrap_or_else(PoisonError::into_inner);
            if warned
                .get_or_insert_with(HashSet::new)
                .insert((where_.to_owned(), key.clone()))
            {
                log::warn!("{where_}: unknown key {} ignored", py_repr(key));
            }
        }
    }
    if let Some(rate) = table.get("rate_ms") {
        if !rate.as_u64().is_some_and(|r| r > 0) {
            return Err(format!("{where_}: rate_ms must be an integer > 0"));
        }
    }
    Ok(table
        .iter()
        .filter(|(k, _)| is_decorator_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect())
}

/// The fields of a `[udt]` or `[tags]` entry: `"name"`, `["name", ...]` or `{use = ..., <fields>}`. Its
/// decorators in list order (later wins), then its own fields; `rate_ms` comes with `group`, the name that set it.
fn entry(value: &Json, decorators: &Map<String, Json>, where_: &str) -> Result<Settings, String> {
    let mut own = Settings::new();
    let mut value = value;
    let empty = Json::Array(Vec::new());
    if let Json::Object(table) = value {
        let rest: Map<String, Json> = table
            .iter()
            .filter(|(k, _)| k.as_str() != "use")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        own = fields(&rest, where_)?;
        value = table.get("use").unwrap_or(&empty);
    }
    let bad = || format!("{where_}: expected a decorator name, a list of names or a table");
    let names: Vec<&str> = match value {
        Json::String(s) => vec![s.as_str()],
        Json::Array(items) => items
            .iter()
            .map(|n| n.as_str().ok_or_else(bad))
            .collect::<Result<_, _>>()?,
        _ => return Err(bad()),
    };
    let mut result = Settings::new();
    for name in names {
        let Some(Json::Object(decorator)) = decorators.get(name) else {
            return Err(format!("{where_}: unknown decorator {}", py_repr(name)));
        };
        for (k, v) in decorator {
            result.insert(k.clone(), v.clone());
        }
        if decorator.contains_key("rate_ms") {
            result.insert("group".into(), Json::String(name.to_owned()));
        }
    }
    let own_rate = own.contains_key("rate_ms");
    result.extend(own);
    if own_rate {
        result.insert("group".into(), Json::String("tag".into()));
    }
    Ok(result)
}

/// A poll rate and the name it is shown under: a poll group, a decorator, or `"tag"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// The group's name.
    pub name: String,
    /// The group's poll period.
    pub rate_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Tag,
    Member,
    Element,
    Bit,
}

/// (name as the controller spells it, lowercase type name, dims).
type TypeEntry = (String, String, Option<Vec<u64>>);

/// Effective settings of tag paths in one PLC, from the decorators, its `[udt]` and `[tags]` entries, its rules
/// and groups, and the controller's types (the `/tags` `tags` and `types`; UDT entries need them).
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    udt: HashMap<String, HashMap<String, Settings>>,
    tags: IndexMap<String, Settings>,
    names: HashMap<String, String>,
    rules: Vec<Map<String, Json>>,
    groups: Vec<Map<String, Json>>,
    tag_types: IndexMap<String, TypeEntry>,
    types: HashMap<String, IndexMap<String, TypeEntry>>,
}

fn dims_of(value: Option<&Json>) -> Option<Vec<u64>> {
    value?.as_array()?.iter().map(Json::as_u64).collect()
}

impl Resolver {
    /// A resolver without the controller's types; an unknown decorator or a bad entry is an error naming its place.
    pub fn new(
        decorators: &Map<String, Json>,
        udt: &Map<String, Json>,
        tags: &Map<String, Json>,
        rules: Vec<Map<String, Json>>,
        groups: Vec<Map<String, Json>>,
        where_: &str,
    ) -> Result<Self, String> {
        let mut checked = Map::new();
        for (name, d) in decorators {
            let table = d
                .as_object()
                .ok_or_else(|| format!("decorator.{name} must be a table"))?;
            checked.insert(
                name.clone(),
                Json::Object(fields(table, &format!("decorator.{name}"))?),
            );
        }
        let mut udt_map = HashMap::new();
        for (u, members) in udt {
            let members = members
                .as_object()
                .ok_or_else(|| format!("{where_}.udt.{u} must be a table"))?;
            let mut resolved = HashMap::new();
            for (m, e) in members {
                resolved.insert(
                    m.to_lowercase(),
                    entry(e, &checked, &format!("{where_}.udt.{u}.{m}"))?,
                );
            }
            udt_map.insert(u.to_lowercase(), resolved);
        }
        let mut tag_map = IndexMap::new();
        let mut names = HashMap::new();
        for (k, e) in tags {
            tag_map.insert(
                normalize(k),
                entry(e, &checked, &format!("{where_}.tags.{k}"))?,
            );
            names.insert(normalize(k), canonical(k));
        }
        Ok(Resolver {
            udt: udt_map,
            tags: tag_map,
            names,
            rules,
            groups,
            ..Resolver::default()
        })
    }

    /// From a `GET /tags` body, as codegen sees it.
    pub fn from_body(body: &Json) -> Result<Self, String> {
        let empty = Map::new();
        let obj = |key: &str| body.get(key).and_then(Json::as_object).unwrap_or(&empty);
        let list = |key: &str| -> Vec<Map<String, Json>> {
            body.get(key)
                .and_then(Json::as_array)
                .map(|a| a.iter().filter_map(|t| t.as_object().cloned()).collect())
                .unwrap_or_default()
        };
        let mut resolver = Resolver::new(
            obj("decorators"),
            obj("udt"),
            obj("tag_settings"),
            list("rules"),
            list("groups"),
            body.get("plc").and_then(Json::as_str).unwrap_or("plc"),
        )?;
        let tags = body
            .get("tags")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        resolver.set_types(&tags, obj("types"));
        Ok(resolver)
    }

    /// The controller structure (empty: unknown, so only `[tags]` entries and rules apply).
    pub fn set_types(&mut self, tag_list: &[Json], types: &Map<String, Json>) {
        self.tag_types = tag_list
            .iter()
            .filter_map(|t| {
                let name = t.get("name")?.as_str()?;
                let type_ = t
                    .get("type")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_lowercase();
                Some((
                    name.to_lowercase(),
                    (name.to_owned(), type_, dims_of(t.get("dims"))),
                ))
            })
            .collect();
        self.types = types
            .iter()
            .map(|(u, t)| {
                let members = t
                    .get("members")
                    .and_then(Json::as_object)
                    .map(|members| {
                        members
                            .iter()
                            .map(|(m, i)| {
                                let type_ = i
                                    .get("type")
                                    .and_then(Json::as_str)
                                    .unwrap_or("")
                                    .to_lowercase();
                                (m.to_lowercase(), (m.clone(), type_, dims_of(i.get("dims"))))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                (u.to_lowercase(), members)
            })
            .collect();
    }

    fn member_type(&self, udt: Option<&str>, member: &str) -> Option<&TypeEntry> {
        self.types.get(udt?)?.get(&member.to_lowercase())
    }

    /// `[(kind, fields set at that node)]` from the base tag to the leaf.
    fn nodes(&self, tag: &str) -> Vec<(Kind, Settings)> {
        let (prefix, rest) = program_split(tag);
        let parts = parts(rest);
        if parts.is_empty() {
            return vec![(
                Kind::Tag,
                self.tags.get(&normalize(tag)).cloned().unwrap_or_default(),
            )];
        }
        let mut path = format!("{prefix}{}", parts[0]);
        let mut type_: Option<String> = self
            .tag_types
            .get(&path.to_lowercase())
            .map(|t| t.1.clone());
        let mut result = vec![(
            Kind::Tag,
            self.tags
                .get(&normalize(&path))
                .cloned()
                .unwrap_or_default(),
        )];
        for (i, part) in parts.iter().enumerate().skip(1) {
            let mut udt = None;
            let kind = if part.starts_with('[') {
                path.push_str(part);
                Kind::Element
            } else if part.bytes().all(|b| b.is_ascii_digit()) && i + 1 == parts.len() {
                path = format!("{path}.{part}");
                type_ = None;
                Kind::Bit
            } else {
                path = format!("{path}.{part}");
                udt = type_.take();
                type_ = self.member_type(udt.as_deref(), part).map(|t| t.1.clone());
                Kind::Member
            };
            let key = normalize(&path);
            let mut found = udt
                .as_deref()
                .and_then(|u| self.udt.get(u))
                .and_then(|members| members.get(&part.to_lowercase()))
                .cloned()
                .unwrap_or_default();
            let stripped = strip_indexes(&key);
            if stripped != key {
                if let Some(s) = self.tags.get(&stripped) {
                    found.extend(s.clone());
                }
            }
            if let Some(s) = self.tags.get(&key) {
                found.extend(s.clone());
            }
            result.push((kind, found));
        }
        result
    }

    /// Settings of a tag path: `rate_ms` and `together` from the closest node that sets them, the other fields
    /// from the path itself (an element also from its array); then the rules, per field the first rule (file
    /// order) that sets it. A bit keeps no min, max, units, deadband, bits or together; writable falls back to
    /// its word's.
    pub fn effective(&self, tag: &str) -> Settings {
        let nodes = self.nodes(tag);
        let mut result = Settings::new();
        for (_, found) in &nodes {
            for key in INHERITED {
                if let Some(v) = found.get(key) {
                    result.insert(key.into(), v.clone());
                    if key == "rate_ms" {
                        result.insert(
                            "group".into(),
                            found.get("group").cloned().unwrap_or(Json::Null),
                        );
                    }
                }
            }
        }
        let mut i = nodes.len() - 1;
        let mut chain = vec![&nodes[i]];
        while nodes[i].0 == Kind::Element {
            i -= 1;
            chain.insert(0, &nodes[i]);
        }
        for (_, found) in chain {
            for (k, v) in found {
                if !INHERITED.contains(&k.as_str()) && k != "group" {
                    result.insert(k.clone(), v.clone());
                }
            }
        }
        for rule in &self.rules {
            if matches(rule, tag) {
                for key in RULE_KEYS {
                    if let Some(v) = rule.get(key) {
                        if !result.contains_key(key) {
                            result.insert(key.into(), v.clone());
                        }
                    }
                }
            }
        }
        if let Some((word, _)) = split_bit(tag) {
            result.retain(|k, _| !NOT_FOR_BITS.contains(&k.as_str()));
            if !result.contains_key("writable") {
                if let Some(w) = self.effective(word).get("writable") {
                    result.insert("writable".into(), w.clone());
                }
            }
        }
        result
    }

    /// The tag's poll rate: from a decorator (named after it, `"tag"` when set inline), else the first matching
    /// poll group; None if neither sets one.
    pub fn group(&self, tag: &str, settings: &Settings) -> Option<Group> {
        if let Some(rate) = settings.get("rate_ms").and_then(Json::as_u64) {
            let name = settings
                .get("group")
                .and_then(Json::as_str)
                .unwrap_or("tag");
            return Some(Group {
                name: name.to_owned(),
                rate_ms: rate,
            });
        }
        self.groups.iter().find(|g| matches(g, tag)).and_then(|g| {
            Some(Group {
                name: match g.get("name")? {
                    Json::String(s) => s.clone(),
                    other => other.to_string(),
                },
                rate_ms: g.get("rate_ms")?.as_u64()?,
            })
        })
    }

    /// Tags read at tier 1 even with no subscribers: literal rule names and `[tags]` keys, and every instance of a
    /// UDT member whose entry says always (once the types are known).
    pub fn always(&self) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for rule in &self.rules {
            if truthy(rule.get("always")) {
                for name in patterns(rule) {
                    if name.contains(['*', '?']) {
                        log::warn!(
                            "always ignored for the pattern {}, it takes tag names only",
                            py_repr(name)
                        );
                    } else {
                        result.push(name.to_owned());
                    }
                }
            }
        }
        for (k, found) in &self.tags {
            if truthy(found.get("always")) {
                result.extend(self.expand(&self.names[k]));
            }
        }
        let mut targets = HashSet::new();
        for (u, members) in &self.udt {
            for (m, found) in members {
                if truthy(found.get("always")) {
                    targets.insert((u.clone(), m.clone()));
                }
            }
        }
        result.extend(self.instances(&targets));
        let mut seen = HashSet::new();
        result
            .into_iter()
            .filter(|name| seen.insert(name.clone()))
            .filter(|name| truthy(self.effective(name).get("always")))
            .collect()
    }

    /// The paths an index-less `[tags]` key stands for: every element of each array it passes through (by the
    /// types; unknown, the key itself). A key with indexes, or one ending at an array, is the path itself.
    fn expand(&self, key: &str) -> Vec<String> {
        let (prefix, rest) = program_split(key);
        let parts = parts(rest);
        let found = parts
            .first()
            .and_then(|p| self.tag_types.get(&format!("{prefix}{p}").to_lowercase()));
        let Some(found) = found.filter(|_| !key.contains('[')) else {
            return vec![key.to_owned()];
        };
        let mut paths = vec![found.0.clone()];
        let (mut type_, mut dims) = (Some(found.1.clone()), found.2.clone());
        for part in &parts[1..] {
            if let Some(d) = dims.as_deref().filter(|d| !d.is_empty()) {
                paths = paths
                    .iter()
                    .flat_map(|p| {
                        product(d)
                            .into_iter()
                            .map(move |i| format!("{p}[{}]", join(&i)))
                    })
                    .collect();
            }
            let (name, t, d) = match self.member_type(type_.as_deref(), part) {
                Some((name, t, d)) => (name.clone(), Some(t.clone()), d.clone()),
                None => ((*part).to_owned(), None, None),
            };
            paths = paths.into_iter().map(|p| format!("{p}.{name}")).collect();
            type_ = t;
            dims = d;
        }
        paths
    }

    /// Paths of every instance of the (udt, member) targets in the controller, array elements expanded.
    fn instances(&self, targets: &HashSet<(String, String)>) -> Vec<String> {
        if targets.is_empty() {
            return Vec::new();
        }
        let mut reach: HashMap<String, bool> = HashMap::new();
        let mut found = Vec::new();
        for (name, type_, dims) in self.tag_types.values() {
            if self.reaches(type_, targets, &mut reach) {
                self.walk(
                    name,
                    type_,
                    dims.as_deref(),
                    targets,
                    &mut reach,
                    &mut found,
                );
            }
        }
        found
    }

    fn reaches(
        &self,
        type_: &str,
        targets: &HashSet<(String, String)>,
        reach: &mut HashMap<String, bool>,
    ) -> bool {
        if let Some(r) = reach.get(type_) {
            return *r;
        }
        reach.insert(type_.to_owned(), false); // guards recursive types
        let result = self.types.get(type_).is_some_and(|members| {
            members.iter().any(|(m, (_, t, _))| {
                targets.contains(&(type_.to_owned(), m.clone())) || self.reaches(t, targets, reach)
            })
        });
        reach.insert(type_.to_owned(), result);
        result
    }

    fn walk(
        &self,
        path: &str,
        type_: &str,
        dims: Option<&[u64]>,
        targets: &HashSet<(String, String)>,
        reach: &mut HashMap<String, bool>,
        found: &mut Vec<String>,
    ) {
        if let Some(d) = dims.filter(|d| !d.is_empty()) {
            for index in product(d) {
                self.walk(
                    &format!("{path}[{}]", join(&index)),
                    type_,
                    None,
                    targets,
                    reach,
                    found,
                );
            }
            return;
        }
        let Some(members) = self.types.get(type_) else {
            return;
        };
        for (m, (name, t, member_dims)) in members {
            if targets.contains(&(type_.to_owned(), m.clone())) {
                found.push(format!("{path}.{name}"));
            }
            if self.reaches(t, targets, reach) {
                self.walk(
                    &format!("{path}.{name}"),
                    t,
                    member_dims.as_deref(),
                    targets,
                    reach,
                    found,
                );
            }
        }
    }
}

/// Every index of an array of these dims, in row-major order.
fn product(dims: &[u64]) -> Vec<Vec<u64>> {
    let mut result = vec![Vec::new()];
    for &n in dims {
        result = result
            .into_iter()
            .flat_map(|prefix| {
                (0..n).map(move |i| {
                    let mut next = prefix.clone();
                    next.push(i);
                    next
                })
            })
            .collect();
    }
    result
}

fn join(index: &[u64]) -> String {
    index
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The resolvers of every PLC in a Config, memoized; `set_types` clears the memo.
#[derive(Debug)]
pub struct Rules {
    resolvers: HashMap<String, RwLock<Resolver>>,
    groups: HashMap<String, Vec<Map<String, Json>>>,
    memo: Mutex<HashMap<(String, String), Settings>>,
}

const MEMO_MAX: usize = 10_000;

impl Rules {
    /// The rules of every PLC of the config (already checked by `parse_config`).
    pub fn new(config: &Config) -> Result<Self, String> {
        let mut resolvers = HashMap::new();
        let mut groups = HashMap::new();
        for (name, plc) in &config.plcs {
            let resolver = Resolver::new(
                &config.decorators,
                &plc.udt,
                &plc.tags,
                plc.rules.clone(),
                plc.groups.clone(),
                &format!("plc.{name}"),
            )?;
            resolvers.insert(name.clone(), RwLock::new(resolver));
            groups.insert(name.clone(), plc.groups.clone());
        }
        Ok(Rules {
            resolvers,
            groups,
            memo: Mutex::new(HashMap::new()),
        })
    }

    fn with<T>(&self, plc: &str, f: impl FnOnce(&Resolver) -> T) -> T {
        match self.resolvers.get(plc) {
            Some(r) => f(&r.read().unwrap_or_else(PoisonError::into_inner)),
            None => f(&Resolver::default()),
        }
    }

    /// The PLC's controller structure, after a connect or a tag table reload.
    pub fn set_types(&self, plc: &str, tag_list: &[Json], types: &Map<String, Json>) {
        if let Some(r) = self.resolvers.get(plc) {
            r.write()
                .unwrap_or_else(PoisonError::into_inner)
                .set_types(tag_list, types);
        }
        self.memo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// See [`Resolver::effective`].
    pub fn effective(&self, plc: &str, tag: &str) -> Settings {
        let key = (plc.to_owned(), tag.to_lowercase());
        if let Some(s) = self
            .memo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return s.clone();
        }
        let settings = self.with(plc, |r| r.effective(tag));
        let mut memo = self.memo.lock().unwrap_or_else(PoisonError::into_inner);
        if memo.len() >= MEMO_MAX {
            memo.clear();
        }
        memo.insert(key, settings.clone());
        settings
    }

    /// A bit name `X.EStop` as `X.<n>` from the bits of X; anything else unchanged.
    pub fn resolve(&self, plc: &str, tag: &str) -> String {
        if !tag.contains('.') || split_bit(tag).is_some() {
            return tag.to_owned();
        }
        let Some((word, name)) = tag.rsplit_once('.') else {
            return tag.to_owned();
        };
        if let Some(Json::Object(bits)) = self.effective(plc, word).get("bits") {
            for (bit_name, n) in bits {
                if bit_name.to_lowercase() == name.to_lowercase() {
                    let n = match n {
                        Json::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    return format!("{word}.{n}");
                }
            }
        }
        tag.to_owned()
    }

    /// The tag's poll rate, see [`Resolver::group`].
    pub fn group(&self, plc: &str, tag: &str) -> Option<Group> {
        let settings = self.effective(plc, tag);
        self.with(plc, |r| r.group(tag, &settings))
    }

    /// The PLC's `[[plc.X.group]]` tables.
    pub fn groups(&self, plc: &str) -> &[Map<String, Json>] {
        self.groups.get(plc).map_or(&[], Vec::as_slice)
    }

    /// See [`Resolver::always`].
    pub fn always(&self, plc: &str) -> Vec<String> {
        self.with(plc, Resolver::always)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Json) -> Map<String, Json> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn glob_patterns() {
        assert!(glob_match("Tank[*].Level", "tank[3].LEVEL"));
        assert!(glob_match("PLC1/Bench.*", "PLC1/Bench.SpeedSP"));
        assert!(glob_match("A?C", "abc"));
        assert!(!glob_match("A?C", "abbc"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("Arr[[]3]", "Arr[3]"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn canonical_indexes() {
        assert_eq!(canonical("A[02].B[ 3, 4]"), "A[2].B[3,4]");
        assert_eq!(canonical("A[x]"), "A[x]");
        assert_eq!(normalize("Tank[01].Level"), "tank[1].level");
        assert_eq!(strip_indexes("a[1].b[2,3]"), "a.b");
    }

    #[test]
    fn parts_and_bits() {
        assert_eq!(parts("A[1].B.3"), vec!["A", "[1]", "B", "3"]);
        assert_eq!(split_bit("X.3"), Some(("X", "3")));
        assert_eq!(split_bit("X.Y"), None);
        assert_eq!(split_bit(".3"), None);
        assert_eq!(
            program_split("Program:Main.Tag.X"),
            ("Program:Main.".into(), "Tag.X")
        );
        assert_eq!(program_split("Program:Main"), ("Program:Main.".into(), ""));
    }

    fn resolver() -> Resolver {
        let decorators = obj(json!({
            "temperature": {"units": "°C", "rate_ms": 1000},
            "speed": {"units": "rpm", "min": 0, "max": 3000},
            "setpoint": {"writable": true},
            "fast": {"rate_ms": 250},
        }));
        let udt = obj(json!({
            "MotorData": {"Temp": "temperature", "SpeedSP": {"use": ["speed", "setpoint"], "description": "SP"}},
            "PumpData": {"Motor": "fast"},
        }));
        let tags = obj(json!({
            "Pump1": "fast",
            "TankLevel": "temperature",
            "Pumps[2].Motor.SpeedSP": {"max": 1500},
            "Program:Main.StatusWord": {"bits": {"EStop": 0, "DoorOpen": 1}},
        }));
        let rules = vec![obj(
            json!({"match": "Line.*", "units": "m", "writable": true}),
        )];
        let mut r = Resolver::new(&decorators, &udt, &tags, rules, vec![], "plc.P").unwrap();
        let tag_list = vec![
            json!({"name": "Pump1", "type": "PumpData"}),
            json!({"name": "Pumps", "type": "PumpData", "dims": [3]}),
            json!({"name": "TankLevel", "type": "REAL", "dims": [4]}),
        ];
        let types = obj(json!({
            "PumpData": {"members": {"Motor": {"type": "MotorData"}}},
            "MotorData": {"members": {"Temp": {"type": "REAL"}, "SpeedSP": {"type": "REAL"}}},
        }));
        r.set_types(&tag_list, &types);
        r
    }

    #[test]
    fn decorators_resolve_like_the_python_server() {
        let r = resolver();
        let sp = r.effective("Pumps[1].Motor.SpeedSP");
        assert_eq!(sp.get("max"), Some(&json!(3000)));
        assert_eq!(sp.get("writable"), Some(&json!(true)));
        assert_eq!(sp.get("rate_ms"), Some(&json!(250)));
        assert_eq!(sp.get("group"), Some(&json!("fast")));
        assert_eq!(
            r.effective("Pumps[2].Motor.SpeedSP").get("max"),
            Some(&json!(1500))
        );
        let temp = r.effective("Pump1.Motor.Temp");
        assert_eq!(temp.get("rate_ms"), Some(&json!(1000)));
        assert_eq!(temp.get("group"), Some(&json!("temperature")));
        assert_eq!(r.effective("TankLevel[3]").get("units"), Some(&json!("°C")));
        // a bit: writable from its word only
        let bit = r.effective("Pumps[1].Motor.SpeedSP.3");
        assert_eq!(bit.get("writable"), Some(&json!(true)));
        assert!(!bit.contains_key("max"));
        // rules fill what decorators leave unset
        assert_eq!(r.effective("Line.Speed").get("units"), Some(&json!("m")));
    }

    #[test]
    fn groups_from_decorators_then_tables() {
        let mut r = resolver();
        r.groups = vec![obj(
            json!({"name": "slow", "rate_ms": 2000, "match": "Other*"}),
        )];
        let s = r.effective("OtherTag");
        assert_eq!(
            r.group("OtherTag", &s),
            Some(Group {
                name: "slow".into(),
                rate_ms: 2000
            })
        );
        let s = r.effective("Pump1.Motor.Temp");
        assert_eq!(
            r.group("Pump1.Motor.Temp", &s),
            Some(Group {
                name: "temperature".into(),
                rate_ms: 1000
            })
        );
    }

    #[test]
    fn always_expands_udt_members_and_keys() {
        let decorators = obj(json!({"alarm": {"always": true}}));
        let udt = obj(json!({"MotorData": {"Fault": "alarm"}}));
        let tags = obj(json!({"Pumps.Motor.Temp": "alarm"}));
        let rules = vec![obj(json!({"match": ["Status", "Bad*"], "always": true}))];
        let mut r = Resolver::new(&decorators, &udt, &tags, rules, vec![], "plc.P").unwrap();
        r.set_types(
            &[
                json!({"name": "Pumps", "type": "PumpData", "dims": [2]}),
                json!({"name": "M", "type": "MotorData"}),
            ],
            &obj(json!({
                "PumpData": {"members": {"Motor": {"type": "MotorData"}}},
                "MotorData": {"members": {"Temp": {"type": "REAL"}, "Fault": {"type": "BOOL"}}},
            })),
        );
        assert_eq!(
            r.always(),
            vec![
                "Status",
                "Pumps[0].Motor.Temp",
                "Pumps[1].Motor.Temp",
                "Pumps[0].Motor.Fault",
                "Pumps[1].Motor.Fault",
                "M.Fault"
            ]
        );
    }

    #[test]
    fn bit_names_resolve() {
        let config = crate::config::parse_config(
            &toml::from_str::<Json>(
                "[plc.P]\npath=\"x\"\n[[plc.P.rule]]\nmatch=\"W\"\nbits={EStop=0, Door=1}\n",
            )
            .unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let rules = Rules::new(&config).unwrap();
        assert_eq!(rules.resolve("P", "W.estop"), "W.0");
        assert_eq!(rules.resolve("P", "W.Door"), "W.1");
        assert_eq!(rules.resolve("P", "W.Other"), "W.Other");
        assert_eq!(rules.resolve("P", "W.3"), "W.3");
    }
}
