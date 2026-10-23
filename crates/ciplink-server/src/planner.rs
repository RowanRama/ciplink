//! Read planner: one read of a struct instead of several reads of its members, which are sliced out of it.
//!
//! A poll costs about 12 ms per packet plus 1.35 ms per read service, so fewer reads matter, but an extra packet
//! costs far more than a few reads. For the tags of one cycle, a struct (a tag, an array element or a nested
//! member, at most `whole_max_bytes`) or a run of elements of one atomic array (`A[3]{5}`) replaces the reads of
//! the tags under it when that pays: groups are taken best first by extra reply bytes per read saved, each only if
//! it costs at most [`BYTES_PER_READ`] extra reply bytes per read saved and the cycle's estimated packet count does
//! not grow over plain reads. A `together` struct is always read whole.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

use ciplink::Value;
use ciplink::cip::TagResult;
use indexmap::IndexMap;

use crate::plc::{Catalog, Kind, Node, Plc, atomic_size};

/// One read service (~1.35 ms) costs about as much packet time as this many reply bytes.
pub const BYTES_PER_READ: u64 = 450;
/// Request and reply budget of a packet when the driver has no connection size.
pub const PACKET_BYTES: usize = 4000;
/// Request bytes of ciplink's tag table version check, sent in every packet with instance IDs.
pub const VERSION_REQUEST: usize = 20;
/// Reply bytes of ciplink's tag table version check.
pub const VERSION_REPLY: usize = 44;

/// A slice step into a read value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    /// A struct member (matched ignoring case).
    Member(String),
    /// An array element.
    Index(usize),
}

/// One read service of a plan and the requested tags it serves.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Read {
    /// The tag name read: a tag, a struct (`Line1.Motor`) or a run (`Trend[3]{5}`).
    pub name: String,
    /// `(tag, path)`: the keys that slice the tag's value out of the read value, None for the value as read.
    pub members: Vec<(String, Option<Vec<Key>>)>,
}

// ------------------------------------------------------------------------------------------------ names

/// What a token of a tag name addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Name(String),
    Index(usize),
    /// A multi-dimensional index; never sliced through.
    Multi(Vec<usize>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    text: String,
    key: Tok,
}

/// The tokens of a tag name; None for what is never grouped: bit access (`X.5`), `X{3}`, odd syntax.
fn tokenize(name: &str) -> Option<Vec<Token>> {
    let (prefix, rest) = match name.get(..8) {
        Some(head) if head.eq_ignore_ascii_case("program:") => {
            let dot = name.find('.')?;
            (&name[..=dot], &name[dot + 1..])
        }
        _ => ("", name),
    };
    let bytes = rest.as_bytes();
    let mut tokens: Vec<Token> = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;
        if bytes[pos] == b'[' {
            let end = pos + rest[pos..].find(']')?;
            let index = rest[pos + 1..end]
                .split(',')
                .map(|i| {
                    if i.is_empty() || !i.bytes().all(|b| b.is_ascii_digit()) {
                        None
                    } else {
                        i.parse::<usize>().ok()
                    }
                })
                .collect::<Option<Vec<_>>>()?;
            pos = end + 1;
            let key = match index.as_slice() {
                [one] => Tok::Index(*one),
                _ => Tok::Multi(index),
            };
            tokens.push(Token {
                text: rest[start..pos].to_owned(),
                key,
            });
            continue;
        }
        let dotted = bytes[pos] == b'.';
        if dotted != (pos > 0) {
            return None; // the first name has no dot, the others need one
        }
        if dotted {
            pos += 1;
        }
        if !bytes
            .get(pos)
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        {
            return None;
        }
        let name_start = pos;
        while bytes
            .get(pos)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            pos += 1;
        }
        tokens.push(Token {
            text: rest[start..pos].to_owned(),
            key: Tok::Name(rest[name_start..pos].to_owned()),
        });
    }
    let first = tokens.first_mut()?;
    let Tok::Name(base) = &first.key else {
        return None;
    };
    first.key = Tok::Name(format!("{prefix}{base}"));
    first.text = format!("{prefix}{}", first.text);
    Some(tokens)
}

fn join(tokens: &[Token]) -> String {
    tokens.iter().map(|t| t.text.as_str()).collect()
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn padded(text: &str) -> usize {
    2 + text.len() + text.len() % 2
}

fn index_size(i: usize) -> usize {
    if i < 256 { 2 } else { 4 }
}

/// A BOOL array: its elements are bits, never sliced through or read as a run.
fn bools(node: &Node) -> bool {
    node.bool_array() || node.type_name == "BOOL"
}

// ------------------------------------------------------------------------------------------------ sizes

/// Estimated size of a Read Tag service for `name`, the base tag addressed by its instance ID (a 16-bit ID when
/// unknown, as on most real controllers).
fn request_size(name: &str, catalog: &Catalog) -> usize {
    let Some(tokens) = tokenize(name) else {
        return 10 + name.len() + name.len() % 2;
    };
    let base = &tokens[0].text;
    let instance = catalog.info(base).and_then(|n| n.instance_id);
    let mut size = 8 + match instance {
        Some(i) if i < 256 => 2,
        Some(i) if i >= 65536 => 6,
        _ => 4,
    };
    if base
        .get(..8)
        .is_some_and(|h| h.eq_ignore_ascii_case("program:"))
    {
        size += padded(base.split('.').next().unwrap_or_default());
    }
    for token in &tokens[1..] {
        size += match &token.key {
            Tok::Name(n) => padded(n),
            Tok::Index(i) => index_size(*i),
            Tok::Multi(v) => v.iter().map(|i| index_size(*i)).sum(),
        };
    }
    size
}

/// Estimated reply size of a read of one element of `node` (12 when unknown).
fn reply_size(node: Option<&Node>) -> usize {
    match node {
        None => 12,
        Some(n) if n.kind != Kind::Atomic => {
            to_usize(n.structure_size.unwrap_or(4)).saturating_add(10)
        }
        Some(n) => to_usize(atomic_size(&n.type_name).unwrap_or(4)) + 8,
    }
}

/// `A[3]{5}` as `("A[3]", 5)`.
fn range(name: &str) -> Option<(&str, usize)> {
    let digits = name.strip_suffix('}')?;
    let brace = digits.rfind('{')?;
    let (base, count) = (&digits[..brace], &digits[brace + 1..]);
    if base.is_empty() || count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((base, count.parse().ok()?))
}

/// Estimated (request, reply) sizes of a read of `name` as [`plan`] writes it, `A[3]{5}` included.
fn read_size(name: &str, catalog: &Catalog) -> (usize, usize) {
    let Some((base, count)) = range(name) else {
        return (request_size(name, catalog), reply_size(catalog.info(name)));
    };
    let array = catalog.info(base);
    let request = request_size(base, catalog);
    if array.is_some_and(bools) {
        return (request, count.div_ceil(32) * 4 + 8); // BOOLs, 32 per word
    }
    let overhead = if array.is_some_and(|a| a.kind != Kind::Atomic) {
        10
    } else {
        8
    };
    let element = reply_size(array).saturating_sub(overhead);
    (
        request,
        count.saturating_mul(element).saturating_add(overhead),
    )
}

/// Size of one element of an atomic 1-D array whose elements can be read as a run, else None. Elements of
/// BOOL arrays and of bit strings (BYTE, WORD, DWORD, LWORD) are bits and never run.
fn element_size(node: Option<&Node>) -> Option<usize> {
    let node = node?;
    if node.kind != Kind::Atomic || node.dims.len() != 1 {
        return None;
    }
    match node.type_name.as_str() {
        "BOOL" | "BYTE" | "WORD" | "DWORD" | "LWORD" => None,
        t => atomic_size(t).map(to_usize),
    }
}

/// The structure size if the path is one struct that can be read whole, else None.
fn struct_size(catalog: &Catalog, node: Option<&Node>, last: &Tok) -> Option<u64> {
    let node = node?;
    if matches!(last, Tok::Name(_)) && !node.dims.is_empty() {
        return None; // a whole array: a read without an index gets its first element only
    }
    catalog.struct_size(node)
}

// ------------------------------------------------------------------------------------------------ packets

/// The indexes of the reads in each packet and the packet count, packed in order as ciplink does: the other
/// reads first, then each fragmented read alone, taking several packets. A read sent alone also gets a
/// standalone version check before and after it (the worker sends each in its own plc.read, so both count).
fn pack(sizes: &[(usize, usize)], budget: usize) -> (Vec<Vec<usize>>, usize) {
    let (empty_request, empty_reply) = (10 + VERSION_REQUEST, 8 + VERSION_REPLY);
    let mut groups = Vec::new();
    let mut fragmented = Vec::new();
    let mut count = 0;
    let mut current = Vec::new();
    let (mut request, mut reply) = (empty_request, empty_reply);
    for (i, &(req, rep)) in sizes.iter().enumerate() {
        if empty_request.saturating_add(req) > budget || empty_reply.saturating_add(rep) > budget {
            fragmented.push(vec![i]);
            count += rep
                .div_ceil(budget.saturating_sub(empty_reply).max(1))
                .max(1)
                + 2;
            continue;
        }
        if !current.is_empty() && (request + req > budget || reply + rep > budget) {
            groups.push(std::mem::take(&mut current));
            count += 1;
            (request, reply) = (empty_request, empty_reply);
        }
        current.push(i);
        request += req;
        reply += rep;
    }
    if !current.is_empty() {
        groups.push(current);
        count += 1;
    }
    groups.extend(fragmented);
    (groups, count)
}

/// Packets for reads of these (request, reply) sizes, packed in order as ciplink does.
pub fn packets(sizes: &[(usize, usize)], budget: usize) -> usize {
    pack(sizes, budget).1
}

// ------------------------------------------------------------------------------------------------ plan

/// A read while planning: its group key (None for a plain read), the tags it serves, sizes and name.
#[derive(Clone)]
struct Pending {
    key: Option<String>,
    members: Vec<String>,
    size: (usize, usize),
    name: String,
}

/// A run of requested elements of one atomic array.
struct Run<'a> {
    array: String,
    size: usize,
    index: HashMap<&'a str, usize>,
}

/// A merge of the reads under one key.
struct Merged {
    reads: Vec<Pending>,
    saved: usize,
    extra: i128,
    name: String,
}

/// The reads for `tags` in packet order. `catalog` holds the tag definitions; names in `no_group` (lowercase)
/// are not read whole; `budget` is bytes per packet; `together(struct path)` is true if the requested tags under
/// that struct are always read in one read.
pub fn plan(
    tags: &[String],
    catalog: &Catalog,
    whole_max_bytes: u64,
    no_group: &HashSet<String>,
    budget: usize,
    together: Option<&dyn Fn(&str) -> bool>,
) -> Vec<Read> {
    let mut parsed: HashMap<&str, Vec<Token>> = HashMap::new();
    let mut ancestors: Vec<(&str, Vec<String>)> = Vec::new(); // structs above a tag that read whole, deepest first
    let mut depth: HashMap<&str, HashMap<String, usize>> = HashMap::new(); // tag -> key -> tokens of that struct
    let mut names: HashMap<String, String> = HashMap::new(); // struct key -> read name
    let mut sizes: IndexMap<String, u64> = IndexMap::new(); // struct key -> structure size
    let mut levels: HashMap<String, usize> = HashMap::new(); // struct key -> number of tokens
    let mut whole: HashMap<String, &str> = HashMap::new(); // key -> requested tag that is itself that struct
    let mut elements: IndexMap<String, Vec<(usize, &str)>> = IndexMap::new(); // array key -> requested elements
    let mut arrays: HashMap<String, (String, usize)> = HashMap::new(); // array key -> (name, element size)
    let mut seen = HashSet::new();
    for tag in tags {
        let Some(tokens) = tokenize(tag) else {
            continue;
        };
        if !seen.insert(tag.to_lowercase()) {
            continue;
        }
        let n = tokens.len();
        let last = &tokens[n - 1].key;
        let Some(info) = catalog.info(tag) else {
            continue;
        };
        if !info.dims.is_empty() && matches!(last, Tok::Name(_)) {
            continue; // an array read without an index (its first element only)
        }
        if let (true, Tok::Index(i)) = (n > 1, last) {
            let array = join(&tokens[..n - 1]);
            let akey = array.to_lowercase();
            if let Some(size) = element_size(catalog.info(&array)) {
                if !no_group.contains(&akey) {
                    elements
                        .entry(akey.clone())
                        .or_default()
                        .push((*i, tag.as_str()));
                    arrays.insert(akey, (array, size));
                }
            }
        }
        let mut found = Vec::new();
        for k in (1..=n).rev() {
            if k < n {
                // the slice gains token k: a name, or an index of an array that is not BOOLs
                match &tokens[k].key {
                    Tok::Multi(_) => break,
                    Tok::Index(_) => {
                        if !catalog.info(&join(&tokens[..k])).is_some_and(|a| !bools(a)) {
                            break;
                        }
                    }
                    Tok::Name(_) => {}
                }
            }
            let prefix = join(&tokens[..k]);
            let key = prefix.to_lowercase();
            if no_group.contains(&key) {
                continue;
            }
            let Some(size) = struct_size(catalog, catalog.info(&prefix), &tokens[k - 1].key) else {
                continue;
            };
            depth
                .entry(tag.as_str())
                .or_default()
                .insert(key.clone(), k);
            names.entry(key.clone()).or_insert(prefix);
            sizes.insert(key.clone(), size);
            levels.insert(key.clone(), k);
            if k == n {
                whole.insert(key, tag.as_str());
            } else {
                found.push(key);
            }
        }
        ancestors.push((tag.as_str(), found));
        parsed.insert(tag.as_str(), tokens);
    }

    let mut under: HashMap<String, HashSet<&str>> = HashMap::new(); // key -> the tags it can serve
    for (tag, found) in &ancestors {
        for key in found {
            under.entry(key.clone()).or_default().insert(tag);
        }
    }
    for (key, tag) in &whole {
        under.entry(key.clone()).or_default().insert(tag);
    }
    let mut candidates: BTreeSet<String> = under
        .iter()
        .filter(|(key, served)| {
            served.len() >= 2
                && (whole.contains_key(*key)
                    || sizes.get(*key).is_some_and(|s| *s <= whole_max_bytes))
        })
        .map(|(key, _)| key.clone())
        .collect();

    // array runs: the requested elements, split where bridging the gap alone would break the cost rule
    let mut runs: HashMap<String, Run> = HashMap::new();
    for (akey, items) in &mut elements {
        items.sort_unstable();
        let (array, size) = &arrays[akey];
        let mut clusters: Vec<Vec<(usize, &str)>> = Vec::new();
        for &(index, tag) in items.iter() {
            let gap = clusters.last().and_then(|c| c.last()).map(|&(prev, _)| {
                index
                    .saturating_sub(prev)
                    .saturating_sub(1)
                    .saturating_mul(*size)
            });
            if gap.is_none_or(|g| g as u64 > BYTES_PER_READ) {
                clusters.push(Vec::new());
            }
            if let Some(c) = clusters.last_mut() {
                c.push((index, tag));
            }
        }
        for (c, cluster) in clusters.iter().enumerate() {
            if cluster.len() >= 2 {
                let key = format!("{akey}{{{c}"); // a "{" is never in a struct key
                under.insert(key.clone(), cluster.iter().map(|&(_, t)| t).collect());
                runs.insert(
                    key.clone(),
                    Run {
                        array: array.clone(),
                        size: *size,
                        index: cluster.iter().map(|&(i, t)| (t, i)).collect(),
                    },
                );
                candidates.insert(key);
            }
        }
    }

    let start_of = |run: &Run, members: &[String]| -> (usize, usize) {
        let indexes = members
            .iter()
            .filter_map(|t| run.index.get(t.as_str()).copied());
        let start = indexes.clone().min().unwrap_or(0);
        (start, indexes.max().unwrap_or(start) - start + 1)
    };
    // the read name and sizes of the read of `key` that serves `members`
    let group = |key: &str, members: &[String]| -> (String, (usize, usize)) {
        match runs.get(key) {
            None => {
                let name = names.get(key).cloned().unwrap_or_default();
                let reply = to_usize(sizes.get(key).copied().unwrap_or(0)).saturating_add(10);
                let request = request_size(&name, catalog);
                (name, (request, reply))
            }
            Some(run) => {
                let (start, count) = start_of(run, members);
                let element = format!("{}[{start}]", run.array);
                let reply = count.saturating_mul(run.size).saturating_add(8);
                (
                    format!("{element}{{{count}}}"),
                    (request_size(&element, catalog), reply),
                )
            }
        }
    };
    // the reads with the ones all under `key` merged at the first one's place, None if fewer than two
    let merge = |key: &str, reads: &[Pending]| -> Option<Merged> {
        let served = under.get(key)?;
        let covered: Vec<usize> = (0..reads.len())
            .filter(|&i| reads[i].members.iter().all(|t| served.contains(t.as_str())))
            .collect();
        if covered.len() < 2 {
            return None;
        }
        let members: Vec<String> = covered
            .iter()
            .flat_map(|&i| reads[i].members.iter().cloned())
            .collect();
        let (name, size) = group(key, &members);
        let before: usize = covered.iter().map(|&i| reads[i].size.1).sum();
        let extra = size.1 as i128 - before as i128;
        let mut new = Vec::with_capacity(reads.len() + 1 - covered.len());
        for (i, r) in reads.iter().enumerate() {
            if i == covered[0] {
                new.push(Pending {
                    key: Some(key.to_owned()),
                    members: members.clone(),
                    size,
                    name: name.clone(),
                });
            } else if !covered.contains(&i) {
                new.push(r.clone());
            }
        }
        Some(Merged {
            reads: new,
            saved: covered.len() - 1,
            extra,
            name,
        })
    };
    let sizes_of =
        |reads: &[Pending]| -> Vec<(usize, usize)> { reads.iter().map(|r| r.size).collect() };

    // start plain, sized as chunks() sizes them
    let mut reads: Vec<Pending> = tags
        .iter()
        .map(|tag| Pending {
            key: None,
            members: vec![tag.clone()],
            size: read_size(tag, catalog),
            name: tag.clone(),
        })
        .collect();
    if let Some(together) = together {
        // outermost first; ignores whole_max_bytes and the cost rule, but must fit one packet
        let fits = budget.saturating_sub(8 + VERSION_REPLY);
        let mut keys: Vec<&String> = sizes
            .iter()
            .filter(|(k, s)| {
                under.get(*k).is_some_and(|u| u.len() >= 2)
                    && to_usize(**s).saturating_add(10) <= fits
            })
            .map(|(k, _)| k)
            .collect();
        keys.sort_by_key(|k| levels.get(*k).copied().unwrap_or(0)); // stable: upload order within a level
        for key in keys {
            if together(names.get(key).map_or("", String::as_str)) {
                if let Some(merged) = merge(key, &reads) {
                    reads = merged.reads;
                }
                candidates.remove(key);
            }
        }
    }
    let limit = packets(&sizes_of(&reads), budget);
    loop {
        // best: lowest extra bytes per read saved, then most reads saved, then key
        let mut best: Option<(String, Merged)> = None;
        for key in &candidates {
            let Some(merged) = merge(key, &reads) else {
                continue;
            };
            if merged.extra > i128::from(BYTES_PER_READ) * merged.saved as i128
                || no_group.contains(&merged.name.to_lowercase())
                || packets(&sizes_of(&merged.reads), budget) > limit
            {
                continue;
            }
            let better = best.as_ref().is_none_or(|(_, b)| {
                (merged.extra * b.saved as i128)
                    .cmp(&(b.extra * merged.saved as i128))
                    .then(b.saved.cmp(&merged.saved))
                    == Ordering::Less
            });
            if better {
                best = Some((key.clone(), merged));
            }
        }
        let Some((key, merged)) = best else { break };
        reads = merged.reads;
        candidates.remove(&key);
    }

    reads
        .into_iter()
        .map(|r| {
            let members = match &r.key {
                None => vec![(r.name.clone(), None)],
                Some(key) => match runs.get(key) {
                    Some(run) => {
                        let (start, _) = start_of(run, &r.members);
                        r.members
                            .iter()
                            .map(|t| {
                                let i = run.index.get(t.as_str()).copied().unwrap_or(start);
                                (t.clone(), Some(vec![Key::Index(i - start)]))
                            })
                            .collect()
                    }
                    None => r
                        .members
                        .iter()
                        .map(|t| {
                            let tokens = parsed.get(t.as_str()).map_or(&[][..], Vec::as_slice);
                            let k = depth
                                .get(t.as_str())
                                .and_then(|d| d.get(key))
                                .copied()
                                .unwrap_or(tokens.len());
                            let path = (k < tokens.len()).then(|| {
                                tokens[k..]
                                    .iter()
                                    .map(|tok| match &tok.key {
                                        Tok::Name(n) => Key::Member(n.clone()),
                                        Tok::Index(i) => Key::Index(*i),
                                        // never in a path: plan() stops slicing at a multi-dimensional index
                                        Tok::Multi(v) => {
                                            Key::Index(v.first().copied().unwrap_or(0))
                                        }
                                    })
                                    .collect()
                            });
                            (t.clone(), path)
                        })
                        .collect(),
                },
            };
            Read {
                name: r.name,
                members,
            }
        })
        .collect()
}

/// `reads` (a plan) split into lists of about one packet each, packed as [`packets`] counts them.
pub fn chunks(reads: Vec<Read>, catalog: &Catalog, budget: usize) -> Vec<Vec<Read>> {
    let sizes: Vec<_> = reads.iter().map(|r| read_size(&r.name, catalog)).collect();
    let (groups, _) = pack(&sizes, budget);
    let mut slots: Vec<Option<Read>> = reads.into_iter().map(Some).collect();
    groups
        .into_iter()
        .map(|g| {
            g.into_iter()
                .filter_map(|i| slots.get_mut(i).and_then(Option::take))
                .collect()
        })
        .collect()
}

/// The part of a read value at `path` (member names ignoring case, array indexes), None if it isn't there.
pub fn dig(value: &Value, path: &[Key]) -> Option<Value> {
    let mut value = value;
    for key in path {
        value = match (key, value) {
            (Key::Index(i), Value::Array(items)) => items.get(*i)?,
            (Key::Member(m), Value::Struct(members)) => members.get(m).or_else(|| {
                members
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(m))
                    .map(|(_, v)| v)
            })?,
            _ => return None,
        };
    }
    Some(value.clone())
}

/// Runs a plan split in chunks, one `plc.read` per chunk; `between(plc, partial results)` runs after every chunk
/// but the last (the worker publishes those results and runs queued writes there), and its results are left out
/// of the returned ones. Returns (results by tag, names of failed group reads, read services sent). The members
/// of failed group reads are read one by one after the last chunk, so no value is ever wrong. Err = a lost
/// connection from `plc.read`, or an error from `between`.
#[allow(clippy::type_complexity)]
pub fn execute(
    plc: &mut dyn Plc,
    chunks: &[Vec<Read>],
    between: &mut dyn FnMut(&mut dyn Plc, HashMap<String, TagResult>) -> Result<(), String>,
) -> Result<(HashMap<String, TagResult>, Vec<String>, usize), String> {
    let mut out = HashMap::new();
    let mut retry: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let mut services = 0;
    for (n, chunk) in chunks.iter().enumerate() {
        let names: Vec<&str> = chunk.iter().map(|r| r.name.as_str()).collect();
        let results = if names.is_empty() {
            Vec::new()
        } else {
            plc.read(&names)?
        };
        services += names.len();
        let mut part = HashMap::new();
        for (read, result) in chunk.iter().zip(results) {
            if let [(tag, None)] = read.members.as_slice() {
                part.insert(tag.clone(), result);
                continue;
            }
            if result.error.is_some() {
                failed.push(read.name.clone());
                retry.extend(read.members.iter().map(|(t, _)| t.clone()));
                continue;
            }
            for (tag, path) in &read.members {
                let Some(path) = path else {
                    part.insert(tag.clone(), result.clone());
                    continue;
                };
                match result.value.as_ref().and_then(|v| dig(v, path)) {
                    Some(value) => {
                        let sliced = TagResult {
                            tag: tag.clone(),
                            value: Some(value),
                            data_type: None,
                            error: None,
                        };
                        part.insert(tag.clone(), sliced);
                    }
                    None => {
                        if !failed.contains(&read.name) {
                            failed.push(read.name.clone());
                        }
                        retry.push(tag.clone());
                    }
                }
            }
        }
        if n + 1 < chunks.len() {
            between(&mut *plc, part)?;
        } else {
            out.extend(part);
        }
    }
    if !retry.is_empty() {
        let names: Vec<&str> = retry.iter().map(String::as_str).collect();
        let results = plc.read(&names)?;
        out.extend(retry.iter().cloned().zip(results));
    }
    Ok((out, failed, services + retry.len()))
}

#[cfg(test)]
mod tests {
    //! Ports of ciplink-tagserver's tests/test_planner.py, on the same fake controller (its conftest.py).

    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ciplink::{ErrorKind, TagError};
    use regex::Regex;
    use serde_json::Value as Json;

    use super::*;
    use crate::plc::{Aoi, TypeDef};

    // -------------------------------------------------------------------------------------------- catalog

    fn atomic(t: &str, dims: &[u64]) -> Node {
        Node {
            type_name: t.into(),
            kind: Kind::Atomic,
            dims: dims.to_vec(),
            member: false,
            instance_id: None,
            structure_size: None,
        }
    }

    fn strct(t: &str, size: u64, dims: &[u64]) -> Node {
        Node {
            kind: Kind::Struct,
            structure_size: Some(size),
            ..atomic(t, dims)
        }
    }

    fn udt(size: u64, members: Vec<(&str, Node)>, whole_read: Option<bool>) -> TypeDef {
        TypeDef {
            public: members.iter().map(|(m, _)| (*m).to_owned()).collect(),
            members: members
                .into_iter()
                .map(|(m, n)| (m.to_owned(), Node { member: true, ..n }))
                .collect(),
            structure_size: size,
            aoi: whole_read.map(|whole_read| Aoi {
                whole_read,
                readable: Vec::new(),
            }),
            whole_readable: true,
        }
    }

    fn dints(size: u64) -> TypeDef {
        udt(
            size,
            vec![("A", atomic("DINT", &[])), ("B", atomic("DINT", &[]))],
            None,
        )
    }

    fn base_types() -> Vec<(&'static str, TypeDef)> {
        let bools = |names: &[&'static str]| {
            names
                .iter()
                .map(|n| (*n, atomic("BOOL", &[])))
                .collect::<Vec<_>>()
        };
        let valve = bools(&["EnableIn", "EnableOut", "Open", "Cmd"]);
        let mut pump = bools(&["EnableIn", "EnableOut", "Run"]);
        pump.push(("Speed", atomic("REAL", &[])));
        let real = || atomic("REAL", &[]);
        let dint = || atomic("DINT", &[]);
        let motor = vec![
            ("Speed", real()),
            ("Current", real()),
            ("Running", atomic("BOOL", &[])),
            ("Count", dint()),
        ];
        let station = vec![
            ("Motor", strct("Motor", 40, &[])),
            ("Ready", atomic("BOOL", &[])),
            ("Data", atomic("DINT", &[4])),
            ("Bits", atomic("DWORD", &[1])), // a BOOL[32] member
        ];
        // Cell holds an AOI that can't be read whole
        let cell = vec![
            ("Valve", strct("Valve_AOI", 60, &[])),
            ("Mode", dint()),
            ("Step", dint()),
        ];
        let tank = vec![
            ("Level", real()),
            ("Temp", real()),
            ("Valve", atomic("BOOL", &[])),
        ];
        vec![
            ("Motor", udt(40, motor, None)),
            ("Station", udt(200, station, None)),
            ("Big", dints(4000)),
            ("Valve_AOI", udt(60, valve, Some(false))),
            ("Pump_AOI", udt(40, pump, Some(true))),
            ("Cell", udt(300, cell, None)),
            ("Tank", udt(12, tank, None)),
        ]
    }

    fn base_tags() -> Vec<(&'static str, Node)> {
        let string = Node {
            kind: Kind::String,
            ..strct("STRING", 88, &[])
        };
        vec![
            ("Line1", strct("Station", 200, &[])),
            ("Line2", strct("Station", 200, &[])),
            ("Arr", strct("Station", 200, &[5])),
            ("Program:Station1.Motor", strct("Motor", 40, &[])),
            ("Big1", strct("Big", 4000, &[])),
            ("Valve1", strct("Valve_AOI", 60, &[])),
            ("Pump1", strct("Pump_AOI", 40, &[])),
            ("Cell1", strct("Cell", 300, &[])),
            ("Name1", string),
            ("Speed", atomic("REAL", &[])),
            ("Count", atomic("DINT", &[])),
            ("Flags", atomic("DINT", &[])),
            ("Trend", atomic("REAL", &[16])),
            ("Long", atomic("REAL", &[1000])),
            ("BoolArr", atomic("DWORD", &[32])), // ciplink's BOOL[32]
            ("Tank", strct("Tank", 12, &[4])),
            ("Grid", atomic("DINT", &[4, 4])),
        ]
    }

    fn catalog_with(tags: Vec<(&str, Node)>, types: Vec<(&str, TypeDef)>) -> Catalog {
        let tags = base_tags()
            .into_iter()
            .chain(tags)
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        let types = base_types()
            .into_iter()
            .chain(types)
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        Catalog::new(Json::Null, tags, types)
    }

    fn catalog() -> Catalog {
        catalog_with(vec![], vec![])
    }

    fn blob(size: u64) -> Catalog {
        catalog_with(
            vec![("Blob1", strct("Blob", size, &[]))],
            vec![("Blob", dints(size))],
        )
    }

    // -------------------------------------------------------------------------------------------- values

    fn st(members: Vec<(&str, Value)>) -> Value {
        Value::Struct(
            members
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }

    fn motor(speed: f32) -> Value {
        st(vec![
            ("Speed", Value::Real(speed)),
            ("Current", Value::Real(speed / 10.0)),
            ("Running", Value::Bool(true)),
            ("Count", Value::DInt(0b101101)),
        ])
    }

    fn station(n: i32) -> Value {
        st(vec![
            ("Motor", motor(n as f32 * 1.5)),
            ("Ready", Value::Bool(n % 2 == 0)),
            ("Data", Value::Array((n..n + 4).map(Value::DInt).collect())),
            ("Bits", Value::Array(vec![Value::Bool(true); 32])),
        ])
    }

    fn values() -> HashMap<String, Value> {
        let b = Value::Bool;
        let tank = |i: i32| {
            st(vec![
                ("Level", Value::Real(i as f32 * 10.0)),
                ("Temp", Value::Real(20.0 + i as f32)),
                ("Valve", b(i % 2 == 0)),
            ])
        };
        let pump = vec![
            ("EnableIn", b(true)),
            ("EnableOut", b(true)),
            ("Run", b(true)),
            ("Speed", Value::Real(12.5)),
        ];
        let cell = vec![
            (
                "Valve",
                st(vec![
                    ("EnableIn", b(true)),
                    ("EnableOut", b(false)),
                    ("Open", b(true)),
                ]),
            ),
            ("Mode", Value::DInt(2)),
            ("Step", Value::DInt(30)),
        ];
        let pairs = vec![
            ("Line1", station(1)),
            ("Line2", station(2)),
            ("Arr", Value::Array((0..5).map(station).collect())),
            ("Program:Station1.Motor", motor(7.5)),
            (
                "Big1",
                st(vec![("A", Value::DInt(1)), ("B", Value::DInt(2))]),
            ),
            // Cmd is local: not readable
            (
                "Valve1",
                st(vec![
                    ("EnableIn", b(true)),
                    ("EnableOut", b(true)),
                    ("Open", b(false)),
                ]),
            ),
            ("Pump1", st(pump)),
            ("Cell1", st(cell)),
            ("Name1", Value::String("hello".into())),
            ("Speed", Value::Real(3.5)),
            ("Count", Value::DInt(9)),
            ("Flags", Value::DInt(0b1010)),
            (
                "Trend",
                Value::Array((0..16).map(|i| Value::Real(i as f32 / 2.0)).collect()),
            ),
            (
                "Long",
                Value::Array((0..1000).map(|i| Value::Real(i as f32)).collect()),
            ),
            (
                "BoolArr",
                Value::Array((0..32).map(|i| b(i % 3 == 0)).collect()),
            ),
            ("Tank", Value::Array((0..4).map(tank).collect())),
        ];
        pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }

    // -------------------------------------------------------------------------------------------- fake PLC

    #[derive(Debug, PartialEq)]
    enum Event {
        Read(Vec<String>),
        Between(Vec<String>),
    }

    /// The fake driver of conftest.py: values by tag; member paths, bits and ranges are read out of them.
    struct Fake {
        catalog: Catalog,
        values: HashMap<String, Value>,
        errors: HashMap<String, String>,
        log: Arc<Mutex<Vec<Event>>>,
    }

    impl Fake {
        fn new(catalog: Catalog) -> Self {
            Fake {
                catalog,
                values: values(),
                errors: HashMap::new(),
                log: Arc::default(),
            }
        }

        fn reads(&self) -> Vec<Vec<String>> {
            let log = self.log.lock().expect("log");
            log.iter()
                .filter_map(|e| match e {
                    Event::Read(names) => Some(names.clone()),
                    Event::Between(_) => None,
                })
                .collect()
        }

        fn value(&self, name: &str) -> Option<Value> {
            if let Some(v) = self.values.get(name) {
                return Some(v.clone());
            }
            let (prefix, rest) = if name.to_lowercase().starts_with("program:") {
                let (p, r) = name.split_once('.')?;
                (format!("{p}."), r)
            } else {
                (String::new(), name)
            };
            let re = Regex::new(r"[^.\[\]]+|\[\d+\]").expect("regex");
            let parts: Vec<&str> = re.find_iter(rest).map(|m| m.as_str()).collect();
            let base = format!("{prefix}{}", parts.first()?);
            let mut value = self
                .values
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&base))
                .map(|(_, v)| v.clone())?;
            for part in &parts[1..] {
                value = if let Some(i) = part.strip_prefix('[') {
                    dig(&value, &[Key::Index(i.trim_end_matches(']').parse().ok()?)])?
                } else if part.bytes().all(|b| b.is_ascii_digit()) {
                    let bit: u32 = part.parse().ok()?;
                    match value {
                        Value::DInt(v) => Value::Bool(v >> bit & 1 == 1),
                        _ => return None,
                    }
                } else {
                    dig(&value, &[Key::Member((*part).to_owned())])?
                };
            }
            Some(value)
        }

        fn result(&self, tag: &str, range: &Regex) -> TagResult {
            let mut result = TagResult {
                tag: tag.to_owned(),
                value: None,
                data_type: None,
                error: None,
            };
            if let Some(e) = self.errors.get(tag) {
                result.error = Some(TagError::new(e.clone(), ErrorKind::Device));
                return result;
            }
            let value = match range.captures(tag) {
                Some(c) => {
                    let start: usize = c.get(2).map_or(0, |m| m.as_str().parse().expect("start"));
                    let count: usize = c[3].parse().expect("count");
                    match self.value(&c[1]) {
                        Some(Value::Array(items)) if items.len() >= start + count => {
                            Some(Value::Array(items[start..start + count].to_vec()))
                        }
                        _ => None,
                    }
                }
                None => self.value(tag),
            };
            match value {
                Some(v) => {
                    result.value = Some(v);
                    result.data_type = Some("DINT".into());
                }
                None => {
                    let message = format!("Tag doesn't exist - {tag}");
                    result.error = Some(TagError::new(message, ErrorKind::NotFound));
                }
            }
            result
        }
    }

    impl Plc for Fake {
        fn open(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn close(&mut self) {}

        fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>, String> {
            let names = tags.iter().map(|t| (*t).to_owned()).collect();
            self.log.lock().expect("log").push(Event::Read(names));
            let range = Regex::new(r"^(.+?)(?:\[(\d+)\])?\{(\d+)\}$").expect("regex");
            Ok(tags.iter().map(|tag| self.result(tag, &range)).collect())
        }

        fn write(&mut self, _tag: &str, _value: &Value) -> Result<TagResult, String> {
            Err("not used".into())
        }

        fn catalog(&mut self) -> Catalog {
            self.catalog.clone()
        }

        fn version(&mut self) -> Json {
            Json::Null
        }

        fn connection_size(&self) -> usize {
            PACKET_BYTES
        }
    }

    // -------------------------------------------------------------------------------------------- helpers

    type Grouped = BTreeMap<String, Vec<String>>;
    type Got = HashMap<String, (Option<Value>, Option<TagError>)>;
    type Together<'a> = Option<&'a dyn Fn(&str) -> bool>;

    fn owned(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|t| (*t).to_owned()).collect()
    }

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|t| (*t).to_owned()).collect()
    }

    fn grouped(reads: Vec<Read>) -> Grouped {
        reads
            .into_iter()
            .map(|r| {
                let mut tags: Vec<String> = r.members.into_iter().map(|(t, _)| t).collect();
                tags.sort();
                (r.name, tags)
            })
            .collect()
    }

    /// {read name: sorted requested tags it serves}
    fn reads_with(
        c: &Catalog,
        tags: &[&str],
        whole_max: u64,
        no_group: &[&str],
        budget: usize,
        together: Together,
    ) -> Grouped {
        grouped(plan(
            &owned(tags),
            c,
            whole_max,
            &set(no_group),
            budget,
            together,
        ))
    }

    fn reads(c: &Catalog, tags: &[&str]) -> Grouped {
        reads_with(c, tags, 1500, &[], 4000, None)
    }

    fn expect(pairs: &[(&str, &[&str])]) -> Grouped {
        pairs
            .iter()
            .map(|(name, tags)| ((*name).to_owned(), owned(tags)))
            .collect()
    }

    fn plain(tags: &[&str]) -> Grouped {
        tags.iter()
            .map(|t| ((*t).to_owned(), vec![(*t).to_owned()]))
            .collect()
    }

    fn got(results: HashMap<String, TagResult>) -> Got {
        results
            .into_iter()
            .map(|(t, r)| (t, (r.value, r.error)))
            .collect()
    }

    /// What reading each tag on its own gives.
    fn direct(fake: &mut Fake, tags: &[&str]) -> Got {
        let results = fake.read(tags).expect("read");
        got(owned(tags).into_iter().zip(results).collect())
    }

    /// Plans, chunks and executes `tags`: (results of every chunk, failed group reads, services).
    fn run(fake: &mut Fake, tags: &[&str], together: Together) -> (Got, Vec<String>, usize) {
        let c = fake.catalog.clone();
        let parts = chunks(
            plan(&owned(tags), &c, 1500, &set(&[]), 4000, together),
            &c,
            4000,
        );
        let mut given = HashMap::new();
        let (out, failed, services) = execute(fake, &parts, &mut |_, part| {
            given.extend(part);
            Ok(())
        })
        .expect("execute");
        given.extend(out);
        (got(given), failed, services)
    }

    fn sizes(names: &[&str], c: &Catalog) -> Vec<(usize, usize)> {
        names.iter().map(|n| read_size(n, c)).collect()
    }

    // -------------------------------------------------------------------------------------------- tests

    #[test]
    fn tokenize_splits_names_and_refuses_what_is_never_grouped() {
        let toks = |name: &str| {
            tokenize(name).map(|t| t.into_iter().map(|t| (t.text, t.key)).collect::<Vec<_>>())
        };
        let n = |s: &str| Tok::Name(s.into());
        let expected = vec![
            ("Arr".into(), n("Arr")),
            ("[3]".into(), Tok::Index(3)),
            (".Status".into(), n("Status")),
            (".Ready".into(), n("Ready")),
        ];
        assert_eq!(toks("Arr[3].Status.Ready"), Some(expected));
        let expected = vec![
            ("Program:Station1.Motor".into(), n("Program:Station1.Motor")),
            (".Speed".into(), n("Speed")),
        ];
        assert_eq!(toks("Program:Station1.Motor.Speed"), Some(expected));
        assert_eq!(
            toks("M[1,2].X").expect("tokens")[1],
            ("[1,2]".into(), Tok::Multi(vec![1, 2]))
        );
        for never in ["X.Count.5", "X{3}", "X..Y", "[1]", "Program:Main", ""] {
            assert_eq!(toks(never), None, "{never}");
        }
    }

    #[test]
    fn groups_members_and_merges_child_groups_into_the_parent() {
        let c = catalog();
        assert_eq!(
            reads(&c, &["Line1.Motor.Speed", "Line1.Motor.Current", "Speed"]),
            expect(&[
                ("Line1.Motor", &["Line1.Motor.Current", "Line1.Motor.Speed"]),
                ("Speed", &["Speed"])
            ])
        );
        // Line1.Motor (40 B) first, then Line1 (200 B) takes it and two more: 4 reads -> 1
        let tags = [
            "Line1.Motor.Speed",
            "Line1.Motor.Current",
            "Line1.Ready",
            "Line1.Data[2]",
            "Speed",
        ];
        let line1: &[&str] = &[
            "Line1.Data[2]",
            "Line1.Motor.Current",
            "Line1.Motor.Speed",
            "Line1.Ready",
        ];
        assert_eq!(
            reads(&c, &tags),
            expect(&[("Line1", line1), ("Speed", &["Speed"])])
        );
        let tags = ["Line1.Motor.Speed", "Line2.Motor.Speed"]; // no common struct
        assert_eq!(reads(&c, &tags), plain(&tags));
    }

    #[test]
    fn array_elements_and_program_tags() {
        let tags = [
            "Arr[3].Motor.Speed",
            "Arr[3].Ready",
            "Arr[1].Ready",
            "Program:Station1.Motor.Speed",
            "Program:Station1.Motor.Running",
        ];
        let program: &[&str] = &[
            "Program:Station1.Motor.Running",
            "Program:Station1.Motor.Speed",
        ];
        assert_eq!(
            reads(&catalog(), &tags),
            expect(&[
                ("Arr[3]", &["Arr[3].Motor.Speed", "Arr[3].Ready"]),
                ("Program:Station1.Motor", program),
                ("Arr[1].Ready", &["Arr[1].Ready"]), // a whole array is never read for its elements
            ])
        );
    }

    #[test]
    fn whole_max_bytes_caps_the_struct_size() {
        let c = blob(300);
        let tags = ["Blob1.A", "Blob1.B"];
        assert_eq!(reads(&c, &tags), expect(&[("Blob1", &tags)]));
        assert_eq!(reads_with(&c, &tags, 299, &[], 4000, None), plain(&tags));
        let tags = ["Line1.Motor.Speed", "Line1.Ready"];
        assert_eq!(reads_with(&c, &tags, 100, &[], 4000, None), plain(&tags));
    }

    #[test]
    fn extra_reply_bytes_per_read_saved_threshold() {
        // reply: size + 10 whole vs 2 x (4 + 8) plain, so 450 extra bytes for one saved read at 464
        let tags = ["Blob1.A", "Blob1.B"];
        assert_eq!(reads(&blob(464), &tags), expect(&[("Blob1", &tags)]));
        assert_eq!(reads(&blob(465), &tags), plain(&tags));
        // a big struct is fine when it saves enough reads (Big1 is 4000 B, never with the default cap)
        assert_eq!(
            reads_with(&catalog(), &["Big1.A", "Big1.B"], 5000, &[], 4000, None).len(),
            2
        );
    }

    #[test]
    fn a_group_never_adds_a_packet() {
        let c = catalog();
        let tags = ["Line1.Motor.Speed", "Line1.Motor.Current"];
        let plain_sizes: Vec<_> = tags
            .iter()
            .map(|t| (request_size(t, &c), reply_size(c.info(t))))
            .collect();
        let group = [(
            request_size("Line1.Motor", &c),
            reply_size(c.info("Line1.Motor")),
        )];
        let plain_reply: usize = plain_sizes.iter().map(|s| s.1).sum();
        let plain_request: usize = plain_sizes.iter().map(|s| s.0).sum();
        assert!(group[0].1 > plain_reply); // the whole read is the bigger reply
        let budget = (52 + plain_reply).max(30 + plain_request) + 10; // room for the plain reads,
        assert!(52 + group[0].1 > budget); // not for the whole reply
        assert_eq!(packets(&plain_sizes, budget), 1);
        assert_eq!(packets(&group, budget), 2 + 2); // fragmented: version checks around
        assert_eq!(reads_with(&c, &tags, 1500, &[], budget, None), plain(&tags));
        assert_eq!(
            reads(&c, &tags),
            expect(&[("Line1.Motor", &[tags[1], tags[0]])])
        );
    }

    #[test]
    fn packet_estimate_packs_in_order() {
        assert_eq!(packets(&[(30, 1000); 3], 4000), 1);
        assert_eq!(packets(&[(30, 1000); 4], 4000), 2); // 52 bytes of reply overhead per packet
        assert_eq!(packets(&[(30, 5000)], 4000), 2 + 2); // fragmented, with a version check before and after
        assert_eq!(packets(&[], 4000), 0);
    }

    #[test]
    fn aois_are_read_whole_only_when_the_probe_allows() {
        let c = catalog();
        assert_eq!(reads(&c, &["Valve1.Open", "Valve1.EnableIn"]).len(), 2); // whole read refused
        let tags = ["Pump1.Run", "Pump1.Speed"];
        assert_eq!(reads(&c, &tags), expect(&[("Pump1", &tags)]));
        assert_eq!(reads(&c, &["Cell1.Mode", "Cell1.Step"]).len(), 2); // holds such an AOI
        let tags = ["Cell1.Valve.Open", "Cell1.Mode"];
        assert_eq!(reads(&c, &tags), plain(&tags));
    }

    #[test]
    fn never_grouped() {
        // Line1.Bits[3] is an element of a BOOL array: never sliced out of Line1
        let tags = [
            "Line1.Motor.Count.0",
            "Line1.Motor.Count.2",
            "Line1.Data{2}",
            "Line1.Motor.Speed",
            "Line1.Bits[3]",
            "Line1.Data",
            "Name1.LEN",
            "Name1.DATA",
            "Nope.A",
            "Nope.B",
        ];
        assert_eq!(reads(&catalog(), &tags), plain(&tags));
    }

    #[test]
    fn requested_struct_is_the_group_read() {
        let c = catalog();
        let tags = ["Line1.Motor", "Line1.Motor.Speed", "Line1.Motor.Running"];
        let mut sorted = tags;
        sorted.sort_unstable();
        assert_eq!(reads(&c, &tags), expect(&[("Line1.Motor", &sorted)]));
        // also when it is too big to be chosen otherwise
        assert_eq!(
            reads(&c, &["Big1", "Big1.A"]),
            expect(&[("Big1", &["Big1", "Big1.A"])])
        );
        // and it joins a bigger group when there is one anyway
        let tags = ["Line1.Motor", "Line1.Motor.Speed", "Line1.Ready"];
        assert_eq!(reads(&c, &tags), expect(&[("Line1", &tags)]));
    }

    #[test]
    fn sliced_values_are_what_member_reads_give() {
        let mut fake = Fake::new(catalog());
        let tags = [
            "Line1.Motor.Speed",
            "line1.motor.current",
            "Line1.Ready",
            "Line1.Data[2]",
            "Arr[3].Motor.Speed",
            "Arr[3].Data[0]",
            "Program:Station1.Motor.Speed",
            "Program:Station1.Motor.Count",
            "Line2.Motor",
            "Line2.Motor.Running",
            "Pump1.Speed",
            "Pump1.Run",
            "Speed",
            "Count.1",
            "Nope",
        ];
        let (got, failed, services) = run(&mut fake, &tags, None);
        assert_eq!(got, direct(&mut fake, &tags));
        assert!(failed.is_empty());
        // Line1, Arr[3], Program:Station1.Motor, Line2.Motor, Pump1, Speed, Count.1, Nope
        assert_eq!(services, 8);
    }

    #[test]
    fn group_error_falls_back_to_member_reads() {
        let mut fake = Fake::new(catalog());
        fake.errors
            .insert("Line1.Motor".into(), "General error".into());
        let tags = ["Line1.Motor.Speed", "Line1.Motor.Current", "Speed"];
        let (got, failed, services) = run(&mut fake, &tags, None);
        assert_eq!(
            fake.reads()[1],
            owned(&["Line1.Motor.Speed", "Line1.Motor.Current"])
        );
        assert_eq!(got, direct(&mut fake, &tags));
        assert_eq!((failed, services), (owned(&["Line1.Motor"]), 4));
        // once known bad, it isn't read whole again; the next struct up still can be
        let c = catalog();
        assert_eq!(
            reads_with(&c, &tags, 1500, &["line1.motor"], 4000, None),
            expect(&[
                ("Line1", &["Line1.Motor.Current", "Line1.Motor.Speed"]),
                ("Speed", &["Speed"])
            ])
        );
        assert_eq!(
            reads_with(&c, &tags, 1500, &["line1.motor", "line1"], 4000, None),
            plain(&tags)
        );
    }

    #[test]
    fn slice_failure_falls_back() {
        let mut fake = Fake::new(catalog());
        if let Some(Value::Struct(line1)) = fake.values.get_mut("Line1") {
            line1.insert("Motor".into(), Value::DInt(5)); // the whole read no longer holds the member
        }
        fake.values
            .insert("Line1.Motor.Speed".into(), Value::Real(1.0));
        fake.values
            .insert("Line1.Motor.Current".into(), Value::Real(2.0));
        let (got, failed, _) = run(
            &mut fake,
            &["Line1.Motor.Speed", "Line1.Ready", "Line1.Motor.Current"],
            None,
        );
        assert_eq!(got["Line1.Motor.Speed"], (Some(Value::Real(1.0)), None));
        assert_eq!(got["Line1.Motor.Current"], (Some(Value::Real(2.0)), None));
        assert_eq!(failed, owned(&["Line1"]));
    }

    #[test]
    fn array_runs() {
        let bit_strings = vec![
            ("Words", atomic("WORD", &[10])),
            ("Bytes", atomic("BYTE", &[10])),
        ];
        let c = catalog_with(bit_strings, vec![]);
        assert_eq!(
            reads(&c, &["Trend[3]", "Trend[4]", "Trend[7]", "Speed"]),
            expect(&[
                ("Trend[3]{5}", &["Trend[3]", "Trend[4]", "Trend[7]"]),
                ("Speed", &["Speed"])
            ])
        );
        // a member array: the run is cheaper than the whole struct
        assert_eq!(
            reads(
                &c,
                &[
                    "Line1.Data[0]",
                    "Line1.Data[3]",
                    "Arr[2].Data[1]",
                    "Arr[2].Data[2]"
                ]
            ),
            expect(&[
                ("Line1.Data[0]{4}", &["Line1.Data[0]", "Line1.Data[3]"]),
                ("Arr[2].Data[1]{2}", &["Arr[2].Data[1]", "Arr[2].Data[2]"]),
            ])
        );
        // never runs: BOOL bits, bit string elements (new in the Rust port), struct elements, members of
        // elements, 2-D, whole arrays, a single element
        let never: [&[&str]; 9] = [
            &["BoolArr[1]", "BoolArr[2]"],
            &["Line1.Bits[0]", "Line1.Bits[1]"],
            &["Words[1]", "Words[2]"],
            &["Bytes[1]", "Bytes[2]"],
            &["Tank[1].Level", "Tank[2].Level"],
            &["Grid[1,1]", "Grid[1,2]"],
            &["Trend", "Trend[1]"],
            &["Trend[5]", "Speed"],
            &["Arr[1]", "Arr[2]"],
        ];
        for tags in never {
            assert_eq!(reads(&c, tags), plain(tags), "{tags:?}");
        }
        // a run that failed is not used again, nor is anything of a failed array
        let tags = ["Trend[3]", "Trend[4]"];
        assert_eq!(
            reads_with(&c, &tags, 1500, &["trend[3]{2}"], 4000, None).len(),
            2
        );
        assert_eq!(reads_with(&c, &tags, 1500, &["trend"], 4000, None).len(), 2);
    }

    #[test]
    fn array_run_cost_rule() {
        let c = catalog();
        // REAL: (last + 1) * 4 + 8 reply bytes vs 2 x 12 plain: 440 extra bytes for one saved read at 113
        for (last, grouped) in [(113, true), (114, false)] {
            let last_tag = format!("Long[{last}]");
            let tags = ["Long[0]", last_tag.as_str()];
            let run = BTreeMap::from([(format!("Long[0]{{{}}}", last + 1), owned(&tags))]);
            assert_eq!(reads(&c, &tags) == run, grouped, "{last}");
        }
        // far apart elements make separate runs
        assert_eq!(
            reads(&c, &["Long[0]", "Long[1]", "Long[500]", "Long[502]"]),
            expect(&[
                ("Long[0]{2}", &["Long[0]", "Long[1]"]),
                ("Long[500]{3}", &["Long[500]", "Long[502]"])
            ])
        );
    }

    #[test]
    fn array_run_never_adds_a_packet() {
        let c = catalog();
        let tags = ["Trend[0]", "Trend[15]"];
        let plain_sizes = sizes(&tags, &c);
        let whole = sizes(&["Trend[0]{16}"], &c);
        assert_eq!((whole[0].1, plain_sizes[0].1), (16 * 4 + 8, 12));
        assert_eq!(
            (packets(&plain_sizes, 100), packets(&whole, 100)),
            (1, 2 + 2)
        );
        assert_eq!(reads_with(&c, &tags, 1500, &[], 100, None), plain(&tags));
        assert_eq!(reads(&c, &tags), expect(&[("Trend[0]{16}", &tags)]));
    }

    #[test]
    fn array_run_values_are_sliced() {
        let mut fake = Fake::new(catalog());
        let tags = [
            "Trend[3]",
            "Trend[4]",
            "Trend[7]",
            "Line1.Data[0]",
            "Line1.Data[3]",
            "Line1.Ready",
            "Speed",
        ];
        let (got, failed, services) = run(&mut fake, &tags, None);
        assert_eq!(got, direct(&mut fake, &tags));
        assert!(failed.is_empty());
        assert_eq!(got["Trend[7]"], (Some(Value::Real(3.5)), None));
        assert_eq!(services, 3); // Trend run, Line1 (it took the Data run), Speed
        // the run now reads past the end: its members are read one by one
        fake.values.insert(
            "Trend".into(),
            Value::Array(vec![Value::Real(1.0), Value::Real(2.0)]),
        );
        let (got, failed, _) = run(&mut fake, &["Trend[0]", "Trend[1]", "Trend[3]"], None);
        assert_eq!(failed, owned(&["Trend[0]{4}"]));
        assert_eq!(got["Trend[1]"], (Some(Value::Real(2.0)), None));
        assert_eq!(
            got["Trend[3]"].1.as_ref().map(|e| e.kind),
            Some(ErrorKind::NotFound)
        );
    }

    #[test]
    fn together_reads_a_struct_whole() {
        let c = catalog();
        let all = |_: &str| true;
        let line1 = |p: &str| p == "Line1";
        let tags = ["Line1.Motor.Speed", "Line1.Ready"];
        assert_eq!(reads_with(&c, &tags, 100, &[], 4000, None), plain(&tags));
        assert_eq!(
            reads_with(&c, &tags, 100, &[], 4000, Some(&line1)),
            expect(&[("Line1", &tags)])
        );
        // regardless of cost; outermost first; never for one tag or a struct over one packet
        let tags = ["Blob1.A", "Blob1.B"];
        assert_eq!(
            reads_with(&blob(3000), &tags, 1500, &[], 4000, Some(&all)),
            expect(&[("Blob1", &tags)])
        );
        let tags = ["Line1.Motor.Speed", "Line1.Motor.Current", "Line1.Ready"];
        assert_eq!(
            reads_with(&c, &tags, 1500, &[], 4000, Some(&all)),
            expect(&[(
                "Line1",
                &["Line1.Motor.Current", "Line1.Motor.Speed", "Line1.Ready"]
            )])
        );
        let two = ["Line1.Motor.Speed", "Speed"];
        assert_eq!(
            reads_with(&c, &two, 1500, &[], 4000, Some(&all)),
            plain(&two)
        );
        let big = ["Big1.A", "Big1.B"];
        assert_eq!(
            reads_with(&c, &big, 1500, &[], 4000, Some(&all)),
            plain(&big)
        );
        let seen = RefCell::new(Vec::new());
        let record = |p: &str| {
            seen.borrow_mut().push(p.to_owned());
            false
        };
        reads_with(
            &c,
            &["Arr[1].Motor.Speed", "Arr[1].Motor.Count"],
            1500,
            &[],
            4000,
            Some(&record),
        );
        assert_eq!(seen.into_inner(), owned(&["Arr[1]", "Arr[1].Motor"]));
        // a failed together read falls back to its members like any group
        let mut fake = Fake::new(catalog());
        fake.errors.insert("Line1".into(), "General error".into());
        let (got, failed, _) = run(&mut fake, &tags, Some(&line1));
        assert_eq!(failed, owned(&["Line1"]));
        assert_eq!(got, direct(&mut fake, &tags));
    }

    #[test]
    fn chunks_are_one_packet_each() {
        let c = catalog();
        let mut tags = owned(&["Line1.Motor.Speed", "Line2.Motor.Speed"]);
        tags.extend((0..16).step_by(5).map(|i| format!("Trend[{i}]")));
        tags.extend((0..5).map(|i| format!("Arr[{i}].Ready")));
        tags.extend(owned(&["Speed", "Count", "Name1", "Big1", "Flags"]));
        let budget = 200;
        let planned = plan(&tags, &c, 1500, &set(&[]), budget, None);
        let parts = chunks(planned.clone(), &c, budget);
        let mut flat: Vec<Read> = parts.iter().flatten().cloned().collect();
        let mut sorted = planned;
        flat.sort();
        sorted.sort();
        assert_eq!(flat, sorted);
        assert_eq!(parts.len(), 3);
        // as ciplink: the fragmented read after the others
        let big1 = Read {
            name: "Big1".into(),
            members: vec![("Big1".into(), None)],
        };
        assert_eq!(parts[2], vec![big1]);
        let part_sizes: Vec<Vec<(usize, usize)>> = parts
            .iter()
            .map(|part| part.iter().map(|r| read_size(&r.name, &c)).collect())
            .collect();
        let big = packets(&sizes(&["Big1"], &c), budget); // fragmented: alone, several packets
        let all: Vec<(usize, usize)> = part_sizes.iter().flatten().copied().collect();
        assert!(big > 1);
        assert_eq!(parts.len(), packets(&all, budget) - big + 1);
        for (part, size) in parts.iter().zip(&part_sizes) {
            assert!(
                packets(size, budget) == 1 || part.iter().map(|r| r.name.as_str()).eq(["Big1"])
            );
        }
        assert!(chunks(Vec::new(), &c, PACKET_BYTES).is_empty());
    }

    #[test]
    fn a_fragmented_read_does_not_split_the_reads_around_it() {
        let sizes = [(30, 100), (30, 5000), (30, 100)];
        assert_eq!(packets(&sizes, 4000), 5); // one packet for both small reads
        assert_eq!(pack(&sizes, 4000).0, vec![vec![0, 2], vec![1]]);
    }

    #[test]
    fn read_size_of_ranges() {
        let c = catalog_with(vec![("Bits", atomic("DWORD", &[128]))], vec![]); // ciplink's BOOL[128]
        let station = reply_size(c.info("Arr")); // structure_size + 10
        assert_eq!(read_size("Arr{4}", &c).1, 4 * (station - 10) + 10);
        assert_eq!(read_size("Bits{64}", &c).1, 2 * 4 + 8);
        assert_eq!(read_size("Trend[2]{3}", &c).1, 3 * 4 + 8);
    }

    #[test]
    fn between_runs_after_each_chunk_but_the_last() {
        let mut fake = Fake::new(catalog());
        let c = fake.catalog.clone();
        let tags = [
            "Line1.Motor.Speed",
            "Line1.Motor.Current",
            "Speed",
            "Count",
            "Trend[1]",
            "Trend[2]",
            "Flags",
            "Name1",
        ];
        let planned = plan(&owned(&tags), &c, 1500, &set(&[]), 100, None);
        let count = planned.len();
        let parts = chunks(planned, &c, 100);
        assert!(parts.len() >= 3);
        let log = Arc::clone(&fake.log);
        let mut given = HashMap::new();
        let (out, failed, services) = execute(&mut fake, &parts, &mut |_, part| {
            let mut names: Vec<String> = part.keys().cloned().collect();
            names.sort();
            log.lock().expect("log").push(Event::Between(names));
            given.extend(part);
            Ok(())
        })
        .expect("execute");
        let mut expected = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            expected.push(Event::Read(part.iter().map(|r| r.name.clone()).collect()));
            if i + 1 < parts.len() {
                let mut names: Vec<String> = part
                    .iter()
                    .flat_map(|r| r.members.iter().map(|(t, _)| t.clone()))
                    .collect();
                names.sort();
                expected.push(Event::Between(names));
            }
        }
        assert_eq!(*fake.log.lock().expect("log"), expected);
        assert!(out.keys().all(|t| !given.contains_key(t)));
        given.extend(out);
        assert_eq!(given.keys().cloned().collect::<HashSet<_>>(), set(&tags));
        assert_eq!(got(given), direct(&mut fake, &tags));
        assert_eq!((services, failed.len()), (count, 0));
    }

    #[test]
    fn failed_group_is_read_after_the_last_chunk() {
        let mut fake = Fake::new(catalog());
        let c = fake.catalog.clone();
        fake.errors
            .insert("Line1.Motor".into(), "General error".into());
        let tags = [
            "Line1.Motor.Speed",
            "Line1.Motor.Current",
            "Speed",
            "Count",
            "Flags",
            "Name1",
        ];
        let parts = chunks(plan(&owned(&tags), &c, 1500, &set(&[]), 150, None), &c, 150);
        assert!(parts.len() >= 2 && parts[0][0].name == "Line1.Motor");
        let mut given = HashMap::new();
        let (out, failed, _) = execute(&mut fake, &parts, &mut |_, part| {
            given.extend(part);
            Ok(())
        })
        .expect("execute");
        let sent = fake.reads();
        assert_eq!(sent.len(), parts.len() + 1);
        assert_eq!(
            sent.last(),
            Some(&owned(&["Line1.Motor.Speed", "Line1.Motor.Current"]))
        );
        assert_eq!(failed, owned(&["Line1.Motor"]));
        assert!(out.contains_key("Line1.Motor.Speed") && !given.contains_key("Line1.Motor.Speed"));
        given.extend(out);
        assert_eq!(got(given), direct(&mut fake, &tags));
    }

    #[test]
    fn execute_takes_a_plain_plan_or_nothing() {
        let mut fake = Fake::new(catalog());
        let c = fake.catalog.clone();
        let planned = plan(
            &owned(&["Speed", "Count"]),
            &c,
            1500,
            &set(&[]),
            PACKET_BYTES,
            None,
        );
        let mut never =
            |_: &mut dyn Plc, _| -> Result<(), String> { panic!("one chunk: no between") };
        let (out, failed, services) = execute(&mut fake, &[planned], &mut never).expect("execute");
        let values: HashMap<String, Option<Value>> =
            out.into_iter().map(|(t, r)| (t, r.value)).collect();
        let expected = HashMap::from([
            ("Speed".to_owned(), Some(Value::Real(3.5))),
            ("Count".to_owned(), Some(Value::DInt(9))),
        ]);
        assert_eq!(values, expected);
        assert_eq!((failed.len(), services), (0, 2));
        let (out, failed, services) = execute(&mut fake, &[], &mut never).expect("execute");
        assert!(out.is_empty() && failed.is_empty() && services == 0);
    }

    #[test]
    fn execute_passes_on_a_lost_connection() {
        let mut fake = Fake::new(catalog());
        let parts = vec![vec![Read {
            name: "Speed".into(),
            members: vec![("Speed".into(), None)],
        }]];
        struct Lost<'a>(&'a mut Fake);
        impl Plc for Lost<'_> {
            fn open(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn close(&mut self) {}
            fn read(&mut self, _: &[&str]) -> Result<Vec<TagResult>, String> {
                Err("connection lost".into())
            }
            fn write(&mut self, tag: &str, value: &Value) -> Result<TagResult, String> {
                self.0.write(tag, value)
            }
            fn catalog(&mut self) -> Catalog {
                self.0.catalog()
            }
            fn version(&mut self) -> Json {
                Json::Null
            }
            fn connection_size(&self) -> usize {
                PACKET_BYTES
            }
        }
        let result = execute(&mut Lost(&mut fake), &parts, &mut |_, _| Ok(()));
        assert_eq!(result, Err("connection lost".into()));
    }

    #[test]
    fn request_size_follows_the_instance_id_and_assumes_16_bits() {
        let tag = |id| Node {
            instance_id: Some(id),
            ..atomic("DINT", &[])
        };
        let tags = [("small", tag(5)), ("mid", tag(300)), ("big", tag(70000))];
        let tags = tags.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
        let c = Catalog::new(Json::Null, tags, IndexMap::new());
        let got: Vec<usize> = ["small", "mid", "big"]
            .iter()
            .map(|n| request_size(&format!("{n}.Level"), &c))
            .collect();
        assert_eq!(got, vec![18, 20, 22]);
        assert_eq!(request_size("Motor7.Level", &c), 20); // unknown: 16 bits
    }

    #[test]
    fn a_run_that_turns_fragmented_is_not_taken_for_free() {
        let tags = IndexMap::from([("Trend".to_owned(), atomic("REAL", &[2000]))]);
        let c = Catalog::new(Json::Null, tags, IndexMap::new());
        let tags: Vec<String> = (0..1000)
            .step_by(2)
            .map(|i| format!("Trend[{i}]"))
            .collect();
        // ciplink sends it as check, 2 fragments, check: more than the 2 packets of plain reads
        assert_eq!(packets(&sizes(&["Trend[0]{999}"], &c), 4000), 2 + 2);
        assert_eq!(
            plan(&tags, &c, 1500, &set(&[]), 4000, None).len(),
            tags.len()
        );
    }

    #[test]
    fn dig_slices_members_ignoring_case_and_elements() {
        let value = station(1);
        let path = [Key::Member("motor".into()), Key::Member("SPEED".into())];
        assert_eq!(dig(&value, &path), Some(Value::Real(1.5)));
        assert_eq!(
            dig(&value, &[Key::Member("Data".into()), Key::Index(3)]),
            Some(Value::DInt(4))
        );
        assert_eq!(
            dig(&value, &[Key::Member("Data".into()), Key::Index(4)]),
            None
        );
        assert_eq!(dig(&value, &[Key::Index(0)]), None); // not an array
        assert_eq!(dig(&Value::DInt(5), &[Key::Member("Speed".into())]), None); // not a struct
        assert_eq!(dig(&value, &[]), Some(value.clone()));
    }
}
