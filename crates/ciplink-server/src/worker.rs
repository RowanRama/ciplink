//! One thread per PLC: owns the driver, polls the subscribed tags by tier and poll group, runs the queued writes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ciplink::Value;
use ciplink::cip::TagResult;
use indexmap::IndexMap;
use serde_json::{Map, Value as Json, json};

use crate::config::PlcConfig;
use crate::planner::{self, Read};
use crate::plc::{Catalog, Factory, Plc};
use crate::rules::{Group, Rules, split_bit, truthy};
use crate::values::{Entry, merge, now_ms, to_value};

/// Seconds between reconnect attempts, the last one repeats.
const BACKOFF: [f64; 4] = [1.0, 2.0, 5.0, 10.0];
/// Seconds before a tag the PLC doesn't have is asked for again, unless the tag table reloads.
const MISSING_RETRY: f64 = 10.0;
/// Seconds before a struct whose whole read failed is read whole again, unless it reloads.
const GROUP_RETRY: f64 = 60.0;

/// What a worker tells the hub, from its thread.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Changed cache entries of the PLC's tags.
    Values(String, Vec<(String, Entry)>),
    /// The PLC's connection state changed.
    Status(String, &'static str),
    /// The PLC's tag table was reloaded (online edit, download).
    Meta(String),
    /// Controller descriptions of these tags were read.
    Info(String, Vec<String>),
}

/// The outcome of a write: (ok, error, kind, read-back value).
#[derive(Clone, Debug, PartialEq)]
pub struct WriteResult {
    /// The write went through.
    pub ok: bool,
    /// Why it failed.
    pub error: Option<String>,
    /// The error kind (`refused`, `comm`, ciplink's kinds, or the hub's checks).
    pub kind: Option<String>,
    /// The value read back after the write, null if it could not be read.
    pub value: Json,
}

impl WriteResult {
    /// A failed write.
    pub fn failed(error: impl Into<String>, kind: &str) -> Self {
        WriteResult {
            ok: false,
            error: Some(error.into()),
            kind: Some(kind.to_owned()),
            value: Json::Null,
        }
    }
}

/// Called once with a write's result, from whichever thread finishes it.
pub type WriteDone = Box<dyn FnOnce(WriteResult) + Send>;

struct WriteRequest {
    tag: String,
    value: Value,
    done: WriteDone,
}

/// The type of a tag as tag info shows it: null when unknown, dims of a whole array.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeInfo {
    /// The type name, None while unknown.
    pub type_: Option<String>,
    /// Dims of a whole array.
    pub dims: Option<Vec<u64>>,
}

/// The controller structure the worker last loaded, with its `/tags` JSON.
#[derive(Debug, Default)]
pub struct Structure {
    /// Tags and types.
    pub catalog: Catalog,
    /// `GET /tags` `tags`.
    pub tag_list: Vec<Json>,
    /// `GET /tags` `types`.
    pub types: Map<String, Json>,
}

/// Counters for `/health` and `/stats`.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Duration of the last tick.
    pub last_cycle_ms: Option<f64>,
    /// Time of the last good tick, ms since the epoch.
    pub last_ok_ts: Option<i64>,
    /// Read services sent in the last tick, after planning.
    pub reads_per_cycle: usize,
    /// Tags read in the last tick.
    pub tags_per_cycle: usize,
    /// Whole struct reads that failed, their members read one by one instead.
    pub group_fallbacks: u64,
    /// Ticks that took longer than the tick.
    pub overruns: u64,
    /// Reconnect attempts.
    pub reconnects: u64,
    /// Tag table reloads seen.
    pub reloads: u64,
}

#[derive(Default)]
struct Inner {
    /// tag -> 1 (read at its rate), 2 (round robin, every tier2_period) or 3 (not read)
    tiers: IndexMap<String, u8>,
    /// tag that left tier 1 -> (clock time it leaves tier 2, tier after that)
    grace: IndexMap<String, (f64, Option<u8>)>,
    /// tier-2 tags in name order, None when to be rebuilt
    tier2: Option<Vec<String>>,
    slice: usize,
    /// tier-1 tag -> clock time of its last read
    last_read: HashMap<String, f64>,
    /// clock time of the last cycle_ms boundary
    last_cycle: Option<f64>,
    /// tag -> its poll group, memoized
    groups: HashMap<String, Option<Group>>,
    /// group name -> (previous, last) clock time it was read
    group_reads: HashMap<String, (Option<f64>, f64)>,
    /// group name -> rate_ms, of the groups read since the start
    group_rates: IndexMap<String, u64>,
    /// sorted tags -> read chunks, cleared when the subscriptions or the tag table change
    plans: HashMap<Vec<String>, Arc<Vec<Vec<Read>>>>,
    /// lowercase struct path whose whole read failed -> clock time it failed
    no_group: HashMap<String, f64>,
    /// tags just added at tier 2: read in the next tick, then in their slice
    new_tier2: HashSet<String>,
    /// tag -> the latest entry
    cache: HashMap<String, Entry>,
    /// tag -> the entry last given to the hub (deadband reference)
    published: HashMap<String, Entry>,
    /// tag -> clock time to ask for it again; skipped until then
    missing: HashMap<String, f64>,
    /// tags that entered tiers, described in the next tick
    want_descriptions: HashSet<String>,
}

/// Static settings of a worker.
#[derive(Clone)]
pub struct WorkerOptions {
    /// Poll period in seconds.
    pub cycle: f64,
    /// Each tier-2 tag is read about this often.
    pub tier2_period: f64,
    /// A tag leaving tier 1 stays at tier 2 this long.
    pub grace_s: f64,
    /// Read structs whole when that saves reads.
    pub planner: bool,
    /// Largest struct the planner reads whole.
    pub whole_max_bytes: u64,
}

struct Shared {
    name: String,
    cfg: PlcConfig,
    factory: Factory,
    options: WorkerOptions,
    rules: Arc<Rules>,
    on_event: Arc<dyn Fn(Event) + Send + Sync>,
    epoch: Instant,
    state: Mutex<&'static str>,
    inner: Mutex<Inner>,
    writes: Mutex<VecDeque<WriteRequest>>,
    wake: Condvar,
    stop: AtomicBool,
    structure: RwLock<Arc<Structure>>,
    version: Mutex<Json>,
    descriptions: Mutex<HashMap<String, Option<String>>>,
    stats: Mutex<Stats>,
}

/// The poller of one PLC; methods are called from the hub, the thread does the I/O.
pub struct PlcWorker {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Python's `round(x, 1)` for display.
fn round1(x: f64) -> f64 {
    (x * 10.0).round_ties_even() / 10.0
}

impl PlcWorker {
    /// A worker of `cfg`, not started.
    pub fn new(
        cfg: PlcConfig,
        factory: Factory,
        options: WorkerOptions,
        rules: Arc<Rules>,
        on_event: Arc<dyn Fn(Event) + Send + Sync>,
    ) -> Self {
        PlcWorker {
            shared: Arc::new(Shared {
                name: cfg.name.clone(),
                cfg,
                factory,
                options,
                rules,
                on_event,
                epoch: Instant::now(),
                state: Mutex::new("connecting"),
                inner: Mutex::new(Inner::default()),
                writes: Mutex::new(VecDeque::new()),
                wake: Condvar::new(),
                stop: AtomicBool::new(false),
                structure: RwLock::new(Arc::new(Structure::default())),
                version: Mutex::new(Json::Null),
                descriptions: Mutex::new(HashMap::new()),
                stats: Mutex::new(Stats::default()),
            }),
            thread: Mutex::new(None),
        }
    }

    /// Starts the thread.
    pub fn start(&self) {
        let shared = Arc::clone(&self.shared);
        let handle = std::thread::Builder::new()
            .name(format!("plc-{}", self.shared.name))
            .spawn(move || shared.run())
            .ok();
        *lock(&self.thread) = handle;
    }

    /// Stops the thread; writes queued until then still run (a momentary release must reach the PLC).
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        {
            let _writes = lock(&self.shared.writes);
            self.shared.wake.notify_all();
        }
        if let Some(handle) = lock(&self.thread).take() {
            let _ = handle.join();
        }
        self.shared.fail_writes("server stopping"); // any queued after the thread ended
    }

    /// `connecting`, `connected`, `disconnected` or `stopped`.
    pub fn state(&self) -> &'static str {
        *lock(&self.shared.state)
    }

    /// The tag table version, null when unknown.
    pub fn version(&self) -> Json {
        lock(&self.shared.version).clone()
    }

    /// The controller structure last loaded.
    pub fn structure(&self) -> Arc<Structure> {
        Arc::clone(
            &self
                .shared
                .structure
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Counters for `/health` and `/stats`.
    pub fn stats(&self) -> Stats {
        lock(&self.shared.stats).clone()
    }

    /// Number of tags with a tier.
    pub fn subscriptions(&self) -> usize {
        lock(&self.shared.inner).tiers.len()
    }

    /// `{"tier1": n, "tier2": n, "tier3": n}`.
    pub fn tier_counts(&self) -> Map<String, Json> {
        let inner = lock(&self.shared.inner);
        (1..=3u8)
            .map(|n| {
                let count = inner.tiers.values().filter(|&&t| t == n).count();
                (format!("tier{n}"), json!(count))
            })
            .collect()
    }

    /// `{group: {rate_ms, tags (at tier 1 now), last_period_ms}}` for `/stats`: the poll groups, and the decorators
    /// (or `"tag"` for a rate_ms set inline) whose rate a tag was read at.
    pub fn group_stats(&self) -> Map<String, Json> {
        let shared = &self.shared;
        let (counts, reads, rates) = {
            let mut inner = lock(&shared.inner);
            let mut counts: HashMap<String, u64> = HashMap::new();
            let tier1: Vec<String> = inner
                .tiers
                .iter()
                .filter(|(_, t)| **t == 1)
                .map(|(tag, _)| tag.clone())
                .collect();
            for tag in tier1 {
                if let Some(group) = shared.group(&mut inner, &tag) {
                    *counts.entry(group.name).or_default() += 1;
                }
            }
            let mut rates: IndexMap<String, u64> = IndexMap::new();
            for g in shared.rules.groups(&shared.name) {
                if let (Some(name), Some(rate)) =
                    (g.get("name"), g.get("rate_ms").and_then(Json::as_u64))
                {
                    let name = name
                        .as_str()
                        .map_or_else(|| name.to_string(), str::to_owned);
                    rates.insert(name, rate);
                }
            }
            for (name, rate) in &inner.group_rates {
                rates.insert(name.clone(), *rate);
            }
            (counts, inner.group_reads.clone(), rates)
        };
        rates
            .into_iter()
            .map(|(name, rate)| {
                let period = match reads.get(&name) {
                    Some((Some(prev), last)) => json!(round1((last - prev) * 1000.0)),
                    _ => Json::Null,
                };
                let tags = counts.get(&name).copied().unwrap_or(0);
                (
                    name,
                    json!({"rate_ms": rate, "tags": tags, "last_period_ms": period}),
                )
            })
            .collect()
    }

    /// A tag's tier, None when nothing subscribes it. A tag leaving tier 1 for tier 3 or nothing is read at tier 2
    /// for grace_s first, so a page visited again finds its values fresh.
    pub fn set_tier(&self, tag: &str, tier: Option<u8>) {
        let shared = &self.shared;
        let mut inner = lock(&shared.inner);
        if tier.is_some_and(|t| t <= 2) || shared.options.grace_s <= 0.0 {
            shared.set(&mut inner, tag, tier);
        } else if inner.tiers.get(tag) == Some(&1) {
            shared.set(&mut inner, tag, Some(2));
            let deadline = shared.clock() + shared.options.grace_s;
            inner.grace.insert(tag.to_owned(), (deadline, tier));
        } else if let Some(grace) = inner.grace.get_mut(tag) {
            grace.1 = tier;
        } else {
            shared.set(&mut inner, tag, tier);
        }
    }

    /// The latest cache entry of a tag.
    pub fn snapshot(&self, tag: &str) -> Option<Entry> {
        lock(&self.shared.inner).cache.get(tag).cloned()
    }

    /// Queues a write, run between the packets of the current tick; `done` gets the result. Never retried.
    pub fn write(&self, tag: &str, value: Value, done: WriteDone) {
        if self.state() != "connected" {
            done(WriteResult::failed("PLC not connected", "refused"));
            return;
        }
        let mut writes = lock(&self.shared.writes);
        writes.push_back(WriteRequest {
            tag: tag.to_owned(),
            value,
            done,
        });
        self.shared.wake.notify_all();
    }

    /// The type of a tag from the connected controller; a bit is BOOL, the type is None while not connected.
    pub fn type_info(&self, tag: &str) -> TypeInfo {
        if split_bit(tag).is_some() {
            return TypeInfo {
                type_: Some("BOOL".into()),
                dims: None,
            };
        }
        if self.state() != "connected" {
            return TypeInfo::default();
        }
        let structure = self.structure();
        let Some(node) = structure.catalog.info(tag) else {
            return TypeInfo::default();
        };
        let type_ = Some(node.client_type().to_owned()).filter(|t| !t.is_empty());
        let dims = (!tag.ends_with(']') && !node.dims.is_empty()).then(|| node.client_dims());
        TypeInfo { type_, dims }
    }

    /// The controller description of a tag, if read.
    pub fn description(&self, tag: &str) -> Option<String> {
        lock(&self.shared.descriptions).get(tag).cloned().flatten()
    }
}

impl Shared {
    fn clock(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }

    fn emit(&self, event: Event) {
        (self.on_event)(event);
    }

    fn set_state(&self, state: &'static str) {
        let changed = {
            let mut current = lock(&self.state);
            let changed = *current != state;
            *current = state;
            changed
        };
        if changed {
            log::info!("{}: {state}", self.name);
            self.emit(Event::Status(self.name.clone(), state));
        }
    }

    /// Sets a tag's tier, holding the lock.
    fn set(&self, inner: &mut Inner, tag: &str, tier: Option<u8>) {
        inner.grace.shift_remove(tag);
        match tier {
            None => {
                inner.tiers.shift_remove(tag);
                inner.cache.remove(tag);
                inner.published.remove(tag);
                inner.missing.remove(tag);
                inner.groups.remove(tag);
                inner.want_descriptions.remove(tag);
            }
            Some(t) => {
                if t == 2 && matches!(inner.tiers.get(tag), None | Some(3)) {
                    inner.new_tier2.insert(tag.to_owned()); // never read yet: once now, not a period later
                }
                if !inner.tiers.contains_key(tag) && split_bit(tag).is_none() {
                    inner.want_descriptions.insert(tag.to_owned());
                }
                inner.tiers.insert(tag.to_owned(), t);
            }
        }
        if tier != Some(2) {
            inner.new_tier2.remove(tag);
        }
        if tier != Some(1) {
            inner.last_read.remove(tag); // back at tier 1 it is due at the next tick
        }
        inner.tier2 = None;
        inner.plans.clear();
    }

    fn group(&self, inner: &mut Inner, tag: &str) -> Option<Group> {
        if let Some(g) = inner.groups.get(tag) {
            return g.clone();
        }
        let g = self.rules.group(&self.name, tag);
        inner.groups.insert(tag.to_owned(), g.clone());
        g
    }

    fn rate(&self, inner: &mut Inner, tag: &str) -> f64 {
        self.group(inner, tag)
            .map_or(self.options.cycle, |g| g.rate_ms as f64 / 1000.0)
    }

    /// (tags to read this tick, tick in seconds, whether it is a cycle_ms boundary), holding the lock. Tier-1 tags
    /// when due at their rate; the tier-2 slice, grace expiry and version check on boundaries.
    fn cycle_tags(&self, inner: &mut Inner, now: f64) -> (Vec<String>, f64, bool) {
        let cycle = self.options.cycle;
        let tier1 = |inner: &Inner| -> Vec<String> {
            inner
                .tiers
                .iter()
                .filter(|(_, t)| **t == 1)
                .map(|(tag, _)| tag.clone())
                .collect()
        };
        let mut tier1_tags = tier1(inner);
        let mut tick = cycle;
        for tag in &tier1_tags {
            tick = tick.min(self.rate(inner, tag));
        }
        let half = tick / 2.0;
        let boundary = inner
            .last_cycle
            .is_none_or(|last| now + half >= last + cycle);
        let mut tags = Vec::new();
        if boundary {
            inner.last_cycle = Some(now);
            let expired: Vec<(String, Option<u8>)> = inner
                .grace
                .iter()
                .filter(|(_, (deadline, _))| *deadline <= now)
                .map(|(tag, (_, tier))| (tag.clone(), *tier))
                .collect();
            for (tag, tier) in expired {
                self.set(inner, &tag, tier);
            }
            tier1_tags = tier1(inner);
        }
        let mut groups = HashSet::new();
        for tag in tier1_tags {
            let rate = self.rate(inner, &tag);
            let last = inner
                .last_read
                .get(&tag)
                .copied()
                .unwrap_or(f64::NEG_INFINITY);
            if now + half >= last + rate {
                inner.last_read.insert(tag.clone(), now);
                if let Some(group) = self.group(inner, &tag) {
                    inner.group_rates.insert(group.name.clone(), group.rate_ms);
                    groups.insert(group.name);
                }
                tags.push(tag);
            }
        }
        for name in groups {
            let prev = inner.group_reads.get(&name).map(|r| r.1);
            inner.group_reads.insert(name, (prev, now));
        }
        if boundary {
            if inner.tier2.is_none() {
                // in name order, so members of one struct tend to share a slice
                let mut tier2: Vec<String> = inner
                    .tiers
                    .iter()
                    .filter(|(_, t)| **t == 2)
                    .map(|(tag, _)| tag.clone())
                    .collect();
                tier2.sort_by_key(|t| t.to_lowercase());
                inner.tier2 = Some(tier2);
            }
            let tier2 = inner.tier2.clone().unwrap_or_default();
            if !tier2.is_empty() {
                let slices = if cycle > 0.0 {
                    ((self.options.tier2_period / cycle).round_ties_even() as usize).max(1)
                } else {
                    1
                };
                let size = tier2.len().div_ceil(slices);
                let i = inner.slice % slices;
                inner.slice += 1;
                let start = (i * size).min(tier2.len());
                let end = ((i + 1) * size).min(tier2.len());
                tags.extend_from_slice(&tier2[start..end]);
            }
        }
        if !inner.new_tier2.is_empty() {
            let have: HashSet<&String> = tags.iter().collect();
            let mut new: Vec<String> = inner
                .new_tier2
                .iter()
                .filter(|t| !have.contains(t))
                .cloned()
                .collect();
            new.sort();
            tags.extend(new);
            inner.new_tier2.clear();
        }
        let tags = tags
            .into_iter()
            .filter(|tag| inner.missing.get(tag).is_none_or(|&at| at <= now))
            .collect();
        (tags, tick, boundary)
    }

    // ------------------------------------------------------------------------------------------ the thread

    /// The default wait: returns early when a write is queued, true once stopped.
    fn wait(&self, seconds: f64) -> bool {
        let writes = lock(&self.writes);
        if writes.is_empty() && !self.stop.load(Ordering::SeqCst) {
            let _ = self
                .wake
                .wait_timeout(writes, Duration::from_secs_f64(seconds.max(0.0)))
                .unwrap_or_else(PoisonError::into_inner);
        }
        self.stop.load(Ordering::SeqCst)
    }

    /// Sleeps until the next tick, running each write as it is queued; true once stopped.
    fn idle(&self, plc: &mut dyn Plc, start: f64, tick: f64) -> Result<bool, String> {
        loop {
            let remaining = tick - (self.clock() - start);
            if remaining <= 1e-4 {
                return Ok(false);
            }
            if self.wait(remaining) {
                return Ok(true);
            }
            self.run_writes(plc)?;
        }
    }

    fn run(&self) {
        let mut attempt = 0;
        while !self.stop.load(Ordering::SeqCst) {
            match (self.factory)(&self.cfg) {
                Ok(mut plc) => {
                    if let Err(err) = self.connected(plc.as_mut(), &mut attempt) {
                        log::warn!("{}: {err}", self.name);
                    }
                    plc.close();
                }
                Err(err) => log::warn!("{}: {err}", self.name),
            }
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            self.fail_writes("PLC disconnected");
            self.mark_stale();
            self.set_state("disconnected");
            let delay = BACKOFF[attempt.min(BACKOFF.len() - 1)];
            attempt += 1;
            if self.wait(delay) {
                break;
            }
            lock(&self.stats).reconnects += 1;
            self.set_state("connecting");
        }
        *lock(&self.state) = "stopped"; // later writes are refused
        self.fail_writes("server stopping");
    }

    fn connected(&self, plc: &mut dyn Plc, attempt: &mut usize) -> Result<(), String> {
        plc.open()?;
        self.fail_writes("PLC disconnected"); // any left over from before the connect
        self.check_version(plc, true);
        *attempt = 0;
        self.set_state("connected");
        self.poll(plc)
    }

    fn poll(&self, plc: &mut dyn Plc) -> Result<(), String> {
        while !self.stop.load(Ordering::SeqCst) {
            let start = self.clock();
            let (tags, tick, boundary) = self.cycle_tags(&mut lock(&self.inner), start);
            let mut services = 0;
            if !tags.is_empty() {
                let (results, sent) = self.read(plc, &tags, start)?;
                services = sent;
                self.apply(results, start, true);
            }
            {
                let mut stats = lock(&self.stats);
                stats.reads_per_cycle = services;
                stats.tags_per_cycle = tags.len();
            }
            self.describe(plc);
            if boundary {
                self.check_version(plc, false);
            }
            self.run_writes(plc)?;
            let elapsed = self.clock() - start;
            {
                let mut stats = lock(&self.stats);
                stats.last_ok_ts = Some(now_ms());
                stats.last_cycle_ms = Some(round1(elapsed * 1000.0));
                if elapsed > tick {
                    stats.overruns += 1;
                }
            }
            if elapsed <= tick && self.idle(plc, start, tick)? {
                break;
            }
        }
        self.run_writes(plc) // stopping: the last queued writes (a momentary release) still go out
    }

    /// Caches read results and publishes the changes: quality or error changed, or the value moved past the
    /// deadband from the last published value. A read-back (no deadband) is published unless already published.
    fn apply(&self, results: HashMap<String, TagResult>, start: f64, deadband: bool) {
        let t = now_ms();
        let mut changes = Vec::new();
        {
            let mut inner = lock(&self.inner);
            let mut ordered: Vec<(String, TagResult)> = results.into_iter().collect();
            ordered.sort_by(|a, b| a.0.cmp(&b.0));
            for (tag, result) in ordered {
                if !inner.tiers.contains_key(&tag) {
                    continue; // unsubscribed during the read
                }
                let old = inner.cache.get(&tag).cloned();
                let entry = merge(old.as_ref(), &result, t);
                if entry.quality == "missing" {
                    inner.missing.insert(tag.clone(), start + MISSING_RETRY); // don't ask every tick
                } else {
                    inner.missing.remove(&tag);
                }
                if old.as_ref().is_none_or(|o| !o.same(&entry)) {
                    inner.cache.insert(tag.clone(), entry.clone());
                } else if deadband {
                    continue;
                }
                if let Some(published) = inner.published.get(&tag) {
                    let skip = if deadband {
                        self.within_deadband(&tag, published, &entry)
                    } else {
                        published.same(&entry)
                    };
                    if skip {
                        continue;
                    }
                }
                inner.published.insert(tag.clone(), entry.clone());
                changes.push((tag, entry));
            }
        }
        if !changes.is_empty() {
            self.emit(Event::Values(self.name.clone(), changes));
        }
    }

    fn within_deadband(&self, tag: &str, published: &Entry, entry: &Entry) -> bool {
        if published.quality != "good" || entry.quality != "good" || published.error != entry.error
        {
            return false;
        }
        let settings = self.rules.effective(&self.name, tag);
        let band = settings
            .get("deadband")
            .and_then(Json::as_f64)
            .unwrap_or(0.0);
        match (published.value.as_f64(), entry.value.as_f64()) {
            (Some(a), Some(b)) if truthy(settings.get("deadband")) => (b - a).abs() < band,
            _ => false,
        }
    }

    /// (results by tag, read services sent), through the planner unless it is off. Queued writes run between the
    /// packet chunks, after the chunk's results are published.
    fn read(
        &self,
        plc: &mut dyn Plc,
        tags: &[String],
        start: f64,
    ) -> Result<(HashMap<String, TagResult>, usize), String> {
        let parts: Arc<Vec<Vec<Read>>> = if self.options.planner {
            let structure = Arc::clone(
                &self
                    .structure
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            );
            let mut inner = lock(&self.inner);
            let retry: Vec<String> = inner
                .no_group
                .iter()
                .filter(|(_, at)| start - **at >= GROUP_RETRY)
                .map(|(name, _)| name.clone())
                .collect();
            if !retry.is_empty() {
                for name in retry {
                    inner.no_group.remove(&name); // read those whole again
                }
                inner.plans.clear();
            }
            let mut key = tags.to_vec();
            key.sort();
            if let Some(parts) = inner.plans.get(&key) {
                Arc::clone(parts)
            } else {
                if inner.plans.len() > 100 {
                    inner.plans.clear(); // tier-2 slices and groups make a few sets per subscription change
                }
                let budget = match plc.connection_size() {
                    0 => planner::PACKET_BYTES,
                    n => n,
                };
                let no_group: HashSet<String> = inner.no_group.keys().cloned().collect();
                let together =
                    |path: &str| truthy(self.rules.effective(&self.name, path).get("together"));
                let reads = planner::plan(
                    tags,
                    &structure.catalog,
                    self.options.whole_max_bytes,
                    &no_group,
                    budget,
                    Some(&together),
                );
                let parts = Arc::new(planner::chunks(reads, &structure.catalog, budget));
                inner.plans.insert(key, Arc::clone(&parts));
                parts
            }
        } else {
            let reads = tags
                .iter()
                .map(|tag| Read {
                    name: tag.clone(),
                    members: vec![(tag.clone(), None)],
                })
                .collect();
            Arc::new(vec![reads])
        };
        let mut between =
            |plc: &mut dyn Plc, partial: HashMap<String, TagResult>| -> Result<(), String> {
                self.apply(partial, start, true);
                self.run_writes(plc)
            };
        let (results, failed, services) = planner::execute(plc, &parts, &mut between)?;
        if !failed.is_empty() {
            lock(&self.stats).group_fallbacks += failed.len() as u64;
            log::warn!(
                "{}: whole read of {} failed, reading the members instead",
                self.name,
                failed.join(", ")
            );
            let mut inner = lock(&self.inner);
            for name in failed {
                inner.no_group.insert(name.to_lowercase(), start);
            }
            inner.plans.clear();
        }
        Ok((results, services))
    }

    fn run_writes(&self, plc: &mut dyn Plc) -> Result<(), String> {
        loop {
            let Some(request) = lock(&self.writes).pop_front() else {
                return Ok(());
            };
            let WriteRequest { tag, value, done } = request;
            let result = match plc.write(&tag, &value) {
                Ok(result) => result,
                Err(err) => {
                    done(WriteResult::failed(err.clone(), "comm"));
                    return Err(err);
                }
            };
            if let Some(error) = result.error {
                done(WriteResult::failed(error.message, error.kind.as_str()));
                continue;
            }
            let mut names = vec![tag.clone()];
            if let Some((word, _)) = split_bit(&tag) {
                names.push(word.to_owned());
            }
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let results = match plc.read(&refs) {
                Ok(results) => results,
                Err(err) => {
                    done(WriteResult {
                        ok: true,
                        error: None,
                        kind: None,
                        value: Json::Null,
                    });
                    return Err(err);
                }
            };
            let results: HashMap<String, TagResult> = names.into_iter().zip(results).collect();
            let value = results.get(&tag).map_or(Json::Null, |r| {
                let (value, quality, _) = to_value(r);
                if quality == "good" { value } else { Json::Null }
            });
            done(WriteResult {
                ok: true,
                error: None,
                kind: None,
                value,
            });
            self.apply(results, self.clock(), false);
        }
    }

    /// Reads the controller descriptions of tags that entered tiers, in one call, and tells the hub.
    fn describe(&self, plc: &mut dyn Plc) {
        let mut tags: Vec<String> = {
            let mut inner = lock(&self.inner);
            inner.want_descriptions.drain().collect()
        };
        tags.sort();
        // a rule description wins: no need to ask
        tags.retain(|t| !truthy(self.rules.effective(&self.name, t).get("description")));
        {
            let known = lock(&self.descriptions);
            tags.retain(|t| !known.contains_key(t));
        }
        if tags.is_empty() {
            return;
        }
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        let found = match plc.descriptions(&refs) {
            Ok(found) => found,
            Err(err) => {
                log::info!("{}: descriptions not read: {err}", self.name);
                vec![None; tags.len()]
            }
        };
        {
            let mut known = lock(&self.descriptions);
            for (tag, description) in tags.iter().zip(found) {
                known.insert(tag.clone(), description);
            }
        }
        self.emit(Event::Info(self.name.clone(), tags));
    }

    /// Counts a reload and tells the clients when the driver's tag table version changed.
    fn check_version(&self, plc: &mut dyn Plc, connecting: bool) {
        let version = plc.version();
        let (changed, reloaded) = {
            let mut current = lock(&self.version);
            let changed = version != *current;
            let reloaded = changed && !current.is_null();
            *current = version.clone();
            (changed, reloaded)
        };
        if reloaded {
            lock(&self.stats).reloads += 1;
            log::info!("{}: tag table reloaded (version {version})", self.name);
        }
        if changed || connecting {
            let catalog = plc.catalog();
            let tag_list = catalog.tag_list();
            let types = catalog.type_map();
            self.rules.set_types(&self.name, &tag_list, &types); // UDT entries apply from now on
            *self
                .structure
                .write()
                .unwrap_or_else(PoisonError::into_inner) = Arc::new(Structure {
                catalog,
                tag_list,
                types,
            });
            let mut inner = lock(&self.inner);
            inner.groups.clear();
            inner.missing.clear(); // a new or renamed tag may exist now
            inner.no_group.clear();
            inner.plans.clear(); // members or struct sizes may have changed
            if changed {
                // descriptions are cached per version: ask again for the subscribed tags
                lock(&self.descriptions).clear();
                let tags: Vec<String> = inner
                    .tiers
                    .keys()
                    .filter(|t| split_bit(t).is_none())
                    .cloned()
                    .collect();
                inner.want_descriptions.extend(tags);
            }
        }
        if reloaded {
            self.emit(Event::Meta(self.name.clone()));
        }
    }

    fn fail_writes(&self, error: &str) {
        loop {
            let Some(request) = lock(&self.writes).pop_front() else {
                return;
            };
            (request.done)(WriteResult::failed(error, "comm"));
        }
    }

    fn mark_stale(&self) {
        let mut changes = Vec::new();
        {
            let mut inner = lock(&self.inner);
            let Inner {
                cache, published, ..
            } = &mut *inner;
            for (tag, entry) in cache.iter_mut() {
                if entry.quality != "stale" {
                    entry.quality = "stale";
                    entry.error = Json::Null;
                    published.insert(tag.clone(), entry.clone());
                    changes.push((tag.clone(), entry.clone()));
                }
            }
        }
        if !changes.is_empty() {
            changes.sort_by(|a, b| a.0.cmp(&b.0));
            self.emit(Event::Values(self.name.clone(), changes));
        }
    }
}
