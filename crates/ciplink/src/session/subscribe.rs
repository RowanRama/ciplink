//! Subscriptions: tags polled on the session thread at an interval, with only their changes delivered.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use indexmap::IndexMap;

use super::dispatch::Dispatcher;
use crate::cip::TagResult;
use crate::{Error, ErrorKind, Result, TagError};

/// How a subscription polls and what it delivers.
#[derive(Clone, Debug, PartialEq)]
pub struct SubscribeOptions {
    /// Poll period. Default 1 s. Must be more than zero.
    pub interval: Duration,
    /// Numeric tags: a change smaller than this (absolute) since the last delivered value is not delivered.
    /// None delivers every change. Default None.
    pub deadband: Option<f64>,
}

impl Default for SubscribeOptions {
    fn default() -> Self {
        SubscribeOptions {
            interval: Duration::from_secs(1),
            deadband: None,
        }
    }
}

/// The tags of one subscription that changed since they were last delivered.
#[derive(Clone, Debug, PartialEq)]
pub struct Changes {
    /// When the latest poll with a change completed.
    pub time: SystemTime,
    /// The changed tags, in subscription order. Quality is the result's `error`: None is good, Some is failed
    /// with that error (kind Comm for a whole-read failure or a lost link).
    pub results: Vec<TagResult>,
}

type ChangesFn = Arc<dyn Fn(Changes) + Send + Sync>;

struct SubState {
    /// The last delivered result of each tag.
    last: Vec<Option<TagResult>>,
    /// Tag index to its latest undelivered result: a slow consumer gets the latest state of each tag.
    pending: IndexMap<usize, TagResult>,
    time: SystemTime,
    callback: Option<ChangesFn>,
    /// A delivery task is posted and has not taken `pending` yet.
    posted: bool,
}

/// What a subscription shares between its owner, the session thread and the callback thread.
pub(crate) struct SubShared {
    tags: Vec<String>,
    options: SubscribeOptions,
    dispatcher: Dispatcher,
    closed: AtomicBool,
    /// A poll is queued or in flight.
    polling: AtomicBool,
    state: Mutex<SubState>,
    ready: Condvar,
    /// Held while the callback runs, so unsubscribing can wait for it.
    call: Mutex<()>,
}

/// Where a subscription's poll phase falls within its interval, for a random `r`: subscriptions with the same
/// interval spread out instead of all falling due at once.
pub(crate) fn phase(interval: Duration, r: u64) -> Duration {
    interval.mul_f64(r as f64 / u64::MAX as f64)
}

/// A random poll phase within `interval`.
pub(crate) fn random_phase(interval: Duration) -> Duration {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    phase(interval, u64::from_le_bytes(bytes))
}

/// The first time after `now` that is `next` plus whole intervals: missed periods are skipped.
pub(crate) fn next_due(next: Instant, interval: Duration, now: Instant) -> Instant {
    if next > now {
        return next;
    }
    let behind = now.duration_since(next).as_nanos();
    let periods = behind / interval.as_nanos().max(1) + 1;
    let skip = u32::try_from(periods)
        .ok()
        .and_then(|n| interval.checked_mul(n));
    skip.and_then(|d| next.checked_add(d))
        .unwrap_or(now + interval)
}

/// True if `new` is to be delivered after `last`.
fn changed(last: Option<&TagResult>, new: &TagResult, deadband: Option<f64>) -> bool {
    let Some(last) = last else {
        return true;
    };
    if last.error != new.error || last.data_type != new.data_type {
        return true;
    }
    if last.value == new.value {
        return false;
    }
    let number = |r: &TagResult| r.value.as_ref().and_then(|v| v.as_f64());
    match (deadband, number(last), number(new)) {
        (Some(band), Some(a), Some(b)) => (b - a).abs() >= band,
        _ => true,
    }
}

/// A tag's result when its whole read failed.
fn failed(tag: &str, error: &Error) -> TagResult {
    TagResult {
        tag: tag.to_owned(),
        value: None,
        data_type: None,
        error: Some(TagError::new(error.to_string(), ErrorKind::Comm)),
    }
}

impl SubShared {
    pub(crate) fn new(
        tags: Vec<String>,
        options: SubscribeOptions,
        dispatcher: Dispatcher,
    ) -> Self {
        let count = tags.len();
        SubShared {
            tags,
            options,
            dispatcher,
            closed: AtomicBool::new(false),
            polling: AtomicBool::new(false),
            state: Mutex::new(SubState {
                last: vec![None; count],
                pending: IndexMap::new(),
                time: SystemTime::now(),
                callback: None,
                posted: false,
            }),
            ready: Condvar::new(),
            call: Mutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SubState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn tags(&self) -> &[String] {
        &self.tags
    }

    pub(crate) fn interval(&self) -> Duration {
        self.options.interval
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Marks a poll queued; false if one already is.
    pub(crate) fn start_poll(&self) -> bool {
        !self.polling.swap(true, Ordering::AcqRel)
    }

    /// A poll finished (or was dropped).
    pub(crate) fn poll_done(&self) {
        self.polling.store(false, Ordering::Release);
    }

    /// Takes a poll's result: the changed tags go to `pending` and on to the consumer. A whole-read error
    /// fails every tag.
    pub(crate) fn deliver(self: &Arc<Self>, result: Result<Vec<TagResult>>) {
        let results = match result {
            Ok(results) => results,
            Err(err) => self.tags.iter().map(|t| failed(t, &err)).collect(),
        };
        let mut state = self.lock();
        if self.is_closed() {
            return;
        }
        let mut any = false;
        for (i, new) in results.into_iter().enumerate().take(self.tags.len()) {
            if changed(state.last[i].as_ref(), &new, self.options.deadband) {
                state.last[i] = Some(new.clone());
                state.pending.insert(i, new);
                any = true;
            }
        }
        if !any {
            return;
        }
        state.time = SystemTime::now();
        if state.callback.is_none() {
            self.ready.notify_all();
        } else if !state.posted {
            state.posted = true;
            drop(state);
            self.post_delivery();
        }
    }

    fn post_delivery(self: &Arc<Self>) {
        let sub = Arc::clone(self);
        self.dispatcher.post(move || {
            let _call = sub.call.lock().unwrap_or_else(PoisonError::into_inner);
            let (changes, callback) = {
                let mut state = sub.lock();
                state.posted = false;
                if sub.is_closed() {
                    return;
                }
                (take_changes(&mut state), state.callback.clone())
            };
            if let (Some(changes), Some(callback)) = (changes, callback) {
                callback(changes);
            }
        });
    }

    /// Ends the subscription: no more polls or callbacks; `recv` returns what is pending, then None.
    pub(crate) fn end(&self) {
        let _state = self.lock();
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }

    /// [`end`](Self::end), then waits for a callback in progress unless this is the callback thread.
    fn close(&self) {
        self.end();
        if !self.dispatcher.is_current() {
            drop(self.call.lock().unwrap_or_else(PoisonError::into_inner));
        }
    }
}

fn take_changes(state: &mut SubState) -> Option<Changes> {
    if state.pending.is_empty() {
        return None;
    }
    let mut pending = std::mem::take(&mut state.pending);
    pending.sort_unstable_keys();
    Some(Changes {
        time: state.time,
        results: pending.into_values().collect(),
    })
}

/// A running subscription: its tags are read every interval, packed with the driver's other reads, and the
/// tags that changed are delivered, through [`recv`](Self::recv) or a callback ([`on_changes`](Self::on_changes)).
/// Dropping it (or [`close`](Self::close)) unsubscribes.
pub struct Subscription {
    shared: Arc<SubShared>,
}

impl Subscription {
    pub(crate) fn new(shared: Arc<SubShared>) -> Self {
        Subscription { shared }
    }

    /// The subscribed tags, in order.
    pub fn tags(&self) -> &[String] {
        self.shared.tags()
    }

    /// Blocks until changes are pending (taking all of them), or the subscription ends (None).
    pub fn recv(&self) -> Option<Changes> {
        let mut state = self.shared.lock();
        loop {
            if let Some(changes) = take_changes(&mut state) {
                return Some(changes);
            }
            if self.shared.is_closed() {
                return None;
            }
            state = self
                .shared
                .ready
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// [`recv`](Self::recv) with a timeout: None on timeout or end; tell them apart with
    /// [`is_closed`](Self::is_closed).
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Changes> {
        let deadline = Instant::now().checked_add(timeout);
        let mut state = self.shared.lock();
        loop {
            if let Some(changes) = take_changes(&mut state) {
                return Some(changes);
            }
            if self.shared.is_closed() {
                return None;
            }
            let left = deadline.map_or(Duration::MAX, |d| {
                d.saturating_duration_since(Instant::now())
            });
            if left.is_zero() {
                return None;
            }
            state = self
                .shared
                .ready
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The pending changes, if any, without blocking.
    pub fn try_recv(&self) -> Option<Changes> {
        take_changes(&mut self.shared.lock())
    }

    /// Delivers pending and later changes to `f` on the driver's callback thread instead of `recv`
    /// (replaces an earlier `f`). `f` may call the driver, blocking calls included.
    pub fn on_changes(&self, f: impl Fn(Changes) + Send + Sync + 'static) {
        let mut state = self.shared.lock();
        state.callback = Some(Arc::new(f));
        if !state.pending.is_empty() && !state.posted {
            state.posted = true;
            drop(state);
            self.shared.post_delivery();
        }
    }

    /// True once unsubscribed, or the driver was closed, stopped or dropped.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Unsubscribes; returns once a callback in progress has returned (unless called from the callback thread
    /// itself). Do not call it while holding a lock the callback waits for.
    pub fn close(&self) {
        self.shared.close();
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("tags", &self.shared.tags)
            .field("closed", &self.is_closed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;
    use std::sync::mpsc::channel;

    fn result(tag: &str, value: i32) -> TagResult {
        TagResult {
            tag: tag.into(),
            value: Some(Value::DInt(value)),
            data_type: Some("DINT".into()),
            error: None,
        }
    }

    fn real(tag: &str, value: f32) -> TagResult {
        TagResult {
            tag: tag.into(),
            value: Some(Value::Real(value)),
            data_type: Some("REAL".into()),
            error: None,
        }
    }

    fn sub(tags: &[&str], deadband: Option<f64>) -> (Arc<SubShared>, Subscription) {
        let shared = Arc::new(SubShared::new(
            tags.iter().map(|t| (*t).to_owned()).collect(),
            SubscribeOptions {
                interval: Duration::from_millis(10),
                deadband,
            },
            Dispatcher::default(),
        ));
        (Arc::clone(&shared), Subscription::new(shared))
    }

    #[test]
    fn first_delivery_has_every_tag() {
        let (s, sub) = sub(&["a", "b"], None);
        s.deliver(Ok(vec![result("a", 1), result("b", 2)]));
        let got = sub.try_recv().expect("changes");
        assert_eq!(got.results, [result("a", 1), result("b", 2)]);
        assert_eq!(sub.try_recv(), None);
    }

    #[test]
    fn only_changed_tags_are_delivered() {
        let (s, sub) = sub(&["a", "b"], None);
        s.deliver(Ok(vec![result("a", 1), result("b", 2)]));
        sub.try_recv();
        s.deliver(Ok(vec![result("a", 1), result("b", 3)]));
        assert_eq!(sub.try_recv().expect("changes").results, [result("b", 3)]);
        s.deliver(Ok(vec![result("a", 1), result("b", 3)]));
        assert_eq!(sub.try_recv(), None);
    }

    #[test]
    fn deadband_holds_small_changes_against_last_delivered() {
        let (s, sub) = sub(&["r"], Some(1.0));
        s.deliver(Ok(vec![real("r", 10.0)]));
        sub.try_recv();
        s.deliver(Ok(vec![real("r", 10.6)]));
        assert_eq!(sub.try_recv(), None);
        // compared with 10.0, the last delivered: slow drift still gets through
        s.deliver(Ok(vec![real("r", 11.2)]));
        assert_eq!(sub.try_recv().expect("changes").results, [real("r", 11.2)]);
    }

    #[test]
    fn error_is_delivered_once() {
        let (s, sub) = sub(&["a", "b"], None);
        s.deliver(Ok(vec![result("a", 1), result("b", 2)]));
        sub.try_recv();
        s.deliver(Err(Error::comm("lost")));
        let got = sub.try_recv().expect("changes").results;
        assert_eq!(got.len(), 2);
        assert!(
            got.iter()
                .all(|r| r.error == Some(TagError::new("lost", ErrorKind::Comm))
                    && r.value.is_none())
        );
        s.deliver(Err(Error::comm("lost")));
        assert_eq!(sub.try_recv(), None);
        s.deliver(Ok(vec![result("a", 1), result("b", 2)]));
        assert_eq!(sub.try_recv().expect("back").results.len(), 2);
    }

    #[test]
    fn pending_changes_coalesce_per_tag() {
        let (s, sub) = sub(&["a", "b"], None);
        s.deliver(Ok(vec![result("a", 1), result("b", 1)]));
        s.deliver(Ok(vec![result("a", 2), result("b", 1)]));
        s.deliver(Ok(vec![result("a", 3), result("b", 1)]));
        assert_eq!(
            sub.try_recv().expect("changes").results,
            [result("a", 3), result("b", 1)]
        );
    }

    #[test]
    fn phase_is_within_the_interval() {
        let interval = Duration::from_millis(1000);
        assert_eq!(phase(interval, 0), Duration::ZERO);
        assert_eq!(phase(interval, u64::MAX / 2), Duration::from_millis(500));
        assert!(phase(interval, u64::MAX) <= interval);
        assert!(random_phase(interval) <= interval);
    }

    #[test]
    fn next_due_skips_missed_periods() {
        let start = Instant::now();
        let i = Duration::from_millis(10);
        assert_eq!(next_due(start + i, i, start), start + i);
        assert_eq!(next_due(start, i, start), start + i);
        assert_eq!(next_due(start, i, start + 35 * i / 10), start + 4 * i);
    }

    #[test]
    fn callback_gets_changes_and_close_stops_it() {
        let (s, sub) = sub(&["a"], None);
        let (tx, rx) = channel();
        sub.on_changes(move |c| tx.send(c.results).expect("send"));
        s.deliver(Ok(vec![result("a", 1)]));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(vec![result("a", 1)])
        );
        sub.close();
        s.deliver(Ok(vec![result("a", 2)]));
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn drop_unsubscribes_and_waits_for_a_callback_in_progress() {
        let (s, sub) = sub(&["a"], None);
        let (started_tx, started) = channel();
        let (finished_tx, finished) = channel::<()>();
        sub.on_changes(move |_| {
            started_tx.send(()).expect("send");
            std::thread::sleep(Duration::from_millis(50));
            finished_tx.send(()).expect("send");
        });
        s.deliver(Ok(vec![result("a", 1)]));
        started
            .recv_timeout(Duration::from_secs(5))
            .expect("started");
        drop(sub);
        // the callback had returned before drop did
        assert_eq!(finished.try_recv(), Ok(()));
        assert!(s.is_closed());
    }

    #[test]
    fn recv_returns_pending_then_none_after_end() {
        let (s, sub) = sub(&["a"], None);
        s.deliver(Ok(vec![result("a", 1)]));
        s.end();
        assert!(sub.recv().is_some());
        assert_eq!(sub.recv(), None);
        assert_eq!(sub.recv_timeout(Duration::from_millis(1)), None);
    }
}
