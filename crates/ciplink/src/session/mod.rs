//! The session core every driver runs on: one **session thread** (the tickler) that does all of a driver's
//! I/O, a shared request queue that packs the reads of several callers into one read, async [`Handle`]s,
//! background reconnect, keep-alive and [`Subscription`]s.
//!
//! A driver's public methods are thin: they queue a job and wait for it (the sync API) or return its
//! [`Handle`] (`read_async`, `write_async`). When the session thread takes work it takes every read at the
//! head of the queue up to the first other job and sends them as one read of the merged tag list, then gives
//! each caller its own results. Writes, generic messages and every other call run alone, in queue order, so a
//! write is never moved past anything queued before it. A caller alone sends exactly the bytes it sent before
//! sessions existed.
//!
//! User callbacks (`Handle::on_complete`, `Subscription::on_changes`, the connection callback) run on the
//! driver's **callback thread**, in order, never on the session thread: a callback may call the driver, blocking
//! calls included.
//!
//! The protocol itself (Logix, SLC, later Modbus, S7comm or OPC UA) is a state type implementing the
//! crate-private `Protocol` trait; the session owns it behind a mutex that only the session thread does I/O
//! under.

mod batch;
mod dispatch;
mod handle;
mod subscribe;

pub use handle::Handle;
pub use subscribe::{Changes, SubscribeOptions, Subscription};

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use batch::{Job, merge_reads, split_reads, take_batch};
use dispatch::{Dispatcher, panic_message};
use handle::{Completer, Panic, mark_session_thread, own_thread_error};
use subscribe::{SubShared, next_due, random_phase};

use crate::cip::TagResult;
use crate::{Error, Result, Value};

// ------------------------------------------------------------------------------------------------ public types

/// Reconnect and keep-alive settings of a driver's session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOptions {
    /// Reconnect in the background after an open link is lost. Default true.
    pub reconnect: bool,
    /// Delay before the first reconnect attempt; doubled after each failed attempt. Default 100 ms.
    pub reconnect_min: Duration,
    /// Longest delay between attempts. Default 10 s.
    pub reconnect_max: Duration,
    /// Send the keep-alive request after this long without traffic; None never sends it. Default Some(30 s).
    pub keep_alive: Option<Duration>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            reconnect: true,
            reconnect_min: Duration::from_millis(100),
            reconnect_max: Duration::from_secs(10),
            keep_alive: Some(Duration::from_secs(30)),
        }
    }
}

impl SessionOptions {
    /// No reconnect and no keep-alive: the behaviour of a driver before sessions (`with_connector` uses it).
    pub fn off() -> Self {
        SessionOptions {
            reconnect: false,
            keep_alive: None,
            ..SessionOptions::default()
        }
    }
}

/// Where the link is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Never opened, closed by the user, or lost with reconnect off. Requests run as before (and fail as before).
    Closed,
    /// Opened, and not lost since.
    Connected,
    /// Lost; reconnecting in the background. Reads, writes and subscription polls fail fast.
    Reconnecting,
}

/// A change of the link, delivered on the callback thread in order.
#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionEvent {
    /// `open()` succeeded, or a reconnect did.
    Connected,
    /// An open link was lost; `error` is what failed (the request's CommError, or the keep-alive's).
    Disconnected {
        /// The failure that lost the link.
        error: Error,
    },
    /// Reconnect attempt `attempt` (1, 2, ...) is due after `delay`.
    Reconnecting {
        /// The attempt number, from 1.
        attempt: u32,
        /// The wait before it.
        delay: Duration,
    },
}

/// The connection-state callback.
pub type ConnectionCallback = Box<dyn Fn(&ConnectionEvent) + Send + Sync + 'static>;

// ------------------------------------------------------------------------------------------------ protocol

/// What a protocol's state gives the session. Every method runs on the session thread with the state locked,
/// except `connected`, which accessors may also call.
pub(crate) trait Protocol: Send + 'static {
    /// The user's `open()`: connect and initialise. Ok(false) if the target refused the session.
    fn open(&mut self) -> Result<bool>;
    /// A background reconnect after the link was lost. Defaults to `open`.
    fn reopen(&mut self) -> Result<bool> {
        self.open()
    }
    /// The user's `close()`: the protocol's closing requests, then drop the link.
    fn close(&mut self) -> Result<()>;
    /// Forget the link without sending anything (after a panic in the middle of a request).
    fn drop_link(&mut self);
    /// True while the link is up (a session is registered, for CIP).
    fn connected(&self) -> bool;
    /// Read tags: one result per tag in order; Err fails the whole call.
    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>>;
    /// True if one read of several callers' tags gives each caller what its own read would.
    fn merges_reads(&self) -> bool {
        true
    }
    /// Write tags: one result per item in order; Err fails the whole call.
    fn write(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>>;
    /// The cheap request sent when the link has been idle for `SessionOptions::keep_alive`.
    fn keep_alive(&mut self) -> Result<()>;
}

// ------------------------------------------------------------------------------------------------ session

/// The error of a request queued when the driver was closed, stopped or dropped.
fn closed_error() -> Error {
    Error::comm("driver closed")
}

/// The error of a read, write or poll while reconnecting.
fn reconnecting_error(cause: Option<&Error>) -> Error {
    let cause = cause.map_or_else(String::new, Error::to_string);
    Error::comm(format!("not connected, reconnecting: {cause}"))
}

fn internal_error(panic: &(dyn std::any::Any + Send)) -> Error {
    let message = panic_message(panic);
    log::error!("ciplink session: a request panicked: {message}");
    Error::comm(format!("internal error: {message}"))
}

/// Runs `f` with the state, catching a panic: the link is dropped (a reply may be unread) and the result is
/// the internal CommError, with the panic for a blocking caller to resume.
fn guarded<P: Protocol, R>(
    p: &mut P,
    f: impl FnOnce(&mut P) -> Result<R>,
) -> (Result<R>, Option<Panic>) {
    match catch_unwind(AssertUnwindSafe(|| f(&mut *p))) {
        Ok(result) => (result, None),
        Err(panic) => {
            p.drop_link();
            (Err(internal_error(&*panic)), Some(panic))
        }
    }
}

/// The delay before reconnect attempt `attempt` (from 1): `min` doubled per earlier attempt, up to `max`.
fn backoff(min: Duration, max: Duration, attempt: u32) -> Duration {
    1u32.checked_shl(attempt.saturating_sub(1))
        .and_then(|factor| min.checked_mul(factor))
        .map_or(max, |d| d.min(max))
}

type EventFn = Arc<dyn Fn(&ConnectionEvent) + Send + Sync>;

/// The connection callback, and the lock held while it runs (so replacing it can wait for it).
#[derive(Default)]
struct Events {
    call: Mutex<()>,
    callback: Mutex<Option<EventFn>>,
}

struct SubEntry {
    sub: Arc<SubShared>,
    next: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopMode {
    /// `close()`: send the protocol's closing requests.
    Close,
    /// `stop()` and drop: leave the link as it is.
    Drop,
}

struct Queue<P> {
    jobs: VecDeque<Job<P>>,
    subs: Vec<SubEntry>,
    state: ConnectionState,
    /// The Disconnected error, while Reconnecting.
    cause: Option<Error>,
    attempt: u32,
    retry_at: Option<Instant>,
    /// The last request on the link.
    last_activity: Instant,
    /// The session thread, until a close or stop takes it to join it.
    thread: Option<JoinHandle<()>>,
    /// Some while a session thread runs.
    thread_id: Option<ThreadId>,
    stopping: Option<StopMode>,
    close_done: Option<Completer<()>>,
}

struct Shared<P> {
    state: Mutex<P>,
    queue: Mutex<Queue<P>>,
    wake: Condvar,
    options: SessionOptions,
    dispatcher: Dispatcher,
    events: Arc<Events>,
    close_lock: Mutex<()>,
}

/// A protocol state run by a session thread. Dropping it stops the thread (see [`Session::stop`]).
pub(crate) struct Session<P: Protocol> {
    shared: Arc<Shared<P>>,
}

impl<P: Protocol> Shared<P> {
    fn lock_queue(&self) -> MutexGuard<'_, Queue<P>> {
        // nothing panics under this lock: user code never runs under it
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Locks the state. If a thread panicked holding it, the link is dropped first (a reply may be unread).
    fn lock_state(&self) -> MutexGuard<'_, P> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.drop_link();
                self.state.clear_poison();
                state
            }
        }
    }

    fn emit(&self, events: Vec<ConnectionEvent>) {
        for event in events {
            log::info!("connection: {event:?}");
            if self
                .events
                .callback
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
            {
                continue;
            }
            let shared = Arc::clone(&self.events);
            self.dispatcher.post(move || {
                let _call = shared.call.lock().unwrap_or_else(PoisonError::into_inner);
                let callback = shared
                    .callback
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                if let Some(callback) = callback {
                    callback(&event);
                }
            });
        }
    }
}

impl<P: Protocol> Session<P> {
    pub(crate) fn new(protocol: P, options: SessionOptions) -> Self {
        Session {
            shared: Arc::new(Shared {
                state: Mutex::new(protocol),
                queue: Mutex::new(Queue {
                    jobs: VecDeque::new(),
                    subs: Vec::new(),
                    state: ConnectionState::Closed,
                    cause: None,
                    attempt: 0,
                    retry_at: None,
                    last_activity: Instant::now(),
                    thread: None,
                    thread_id: None,
                    stopping: None,
                    close_done: None,
                }),
                wake: Condvar::new(),
                options,
                dispatcher: Dispatcher::default(),
                events: Arc::new(Events::default()),
                close_lock: Mutex::new(()),
            }),
        }
    }

    /// The protocol state, for accessors that do no I/O.
    pub(crate) fn lock(&self) -> MutexGuard<'_, P> {
        self.shared.lock_state()
    }

    /// True if a thread panicked holding the state: the next [`lock`](Self::lock) drops the link.
    pub(crate) fn poisoned(&self) -> bool {
        self.shared.state.is_poisoned()
    }

    /// Where the link is; never blocks on I/O.
    pub(crate) fn state(&self) -> ConnectionState {
        self.shared.lock_queue().state
    }

    fn handle<T: Send + 'static>(&self) -> (Handle<T>, Completer<T>) {
        Handle::new(self.shared.dispatcher.clone())
    }

    /// Starts the session thread unless one runs.
    fn ensure_thread(&self, q: &mut Queue<P>) -> Result<()> {
        if q.thread_id.is_some() {
            return Ok(());
        }
        let shared = Arc::clone(&self.shared);
        let thread = std::thread::Builder::new()
            .name("ciplink-session".into())
            .spawn(move || run(&shared))
            .map_err(|e| Error::comm(format!("Failed to start the session thread: {e}")))?;
        q.thread_id = Some(thread.thread().id());
        q.thread = Some(thread);
        Ok(())
    }

    fn submit(&self, job: Job<P>) {
        let mut q = self.shared.lock_queue();
        let reject = if q.thread_id == Some(std::thread::current().id()) {
            Some(own_thread_error())
        } else if q.stopping.is_some() {
            Some(closed_error())
        } else if q.state == ConnectionState::Reconnecting && job.needs_link() {
            Some(reconnecting_error(q.cause.as_ref()))
        } else {
            None
        };
        if let Some(error) = reject {
            drop(q);
            job.fail(error);
            return;
        }
        q.jobs.push_back(job);
        if let Err(error) = self.ensure_thread(&mut q) {
            let jobs = std::mem::take(&mut q.jobs);
            drop(q);
            for job in jobs {
                job.fail(error.clone());
            }
            return;
        }
        self.shared.wake.notify_one();
    }

    /// Queues the user's `open()`.
    pub(crate) fn open(&self) -> Handle<bool> {
        let (handle, done) = self.handle();
        self.submit(Job::Open { done });
        handle
    }

    /// Queues a read; it is merged with the reads queued next to it.
    pub(crate) fn read(&self, tags: &[&str]) -> Handle<Vec<TagResult>> {
        let (handle, done) = self.handle();
        let tags = tags.iter().map(|t| (*t).to_owned()).collect();
        self.submit(Job::Read { tags, done });
        handle
    }

    /// Queues a write.
    pub(crate) fn write(&self, items: &[(&str, Value)]) -> Handle<Vec<TagResult>> {
        let (handle, done) = self.handle();
        let items = items
            .iter()
            .map(|(t, v)| ((*t).to_owned(), v.clone()))
            .collect();
        self.submit(Job::Write { items, done });
        handle
    }

    /// Queues `f` to run on the session thread with the state.
    pub(crate) fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut P) -> Result<R> + Send + 'static,
    ) -> Handle<R> {
        let (handle, done) = self.handle();
        self.submit(Job::Call(Box::new(
            move |state: Result<&mut P>| -> (Option<Error>, Box<dyn FnOnce()>) {
                match state {
                    Ok(p) => {
                        let (result, panic) = guarded(p, f);
                        let error = result.as_ref().err().cloned();
                        (error, Box::new(move || done.finish(result, panic)))
                    }
                    Err(error) => (None, Box::new(move || done.complete(Err(error)))),
                }
            },
        )));
        handle
    }

    /// Subscribes to `tags` (see [`Subscription`]); no I/O here: the first poll is queued at once.
    pub(crate) fn subscribe(
        &self,
        tags: &[&str],
        options: SubscribeOptions,
    ) -> Result<Subscription> {
        if tags.is_empty() {
            return Err(Error::request("A subscription needs at least one tag"));
        }
        if options.interval.is_zero() {
            return Err(Error::request(
                "A subscription interval must be more than zero",
            ));
        }
        let interval = options.interval;
        let sub = Arc::new(SubShared::new(
            tags.iter().map(|t| (*t).to_owned()).collect(),
            options,
            self.shared.dispatcher.clone(),
        ));
        let now = Instant::now();
        let next = now
            .checked_add(interval + random_phase(interval))
            .unwrap_or(now);
        let mut q = self.shared.lock_queue();
        if q.stopping.is_some() {
            return Err(closed_error());
        }
        q.subs.push(SubEntry {
            sub: Arc::clone(&sub),
            next,
        });
        if q.state != ConnectionState::Reconnecting && sub.start_poll() {
            q.jobs.push_back(Job::Poll {
                sub: Arc::clone(&sub),
            });
        }
        self.ensure_thread(&mut q)?;
        self.shared.wake.notify_one();
        Ok(Subscription::new(sub))
    }

    /// Replaces the connection callback (None removes it). Once this returns, the old callback is not running
    /// and will not be called again, unless this runs on the callback thread itself. Do not call it while
    /// holding a lock the callback waits for.
    pub(crate) fn set_connection_callback(&self, callback: Option<ConnectionCallback>) {
        let callback: Option<EventFn> = callback.map(Arc::from);
        let events = &self.shared.events;
        let _call = (!self.shared.dispatcher.is_current())
            .then(|| events.call.lock().unwrap_or_else(PoisonError::into_inner));
        *events
            .callback
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = callback;
    }

    /// Ends the subscriptions and fails the queued jobs (taken out of `q`).
    fn take_all(q: &mut Queue<P>) -> (VecDeque<Job<P>>, Vec<SubEntry>) {
        (std::mem::take(&mut q.jobs), std::mem::take(&mut q.subs))
    }

    fn fail_all(jobs: VecDeque<Job<P>>, subs: Vec<SubEntry>) {
        for job in jobs {
            job.fail(closed_error());
        }
        for entry in subs {
            entry.sub.end();
        }
    }

    /// The user's `close()`: fails the queued requests, ends the subscriptions, lets the request in flight
    /// finish, runs the protocol's close on the session thread and joins it. Reconnecting stops. The driver can
    /// be opened again. Do not call it while holding a lock a callback of this driver waits for.
    pub(crate) fn close(&self) -> Result<()> {
        let _close = self
            .shared
            .close_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut q = self.shared.lock_queue();
        let (jobs, subs) = Self::take_all(&mut q);
        if q.thread_id.is_none() {
            q.state = ConnectionState::Closed;
            drop(q);
            Self::fail_all(jobs, subs);
            return self.shared.lock_state().close();
        }
        let (handle, done) = self.handle();
        q.stopping = Some(StopMode::Close);
        q.close_done = Some(done);
        let thread = q.thread.take();
        let own = q.thread_id == Some(std::thread::current().id());
        self.shared.wake.notify_all();
        drop(q);
        Self::fail_all(jobs, subs);
        if own {
            return Ok(()); // the session thread closes once the current job returns
        }
        let result = handle.wait();
        if let Some(thread) = thread {
            let _ = thread.join();
        }
        result
    }

    /// Stops the session and callback threads and fails the queued requests, without closing the link
    /// (what drop does); reconnecting stops. Every callback already posted runs first. The next request starts
    /// the session thread again. Idempotent. Do not call it while holding a lock a callback waits for.
    pub(crate) fn stop(&self) {
        let close = self
            .shared
            .close_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut q = self.shared.lock_queue();
        let (jobs, subs) = Self::take_all(&mut q);
        let thread = q.thread.take();
        if q.thread_id.is_some() && q.stopping.is_none() {
            q.stopping = Some(StopMode::Drop);
        }
        self.shared.wake.notify_all();
        drop(q);
        Self::fail_all(jobs, subs);
        if let Some(thread) = thread {
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
        // a callback may be waiting for close_lock (it calls close()): let it finish before joining its thread
        drop(close);
        self.shared.dispatcher.stop();
    }
}

impl<P: Protocol> Drop for Session<P> {
    fn drop(&mut self) {
        self.stop();
    }
}

// ------------------------------------------------------------------------------------------------ the thread

enum Work<P> {
    Stop(StopMode, Option<Completer<()>>),
    Batch(Vec<Job<P>>),
    Reconnect,
    KeepAlive,
}

/// Fails the queue if the session thread ends without a stop (only a bug can do that), so no waiter hangs.
struct ExitGuard<'a, P: Protocol>(&'a Arc<Shared<P>>);

impl<P: Protocol> Drop for ExitGuard<'_, P> {
    fn drop(&mut self) {
        let mut q = self.0.lock_queue();
        if q.thread_id != Some(std::thread::current().id()) {
            return;
        }
        q.thread_id = None;
        q.stopping = None;
        let jobs = std::mem::take(&mut q.jobs);
        drop(q);
        for job in jobs {
            job.fail(Error::comm("the session thread ended"));
        }
    }
}

fn run<P: Protocol>(shared: &Arc<Shared<P>>) {
    mark_session_thread();
    let _exit = ExitGuard(shared);
    loop {
        match next_work(shared) {
            Work::Stop(mode, done) => {
                stop_here(shared, mode, done);
                return;
            }
            Work::Batch(batch) => run_batch(shared, batch),
            Work::Reconnect => reconnect(shared),
            Work::KeepAlive => keep_alive(shared),
        }
    }
}

/// Waits for the next work: a stop, a batch (queuing the subscriptions' due polls first), a reconnect attempt
/// or the keep-alive.
fn next_work<P: Protocol>(shared: &Shared<P>) -> Work<P> {
    let mut guard = shared.lock_queue();
    loop {
        let q = &mut *guard;
        if let Some(mode) = q.stopping {
            return Work::Stop(mode, q.close_done.take());
        }
        if q.subs.iter().any(|e| e.sub.is_closed()) {
            let (closed, open): (Vec<_>, Vec<_>) = std::mem::take(&mut q.subs)
                .into_iter()
                .partition(|e| e.sub.is_closed());
            q.subs = open;
            // a closed entry can own the user's callback, and it the last handle on this driver: dropping it
            // stops the session, which takes the queue lock
            drop(guard);
            drop(closed);
            guard = shared.lock_queue();
            continue;
        }
        let now = Instant::now();
        let mut wake_at: Option<Instant> = None;
        if q.state != ConnectionState::Reconnecting {
            for entry in &mut q.subs {
                if now >= entry.next {
                    if entry.sub.start_poll() {
                        q.jobs.push_back(Job::Poll {
                            sub: Arc::clone(&entry.sub),
                        });
                    }
                    entry.next = next_due(entry.next, entry.sub.interval(), now);
                }
                wake_at = Some(wake_at.map_or(entry.next, |w| w.min(entry.next)));
            }
        }
        let batch = take_batch(&mut q.jobs);
        if !batch.is_empty() {
            return Work::Batch(batch);
        }
        match q.state {
            ConnectionState::Reconnecting => {
                if let Some(at) = q.retry_at {
                    if now >= at {
                        return Work::Reconnect;
                    }
                    wake_at = Some(wake_at.map_or(at, |w| w.min(at)));
                }
            }
            ConnectionState::Connected => {
                if let Some(idle) = shared.options.keep_alive {
                    let at = q.last_activity.checked_add(idle).unwrap_or(now);
                    if now >= at {
                        return Work::KeepAlive;
                    }
                    wake_at = Some(wake_at.map_or(at, |w| w.min(at)));
                }
            }
            ConnectionState::Closed => {}
        }
        guard = match wake_at {
            Some(at) => {
                shared
                    .wake
                    .wait_timeout(guard, at.saturating_duration_since(now))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => shared
                .wake
                .wait(guard)
                .unwrap_or_else(PoisonError::into_inner),
        };
    }
}

fn stop_here<P: Protocol>(shared: &Shared<P>, mode: StopMode, done: Option<Completer<()>>) {
    let result = (mode == StopMode::Close).then(|| {
        let mut p = shared.lock_state();
        match catch_unwind(AssertUnwindSafe(|| p.close())) {
            Ok(result) => result,
            Err(panic) => {
                p.drop_link();
                Err(internal_error(&*panic))
            }
        }
    });
    let mut q = shared.lock_queue();
    if mode == StopMode::Close || q.state == ConnectionState::Reconnecting {
        q.state = ConnectionState::Closed;
    }
    q.cause = None;
    q.attempt = 0;
    q.retry_at = None;
    q.stopping = None;
    q.thread_id = None;
    drop(q);
    if let Some(done) = done {
        done.complete(result.unwrap_or(Ok(())));
    }
}

/// What a run of work found: the first error, whether the link is still up, and a user open's result.
#[derive(Default)]
struct Outcome {
    error: Option<Error>,
    connected: bool,
    opened: bool,
}

/// Completions of a batch, run once the queue's state is updated: a caller that sees its result also sees
/// the connection state it left.
type Finish = Vec<Box<dyn FnOnce()>>;

fn run_batch<P: Protocol>(shared: &Shared<P>, batch: Vec<Job<P>>) {
    let (outcome, finish) = if batch.first().is_some_and(Job::is_read) {
        run_reads(shared, batch)
    } else {
        match batch.into_iter().next() {
            Some(job) => run_one(shared, job),
            None => return,
        }
    };
    after_work(shared, outcome);
    for f in finish {
        f();
    }
}

fn refs(list: &[String]) -> Vec<&str> {
    list.iter().map(String::as_str).collect()
}

fn run_reads<P: Protocol>(shared: &Shared<P>, jobs: Vec<Job<P>>) -> (Outcome, Finish) {
    let (results, mut panic, connected) = {
        let lists: Vec<&[String]> = jobs
            .iter()
            .map(|job| match job {
                Job::Read { tags, .. } => tags.as_slice(),
                Job::Poll { sub } => sub.tags(),
                _ => &[],
            })
            .collect();
        let mut p = shared.lock_state();
        let (results, panic) = guarded(&mut *p, |p| {
            Ok(if p.merges_reads() {
                let (merged, positions) = merge_reads(&lists);
                split_reads(p.read(&refs(&merged)), &positions)
            } else {
                lists.iter().map(|list| p.read(&refs(list))).collect()
            })
        });
        let results =
            results.unwrap_or_else(|error| lists.iter().map(|_| Err(error.clone())).collect());
        (results, panic, p.connected())
    };
    let error = results.iter().find_map(|r| r.as_ref().err().cloned());
    let finish: Finish = jobs
        .into_iter()
        .zip(results)
        .map(|(job, result)| -> Box<dyn FnOnce()> {
            match job {
                // the first caller resumes a panic, as it would have alone
                Job::Read { done, .. } => {
                    let panic = panic.take();
                    Box::new(move || done.finish(result, panic))
                }
                Job::Poll { sub } => Box::new(move || {
                    sub.deliver(result);
                    sub.poll_done();
                }),
                other => Box::new(move || other.fail(Error::comm("internal error: not a read"))),
            }
        })
        .collect();
    let outcome = Outcome {
        error,
        connected,
        opened: false,
    };
    (outcome, finish)
}

fn run_one<P: Protocol>(shared: &Shared<P>, job: Job<P>) -> (Outcome, Finish) {
    let mut p = shared.lock_state();
    let mut outcome = Outcome::default();
    let finish: Finish = match job {
        Job::Write { items, done } => {
            let (names, values): (Vec<String>, Vec<Value>) = items.into_iter().unzip();
            let pairs: Vec<(&str, Value)> = names.iter().map(String::as_str).zip(values).collect();
            let (result, panic) = guarded(&mut *p, |p| p.write(&pairs));
            outcome.error = result.as_ref().err().cloned();
            outcome.connected = p.connected();
            vec![Box::new(move || done.finish(result, panic))]
        }
        Job::Open { done } => {
            let (result, panic) = guarded(&mut *p, |p| p.open());
            outcome.opened = matches!(result, Ok(true));
            outcome.error = result.as_ref().err().cloned();
            outcome.connected = p.connected();
            vec![Box::new(move || done.finish(result, panic))]
        }
        Job::Call(f) => {
            // the closure catches its own panic; its completion waits for after_work like the others
            let (error, finish) = f(Ok(&mut *p));
            outcome.error = error;
            outcome.connected = p.connected();
            vec![finish]
        }
        read @ (Job::Read { .. } | Job::Poll { .. }) => {
            drop(p);
            return run_reads(shared, vec![read]);
        }
    };
    (outcome, finish)
}

fn after_work<P: Protocol>(shared: &Shared<P>, outcome: Outcome) {
    let mut q = shared.lock_queue();
    let now = Instant::now();
    q.last_activity = now;
    if outcome.opened {
        let was = q.state;
        q.state = ConnectionState::Connected;
        q.cause = None;
        q.attempt = 0;
        q.retry_at = None;
        if was != ConnectionState::Connected {
            poll_now(&mut q);
            drop(q);
            shared.emit(vec![ConnectionEvent::Connected]);
        }
        return;
    }
    if q.state != ConnectionState::Connected || outcome.connected {
        return;
    }
    // the link was lost
    let cause = match outcome.error {
        Some(error @ Error::Comm(_)) => error,
        _ => Error::comm("connection lost"),
    };
    let reconnect = shared.options.reconnect;
    let fail_with = if reconnect {
        reconnecting_error(Some(&cause))
    } else {
        cause.clone()
    };
    let (failed, kept): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut q.jobs)
        .into_iter()
        .partition(Job::needs_link);
    q.jobs = kept;
    let subs: Vec<_> = q.subs.iter().map(|e| Arc::clone(&e.sub)).collect();
    let mut events = vec![ConnectionEvent::Disconnected {
        error: cause.clone(),
    }];
    if reconnect {
        let delay = shared.options.reconnect_min;
        q.state = ConnectionState::Reconnecting;
        q.attempt = 1;
        q.retry_at = Some(now.checked_add(delay).unwrap_or(now));
        q.cause = Some(cause.clone());
        events.push(ConnectionEvent::Reconnecting { attempt: 1, delay });
    } else {
        q.state = ConnectionState::Closed;
    }
    drop(q);
    for job in failed {
        job.fail(fail_with.clone());
    }
    for sub in subs {
        sub.deliver(Err(cause.clone()));
    }
    shared.emit(events);
}

/// Queues a poll of every subscription on (re)connect. Their due times stay: each keeps its phase.
fn poll_now<P>(q: &mut Queue<P>) {
    for entry in &q.subs {
        if entry.sub.start_poll() {
            q.jobs.push_back(Job::Poll {
                sub: Arc::clone(&entry.sub),
            });
        }
    }
}

fn reconnect<P: Protocol>(shared: &Shared<P>) {
    let reopened = {
        let mut p = shared.lock_state();
        match catch_unwind(AssertUnwindSafe(|| p.reopen())) {
            Ok(Ok(opened)) => opened,
            Ok(Err(err)) => {
                log::info!("reconnect failed: {err}");
                false
            }
            Err(panic) => {
                p.drop_link();
                internal_error(&*panic);
                false
            }
        }
    };
    let mut q = shared.lock_queue();
    if q.state != ConnectionState::Reconnecting {
        return;
    }
    let now = Instant::now();
    let event = if reopened {
        q.state = ConnectionState::Connected;
        q.attempt = 0;
        q.cause = None;
        q.retry_at = None;
        q.last_activity = now;
        poll_now(&mut q);
        ConnectionEvent::Connected
    } else {
        q.attempt = q.attempt.saturating_add(1);
        let delay = backoff(
            shared.options.reconnect_min,
            shared.options.reconnect_max,
            q.attempt,
        );
        q.retry_at = Some(now.checked_add(delay).unwrap_or(now));
        ConnectionEvent::Reconnecting {
            attempt: q.attempt,
            delay,
        }
    };
    drop(q);
    shared.emit(vec![event]);
}

fn keep_alive<P: Protocol>(shared: &Shared<P>) {
    let outcome = {
        let mut p = shared.lock_state();
        let result = catch_unwind(AssertUnwindSafe(|| p.keep_alive())).unwrap_or_else(|panic| {
            p.drop_link();
            Err(internal_error(&*panic))
        });
        Outcome {
            error: result.err(),
            connected: p.connected(),
            opened: false,
        }
    };
    after_work(shared, outcome);
}

#[cfg(test)]
mod tests;
