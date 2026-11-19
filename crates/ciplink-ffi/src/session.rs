//! Async requests, subscriptions and connection events: the C side of the driver's session (its request queue,
//! session thread and callback thread).
//!
//! Every callback of this module runs on the driver's **callback thread**, one at a time and in order, never on
//! the thread that made the call and never on the session thread that does the I/O. A callback may call any
//! ciplink function, blocking ones on the same driver included, but while it runs no other callback of that driver
//! runs: keep it short and do not wait in it for something another callback of the same driver must do.

use super::*;
use ciplink_core::session::{
    ConnectionCallback, ConnectionEvent, ConnectionState, Handle, SessionOptions, SubscribeOptions,
    Subscription,
};
use std::sync::{Arc, Condvar};
use std::time::Instant;

/// Where a driver's link is ([`ciplink_connection_state`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiplinkConnectionState {
    /// Never opened, closed, or lost with reconnect off.
    Closed = 0,
    /// Opened and not lost since.
    Connected = 1,
    /// Lost; reconnecting in the background. Reads, writes and subscription polls fail at once meanwhile.
    Reconnecting = 2,
}

/// Called once with the outcome of a [`ciplink_read_async`] or [`ciplink_write_async`], on the driver's callback
/// thread. With [`CiplinkStatus::Ok`] `json` is the result array (as [`ciplink_read`] returns), otherwise it is the
/// error message. `json` is valid only during the call.
///
/// Every callback of a driver (`CiplinkDone`, `CiplinkChanges`, `CiplinkConnectionCallback`) runs on that
/// driver's one callback thread, one at a time and in order: never on the calling thread's stack and never on the
/// thread that does the I/O. A callback may call any ciplink function, blocking ones on the same driver included,
/// but it must not block for long (the driver's other callbacks wait for it) and must not unwind.
pub type CiplinkDone =
    Option<unsafe extern "C" fn(user: *mut c_void, status: CiplinkStatus, json: *const c_char)>;

/// Called with the tags of a subscription that changed, as a result array (valid only during the call), on the
/// driver's callback thread.
pub type CiplinkChanges =
    Option<unsafe extern "C" fn(user: *mut c_void, results_json: *const c_char)>;

/// Called with each change of the link, on the driver's callback thread, as JSON (valid only during the call):
/// `{"event":"connected"}`, `{"event":"disconnected","error":"..."}` or
/// `{"event":"reconnecting","attempt":3,"delay":0.4}` (the attempt number from 1, the wait before it in seconds).
pub type CiplinkConnectionCallback =
    Option<unsafe extern "C" fn(user: *mut c_void, event_json: *const c_char)>;

/// The caller's `user` pointer, handed to its callback on the callback thread.
struct User(*mut c_void);

// SAFETY: the C contract of every function taking `user` says it is used from the driver's callback thread;
// the library only passes it back and never dereferences it.
unsafe impl Send for User {}
// SAFETY: as above.
unsafe impl Sync for User {}

impl User {
    // a method, not `.0`, so closures capture the whole (Send) struct rather than the raw pointer field
    fn ptr(&self) -> *mut c_void {
        self.0
    }
}

fn c_text(text: &str) -> CString {
    CString::new(text.replace('\0', " ")).unwrap_or_default()
}

// ------------------------------------------------------------------------------------------------ options

fn seconds(j: &Json, key: &str) -> FfiResult<Duration> {
    j.as_f64()
        .filter(|s| s.is_finite() && *s > 0.0)
        .map(Duration::from_secs_f64)
        .ok_or_else(|| FfiError::Invalid(format!("option {key} must be positive seconds")))
}

/// The session keys of a Logix or SLC options object: `reconnect`, `reconnect_min`, `reconnect_max`, `keep_alive`.
pub(crate) fn session_options(o: &Map<String, Json>) -> FfiResult<SessionOptions> {
    let mut s = SessionOptions {
        reconnect: get_bool(o, "reconnect", true)?,
        ..SessionOptions::default()
    };
    if let Some(j) = o.get("reconnect_min") {
        s.reconnect_min = seconds(j, "reconnect_min")?;
    }
    if let Some(j) = o.get("reconnect_max") {
        s.reconnect_max = seconds(j, "reconnect_max")?;
    }
    match o.get("keep_alive") {
        None => {}
        Some(Json::Null) => s.keep_alive = None,
        Some(j) => s.keep_alive = Some(seconds(j, "keep_alive")?),
    }
    Ok(s)
}

fn subscribe_options(o: &Map<String, Json>) -> FfiResult<SubscribeOptions> {
    let mut s = SubscribeOptions::default();
    if let Some(j) = o.get("interval") {
        s.interval = seconds(j, "interval")?;
    }
    match o.get("deadband") {
        None | Some(Json::Null) => {}
        Some(j) => {
            s.deadband = Some(j.as_f64().filter(|d| d.is_finite()).ok_or_else(|| {
                FfiError::Invalid("option deadband must be a number or null".into())
            })?);
        }
    }
    Ok(s)
}

// ------------------------------------------------------------------------------------------------ requests

/// A read or write queued by [`ciplink_read_async`] or [`ciplink_write_async`]: poll it with
/// [`ciplink_request_done`], wait for it with [`ciplink_request_wait`], free it with [`ciplink_request_free`].
pub struct CiplinkRequest {
    slot: Arc<Slot>,
}

#[derive(Default)]
struct Slot {
    state: Mutex<SlotState>,
    ready: Condvar,
}

#[derive(Default)]
enum SlotState {
    #[default]
    Pending,
    Done(CiplinkStatus, String),
    Taken,
}

/// Queues the completion of `pending`: fill the request's slot, then call `done`.
fn submit(
    pending: Handle<Vec<TagResult>>,
    done: CiplinkDone,
    user: *mut c_void,
    out_request: *mut *mut CiplinkRequest,
) {
    let slot = Arc::new(Slot::default());
    if !out_request.is_null() {
        let request = Box::new(CiplinkRequest {
            slot: Arc::clone(&slot),
        });
        // SAFETY: not NULL, and the caller passes a writable location.
        unsafe { *out_request = Box::into_raw(request) };
    }
    let user = User(user);
    pending.on_complete(move |result| {
        let (status, text) = match result {
            Ok(results) => (CiplinkStatus::Ok, results_json(&results)),
            Err(e) => status_of(&FfiError::Core(e)),
        };
        let c = c_text(&text);
        *slot.state.lock().unwrap_or_else(|p| p.into_inner()) = SlotState::Done(status, text);
        slot.ready.notify_all();
        if let Some(done) = done {
            // SAFETY: the caller passes a callback taking `user` and a string valid during the call.
            unsafe { done(user.ptr(), status, c.as_ptr()) };
        }
    });
}

/// Clears an optional out pointer.
fn clear_out<T>(out: *mut *mut T) {
    if !out.is_null() {
        // SAFETY: not NULL, and the caller passes a writable location.
        unsafe { *out = ptr::null_mut() };
    }
}

/// Queues a read of `count` tags (as [`ciplink_read`]) and returns at once. Reads queued together, by any thread
/// or subscription, go out as one read.
///
/// `done` and `out_request` may each be NULL. A non-OK return (bad arguments, or [`CiplinkStatus::Unsupported`]
/// for a plain CIP driver) means nothing was queued and `done` is never called. Otherwise `done` is called exactly
/// once on the driver's callback thread, possibly before this returns (a request that fails at once, e.g. while
/// reconnecting), so set up `user` first. `*out_request` (if not NULL) receives a request handle for
/// [`ciplink_request_wait`]; free it with [`ciplink_request_free`].
///
/// # Safety
/// `handle` is NULL or a live handle; `tags` points to `count` NUL-terminated strings; `done` does not unwind and
/// `user` is whatever it expects, usable from another thread until `done` was called; `out_request` is NULL or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_read_async(
    handle: *const CiplinkDriver,
    tags: *const *const c_char,
    count: usize,
    done: CiplinkDone,
    user: *mut c_void,
    out_request: *mut *mut CiplinkRequest,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        clear_out(out_request);
        let names = arg_names(tags, count)?;
        let pending = match &h.driver {
            Driver::Logix(d) => d.read_async(&names),
            Driver::Slc(d) => d.read_async(&names),
            Driver::Cip(_) => return Err(FfiError::Unsupported("read_async")),
        };
        submit(pending, done, user, out_request);
        Ok(())
    })
}

/// Queues a write of `items_json` (as [`ciplink_write`]) and returns at once; `done`, `user` and `out_request` as
/// [`ciplink_read_async`]. Writes run in the order queued, are never merged and never sent twice: a write whose
/// connection is lost returns its error.
///
/// # Safety
/// As [`ciplink_read_async`]; `items_json` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_write_async(
    handle: *const CiplinkDriver,
    items_json: *const c_char,
    done: CiplinkDone,
    user: *mut c_void,
    out_request: *mut *mut CiplinkRequest,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        clear_out(out_request);
        let (names, values) = write_items(items_json)?;
        let pairs: Vec<(&str, Value)> = names.iter().map(String::as_str).zip(values).collect();
        let pending = match &h.driver {
            Driver::Logix(d) => d.write_async(&pairs),
            Driver::Slc(d) => d.write_async(&pairs),
            Driver::Cip(_) => return Err(FfiError::Unsupported("write_async")),
        };
        submit(pending, done, user, out_request);
        Ok(())
    })
}

/// True once the request's result is in (taken or not); false for NULL.
///
/// # Safety
/// `request` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_request_done(request: *const CiplinkRequest) -> bool {
    // SAFETY: NULL or a live request (caller contract).
    let Some(r) = (unsafe { request.as_ref() }) else {
        return false;
    };
    let state = r.slot.state.lock().unwrap_or_else(|p| p.into_inner());
    !matches!(*state, SlotState::Pending)
}

/// Waits for a request: up to `timeout_ms` milliseconds, or forever if negative. On success writes the result
/// array to `*out_json` (if not NULL; free it with [`ciplink_string_free`]). On failure returns the request's
/// status with its message from [`ciplink_last_error`] with NULL. [`CiplinkStatus::Timeout`] leaves the request
/// pending; a wait after the result was taken is [`CiplinkStatus::InvalidArgument`].
///
/// # Safety
/// `request` is NULL or a live request; `out_json` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_request_wait(
    request: *const CiplinkRequest,
    timeout_ms: i64,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    guard(None, || {
        clear_out(out_json);
        // SAFETY: NULL or a live request (caller contract).
        let r = unsafe { request.as_ref() }
            .ok_or_else(|| FfiError::Invalid("request is NULL".into()))?;
        let deadline = u64::try_from(timeout_ms)
            .ok()
            .and_then(|ms| Instant::now().checked_add(Duration::from_millis(ms)));
        let mut state = r.slot.state.lock().unwrap_or_else(|p| p.into_inner());
        while matches!(*state, SlotState::Pending) {
            state = match (timeout_ms < 0, deadline) {
                (false, Some(deadline)) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(FfiError::Status(
                            CiplinkStatus::Timeout,
                            "the request is not done yet".into(),
                        ));
                    }
                    r.slot
                        .ready
                        .wait_timeout(state, left)
                        .unwrap_or_else(|p| p.into_inner())
                        .0
                }
                _ => r.slot.ready.wait(state).unwrap_or_else(|p| p.into_inner()),
            };
        }
        match std::mem::replace(&mut *state, SlotState::Taken) {
            SlotState::Done(CiplinkStatus::Ok, json) => {
                drop(state);
                if out_json.is_null() {
                    Ok(())
                } else {
                    put_string(out_json, json)
                }
            }
            SlotState::Done(status, message) => Err(FfiError::Status(status, message)),
            _ => Err(FfiError::Invalid(
                "the request's result was already taken".into(),
            )),
        }
    })
}

/// Frees a request handle; NULL is ignored. It can be freed at any time: a pending request still runs and its
/// `done` is still called.
///
/// # Safety
/// `request` is NULL or a request not yet freed, and no other thread is using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_request_free(request: *mut CiplinkRequest) {
    if !request.is_null() {
        // SAFETY: made by Box::into_raw in `submit`, freed once (caller contract).
        let _ = catch_unwind(|| drop(unsafe { Box::from_raw(request) }));
    }
}

// ------------------------------------------------------------------------------------------------ subscriptions

/// A running subscription, made by [`ciplink_subscribe`] and ended by [`ciplink_subscription_free`].
pub struct CiplinkSubscription {
    _subscription: Subscription,
}

/// Subscribes to `count` tags: they are read every interval (packed with the driver's other reads) and the tags
/// whose value or error changed are passed to `on_changes` on the driver's callback thread. The first call has
/// every tag. A failed read (or a lost link) is a change to a tag result with an error of kind `comm`.
///
/// `options_json` may be NULL or `{}`; keys (all optional): `interval` (seconds, default 1), `deadband` (numeric
/// tags: a change smaller than this since the last value passed is not passed; null for none). Unsupported for a
/// plain CIP driver.
///
/// # Safety
/// `handle` is NULL or a live handle; `tags` points to `count` NUL-terminated strings; `options_json` is NULL or
/// NUL-terminated; `on_changes` does not unwind and `user` is whatever it expects, usable from another thread
/// until [`ciplink_subscription_free`] returns; `out_subscription` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_subscribe(
    handle: *const CiplinkDriver,
    tags: *const *const c_char,
    count: usize,
    options_json: *const c_char,
    on_changes: CiplinkChanges,
    user: *mut c_void,
    out_subscription: *mut *mut CiplinkSubscription,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_subscription)?;
        let names = arg_names(tags, count)?;
        let on_changes =
            on_changes.ok_or_else(|| FfiError::Invalid("on_changes is NULL".into()))?;
        let options = subscribe_options(&options_map(options_json)?)?;
        let subscription = match &h.driver {
            Driver::Logix(d) => d.subscribe(&names, options)?,
            Driver::Slc(d) => d.subscribe(&names, options)?,
            Driver::Cip(_) => return Err(FfiError::Unsupported("subscribe")),
        };
        let user = User(user);
        subscription.on_changes(move |changes| {
            let c = c_text(&results_json(&changes.results));
            // SAFETY: the caller passes a callback taking `user` and a string valid during the call.
            unsafe { on_changes(user.ptr(), c.as_ptr()) };
        });
        let boxed = Box::new(CiplinkSubscription {
            _subscription: subscription,
        });
        // SAFETY: `out_subscription` was checked not NULL by check_out.
        unsafe { *out_subscription = Box::into_raw(boxed) };
        Ok(())
    })
}

/// Unsubscribes and frees the subscription; NULL is ignored. Once it returns `on_changes` is not running and will
/// not be called again (unless it is called from the callback thread, e.g. from `on_changes` itself: then the
/// running call finishes after it), so `user` can be freed.
///
/// # Safety
/// `subscription` is NULL or a subscription not yet freed, and no other thread is using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_subscription_free(subscription: *mut CiplinkSubscription) {
    if !subscription.is_null() {
        // SAFETY: made by Box::into_raw in `ciplink_subscribe`, freed once (caller contract).
        let _ = catch_unwind(|| drop(unsafe { Box::from_raw(subscription) }));
    }
}

// ------------------------------------------------------------------------------------------------ connection state

fn event_json(event: &ConnectionEvent) -> String {
    match event {
        ConnectionEvent::Connected => serde_json::json!({"event": "connected"}),
        ConnectionEvent::Disconnected { error } => {
            serde_json::json!({"event": "disconnected", "error": status_of(&FfiError::Core(error.clone())).1})
        }
        ConnectionEvent::Reconnecting { attempt, delay } => serde_json::json!({
            "event": "reconnecting",
            "attempt": attempt,
            "delay": delay.as_secs_f64(),
        }),
    }
    .to_string()
}

/// Sets the callback told of connection changes (see [`CiplinkConnectionCallback`]), or removes it with a NULL
/// `callback`. Once this returns the old callback is not running and will not be called again (unless this is
/// called from the callback thread), so its `user` can be freed. Unsupported for a plain CIP driver.
///
/// A Logix or SLC driver reconnects by itself after an open link is lost (option `reconnect`, default true): the
/// events are `disconnected`, then `reconnecting` before each attempt (100 ms, then doubling up to 10 s), then
/// `connected`. [`ciplink_close`] stops it. Neither [`ciplink_close`] nor a failed [`ciplink_open`] sends an event.
///
/// # Safety
/// `handle` is NULL or a live handle; `callback` does not unwind and `user` is whatever it expects, usable from
/// another thread until the callback is replaced or the driver freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_set_connection_callback(
    handle: *const CiplinkDriver,
    callback: CiplinkConnectionCallback,
    user: *mut c_void,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        let callback = callback.map(|f| {
            let user = User(user);
            Box::new(move |event: &ConnectionEvent| {
                let c = c_text(&event_json(event));
                // SAFETY: the caller passes a callback taking `user` and a string valid during the call.
                unsafe { f(user.ptr(), c.as_ptr()) };
            }) as ConnectionCallback
        });
        match &h.driver {
            Driver::Logix(d) => d.set_connection_callback(callback),
            Driver::Slc(d) => d.set_connection_callback(callback),
            Driver::Cip(_) => return Err(FfiError::Unsupported("set_connection_callback")),
        }
        Ok(())
    })
}

/// Where the driver's link is; never waits for I/O. [`CiplinkConnectionState::Closed`] for NULL; a plain CIP
/// driver reports connected or closed.
///
/// # Safety
/// `handle` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_connection_state(
    handle: *const CiplinkDriver,
) -> CiplinkConnectionState {
    // SAFETY: NULL or a live handle (caller contract).
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return CiplinkConnectionState::Closed;
    };
    let state = catch_unwind(AssertUnwindSafe(|| match &h.driver {
        Driver::Logix(d) => d.connection_state(),
        Driver::Slc(d) => d.connection_state(),
        Driver::Cip(d) if d.connected() => ConnectionState::Connected,
        Driver::Cip(_) => ConnectionState::Closed,
    }))
    .unwrap_or(ConnectionState::Closed);
    match state {
        ConnectionState::Closed => CiplinkConnectionState::Closed,
        ConnectionState::Connected => CiplinkConnectionState::Connected,
        ConnectionState::Reconnecting => CiplinkConnectionState::Reconnecting,
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
