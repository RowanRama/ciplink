//! [`Handle`]: the result of a request that is queued or in flight, and `Completer`, the session's half.

use std::any::Any;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use super::dispatch::Dispatcher;
use crate::{Error, Result};

thread_local! {
    /// True on a session thread: a blocking wait there could only wait for itself.
    static ON_SESSION_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Marks the current thread as a session thread.
pub(crate) fn mark_session_thread() {
    ON_SESSION_THREAD.with(|on| on.set(true));
}

/// True on a session thread.
pub(crate) fn on_session_thread() -> bool {
    ON_SESSION_THREAD.with(Cell::get)
}

/// The error of a blocking wait on a session thread.
pub(crate) fn own_thread_error() -> Error {
    Error::request("cannot wait for the driver on its own session thread")
}

fn taken_error() -> Error {
    Error::request("result already taken")
}

type Callback<T> = Box<dyn FnOnce(Result<T>) + Send>;

/// The payload of a panic in the request.
pub(crate) type Panic = Box<dyn Any + Send>;

struct SlotState<T> {
    result: Option<Result<T>>,
    /// A panic in the request, resumed by `wait` (a blocking caller sees the panic as it did before
    /// sessions); everything else gets the result's internal CommError.
    panic: Option<Panic>,
    done: bool,
    waker: Option<Waker>,
    callback: Option<Callback<T>>,
}

struct Slot<T> {
    state: Mutex<SlotState<T>>,
    ready: Condvar,
    dispatcher: Dispatcher,
}

impl<T> Slot<T> {
    fn lock(&self) -> MutexGuard<'_, SlotState<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The result of a request that is queued or in flight: wait for it, poll it, await it (it is a
/// [`Future`] that needs no particular runtime) or have a callback called with it.
///
/// Dropping it does not cancel the request (a queued write still runs); the result is discarded.
pub struct Handle<T> {
    slot: Arc<Slot<T>>,
}

/// The session's half of a [`Handle`]: completes it exactly once. Dropped without completing (a bug or a
/// panic), it completes the handle with a CommError so no waiter can hang.
pub(crate) struct Completer<T: Send + 'static> {
    slot: Option<Arc<Slot<T>>>,
}

impl<T: Send + 'static> Handle<T> {
    /// A handle and its completer; `on_complete` callbacks run on `dispatcher`'s thread.
    pub(crate) fn new(dispatcher: Dispatcher) -> (Self, Completer<T>) {
        let slot = Arc::new(Slot {
            state: Mutex::new(SlotState {
                result: None,
                panic: None,
                done: false,
                waker: None,
                callback: None,
            }),
            ready: Condvar::new(),
            dispatcher,
        });
        (
            Handle {
                slot: Arc::clone(&slot),
            },
            Completer { slot: Some(slot) },
        )
    }

    /// Blocks until the result is in. A RequestError if [`try_take`](Self::try_take) or
    /// [`wait_timeout`](Self::wait_timeout) already took it, or if called on the driver's session thread
    /// (from a hook running there), where waiting would deadlock. If the request panicked, the panic is
    /// resumed here, on the caller's thread.
    pub fn wait(self) -> Result<T> {
        if on_session_thread() {
            return Err(own_thread_error());
        }
        let mut state = self.slot.lock();
        while !state.done {
            state = self
                .slot
                .ready
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if let Some(panic) = state.panic.take() {
            drop(state);
            std::panic::resume_unwind(panic);
        }
        state.result.take().unwrap_or_else(|| Err(taken_error()))
    }

    /// Blocks up to `timeout`: Some(result) once it is in (taking it), None on timeout (the handle stays
    /// usable).
    pub fn wait_timeout(&self, timeout: Duration) -> Option<Result<T>> {
        if on_session_thread() {
            return Some(Err(own_thread_error()));
        }
        let deadline = Instant::now().checked_add(timeout);
        let mut state = self.slot.lock();
        while !state.done {
            let left = match deadline {
                Some(d) => d.saturating_duration_since(Instant::now()),
                None => Duration::MAX,
            };
            if left.is_zero() {
                return None;
            }
            state = self
                .slot
                .ready
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Some(state.result.take().unwrap_or_else(|| Err(taken_error())))
    }

    /// The result if it is in, taking it; None if it is not in yet, or was already taken.
    pub fn try_take(&self) -> Option<Result<T>> {
        self.slot.lock().result.take()
    }

    /// True once the result is in (taken or not).
    pub fn is_done(&self) -> bool {
        self.slot.lock().done
    }

    /// Calls `f` with the result on the driver's callback thread: later, or soon if it is already in. Never
    /// on the calling thread's stack. If the result was already taken, `f` gets that RequestError.
    pub fn on_complete(self, f: impl FnOnce(Result<T>) + Send + 'static) {
        let mut state = self.slot.lock();
        if state.done {
            let result = state.result.take().unwrap_or_else(|| Err(taken_error()));
            drop(state);
            self.slot.dispatcher.post(move || f(result));
        } else {
            state.callback = Some(Box::new(f));
        }
    }
}

impl<T: Send + 'static> Future for Handle<T> {
    type Output = Result<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.slot.lock();
        if state.done {
            return Poll::Ready(state.result.take().unwrap_or_else(|| Err(taken_error())));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl<T> std::fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("done", &self.slot.lock().done)
            .finish()
    }
}

impl<T: Send + 'static> Completer<T> {
    /// Completes the handle: posts its callback, or stores the result and wakes its waiters. Never blocks.
    pub(crate) fn complete(mut self, result: Result<T>) {
        if let Some(slot) = self.slot.take() {
            finish(&slot, result);
        }
    }

    /// Completes the handle with `error` after the request panicked; a blocking `wait` resumes `panic`.
    pub(crate) fn panicked(mut self, panic: Panic, error: Error) {
        if let Some(slot) = self.slot.take() {
            slot.lock().panic = Some(panic);
            finish(&slot, Err(error));
        }
    }

    /// [`complete`](Self::complete), or [`panicked`](Self::panicked) with `result`'s error if `panic` is set.
    pub(crate) fn finish(self, result: Result<T>, panic: Option<Panic>) {
        match (panic, result) {
            (Some(panic), Err(error)) => self.panicked(panic, error),
            (_, result) => self.complete(result),
        }
    }
}

fn finish<T: Send + 'static>(slot: &Slot<T>, result: Result<T>) {
    let mut state = slot.lock();
    state.done = true;
    if let Some(callback) = state.callback.take() {
        drop(state);
        slot.dispatcher.post(move || callback(result));
        return;
    }
    state.result = Some(result);
    let waker = state.waker.take();
    slot.ready.notify_all();
    drop(state);
    if let Some(waker) = waker {
        waker.wake();
    }
}

impl<T: Send + 'static> Drop for Completer<T> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            finish(&slot, Err(Error::comm("request dropped")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::AssertUnwindSafe;
    use std::sync::mpsc::channel;
    use std::task::Wake;
    use std::thread::Thread;

    fn pair() -> (Handle<u32>, Completer<u32>) {
        Handle::new(Dispatcher::default())
    }

    #[test]
    fn wait_returns_the_result() {
        let (h, c) = pair();
        let t = std::thread::spawn(move || c.complete(Ok(7)));
        assert_eq!(h.wait(), Ok(7));
        t.join().expect("join");
    }

    #[test]
    fn wait_timeout_returns_none_then_the_result() {
        let (h, c) = pair();
        assert_eq!(h.wait_timeout(Duration::from_millis(10)), None);
        assert!(!h.is_done());
        c.complete(Err(Error::comm("x")));
        assert!(h.is_done());
        assert_eq!(
            h.wait_timeout(Duration::from_millis(10)),
            Some(Err(Error::comm("x")))
        );
        assert_eq!(h.wait(), Err(taken_error()));
    }

    #[test]
    fn try_take_takes_once() {
        let (h, c) = pair();
        assert_eq!(h.try_take(), None);
        c.complete(Ok(1));
        assert_eq!(h.try_take(), Some(Ok(1)));
        assert_eq!(h.try_take(), None);
        assert!(h.is_done());
    }

    #[test]
    fn on_complete_runs_on_the_callback_thread() {
        let (h, c) = pair();
        let (tx, rx) = channel();
        h.on_complete(move |r| {
            let name = std::thread::current().name().map(str::to_owned);
            tx.send((r, name)).expect("send");
        });
        c.complete(Ok(3));
        let (r, name) = rx.recv_timeout(Duration::from_secs(5)).expect("called");
        assert_eq!(r, Ok(3));
        assert_eq!(name.as_deref(), Some("ciplink-callbacks"));
    }

    #[test]
    fn on_complete_after_completion_still_posts() {
        let (h, c) = pair();
        c.complete(Ok(4));
        let (tx, rx) = channel();
        let caller = std::thread::current().id();
        h.on_complete(move |r| {
            tx.send((r, std::thread::current().id())).expect("send");
        });
        let (r, thread) = rx.recv_timeout(Duration::from_secs(5)).expect("called");
        assert_eq!(r, Ok(4));
        assert_ne!(thread, caller);
    }

    struct ThreadWaker(Thread);

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn future_wakes_when_completed() {
        let (h, c) = pair();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            c.complete(Ok(9));
        });
        assert_eq!(block_on(h), Ok(9));
        t.join().expect("join");
    }

    #[test]
    fn dropped_completer_fails_the_handle() {
        let (h, c) = pair();
        drop(c);
        assert_eq!(h.wait(), Err(Error::comm("request dropped")));
        let (h, c) = pair();
        let (tx, rx) = channel();
        h.on_complete(move |r| tx.send(r).expect("send"));
        drop(c);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(Err(Error::comm("request dropped")))
        );
    }

    #[test]
    fn a_panic_resumes_in_wait_and_is_an_error_elsewhere() {
        let (h, c) = pair();
        c.panicked(Box::new("boom"), Error::comm("internal error: boom"));
        let caught = std::panic::catch_unwind(AssertUnwindSafe(|| h.wait()));
        assert!(caught.is_err());
        let (h, c) = pair();
        c.panicked(Box::new("boom"), Error::comm("internal error: boom"));
        assert_eq!(h.try_take(), Some(Err(Error::comm("internal error: boom"))));
    }

    #[test]
    fn wait_on_a_session_thread_fails_at_once() {
        let (h, _c) = pair();
        let r = std::thread::spawn(move || {
            mark_session_thread();
            h.wait()
        })
        .join()
        .expect("join");
        assert_eq!(r, Err(own_thread_error()));
    }
}
