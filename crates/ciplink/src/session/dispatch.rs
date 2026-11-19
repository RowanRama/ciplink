//! The callback thread: runs every user callback of one driver (handle completions, subscription changes,
//! connection events) in the order they were posted, never on the session thread or a caller's stack.

use std::any::Any;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

type Task = Box<dyn FnOnce() + Send>;

thread_local! {
    /// On a callback thread, the address of its dispatcher's `worker` (0 elsewhere). Kept on the thread, not
    /// read from `worker`, so it stays true while `stop` joins the thread with the worker taken out.
    static CURRENT: Cell<usize> = const { Cell::new(0) };
}

struct Worker {
    sender: Sender<Task>,
    thread: JoinHandle<()>,
}

/// A handle to a driver's callback thread; clones post to the same thread. The thread starts on the first
/// post and again on the first post after [`stop`](Self::stop).
#[derive(Clone, Default)]
pub(crate) struct Dispatcher {
    worker: Arc<Mutex<Option<Worker>>>,
}

/// The text of a panic payload.
pub(crate) fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".to_owned()
    }
}

impl Dispatcher {
    fn lock(&self) -> MutexGuard<'_, Option<Worker>> {
        self.worker.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn address(&self) -> usize {
        Arc::as_ptr(&self.worker).addr()
    }

    /// Runs `task` on the callback thread after the tasks posted before it. A panic in it is logged and the
    /// thread carries on.
    pub(crate) fn post(&self, task: impl FnOnce() + Send + 'static) {
        let mut worker = self.lock();
        if worker.is_none() {
            let (sender, receiver) = channel::<Task>();
            // a weak reference keeps the address from being reused by another dispatcher while the thread runs
            let this = Arc::downgrade(&self.worker);
            let spawned = std::thread::Builder::new()
                .name("ciplink-callbacks".into())
                .spawn(move || {
                    CURRENT.with(|c| c.set(this.as_ptr().addr()));
                    for task in receiver {
                        if let Err(panic) = catch_unwind(AssertUnwindSafe(task)) {
                            log::error!("a ciplink callback panicked: {}", panic_message(&*panic));
                        }
                    }
                });
            match spawned {
                Ok(thread) => *worker = Some(Worker { sender, thread }),
                Err(err) => {
                    // without a thread the task still has to run once: a waiter depends on it
                    log::error!("Failed to start the callback thread: {err}");
                    drop(worker);
                    task();
                    return;
                }
            }
        }
        if let Some(w) = worker.as_ref() {
            // the receiver lives as long as the thread, which ends only when this sender is dropped
            let _ = w.sender.send(Box::new(task));
        }
    }

    /// True on this dispatcher's callback thread, also while [`stop`](Self::stop) joins it.
    pub(crate) fn is_current(&self) -> bool {
        CURRENT.with(Cell::get) == self.address()
    }

    /// Ends the callback thread after the tasks already posted, joining it unless this is that thread.
    pub(crate) fn stop(&self) {
        let worker = self.lock().take();
        if let Some(Worker { sender, thread }) = worker {
            drop(sender);
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;

    #[test]
    fn tasks_run_in_order_on_one_named_thread() {
        let d = Dispatcher::default();
        let (tx, rx) = channel();
        for i in 0..5 {
            let tx = tx.clone();
            d.post(move || {
                let name = std::thread::current().name().map(str::to_owned);
                tx.send((i, name)).expect("send");
            });
        }
        let got: Vec<_> = (0..5).map(|_| rx.recv().expect("recv")).collect();
        assert!(
            got.iter()
                .enumerate()
                .all(|(i, (n, name))| { *n == i && name.as_deref() == Some("ciplink-callbacks") })
        );
    }

    #[test]
    fn a_panicking_task_does_not_stop_the_thread() {
        let d = Dispatcher::default();
        d.post(|| panic!("boom"));
        let (tx, rx) = sync_channel(1);
        d.post(move || tx.send(()).expect("send"));
        rx.recv_timeout(Duration::from_secs(5)).expect("ran");
    }

    #[test]
    fn stop_runs_what_was_posted_and_a_later_post_starts_again() {
        let d = Dispatcher::default();
        let (tx, rx) = channel();
        let tx2 = tx.clone();
        d.post(move || {
            std::thread::sleep(Duration::from_millis(20));
            tx2.send(1).expect("send");
        });
        d.stop();
        assert_eq!(rx.try_recv(), Ok(1));
        d.post(move || tx.send(2).expect("send"));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(2));
    }

    #[test]
    fn the_callback_thread_is_current_while_stop_joins_it() {
        let d = Dispatcher::default();
        let (entered_tx, entered) = channel();
        let (go_tx, go) = channel::<()>();
        let (tx, rx) = channel();
        let inner = d.clone();
        d.post(move || {
            entered_tx.send(()).expect("send");
            let _ = go.recv_timeout(Duration::from_secs(5));
            tx.send(inner.is_current()).expect("send");
        });
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("entered");
        let stopper = {
            let d = d.clone();
            std::thread::spawn(move || d.stop())
        };
        std::thread::sleep(Duration::from_millis(20)); // stop is joining
        go_tx.send(()).expect("send");
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true));
        stopper.join().expect("joined");
    }

    #[test]
    fn stop_from_the_callback_thread_does_not_join_itself() {
        let d = Dispatcher::default();
        let (tx, rx) = channel();
        let inner = d.clone();
        d.post(move || {
            assert!(inner.is_current());
            inner.stop();
            tx.send(()).expect("send");
        });
        rx.recv_timeout(Duration::from_secs(5)).expect("returned");
        assert!(!d.is_current());
    }
}
