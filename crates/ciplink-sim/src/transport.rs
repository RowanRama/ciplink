//! The in-memory transport: a driver talks to the simulator without sockets.

use crate::encap::{Inner, Outcome, Session};
use crate::{Answer, Deferred};
use ciplink::transport::Transport;
use ciplink::{Error, Result};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// A connection to a [`crate::Simulator`] in memory, as a driver's [`Transport`].
///
/// Each one is a client connection of its own (its own session and CIP connections). A reply that is dropped
/// (see [`crate::Fault::DropReplies`]) or delayed past the timeout makes `receive` fail at once instead of
/// waiting; a delayed reply stays queued and answers the next `receive`, as a late reply on a socket would.
/// With [`crate::Simulator::set_deferred`], `receive` waits up to the timeout for the request to be serviced.
pub struct SimTransport {
    inner: Arc<Mutex<Inner>>,
    deferred: Arc<Deferred>,
    session: Session,
    /// The answer to a deferred request not serviced yet (the session is with it).
    waiting: Option<Receiver<Answer>>,
    replies: VecDeque<(Vec<u8>, Duration)>,
    timeout: Option<Duration>,
    closed: bool,
}

impl SimTransport {
    pub(crate) fn new(
        inner: Arc<Mutex<Inner>>,
        deferred: Arc<Deferred>,
        port: u16,
        timeout: Option<Duration>,
    ) -> Self {
        SimTransport {
            inner,
            deferred,
            session: Session::new(port),
            waiting: None,
            replies: VecDeque::new(),
            timeout,
            closed: false,
        }
    }

    fn outcome(&mut self, outcome: Outcome, delay: Duration) {
        match outcome {
            Outcome::Reply(reply) => self.replies.push_back((reply, delay)),
            Outcome::Silent => {}
            Outcome::Close => self.closed = true,
        }
    }

    /// Waits up to the timeout for a deferred request to be serviced; it stays waiting if it is not.
    fn wait(&mut self) -> Result<()> {
        let Some(waiting) = self.waiting.take() else {
            return Ok(());
        };
        let answer = match self.timeout {
            Some(timeout) => waiting.recv_timeout(timeout),
            None => waiting.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match answer {
            Ok((session, outcome, delay)) => {
                self.session = session;
                self.outcome(outcome, delay);
                Ok(())
            }
            Err(RecvTimeoutError::Timeout) => {
                self.waiting = Some(waiting);
                Err(Error::comm("timed out"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.closed = true;
                Ok(())
            }
        }
    }
}

impl Transport for SimTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.wait()?;
        if self.closed {
            return Err(Error::comm("socket connection broken."));
        }
        match self.deferred.push(std::mem::take(&mut self.session), frame) {
            Ok(answer) => self.waiting = Some(answer),
            Err(session) => {
                self.session = session;
                let (outcome, delay) = self
                    .inner
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .handle(&mut self.session, frame);
                self.outcome(outcome, delay);
            }
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>> {
        if self.replies.is_empty() {
            self.wait()?;
        }
        match self.replies.pop_front() {
            Some((reply, delay)) => {
                if self.timeout.is_some_and(|t| delay >= t) {
                    self.replies.push_front((reply, Duration::ZERO));
                    return Err(Error::comm("timed out"));
                }
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                Ok(reply)
            }
            None if self.closed => Err(Error::comm(
                "socket connection closed before a complete frame was received",
            )),
            None => Err(Error::comm("timed out")),
        }
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}
