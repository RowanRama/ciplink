//! The in-memory transport: a driver talks to the simulator without sockets.

use crate::encap::{Inner, Outcome, Session};
use ciplink::transport::Transport;
use ciplink::{Error, Result};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// A connection to a [`crate::Simulator`] in memory, as a driver's [`Transport`].
///
/// Each one is a client connection of its own (its own session and CIP connections). A reply that is dropped
/// (see [`crate::Fault::DropReplies`]) or delayed past the timeout makes `receive` fail at once instead of
/// waiting; a delayed reply stays queued and answers the next `receive`, as a late reply on a socket would.
pub struct SimTransport {
    inner: Arc<Mutex<Inner>>,
    session: Session,
    replies: VecDeque<(Vec<u8>, Duration)>,
    timeout: Option<Duration>,
    closed: bool,
}

impl SimTransport {
    pub(crate) fn new(inner: Arc<Mutex<Inner>>, port: u16, timeout: Option<Duration>) -> Self {
        SimTransport {
            inner,
            session: Session::new(port),
            replies: VecDeque::new(),
            timeout,
            closed: false,
        }
    }
}

impl Transport for SimTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed {
            return Err(Error::comm("socket connection broken."));
        }
        let (outcome, delay) = self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handle(&mut self.session, frame);
        match outcome {
            Outcome::Reply(reply) => self.replies.push_back((reply, delay)),
            Outcome::Silent => {}
            Outcome::Close => self.closed = true,
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>> {
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
