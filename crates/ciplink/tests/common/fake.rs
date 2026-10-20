//! A scripted fake transport for driver tests.
//!
//! `Fake` is a cheap clonable handle on shared state: hand `fake.connector()` to a driver, queue replies, then
//! check what was sent. Receive serves, in order: queued replies (`reply`, `reply_err`), else the responder
//! closure (`respond`), else an empty frame, like the Python tests' `Mocket`.
#![allow(dead_code, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciplink::Error;
use ciplink::transport::{Connector, Transport};

type Responder = Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, Error> + Send>;

#[derive(Default)]
struct State {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Result<Vec<u8>, Error>>,
    send_errors: VecDeque<Option<Error>>,
    connect_errors: VecDeque<Option<Error>>,
    responder: Option<Responder>,
    connects: Vec<(String, u16, Option<Duration>)>,
    timeouts: Vec<Option<Duration>>,
    closes: usize,
    receives: usize,
}

/// Shared handle on the scripted transport state.
#[derive(Clone, Default)]
pub struct Fake(Arc<Mutex<State>>);

impl Fake {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A connector opening a transport on this state each time (it fails if `fail_connect` queued one).
    pub fn connector(&self) -> Connector {
        let fake = self.clone();
        Box::new(move |host, port, timeout| {
            let mut s = fake.state();
            s.connects.push((host.to_owned(), port, timeout));
            if let Some(Some(err)) = s.connect_errors.pop_front() {
                return Err(err);
            }
            Ok(Box::new(FakeTransport(fake.clone())) as Box<dyn Transport>)
        })
    }

    /// Queues a reply frame.
    pub fn reply(&self, frame: impl Into<Vec<u8>>) -> &Self {
        self.state().replies.push_back(Ok(frame.into()));
        self
    }

    /// Queues several reply frames.
    pub fn replies<I: IntoIterator<Item = Vec<u8>>>(&self, frames: I) -> &Self {
        for f in frames {
            self.reply(f);
        }
        self
    }

    /// Queues a receive failure.
    pub fn reply_err(&self, err: Error) -> &Self {
        self.state().replies.push_back(Err(err));
        self
    }

    /// Makes the next send fail (sends before it succeed: queue `None` for those).
    pub fn fail_send(&self, err: Error) -> &Self {
        self.state().send_errors.push_back(Some(err));
        self
    }

    /// Lets the next send succeed (to fail a later one).
    pub fn pass_send(&self) -> &Self {
        self.state().send_errors.push_back(None);
        self
    }

    /// Makes the next connect fail.
    pub fn fail_connect(&self, err: Error) -> &Self {
        self.state().connect_errors.push_back(Some(err));
        self
    }

    /// Answers receives with `f(last sent frame)` once the queue is empty.
    pub fn respond(
        &self,
        f: impl FnMut(&[u8]) -> Result<Vec<u8>, Error> + Send + 'static,
    ) -> &Self {
        self.state().responder = Some(Box::new(f));
        self
    }

    /// Frames sent so far.
    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.state().sent.clone()
    }

    /// Takes the frames sent so far.
    pub fn take_sent(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.state().sent)
    }

    /// (host, port, timeout) of each connect.
    pub fn connects(&self) -> Vec<(String, u16, Option<Duration>)> {
        self.state().connects.clone()
    }

    /// Timeouts set on open transports.
    pub fn timeouts(&self) -> Vec<Option<Duration>> {
        self.state().timeouts.clone()
    }

    /// Transports dropped (closed) so far.
    pub fn closes(&self) -> usize {
        self.state().closes
    }

    /// Receive calls so far.
    pub fn receives(&self) -> usize {
        self.state().receives
    }

    /// Replies still queued.
    pub fn pending(&self) -> usize {
        self.state().replies.len()
    }
}

struct FakeTransport(Fake);

impl Transport for FakeTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        let mut s = self.0.state();
        s.sent.push(frame.to_vec());
        match s.send_errors.pop_front() {
            Some(Some(err)) => Err(err),
            _ => Ok(()),
        }
    }

    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let mut s = self.0.state();
        s.receives += 1;
        if let Some(reply) = s.replies.pop_front() {
            return reply;
        }
        let last = s.sent.last().cloned().unwrap_or_default();
        match s.responder.as_mut() {
            Some(f) => f(&last),
            None => Ok(Vec::new()),
        }
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        self.0.state().timeouts.push(timeout);
        Ok(())
    }
}

impl Drop for FakeTransport {
    fn drop(&mut self) {
        self.0.state().closes += 1;
    }
}

// ---- reply frames ----

pub const CONTEXT: &[u8; 8] = b"_pycomm_";

/// An encapsulation frame: header (command, length, session, status, context, options) and data.
pub fn encap(command: u16, session: u32, status: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + data.len());
    out.extend(command.to_le_bytes());
    out.extend((data.len() as u16).to_le_bytes());
    out.extend(session.to_le_bytes());
    out.extend(status.to_le_bytes());
    out.extend(CONTEXT);
    out.extend([0; 4]);
    out.extend(data);
    out
}

/// A RegisterSession reply granting `session`.
pub fn register_reply(session: u32) -> Vec<u8> {
    encap(0x65, session, 0, &[1, 0, 0, 0])
}

/// A CIP reply: reply service, reserved, general status, extended status words, data.
pub fn cip_reply(service: u8, status: u8, ext: &[u16], data: &[u8]) -> Vec<u8> {
    let mut out = vec![service | 0x80, 0, status, ext.len() as u8];
    for e in ext {
        out.extend(e.to_le_bytes());
    }
    out.extend(data);
    out
}

/// A SendRRData (unconnected) reply.
pub fn rr_reply(service: u8, status: u8, ext: &[u16], data: &[u8]) -> Vec<u8> {
    let msg = cip_reply(service, status, ext, data);
    let mut cpf = vec![0, 0, 0, 0, 0x0A, 0, 0x02, 0, 0, 0, 0, 0, 0xB2, 0];
    cpf.extend((msg.len() as u16).to_le_bytes());
    cpf.extend(msg);
    encap(0x6F, 1, 0, &cpf)
}

/// A SendUnitData (connected) reply on connection `cid` echoing `sequence`.
pub fn unit_reply(
    cid: [u8; 4],
    sequence: u16,
    service: u8,
    status: u8,
    ext: &[u16],
    data: &[u8],
) -> Vec<u8> {
    let mut msg = sequence.to_le_bytes().to_vec();
    msg.extend(cip_reply(service, status, ext, data));
    let mut cpf = vec![0, 0, 0, 0, 0x0A, 0, 0x02, 0, 0xA1, 0, 0x04, 0];
    cpf.extend(cid);
    cpf.extend([0xB1, 0]);
    cpf.extend((msg.len() as u16).to_le_bytes());
    cpf.extend(msg);
    encap(0x70, 1, 0, &cpf)
}

/// A successful (Large) Forward Open reply assigning target connection ID `cid`.
pub fn forward_open_reply(large: bool, cid: [u8; 4]) -> Vec<u8> {
    let mut data = cid.to_vec();
    data.extend([0; 22]);
    rr_reply(if large { 0x5B } else { 0x54 }, 0, &[], &data)
}

/// The sequence count of a sent SendUnitData frame.
pub fn sent_sequence(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[44], frame[45]])
}

/// The CIP message of a sent frame: after the sequence count of SendUnitData, else from offset 40.
pub fn sent_message(frame: &[u8]) -> &[u8] {
    if frame[0] == 0x70 {
        &frame[46..]
    } else {
        &frame[40..]
    }
}

/// A responder answering a session: RegisterSession, Large/standard Forward Open (accepted with `cid`),
/// Forward Close, and every connected request with `connected(sequence, message)`.
pub fn session_responder(
    cid: [u8; 4],
    mut connected: impl FnMut(u16, &[u8]) -> Vec<u8> + Send + 'static,
) -> impl FnMut(&[u8]) -> Result<Vec<u8>, Error> + Send + 'static {
    move |frame: &[u8]| {
        Ok(match frame.first() {
            Some(0x65) => register_reply(1),
            Some(0x63) => encap(0x63, 1, 1, &[]),
            Some(0x6F) => match frame.get(40) {
                Some(0x5B) => forward_open_reply(true, cid),
                Some(0x54) => forward_open_reply(false, cid),
                Some(0x4E) => rr_reply(0x4E, 0, &[], &[0; 10]),
                Some(&s) => rr_reply(s, 0x08, &[], &[]),
                None => Vec::new(),
            },
            Some(0x70) => connected(sent_sequence(frame), sent_message(frame)),
            _ => Vec::new(),
        })
    }
}
