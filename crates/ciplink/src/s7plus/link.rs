//! One S7comm-plus connection (spec 2 to 6, 10): TCP, COTP, the cleartext InitSsl, TLS 1.3, the session, the
//! sequence number and the two integrity counters. Every error is fatal for the link: the caller drops it.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use super::codec::WireValue;
use super::cotp::{self, Confirm, CotpStream};
use super::pdu::{
    self, Explore, ExploreReply, GetMultiReply, ItemAddress, MAX_PDU, SetMultiReply, error_code,
    function,
};
use super::tls::{self, Fingerprint, PIN_MISMATCH, SeenFingerprint};
use crate::{Error, Result};

/// Idle time before the first TCP keep-alive probe (as `TcpTransport`).
const KEEP_ALIVE_TIME: Duration = Duration::from_secs(10);
/// Time between TCP keep-alive probes.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

type Tls = StreamOwned<ClientConnection, CotpStream<TcpStream>>;

/// The integrity counter a request takes (spec 6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Counter {
    /// SetMultiVariables, DeleteObject (after session setup).
    Set,
    /// Everything else.
    Get,
}

/// An open S7comm-plus session over TLS.
pub(crate) struct Link {
    tls: Tls,
    /// Last sequence number sent.
    sequence: u16,
    /// Last "get" integrity ID sent.
    get: u32,
    /// Last "set" integrity ID sent.
    set: u32,
    /// The session ID (first object ID of the CreateObject response).
    pub(crate) session: u32,
    /// Attribute 306 (ServerSessionVersion) as received.
    pub(crate) session_version: Vec<u8>,
}

fn comm(context: &str, e: impl std::fmt::Display) -> Error {
    Error::comm(format!("S7comm-plus {context}: {e}"))
}

/// TCP connect within `timeout`, nodelay, keep-alive (the same as `TcpTransport::connect`).
fn tcp_connect(host: &str, port: u16, timeout: Option<Duration>) -> Result<TcpStream> {
    let fail = || Error::comm(format!("Failed to open socket to {host}:{port}"));
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|_| fail())?
        .find(|a| a.is_ipv4())
        .ok_or_else(fail)?;
    let stream = match timeout {
        Some(t) => TcpStream::connect_timeout(&addr, t),
        None => TcpStream::connect(addr),
    }
    .map_err(|_| fail())?;
    stream.set_nodelay(true).map_err(|_| fail())?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEP_ALIVE_TIME)
        .with_interval(KEEP_ALIVE_INTERVAL);
    if let Err(err) = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive) {
        log::debug!("TCP keep-alive not set: {err}");
    }
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|_| fail())?;
    Ok(stream)
}

/// Sends `pdu` as one frame and reads the response PDU.
fn exchange_on(stream: &mut (impl Read + Write), pdu: &[u8]) -> Result<Vec<u8>> {
    stream
        .write_all(&pdu::frame(pdu)?)
        .and_then(|()| stream.flush())
        .map_err(|e| comm("send failed", e))?;
    let reply = pdu::read_pdu(stream, MAX_PDU)?;
    let request = pdu::parse_request_header(pdu)?;
    let r = pdu::parse_response(&reply)?;
    if r.version != request.version {
        return Err(comm("response version", format!("0x{:02X}", r.version)));
    }
    if r.function != request.function || r.sequence != request.sequence {
        return Err(Error::comm(format!(
            "S7comm-plus response function 0x{:04X} sequence {} does not answer function 0x{:04X} sequence {}",
            r.function, r.sequence, request.function, request.sequence
        )));
    }
    // Get/SetMultiVariables report failed items with their item list, whatever the sign: their callers decide
    let multi = matches!(
        r.function,
        function::GET_MULTI_VARIABLES | function::SET_MULTI_VARIABLES
    );
    if error_code(r.return_value) < 0 && !multi {
        return Err(refused(r.return_value));
    }
    Ok(reply)
}

/// A negative return value as a ResponseError: the PDU was read whole, so an optional request may fail without
/// losing the link; the driver treats it as fatal everywhere else.
fn refused(return_value: u64) -> Error {
    Error::response(format!(
        "S7comm-plus request failed with return value 0x{return_value:016X} ({})",
        error_code(return_value)
    ))
}

/// The body of a Get/SetMultiVariables response: with a negative return value it counts only if it parses and
/// lists item errors (spec 12, open questions); otherwise the request was refused.
fn multi_body<T>(
    return_value: u64,
    body: Result<T>,
    has_errors: impl FnOnce(&T) -> bool,
) -> Result<T> {
    if error_code(return_value) >= 0 {
        return body;
    }
    match body {
        Ok(b) if has_errors(&b) => Ok(b),
        _ => Err(refused(return_value)),
    }
}

fn pin_error(pin: &Fingerprint, seen: &SeenFingerprint) -> Error {
    let got = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .map_or_else(|| "?".to_string(), |fp| tls::format_fingerprint(&fp));
    Error::comm(format!(
        "TLS certificate fingerprint {got} does not match the pinned {}",
        tls::format_fingerprint(pin)
    ))
}

impl Link {
    /// Connects and creates a session (spec 10.1 steps 1 to 5). Ok(None): the target refused the COTP
    /// connection.
    pub(crate) fn connect(
        host: &str,
        port: u16,
        timeout: Option<Duration>,
        pin: Option<Fingerprint>,
        seen: &SeenFingerprint,
    ) -> Result<Option<Link>> {
        let mut tcp = tcp_connect(host, port, timeout)?;
        let peer = tcp.peer_addr().map_err(|e| comm("socket", e))?;
        tcp.write_all(&cotp::connect_request())
            .map_err(|e| comm("COTP connect failed", e))?;
        let confirm = cotp::read_tpkt(&mut tcp).map_err(|e| comm("COTP connect failed", e))?;
        if cotp::parse_confirm(&confirm).map_err(|e| comm("COTP connect failed", e))?
            == Confirm::Refused
        {
            return Ok(None);
        }
        // a PLC may confirm a smaller TPDU than the 1024 asked for (spec 2.2)
        let tpdu = cotp::confirmed_tpdu(&confirm);
        let mut stream = CotpStream::with_tpdu(tcp, tpdu);

        // the one cleartext exchange
        let reply = exchange_on(&mut stream, &pdu::init_ssl())?;
        pdu::parse_init_ssl(&pdu::parse_response(&reply)?)?;

        let config = tls::client_config(pin, seen.clone())?;
        let name = ServerName::IpAddress(peer.ip().into());
        let mut conn =
            ClientConnection::new(config, name).map_err(|e| comm("TLS setup failed", e))?;
        while conn.is_handshaking() {
            if let Err(e) = conn.complete_io(&mut stream) {
                if let Some(pin) = &pin
                    && e.to_string().contains(PIN_MISMATCH)
                {
                    return Err(pin_error(pin, seen));
                }
                return Err(comm("TLS handshake failed", e));
            }
        }
        log::debug!(
            "S7comm-plus TPDU {tpdu}, TLS {:?} {:?}",
            conn.protocol_version(),
            conn.negotiated_cipher_suite().map(|s| s.suite())
        );
        let mut link = Link {
            tls: StreamOwned::new(conn, stream),
            sequence: 1,
            get: 0,
            set: 0,
            session: pdu::NULL_SESSION,
            session_version: Vec::new(),
        };

        let seq = link.next_sequence();
        let reply = link.exchange(&pdu::create_object(seq))?;
        let created = pdu::parse_create_object(&pdu::parse_response(&reply)?)?;
        link.session = *created
            .object_ids
            .first()
            .ok_or_else(|| Error::comm("S7comm-plus CreateObject returned no session ID"))?;
        link.session_version = created
            .session_version
            .ok_or_else(|| Error::comm("S7comm-plus CreateObject returned no session version"))?;

        let seq = link.next_sequence();
        let pdu = pdu::session_setup(seq, link.session, &link.session_version);
        let reply = link.exchange(&pdu)?;
        let r = pdu::parse_response(&reply)?;
        let setup = multi_body(r.return_value, pdu::parse_set_multi(&r), |_| false)?;
        if !setup.errors.is_empty() {
            return Err(Error::comm("S7comm-plus session setup was refused"));
        }
        Ok(Some(link))
    }

    fn next_sequence(&mut self) -> u16 {
        self.sequence = if self.sequence == u16::MAX {
            1
        } else {
            self.sequence + 1
        };
        self.sequence
    }

    fn next_integrity(&mut self, counter: Counter) -> u32 {
        let c = match counter {
            Counter::Get => &mut self.get,
            Counter::Set => &mut self.set,
        };
        *c = c.wrapping_add(1);
        *c
    }

    fn exchange(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        exchange_on(&mut self.tls, pdu)
    }

    fn check_integrity(sequence: u16, sent: u32, got: u32) -> Result<()> {
        let want = u32::from(sequence).wrapping_add(sent);
        if got != want {
            return Err(Error::comm(format!(
                "S7comm-plus response integrity {got}, expected {want}"
            )));
        }
        Ok(())
    }

    /// Sets the timeout of later socket reads and writes.
    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        let tcp = self.tls.sock.get_ref();
        tcp.set_read_timeout(timeout)
            .and_then(|()| tcp.set_write_timeout(timeout))
            .map_err(|e| comm("socket", e))
    }

    /// GetMultiVariables. Each item number appears once in the values or the errors, or the PDU is malformed.
    pub(crate) fn get_multi(&mut self, items: &[ItemAddress]) -> Result<GetMultiReply> {
        let seq = self.next_sequence();
        let integrity = self.next_integrity(Counter::Get);
        let reply = self.exchange(&pdu::get_multi(seq, self.session, items, integrity))?;
        let r = pdu::parse_response(&reply)?;
        let body = multi_body(r.return_value, pdu::parse_get_multi(&r), |b| {
            !b.errors.is_empty()
        })?;
        Self::check_integrity(seq, integrity, body.integrity)?;
        let mut seen = vec![false; items.len()];
        let numbers = body
            .values
            .iter()
            .map(|(i, _)| *i)
            .chain(body.errors.iter().map(|(i, _)| *i));
        for n in numbers {
            let slot = (n as usize)
                .checked_sub(1)
                .and_then(|i| seen.get_mut(i))
                .filter(|s| !**s)
                .ok_or_else(|| Error::comm("S7comm-plus read response item numbers malformed"))?;
            *slot = true;
        }
        if seen.iter().any(|s| !s) {
            return Err(Error::comm("S7comm-plus read response misses items"));
        }
        Ok(body)
    }

    /// SetMultiVariables tag write.
    pub(crate) fn set_multi(
        &mut self,
        items: &[(ItemAddress, WireValue)],
    ) -> Result<SetMultiReply> {
        let seq = self.next_sequence();
        let integrity = self.next_integrity(Counter::Set);
        let reply = self.exchange(&pdu::set_multi(seq, self.session, items, integrity))?;
        let r = pdu::parse_response(&reply)?;
        let body = multi_body(r.return_value, pdu::parse_set_multi(&r), |b| {
            !b.errors.is_empty()
        })?;
        Self::check_integrity(seq, integrity, body.integrity)?;
        if body
            .errors
            .iter()
            .any(|(n, _)| *n == 0 || *n as usize > items.len())
        {
            return Err(Error::comm(
                "S7comm-plus write response item numbers malformed",
            ));
        }
        Ok(body)
    }

    /// Explore.
    pub(crate) fn explore(&mut self, request: &Explore) -> Result<ExploreReply> {
        let seq = self.next_sequence();
        let integrity = self.next_integrity(Counter::Get);
        let reply = self.exchange(&pdu::explore(seq, self.session, request, integrity))?;
        let body = pdu::parse_explore(&pdu::parse_response(&reply)?)?;
        Self::check_integrity(seq, integrity, body.integrity)?;
        Ok(body)
    }

    /// GetVarSubStreamed of one attribute.
    pub(crate) fn get_var(&mut self, object: u32, attribute: u32) -> Result<WireValue> {
        let seq = self.next_sequence();
        let integrity = self.next_integrity(Counter::Get);
        let pdu = pdu::get_var(seq, self.session, object, attribute, integrity);
        let reply = self.exchange(&pdu)?;
        let (value, got) = pdu::parse_get_var(&pdu::parse_response(&reply)?)?;
        Self::check_integrity(seq, integrity, got)?;
        Ok(value)
    }

    /// DeleteObject of the session, TLS close_notify, TCP close (spec 10.8, 4.4). The PLC never sends its own
    /// close_notify, so nothing more is read.
    pub(crate) fn close(mut self) -> Result<()> {
        let seq = self.next_sequence();
        let integrity = self.next_integrity(Counter::Set);
        let pdu = pdu::delete_object(seq, self.session, self.session, integrity);
        let result = self
            .exchange(&pdu)
            .and_then(|reply| pdu::parse_delete_object(&pdu::parse_response(&reply)?).map(|_| ()));
        self.tls.conn.send_close_notify();
        let _ = self.tls.flush();
        let _ = self.tls.sock.get_ref().shutdown(Shutdown::Both);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_integrity_is_sequence_plus_request_integrity_wrapping() {
        assert!(Link::check_integrity(4, 1, 5).is_ok());
        assert!(Link::check_integrity(4, 1, 6).is_err());
        assert!(Link::check_integrity(u16::MAX, u32::MAX, 0xFFFE).is_ok());
    }

    #[test]
    fn a_negative_multi_return_value_with_item_errors_keeps_the_items() {
        let reply = || -> Result<SetMultiReply> {
            Ok(SetMultiReply {
                errors: vec![(2, 0x8104_8800_0000_FF80)],
                integrity: 7,
            })
        };
        let negative = 0x8027_8000_0000_FFEF;
        let body = multi_body(negative, reply(), |b| !b.errors.is_empty()).expect("items");
        assert_eq!(body.errors.len(), 1);
        let empty = || -> Result<SetMultiReply> {
            Ok(SetMultiReply {
                errors: vec![],
                integrity: 7,
            })
        };
        assert!(matches!(
            multi_body(negative, empty(), |b| !b.errors.is_empty()),
            Err(Error::Response { .. })
        ));
        let malformed = || -> Result<SetMultiReply> { Err(Error::comm("short")) };
        assert!(matches!(
            multi_body(negative, malformed(), |b| !b.errors.is_empty()),
            Err(Error::Response { .. })
        ));
        assert!(matches!(
            multi_body(0x2027_8000_00A1_0013, malformed(), |b| !b.errors.is_empty()),
            Err(Error::Comm(_))
        ));
        assert!(multi_body(0, empty(), |_| false).is_ok());
    }
}
