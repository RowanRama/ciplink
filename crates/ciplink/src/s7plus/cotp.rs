//! TPKT + COTP (spec 2): the connection request, and [`CotpStream`], which makes the DT payloads one byte stream
//! for the cleartext InitSsl exchange and then for TLS.

use std::io::{self, Read, Write};

/// The connection request (spec 2.2): TPDU size 1024, calling TSAP `06 00`, called TSAP `SIMATIC-ROOT-HMI`.
pub fn connect_request() -> Vec<u8> {
    let mut out = vec![
        0x03, 0x00, 0x00, 0x24, // TPKT, 36 bytes
        0x1F, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, // CR, dst 0, src 1, class 0
        0xC0, 0x01, 0x0A, // TPDU size 1024
        0xC1, 0x02, 0x06, 0x00, // calling TSAP
        0xC2, 0x10, // called TSAP, 16 bytes
    ];
    out.extend_from_slice(b"SIMATIC-ROOT-HMI");
    out
}

/// A connection confirm with source reference `source` (for the simulator; the parameters echo the request).
pub fn connect_confirm(source: u16) -> Vec<u8> {
    let mut out = connect_request();
    out[5] = 0xD0;
    out[6..8].copy_from_slice(&[0x00, 0x01]);
    out[8..10].copy_from_slice(&source.to_be_bytes());
    out
}

/// A disconnect request (the target refuses the connection).
pub fn disconnect_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x0B, 0x06, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00,
    ]
}

/// COTP payload bytes per DT frame: the 1024-byte TPDU minus TPKT (4) and the DT header (3).
pub const DT_PAYLOAD: usize = 1017;

/// The TPDU size the client asks for (spec 2.2).
const TPDU: usize = 1024;

/// Largest TPKT frame accepted (the TPDU is 1024; a little slack for peers that round up).
const MAX_TPKT: usize = 1024 + 64;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// Reads one TPKT frame (header and payload).
pub fn read_tpkt(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header)?;
    if header[0] != 0x03 {
        return Err(invalid("TPKT version is not 3"));
    }
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if !(7..=MAX_TPKT).contains(&len) {
        return Err(invalid("TPKT length out of range"));
    }
    let mut frame = vec![0u8; len];
    frame[..4].copy_from_slice(&header);
    r.read_exact(&mut frame[4..])?;
    Ok(frame)
}

/// What the target answered to the connection request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// CC: connected.
    Accepted,
    /// DR: the target refused the connection.
    Refused,
}

/// Classifies the answer to the connection request: CC or DR; anything else is an error.
pub fn parse_confirm(frame: &[u8]) -> io::Result<Confirm> {
    match frame.get(5).map(|b| b & 0xF0) {
        Some(0xD0) => Ok(Confirm::Accepted),
        Some(0x80) => Ok(Confirm::Refused),
        _ => Err(invalid("COTP answer is neither CC nor DR")),
    }
}

/// The TPDU size the CC confirms (parameter C0, 2^n bytes), at most the 1024 asked for; 1024 when absent.
pub fn confirmed_tpdu(frame: &[u8]) -> usize {
    let li = usize::from(frame.get(4).copied().unwrap_or(0));
    let params = frame.get(11..5 + li).unwrap_or_default();
    let mut i = 0;
    while let (Some(&code), Some(&len)) = (params.get(i), params.get(i + 1)) {
        if code == 0xC0
            && len == 1
            && let Some(&n) = params.get(i + 2)
        {
            // ISO 8073 sizes are 2^7 .. 2^13; never above what was asked
            return (1usize << n.clamp(7, 13)).min(TPDU);
        }
        i += 2 + usize::from(len);
    }
    TPDU
}

/// DT frames carrying `data`: at most `payload` bytes each, EOT on the last only (spec 2.3).
pub fn dt_frames(data: &[u8], payload: usize) -> Vec<u8> {
    let payload = payload.max(1);
    let parts = data.len().div_ceil(payload).max(1);
    let mut out = Vec::with_capacity(data.len() + 7 * parts);
    let mut chunks = data.chunks(payload).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80]);
    }
    while let Some(chunk) = chunks.next() {
        let len = (chunk.len() + 7) as u16;
        out.extend_from_slice(&[0x03, 0x00]);
        out.extend_from_slice(&len.to_be_bytes());
        let eot = if chunks.peek().is_none() { 0x80 } else { 0x00 };
        out.extend_from_slice(&[0x02, 0xF0, eot]);
        out.extend_from_slice(chunk);
    }
    out
}

/// The payload of a DT frame; any other TPDU (DR, ER, ...) is an error.
pub fn dt_payload(frame: &[u8]) -> io::Result<&[u8]> {
    let li = usize::from(*frame.get(4).ok_or_else(|| invalid("COTP header missing"))?);
    let code = frame.get(5).map(|b| b & 0xF0);
    if code != Some(0xF0) || li < 2 {
        return Err(match code {
            Some(0x80) => invalid("the PLC closed the connection (COTP DR)"),
            _ => invalid("COTP TPDU is not DT"),
        });
    }
    frame
        .get(5 + li..)
        .ok_or_else(|| invalid("COTP header longer than the frame"))
}

/// DT payloads of a stream as one continuous byte stream: reading ignores EOT (the PLC sets it on frames whose
/// TLS record continues) and skips empty DTs; each write becomes DT frames that fit the negotiated TPDU.
#[derive(Debug)]
pub struct CotpStream<S> {
    inner: S,
    buffer: Vec<u8>,
    pos: usize,
    /// Payload bytes per DT frame sent.
    payload: usize,
}

impl<S: Read + Write> CotpStream<S> {
    /// Wraps a connected stream (after CC) with the 1024-byte TPDU.
    pub fn new(inner: S) -> Self {
        Self::with_tpdu(inner, TPDU)
    }

    /// Wraps a connected stream whose CC confirmed `tpdu` bytes per TPDU (TPKT and DT header included).
    pub fn with_tpdu(inner: S, tpdu: usize) -> Self {
        CotpStream {
            inner,
            buffer: Vec::new(),
            pos: 0,
            payload: tpdu.saturating_sub(7).max(1),
        }
    }

    /// The stream underneath.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// The stream underneath, mutably.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Read + Write> Read for CotpStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.buffer.len() {
            let frame = read_tpkt(&mut self.inner)?;
            self.buffer = dt_payload(&frame)?.to_vec();
            self.pos = 0;
        }
        let n = buf.len().min(self.buffer.len() - self.pos);
        buf[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for CotpStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.inner.write_all(&dt_frames(buf, self.payload))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake byte stream: reads from `input`, collects writes.
    struct Pipe {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn pipe(input: Vec<u8>) -> CotpStream<Pipe> {
        CotpStream::new(Pipe {
            input: io::Cursor::new(input),
            output: Vec::new(),
        })
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn connect_request_is_the_spec_frame() {
        assert_eq!(
            connect_request(),
            hex("030000241fe00000000100c0010ac1020600c21053494d415449432d524f4f542d484d49")
        );
    }

    #[test]
    fn confirm_with_any_source_reference_is_accepted_and_dr_refused() {
        for source in [1u16, 4, 0xBEEF] {
            assert_eq!(
                parse_confirm(&connect_confirm(source)).expect("cc"),
                Confirm::Accepted
            );
        }
        assert_eq!(
            parse_confirm(&hex(
                "030000241FD00001000100C0010AC1020600C21053494D415449432D524F4F542D484D49"
            ))
            .expect("captured cc"),
            Confirm::Accepted
        );
        assert_eq!(
            parse_confirm(&disconnect_request()).expect("dr"),
            Confirm::Refused
        );
        assert!(parse_confirm(&hex("0300000702f080")).is_err());
    }

    #[test]
    fn writes_split_at_1017_with_eot_on_the_last_frame_only() {
        let mut s = pipe(Vec::new());
        let data: Vec<u8> = (0..1611u32).map(|i| i as u8).collect();
        s.write_all(&data).expect("write");
        let out = &s.get_ref().output;
        assert_eq!(&out[..7], &[0x03, 0x00, 0x04, 0x00, 0x02, 0xF0, 0x00]);
        let second = &out[1024..];
        assert_eq!(&second[..7], &[0x03, 0x00, 0x02, 0x59, 0x02, 0xF0, 0x80]);
        assert_eq!(second.len(), 601);
        let mut back = pipe(out.clone());
        let mut got = vec![0u8; data.len()];
        back.read_exact(&mut got).expect("read");
        assert_eq!(got, data);
    }

    #[test]
    fn the_confirmed_tpdu_size_sizes_the_dt_frames() {
        assert_eq!(confirmed_tpdu(&connect_confirm(4)), 1024);
        let mut small = connect_confirm(4);
        small[13] = 0x09;
        assert_eq!(confirmed_tpdu(&small), 512);
        let mut big = connect_confirm(4);
        big[13] = 0x0D;
        assert_eq!(confirmed_tpdu(&big), 1024, "never above what was asked");
        // no parameters at all: the default
        assert_eq!(confirmed_tpdu(&hex("0300000b06d00001000400")), 1024);
        let mut s = CotpStream::with_tpdu(
            Pipe {
                input: io::Cursor::new(Vec::new()),
                output: Vec::new(),
            },
            confirmed_tpdu(&small),
        );
        s.write_all(&[7u8; 1000]).expect("write");
        let out = &s.get_ref().output;
        assert_eq!(&out[..7], &[0x03, 0x00, 0x02, 0x00, 0x02, 0xF0, 0x00]);
        assert_eq!(out.len(), 512 + (1000 - 505 + 7), "505 + 495 payload bytes");
    }

    #[test]
    fn reading_ignores_eot_and_skips_empty_dts() {
        let mut input = hex("0300000702f000"); // empty DT
        input.extend(hex("0300000a02f0800102 03")); // EOT set, 3 bytes
        input.extend(hex("0300000902f0000405")); // EOT clear, 2 bytes
        let mut s = pipe(input);
        let mut got = [0u8; 5];
        s.read_exact(&mut got).expect("read");
        assert_eq!(got, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_dr_after_connect_is_an_error() {
        let mut s = pipe(disconnect_request());
        let mut got = [0u8; 1];
        assert!(s.read(&mut got).is_err());
        let mut bad = pipe(hex("04000007 02f080"));
        assert!(bad.read(&mut got).is_err(), "TPKT version");
        let mut long = pipe(hex("0300ffff02f080"));
        assert!(long.read(&mut got).is_err(), "TPKT length");
    }
}
