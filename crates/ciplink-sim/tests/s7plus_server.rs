//! The S7comm-plus simulator against raw bytes: the hex examples of the public spec
//! (`docs/dev/s7commplus-protocol.md`) are sent as they are (sequence and integrity IDs adjusted where the
//! example's session counted differently) and the replies compared byte for byte.

use ciplink_sim::s7plus::{S7PlusFault, S7PlusSimulator};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The worked example's program (spec 11.4): DB 5 "Line1" with explicit LIDs, and IArea.StartButton.
const SPEC_CONFIG: &str = r#"{"s7plus": {
  "name": "PLC_Line1",
  "dbs": [{"name": "Line1", "number": 5, "members": {
    "Conveyor": {"type": "STRUCT", "lid": 10, "members": {
      "Running": {"type": "BOOL", "lid": 9, "value": true},
      "Speed": {"type": "REAL", "lid": 11, "value": 1.5}}},
    "Count": {"type": "DINT", "lid": 12, "value": -300},
    "Total": {"type": "ULINT", "lid": 13, "value": 1234567},
    "Recipe": {"type": "STRING[10]", "lid": 14, "value": "Mix1"},
    "Label": {"type": "WSTRING[4]", "lid": 15, "value": "OK"},
    "Stamp": {"type": "DTL", "lid": 16, "value": "2026-11-18T16:34:46.1"},
    "Items": {"type": "ARRAY[1..50] OF UINT", "lid": 17},
    "Flags": {"type": "ARRAY[0..15] OF BOOL", "lid": 18},
    "Delay": {"type": "IEC_TIMER", "lid": 19}}}],
  "areas": {"I": {"StartButton": {"type": "BOOL", "lid": 12}}}
}}"#;

/// The object qualifier (spec 9.1).
const QUALIFIER: &str = "000004e8 8969 0012 00000000 896a 0013 00 896b 0004 00 00";

fn vlq64(v: u64) -> Vec<u8> {
    assert!(v >> 56 != 0, "only the 9-byte form is needed here");
    let high = v >> 8;
    let mut out: Vec<u8> = (0..8)
        .rev()
        .map(|i| 0x80 | ((high >> (7 * i)) & 0x7f) as u8)
        .collect();
    out.push(v as u8);
    out
}

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|c| (c as char).to_digit(16).expect("hex") as u8)
        .collect();
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// A spec example with its sequence number and its (one-byte) integrity ID replaced; `end` is the number of
/// zero bytes after the integrity ID (4, or 5 for Explore).
fn patched(text: &str, sequence: u16, integrity: Option<u8>, end: usize) -> Vec<u8> {
    let mut pdu = hex(text);
    pdu[8..10].copy_from_slice(&sequence.to_be_bytes());
    if let Some(integrity) = integrity {
        let at = pdu.len() - end - 1;
        assert!(pdu[at] < 0x80 && integrity < 0x80);
        pdu[at] = integrity;
    }
    pdu
}

#[derive(Debug)]
struct AcceptAny {
    seen: Arc<Mutex<Option<Vec<u8>>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().expect("lock") = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// DT payloads as one stream (client side: EOT only on the last frame of a write).
struct Dt {
    stream: TcpStream,
    buffer: Vec<u8>,
    pos: usize,
}

fn tpdu(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let mut body = vec![0u8; len - 4];
    stream.read_exact(&mut body)?;
    Ok(body)
}

impl Read for Dt {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buffer.len() {
            let body = match tpdu(&mut self.stream) {
                Ok(body) => body,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            };
            assert_eq!(&body[..3], &[0x02, 0xF0, 0x80], "DT with EOT");
            assert!(body.len() <= 1017 + 3);
            self.buffer = body[3..].to_vec();
            self.pos = 0;
        }
        let n = out.len().min(self.buffer.len() - self.pos);
        out[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for Dt {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let chunks: Vec<&[u8]> = data.chunks(1017).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let eot = if i + 1 == chunks.len() { 0x80 } else { 0 };
            let mut frame = vec![3, 0];
            frame.extend_from_slice(&((chunk.len() + 7) as u16).to_be_bytes());
            frame.extend_from_slice(&[2, 0xF0, eot]);
            frame.extend_from_slice(chunk);
            self.stream.write_all(&frame)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

const CR: &str =
    "0300 0024 1fe0 0000 0001 00c0 010a c102 0600 c210 5349 4d41 5449 432d 524f 4f54 2d48 4d49";

/// Sends the spec's COTP CR and returns the reply TPDU (from the length indicator on).
fn cotp_connect(port: u16) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    stream.write_all(&hex(CR)).expect("CR");
    let reply = tpdu(&mut stream).expect("CC");
    (stream, reply)
}

fn read_pdu(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut pdu = Vec::new();
    loop {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        assert_eq!(header[0], 0x72);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if pdu.is_empty() {
            pdu.push(header[1]);
        }
        if header[1] == 0xFE {
            // a system event: no trailer; hand it back alone
            let mut data = vec![0u8; len];
            reader.read_exact(&mut data)?;
            let mut event = vec![0xFE];
            event.extend(data);
            return Ok(event);
        }
        if len == 0 {
            return Ok(pdu);
        }
        let start = pdu.len();
        pdu.resize(start + len, 0);
        reader.read_exact(&mut pdu[start..])?;
    }
}

fn frame(pdu: &[u8]) -> Vec<u8> {
    let mut out = vec![0x72, pdu[0]];
    out.extend_from_slice(&((pdu.len() - 1) as u16).to_be_bytes());
    out.extend_from_slice(&pdu[1..]);
    out.extend_from_slice(&[0x72, pdu[0], 0, 0]);
    out
}

struct Client {
    tls: StreamOwned<ClientConnection, Dt>,
    seen: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Client {
    fn send(&mut self, pdu: &[u8]) {
        self.tls.write_all(&frame(pdu)).expect("send");
        self.tls.flush().expect("flush");
    }

    fn request(&mut self, pdu: &[u8]) -> Vec<u8> {
        self.send(pdu);
        read_pdu(&mut self.tls).expect("reply")
    }

    /// True when the server closed the connection instead of replying.
    fn closed_after(&mut self, pdu: &[u8]) -> bool {
        self.send(pdu);
        read_pdu(&mut self.tls).is_err()
    }
}

/// COTP, InitSsl (spec section 3, byte for byte), TLS.
fn tls_connect(port: u16) -> Client {
    let (mut stream, cc) = cotp_connect(port);
    assert_eq!(cc[1], 0xD0, "CC");
    stream
        .write_all(&hex(
            "030000210 2f080 72010012 310000 05b3 0000 0001 00000120 30 00000000 72010000",
        ))
        .expect("InitSsl");
    let reply = tpdu(&mut stream).expect("InitSsl response");
    let mut wire = vec![3, 0, 0, (reply.len() + 4) as u8];
    wire.extend(reply);
    assert_eq!(
        wire,
        hex("0300001f02f080 72010010 32000005b3000000017000 0000000000 72010000")
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let seen = Arc::new(Mutex::new(None));
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny {
            seen: Arc::clone(&seen),
            provider,
        }))
        .with_no_client_auth();
    let name = ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into());
    let connection = ClientConnection::new(Arc::new(config), name).expect("client");
    let mut tls = StreamOwned::new(
        connection,
        Dt {
            stream,
            buffer: Vec::new(),
            pos: 0,
        },
    );
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).expect("handshake");
    }
    Client { tls, seen }
}

const CREATE: &str = "0131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3822c001280c3c901a1000000
                      d3817f0000a2a200000000";
const CREATED: &str = "0132000004ca0000000236b088d0808084da80110287808094108780809411a100000120821f0100a381690015133030
                       3a30313233343536373839414243444546a3822b000402a3822d0015245365727665723a204f4d53505f31342e30302e
                       30302e30335f36362e30332e30302e3031a3822f100214101112131415161718191a1b1c1d1e1f20212223a382320017
                       0000013a823b00048701823c00048701823d000484818540823e000484818540823f00151a313b36455337203558582d
                       58585858582d584142303b56332e31824000150a323b313233343536373882410003000300a200000000";
const SETUP: &str = "0231000005420000000370000a103470000a10010182320100170000013a823b00048701823c00048701823d00048481
                     8540823e000484818540823f00151a313b36455337203558582d58585858582d584142303b56332e31824000150a323b
                     31323334353637388241000300030000000004e88969001200000000896a001300896b0004000000000000";

/// The challenge (attribute 303) is random: compare everything else.
fn assert_created(reply: &[u8]) {
    let mut expected = hex(CREATED);
    let marker = hex("a3822f100214");
    let at = expected
        .windows(marker.len())
        .position(|w| w == marker.as_slice())
        .expect("303 in the example")
        + marker.len();
    let mut reply = reply.to_vec();
    expected[at..at + 20].fill(0);
    reply[at..at + 20].fill(0);
    assert_eq!(reply, expected);
}

/// A session up to the setup (spec 10.2 to 10.4, byte for byte): the next request is sequence 4.
fn session(port: u16) -> Client {
    let mut client = tls_connect(port);
    assert_created(&client.request(&hex(CREATE)));
    assert_eq!(
        client.request(&hex(SETUP)),
        hex("023200000542000000033400000000000000")
    );
    client
}

fn start(config: &str) -> (S7PlusSimulator, ciplink_sim::s7plus::S7PlusServer) {
    let sim = S7PlusSimulator::from_json(config).expect("config");
    let server = sim.serve("127.0.0.1:0").expect("serve");
    (sim, server)
}

/// The protection-level read (spec 10.6) as the keep-alive request.
fn keep_alive(sequence: u16, integrity: u8) -> Vec<u8> {
    patched(
        "0231000005860000000570000a103470000a102004018e32000004e88969001200000000896a001300896b0004000000010200000000",
        sequence,
        Some(integrity),
        4,
    )
}

#[test]
fn a_whole_session_matches_the_spec_examples_byte_for_byte() {
    let (sim, server) = start(SPEC_CONFIG);
    let (_, cc) = cotp_connect(server.port());
    // CC: echoes the parameters, destination reference = our source reference
    assert_eq!(cc[1], 0xD0);
    assert_eq!(&cc[2..4], &[0, 1]);
    assert_eq!(&cc[7..], &hex(CR)[11..]);

    let mut client = session(server.port());
    assert_eq!(
        client.seen.lock().expect("lock").clone(),
        Some(sim.certificate_der())
    );

    // 10.5 system limits, 10.6 protection level: verbatim
    assert_eq!(
        client.request(&hex("02310000054c0000000470000a103400000000051900814902880d876800814902880d876900814902880d0000814902
                             880d0100814902880d02000004e88969001200000000896a001300896b000400000100000000")),
        hex("02320000054c00000004340001000880640200088064030008817a0400088f50050008a0800000000500000000")
    );
    assert_eq!(
        client.request(&keep_alive(5, 2)),
        hex("023200000586000000053400000004000700000000")
    );

    // 11.4 the nine-item read (sequence 6, integrity 3: response integrity 9)
    let read = patched(
        "02310000054c0000002870000a103400000000092f86f292ce3a88d0b880050393760a0b82aadacc3b88d0b880050393
         760a098dd089d97f88d0b880050293760c86a3b1cc4288d0b880050293760d88e2bad41d88d0b880050293760e8ac7e9
         873e88d0b880050293760f8fe5a1906788d0b88005029376108b9496e00a50029d180c0088d0b8800502937681ff7f00
         0004e88969001200000000896a001300896b000400001e00000000",
        6,
        Some(3),
        4,
    );
    let expected = patched(
        "02320000054c00000028349089f0808082c2801301000e3fc0000002000101030008fd54040005cbad070510020c0a04
         4d6978310000000000000610030600040002004f004b000000000700170200004310ff4ad6dfd5774c020c07ea0b1204
         10222e05f5e100080001000009c0d3d18080a5c5ff01004600000000",
        6,
        Some(9),
        4,
    );
    assert_eq!(client.request(&read), expected);

    // 17.4 write one BOOL (sequence 7, set integrity 1): response integrity 8
    assert_eq!(
        client.request(&patched(
            "0231000005420000002a70000a103400000000010682aadacc3b88d0b880050393760a090100010100000004e8896900
             1200000000896a001300896b000400000100000000",
            7,
            None,
            4
        )),
        hex("023200000542000000073400000800000000")
    );
    // 17.5 three items, the third failing (sequence 8, set integrity 2): response integrity 10
    assert_eq!(
        client.request(&patched(
            "0231000005420000002b70000a103400000000031086f292ce3a88d0b880050393760a0b88e2bad41d88d0b880050293
             760e0088d0b8800502937681ff7f01000e401000000210020c0a044d697832000000000000030007000500000004e889
             69001200000000896a001300896b000400000200000000",
            8,
            None,
            4
        )),
        patched(
            "0232000005420000002b349089f0808082c2801303c0d3d18080a5c5ff01002d00000000",
            8,
            Some(10),
            4
        )
    );
    assert_eq!(
        sim.value("Line1.Conveyor.Speed").expect("speed"),
        json!(2.25)
    );
    assert_eq!(sim.value("Line1.Recipe").expect("recipe"), json!("Mix2"));

    // 13.3 LID 1 of DB 5 (sequence 9, integrity 4)
    assert_eq!(
        client.request(&patched(
            "02310000054c0000000c70000a10340000000001050088d0b8800502937601000004e88969001200000000896a001300
             896b000400000900000000",
            9,
            Some(4),
            4
        )),
        hex("02320000054c000000093400010012920000050000 0d00000000")
    );

    // 13.2 DB list with the filter (sequence 10, integrity 5)
    let dbs = client.request(&patched(
        "0231000004bb0000000e70000a10340000000300010100010017000004de895f0008088961000400896210042000000000
         000000000000000000000000000000000000000000000000000000008963001200000a0e00000181690b0000000000",
        10,
        Some(5),
        5,
    ));
    let mut expected = hex("02320000 04bb 0000 000a 34 00 00000001 0f");
    expected.extend(hex("a1 8a0e0005 940e 20 00 a3 8169 0015 05"));
    expected.extend(b"Line1");
    expected.extend(hex("a2 00000000"));
    assert_eq!(dbs, expected);

    // 13.4 all type information (sequence 11, integrity 6): holds the DTL object of 13.5 verbatim
    let types = client.request(&patched(
        "0231000004bb0000000d70000a1034000002190001010000000a0000000000",
        11,
        Some(6),
        5,
    ));
    assert_eq!(
        &types[..17],
        &hex("02320000 04bb 0000 000b 34 00 000000c9 11")[..]
    );
    let dtl = hex(
        "a102000043837f2000a38169001500a38308000c80000003a38314000400a38411000588bfe9adb6ffaaf74ca38b5e00
         040ca38b5f000800a384630017000006068c0700040c8c0800040c8c0900040c00a3831a000500a3831c000b0001a383
         1d000400a3831e000404ab0084040000800900000093973bd7351a8000000000000a000000147f4ed7341a8000020002
         000b0000006de7eef6341a8000030003000c0000004101e2c2341a8000040004000d00000084d6a870341a8000050005
         000e0000006086d75e341a8000060006000f0000006ea81211341a8000070007001000000073001b76361a8000080008
         000000ac003d045945415200054d4f4e5448000344415900075745454b4441590004484f555200064d494e5554450006
         5345434f4e44000a4e414e4f5345434f4e44000000a2",
    );
    assert!(types.windows(dtl.len()).any(|w| w == dtl.as_slice()));
    assert!(types.ends_with(&hex("a2 00000000")));

    // 10.8 DeleteObject (sequence 12, set integrity 3)
    assert_eq!(
        client.request(&patched(
            "0231000004d40000000e70000a103470000a1000000004e88969001200000000896a001300896b000400000100000000",
            12,
            Some(3),
            4
        )),
        hex("0232000004d40000000c349088f08080828e802d70000a1000000000")
    );
    client.tls.conn.send_close_notify();
    client.tls.flush().expect("close_notify");
    assert!(sim.requests() >= 11);
}

#[test]
fn a_wrong_sequence_or_integrity_closes_the_connection() {
    let (_sim, server) = start(SPEC_CONFIG);
    let mut client = session(server.port());
    assert!(client.closed_after(&keep_alive(5, 1)), "sequence skipped");
    let mut client = session(server.port());
    assert!(client.closed_after(&keep_alive(4, 2)), "integrity skipped");
    let mut client = session(server.port());
    assert_eq!(client.request(&keep_alive(4, 1)).len(), 21);
    assert_eq!(client.request(&keep_alive(5, 2)).len(), 21);
    let mut wrong_session = keep_alive(6, 3);
    wrong_session[10] = 0x71;
    assert!(client.closed_after(&wrong_session), "session ID");
    // a request before the setup
    let mut client = tls_connect(server.port());
    assert!(
        client.closed_after(&hex(SETUP)),
        "setup before CreateObject"
    );
}

#[test]
fn the_setup_must_write_the_session_version_back_unchanged() {
    let (_sim, server) = start(SPEC_CONFIG);
    let mut client = tls_connect(server.port());
    assert_created(&client.request(&hex(CREATE)));
    let mut setup = hex(SETUP);
    let at = setup.len() - 30;
    setup[at] ^= 1;
    assert!(client.closed_after(&setup));
}

/// A GetMultiVariables of `n` items, each LID 1 of DB 5.
fn lid1_reads(n: u32, sequence: u16, integrity: u8) -> Vec<u8> {
    let mut pdu = hex("02310000054c0000000070000a1034 00000000");
    pdu[8..10].copy_from_slice(&sequence.to_be_bytes());
    assert!(n < 128);
    pdu.push(n as u8);
    let fields = n * 5;
    pdu.extend(if fields < 128 {
        vec![fields as u8]
    } else {
        vec![0x80 | (fields >> 7) as u8, (fields & 0x7f) as u8]
    });
    for _ in 0..n {
        pdu.extend(hex("0088d0b88005029376 01"));
    }
    pdu.extend(hex(QUALIFIER));
    pdu.push(integrity);
    pdu.extend([0; 4]);
    pdu
}

#[test]
fn at_most_max_read_items_per_request() {
    let (_sim, server) = start(SPEC_CONFIG);
    let mut client = session(server.port());
    let reply = client.request(&lid1_reads(100, 4, 1));
    assert_eq!(&reply[11..12], &[0], "100 items read");
    let reply = client.request(&lid1_reads(101, 5, 2));
    // a negative return value (bit 63 set): a 9-byte VLQ64 starting with 0xC0 or more
    assert!(reply[11] >= 0xC0, "{reply:02x?}");
    // the connection stays usable
    assert_eq!(client.request(&keep_alive(6, 3)).len(), 21);
}

#[test]
fn a_write_of_more_than_max_write_items_is_refused_with_a_write_reply() {
    use ciplink::s7plus::wire::{
        ItemAddress, Scalar, WireValue, parse_response, parse_set_multi, set_multi,
    };
    let (_sim, server) = start(SPEC_CONFIG);
    let mut client = session(server.port());
    let item = (
        ItemAddress {
            crc: 0,
            area: 0x8A0E_0005,
            sub_area: 2550,
            lids: vec![12],
        },
        WireValue::scalar(Scalar::DInt(1)),
    );
    let reply = client.request(&set_multi(4, 0x7000_0A10, &vec![item; 101], 1));
    let r = parse_response(&reply).expect("header");
    assert!(r.return_value >> 63 == 1, "negative return value");
    // spec 17.2: error list, integrity ID (sequence + request integrity), end; no value list
    let body = parse_set_multi(&r).expect("a SetMultiVariables reply");
    assert_eq!(body.integrity, 5);
}

#[test]
fn faults_close_refuse_drop_delay_and_fail_items() {
    let (sim, server) = start(SPEC_CONFIG);

    // close_connections: the open link ends at once
    let mut client = session(server.port());
    assert_eq!(sim.connections(), 1);
    sim.inject(S7PlusFault::CloseConnections);
    assert!(read_pdu(&mut client.tls).is_err());

    // refuse_connections: a COTP DR instead of the CC
    sim.inject(S7PlusFault::RefuseConnections);
    let (_, dr) = cotp_connect(server.port());
    assert_eq!(dr[1], 0x80);
    sim.clear_faults();

    // drop_replies: no reply to one request, then service as usual
    let mut client = session(server.port());
    sim.inject(S7PlusFault::DropReplies(1));
    client
        .tls
        .sock
        .stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    client.send(&keep_alive(4, 1));
    assert!(read_pdu(&mut client.tls).is_err());
    let mut client = session(server.port());
    let started = std::time::Instant::now();
    sim.inject(S7PlusFault::Delay(Duration::from_millis(150)));
    assert_eq!(client.request(&keep_alive(4, 1)).len(), 21);
    assert!(started.elapsed() >= Duration::from_millis(150));
    sim.clear_faults();

    // item_error: that tag fails, the others are read
    sim.inject(S7PlusFault::ItemError {
        tag: "Line1.Count".into(),
        code: 0x8104_8800_0000_FF80,
    });
    let read = patched(
        "02310000054c0000002870000a103400000000092f86f292ce3a88d0b880050393760a0b82aadacc3b88d0b880050393
         760a098dd089d97f88d0b880050293760c86a3b1cc4288d0b880050293760d88e2bad41d88d0b880050293760e8ac7e9
         873e88d0b880050293760f8fe5a1906788d0b88005029376108b9496e00a50029d180c0088d0b8800502937681ff7f00
         0004e88969001200000000896a001300896b000400001e00000000",
        5,
        Some(2),
        4,
    );
    let reply = client.request(&read);
    let mut error = vec![3];
    error.extend(vlq64(0x8104_8800_0000_FF80));
    assert!(
        reply.windows(error.len()).any(|w| w == error.as_slice()),
        "{reply:02x?}"
    );
    sim.clear_faults();

    // error_pdu: function 04 B1
    sim.inject(S7PlusFault::ErrorPdu);
    let reply = client.request(&keep_alive(6, 3));
    assert_eq!(&reply[4..6], &[0x04, 0xB1]);

    // system_event: an fe frame before the reply
    sim.inject(S7PlusFault::SystemEvent { return_value: -1 });
    client.send(&keep_alive(7, 4));
    let event = read_pdu(&mut client.tls).expect("event");
    assert_eq!(event[0], 0xFE);
    assert_eq!(
        &event[event.len() - 12..event.len() - 4],
        &(-1i64).to_be_bytes()
    );
    assert_eq!(read_pdu(&mut client.tls).expect("reply").len(), 21);
}

#[test]
fn a_program_change_fails_the_old_crc() {
    let (sim, server) = start(SPEC_CONFIG);
    sim.change_program();
    let mut client = tls_connect(server.port());
    // the session version of new sessions changed (project version 12345679)
    let created = client.request(&hex(CREATE));
    assert!(created.windows(10).any(|w| w == b"2;12345679"));
    let start = created
        .windows(6)
        .position(|w| w == hex("a38232 001700").as_slice())
        .expect("306")
        + 3;
    let mut setup = hex("0231000005420000000370000a103470000a1001018232 01");
    setup.extend_from_slice(&created[start..created.len() - 5]);
    setup.extend(hex("00"));
    setup.extend(hex(QUALIFIER));
    setup.extend([0; 4]);
    assert_eq!(
        client.request(&setup),
        hex("023200000542000000033400000000000000")
    );
    // Line1.Conveyor.Running with its old CRC: -17
    let mut read =
        hex("02310000054c0000000470000a1034 00000000 01 06 82aadacc3b88d0b880050393760a09");
    read.extend(hex(QUALIFIER));
    read.extend(hex("01 00000000"));
    let reply = client.request(&read);
    let mut error = vec![1];
    error.extend(vlq64(0x8009_8900_12C9_FFEF));
    assert!(
        reply.windows(error.len()).any(|w| w == error.as_slice()),
        "{reply:02x?}"
    );
    // with CRC 0 it is read
    let mut read = hex("02310000054c0000000570000a1034 00000000 01 06 0088d0b880050393760a09");
    read.extend(hex(QUALIFIER));
    read.extend(hex("02 00000000"));
    assert!(
        client
            .request(&read)
            .ends_with(&hex("01 0001 01 00 00 07 00000000"))
    );
}

#[test]
fn values_can_be_read_and_set_by_name() {
    let (sim, _server) = start(SPEC_CONFIG);
    assert_eq!(
        sim.value("Line1.Stamp").expect("dtl"),
        json!("2026-11-18T16:34:46.100000000")
    );
    assert_eq!(
        sim.value("\"Line1\".Stamp.MONTH").expect("month"),
        json!(11)
    );
    assert_eq!(sim.value("StartButton").expect("tag"), json!(false));
    sim.set_value("IArea.StartButton", &json!(true))
        .expect("set");
    assert_eq!(sim.value("StartButton").expect("tag"), json!(true));
    sim.set_value("Line1.Items[50]", &json!(7)).expect("set");
    assert_eq!(sim.value("Line1.Items").expect("items")[49], json!(7));
    sim.set_value("Line1.Delay", &json!({"PT": 5000, "IN": true}))
        .expect("timer");
    assert_eq!(sim.value("Line1.Delay.PT").expect("pt"), json!(5000));
    assert!(
        sim.set_value("Line1.Recipe", &json!("much too long"))
            .is_err()
    );
    assert!(sim.value("Line1.Nope").is_err());
    assert_eq!(
        sim.command(&json!({"cmd": "fingerprint"})).expect("cmd"),
        json!(sim.fingerprint())
    );
    assert_eq!(sim.fingerprint().len(), 95);
}
