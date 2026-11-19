//! The Modbus simulator over TCP and from the binary, driven with raw frames (not a client).

use ciplink_sim::{Framing, ModbusFault, ModbusSim, crc16};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const CONFIG: &str = r#"{
  "kind": "modbus",
  "units": [
    {"unit": 1, "holding": 1000, "coils": 2000,
     "values": {"holding": {"0": [59769, 17142]}, "coil": {"0": [true, false, true]}}},
    {"unit": 2, "holding": 100}
  ]
}"#;

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    stream
}

fn mbap(transaction: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut adu = transaction.to_be_bytes().to_vec();
    adu.extend_from_slice(&[0, 0]);
    adu.extend_from_slice(&(pdu.len() as u16 + 1).to_be_bytes());
    adu.push(unit);
    adu.extend_from_slice(pdu);
    adu
}

fn rtu(unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut adu = vec![unit];
    adu.extend_from_slice(pdu);
    let crc = crc16(&adu);
    adu.extend_from_slice(&crc.to_le_bytes());
    adu
}

fn read_exactly(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).expect("reply");
    buf
}

#[test]
fn mbap_over_tcp_reads_writes_and_echoes_the_transaction() {
    let sim = ModbusSim::from_json(CONFIG).expect("config");
    let server = sim.serve("127.0.0.1:0", Framing::Mbap).expect("bind");
    let mut stream = connect(server.port());

    stream
        .write_all(&mbap(7, 1, &[3, 0, 0, 0, 2]))
        .expect("send");
    assert_eq!(
        read_exactly(&mut stream, 13),
        [0, 7, 0, 0, 0, 7, 1, 3, 4, 0xE9, 0x79, 0x42, 0xF6]
    );

    // two requests in one write are both answered, in order
    let mut both = mbap(8, 1, &[6, 0, 3, 0, 9]);
    both.extend(mbap(9, 1, &[1, 0, 0, 0, 3]));
    stream.write_all(&both).expect("send");
    assert_eq!(
        read_exactly(&mut stream, 12),
        [0, 8, 0, 0, 0, 6, 1, 6, 0, 3, 0, 9]
    );
    assert_eq!(
        read_exactly(&mut stream, 10),
        [0, 9, 0, 0, 0, 4, 1, 1, 1, 0b101]
    );
    assert_eq!(sim.registers(1, "holding", 3, 1).expect("regs"), [9]);

    // unknown unit through a gateway
    stream
        .write_all(&mbap(10, 5, &[3, 0, 0, 0, 1]))
        .expect("send");
    assert_eq!(
        read_exactly(&mut stream, 9),
        [0, 10, 0, 0, 0, 3, 5, 0x83, 0x0B]
    );
}

#[test]
fn rtu_over_tcp_checks_crc_and_filters_units() {
    let sim = ModbusSim::from_json(CONFIG).expect("config");
    let server = sim.serve("127.0.0.1:0", Framing::Rtu).expect("bind");
    let mut stream = connect(server.port());

    stream.write_all(&rtu(1, &[3, 0, 1, 0, 1])).expect("send");
    assert_eq!(read_exactly(&mut stream, 7), rtu(1, &[3, 2, 0x42, 0xF6]));

    stream
        .write_all(&rtu(2, &[16, 0, 0, 0, 2, 4, 0, 1, 0, 2]))
        .expect("send");
    assert_eq!(read_exactly(&mut stream, 8), rtu(2, &[16, 0, 0, 0, 2]));
    assert_eq!(sim.registers(2, "holding", 0, 2).expect("regs"), [1, 2]);

    // a unit not on the bus and a frame with a bad CRC are not answered; the next request is
    stream.write_all(&rtu(9, &[3, 0, 0, 0, 1])).expect("send");
    let mut bad = rtu(1, &[3, 0, 0, 0, 1]);
    bad[6] ^= 0xFF;
    stream.write_all(&bad).expect("send");
    stream.write_all(&rtu(1, &[3, 0, 0, 0, 1])).expect("send");
    assert_eq!(read_exactly(&mut stream, 7), rtu(1, &[3, 2, 0xE9, 0x79]));

    // an unknown function of unknown length gets exception 01
    stream.write_all(&rtu(1, &[0x41, 1, 2, 3])).expect("send");
    assert_eq!(read_exactly(&mut stream, 5), rtu(1, &[0xC1, 1]));
}

#[test]
fn tcp_faults_refuse_and_close_connections() {
    let sim = ModbusSim::from_json(CONFIG).expect("config");
    let server = sim.serve("127.0.0.1:0", Framing::Mbap).expect("bind");
    let mut open = connect(server.port());
    open.write_all(&mbap(1, 1, &[3, 0, 0, 0, 1])).expect("send");
    read_exactly(&mut open, 11);

    sim.inject(ModbusFault::CloseConnections);
    open.write_all(&mbap(2, 1, &[3, 0, 0, 0, 1])).expect("send");
    let mut buf = [0u8; 16];
    assert_eq!(open.read(&mut buf).unwrap_or(0), 0, "closed");

    sim.inject(ModbusFault::RefuseConnections);
    let mut refused = connect(server.port());
    let _ = refused.write_all(&mbap(3, 1, &[3, 0, 0, 0, 1]));
    assert_eq!(refused.read(&mut buf).unwrap_or(0), 0, "refused");
    sim.clear_faults();

    sim.inject(ModbusFault::Delay(Duration::from_millis(100)));
    let mut slow = connect(server.port());
    let started = std::time::Instant::now();
    slow.write_all(&mbap(4, 1, &[3, 0, 0, 0, 1])).expect("send");
    read_exactly(&mut slow, 11);
    assert!(started.elapsed() >= Duration::from_millis(100));
}

#[test]
fn binary_commands() {
    let dir = std::env::temp_dir().join(format!("ciplink-modbus-sim-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let config = dir.join("modbus.json");
    std::fs::write(&config, CONFIG).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciplink-sim"))
        .args(["--config", config.to_str().expect("path"), "--port", "0"])
        .args(["--framing", "rtu", "--exit-on-eof"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("banner");
    let port: u16 = line
        .trim()
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("listening on HOST:PORT");
    let mut ask = |command: &str| -> serde_json::Value {
        writeln!(stdin, "{command}").expect("command");
        let mut answer = String::new();
        stdout.read_line(&mut answer).expect("answer");
        serde_json::from_str(&answer).expect("JSON answer")
    };

    assert_eq!(
        ask(r#"{"cmd": "registers", "unit": 1, "area": "holding", "address": 0, "count": 2}"#),
        serde_json::json!({"ok": [59769, 17142]})
    );
    ask(
        r#"{"cmd": "set_registers", "unit": 1, "area": "holding", "address": 0, "values": [1, 2]}"#,
    );
    ask(r#"{"cmd": "set_bits", "unit": 1, "area": "coil", "address": 1, "values": [true]}"#);
    assert_eq!(
        ask(r#"{"cmd": "bits", "unit": 1, "area": "coil", "address": 0, "count": 3}"#),
        serde_json::json!({"ok": [true, true, true]})
    );
    assert!(
        ask(r#"{"cmd": "bits", "unit": 1, "area": "holding", "address": 0, "count": 3}"#)
            .get("error")
            .is_some()
    );

    let mut stream = connect(port);
    stream.write_all(&rtu(1, &[3, 0, 0, 0, 2])).expect("send");
    assert_eq!(read_exactly(&mut stream, 9), rtu(1, &[3, 4, 0, 1, 0, 2]));

    let fault =
        r#"{"cmd": "fault", "fault": {"exception": {"unit": 1, "function": 3, "code": 4}}}"#;
    assert_eq!(ask(fault), serde_json::json!({"ok": null}));
    stream.write_all(&rtu(1, &[3, 0, 0, 0, 1])).expect("send");
    assert_eq!(read_exactly(&mut stream, 5), rtu(1, &[0x83, 4]));
    for fault in [
        r#"{"drop_replies": 1}"#,
        r#"{"delay_ms": 1}"#,
        r#"{"no_reply": 2}"#,
        r#"{"bad_crc": 1}"#,
    ] {
        let answer = ask(&format!(r#"{{"cmd": "fault", "fault": {fault}}}"#));
        assert_eq!(answer, serde_json::json!({"ok": null}), "{fault}");
    }
    assert!(
        ask(r#"{"cmd": "fault", "fault": {"nope": 1}}"#)
            .get("error")
            .is_some()
    );
    ask(r#"{"cmd": "clear_faults"}"#);
    assert_eq!(ask(r#"{"cmd": "requests"}"#), serde_json::json!({"ok": 2}));

    drop(stdin);
    assert!(child.wait().expect("exit").success());
    let _ = std::fs::remove_dir_all(&dir);
}
