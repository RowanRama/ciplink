//! The ciplink adapter against the simulator's scanner over real sockets on the loopback: class 1 data both
//! ways, refusals, timeouts and recovery, input-only and listen-only connections, and what browsers read.
#![allow(clippy::unwrap_used)]

use ciplink::adapter::{Adapter, AdapterConfig, AdapterIdentity, Assembly, ConnectionKind, Event};
use ciplink::cip::{CipDriver, CipOptions, GenericMessage, RoutePath};
use ciplink::epath::LogicalValue;
use ciplink::transport::{Connector, TcpTransport, Transport};
use ciplink_sim::{IoRequest, ScanError, Scanner};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const RPI: Duration = Duration::from_millis(10);

/// A station layout: three inputs, three outputs, one configuration assembly.
/// The socket tests run one at a time: they measure RPIs and time out after a few of them, which a dozen tests
/// at once, each with I/O threads at 10 ms, would turn into flakes.
fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn adapter() -> Adapter {
    Adapter::start(AdapterConfig {
        identity: AdapterIdentity {
            vendor_id: 1234,
            product_code: 42,
            revision: (1, 1),
            serial: 0x0102_0304,
            product_name: "Station".into(),
            ..AdapterIdentity::default()
        },
        assemblies: vec![
            Assembly::input(100, 148),
            Assembly::input(101, 276),
            Assembly::input(102, 500),
            Assembly::output(150, 32),
            Assembly::output(151, 64),
            Assembly::output(152, 128),
            Assembly::config(199, 4),
        ],
        eds: Some(b"[File]\nDescText = \"Station\";\n".to_vec()),
        eds_name: "station.eds".into(),
        app_name: "Station".into(),
        app_version: "2.1".into(),
        bind: Ipv4Addr::LOCALHOST,
        port: 0,
        io_port: 0,
        rpi_min: Duration::from_millis(1),
        ..AdapterConfig::default()
    })
    .unwrap()
}

fn open(adapter: &Adapter, request: IoRequest) -> Result<Scanner, ScanError> {
    Scanner::open(adapter.addr(), adapter.io_addr(), request)
}

fn refusal(adapter: &Adapter, request: IoRequest) -> Vec<u16> {
    match open(adapter, request) {
        Err(ScanError::Refused {
            general: 1,
            extended,
        }) => extended,
        other => panic!("not refused: {other:?}"),
    }
}

/// The next event that is not an Output event, within `limit`.
fn next_event(adapter: &Adapter, limit: Duration) -> Option<Event> {
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        match adapter.next_event(Some(left))? {
            Event::Output { .. } => continue,
            event => return Some(event),
        }
    }
}

/// Waits until `check` holds, at most `limit`.
fn eventually(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn an_exclusive_owner_exchanges_data_both_ways_at_the_rpi() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    adapter.set_input(101, &[0xAB; 276]).unwrap();
    let scanner = open(&adapter, IoRequest::owner(151, 64, 101, 276, RPI)).unwrap();
    assert_eq!(scanner.api, (RPI, RPI));
    assert_eq!(scanner.multicast_group, None);
    let Some(Event::Opened(info)) = next_event(&adapter, Duration::from_secs(1)) else {
        panic!("no Opened event");
    };
    assert_eq!(info.kind, ConnectionKind::ExclusiveOwner);
    assert_eq!((info.input, info.input_size), (101, 276));
    assert_eq!((info.output, info.output_size), (Some(151), 64));
    assert_eq!(info.originator, Ipv4Addr::LOCALHOST);

    // T->O: the input assembly arrives every RPI
    assert!(scanner.wait_for_packets(30, Duration::from_secs(3)));
    assert_eq!(scanner.input().unwrap(), vec![0xAB; 276]);
    let intervals = scanner.intervals();
    let mean = intervals.iter().sum::<Duration>() / intervals.len() as u32;
    assert!(
        mean > Duration::from_millis(7) && mean < Duration::from_millis(25), // loose: shared CI runners
        "mean interval {mean:?}, adapter {:?}, longest gaps {:?}",
        adapter.stats(),
        {
            let mut sorted = intervals.clone();
            sorted.sort();
            sorted.into_iter().rev().take(5).collect::<Vec<_>>()
        }
    );

    // O->T: the output assembly and the run bit arrive, and an Output event says so
    scanner.set_output(&[7; 64], true);
    assert!(eventually(Duration::from_secs(2), || {
        adapter.output(151).unwrap().data == [7; 64]
    }));
    assert!(adapter.output(151).unwrap().run);
    adapter.set_input(101, &[1, 2, 3]).unwrap();
    assert!(eventually(Duration::from_secs(2), || {
        scanner.input().is_some_and(|i| i[..4] == [1, 2, 3, 0])
    }));

    // Forward Close: closed, outputs idle
    assert_eq!(scanner.close().unwrap(), (0, vec![]));
    assert!(matches!(
        next_event(&adapter, Duration::from_secs(1)),
        Some(Event::Closed(_))
    ));
    assert!(adapter.connections().is_empty());
    assert!(!adapter.output(151).unwrap().run);
    assert!(adapter.stats().produced >= 30);
}

#[test]
fn every_input_and_output_pair_opens() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    let mut serial = 0;
    for (input, input_size) in [(100, 148), (101, 276), (102, 500)] {
        for (output, output_size) in [(150, 32), (151, 64), (152, 128)] {
            serial += 1;
            let scanner = open(
                &adapter,
                IoRequest {
                    serial,
                    ..IoRequest::owner(output, output_size, input, input_size, RPI)
                },
            )
            .unwrap();
            let info = adapter.connections().pop().unwrap();
            assert_eq!(
                (info.input, info.input_size, info.output, info.output_size),
                (input, input_size, Some(output), output_size)
            );
            assert!(scanner.wait_for_packets(2, Duration::from_secs(2)));
            assert_eq!(scanner.input().unwrap().len(), input_size);
            assert_eq!(scanner.close().unwrap(), (0, vec![]));
        }
    }
}

#[test]
fn refusals_carry_the_extended_status() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    // wrong sizes: the extended status names the right connection size
    assert_eq!(
        refusal(&adapter, IoRequest::owner(150, 30, 100, 148, RPI)),
        [0x0109, 38]
    );
    assert_eq!(
        refusal(&adapter, IoRequest::owner(150, 32, 100, 100, RPI)),
        [0x0109, 150]
    );
    // an assembly that does not exist, an RPI out of range, a wrong key
    assert_eq!(
        refusal(&adapter, IoRequest::owner(153, 32, 100, 148, RPI)),
        [0x0117]
    );
    assert_eq!(
        refusal(
            &adapter,
            IoRequest::owner(150, 32, 100, 148, Duration::from_secs(5))
        ),
        [0x0111]
    );
    let keyed = |key| IoRequest {
        key: Some(key),
        ..IoRequest::owner(150, 32, 100, 148, RPI)
    };
    assert_eq!(refusal(&adapter, keyed((1, 0x2B, 42, 1, 1))), [0x0114]);
    let scanner = open(&adapter, keyed((1234, 0x2B, 42, 0x81, 1))).unwrap();
    // a second owner of the same output
    let other = IoRequest {
        serial: 2,
        ..IoRequest::owner(150, 32, 101, 276, RPI)
    };
    assert_eq!(refusal(&adapter, other), [0x0106]);
    // the configuration assembly takes exactly its size
    let config = |data: Vec<u8>| IoRequest {
        serial: 3,
        config_point: 199,
        config_data: data,
        ..IoRequest::owner(151, 64, 100, 148, RPI)
    };
    assert_eq!(refusal(&adapter, config(vec![1, 2])), [0x0109, 4]);
    drop(scanner);
}

#[test]
fn configuration_data_reaches_the_application() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    let _scanner = open(
        &adapter,
        IoRequest {
            config_point: 199,
            config_data: vec![2, 0, 0, 0],
            ..IoRequest::owner(150, 32, 100, 148, RPI)
        },
    )
    .unwrap();
    assert!(matches!(
        next_event(&adapter, Duration::from_secs(1)),
        Some(Event::Opened(_))
    ));
    assert_eq!(
        next_event(&adapter, Duration::from_secs(1)),
        Some(Event::Config {
            instance: 199,
            data: vec![2, 0, 0, 0]
        })
    );
    assert_eq!(adapter.config(199).unwrap(), [2, 0, 0, 0]);
}

#[test]
fn a_quiet_scanner_times_out_and_the_next_open_recovers() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    // timeout 10 ms x 4 << 0 = 40 ms
    let quiet = open(
        &adapter,
        IoRequest {
            multiplier: 0,
            ..IoRequest::owner(150, 32, 100, 148, RPI)
        },
    )
    .unwrap();
    assert!(matches!(
        next_event(&adapter, Duration::from_secs(1)),
        Some(Event::Opened(_))
    ));
    quiet.set_output(&[1], true);
    assert!(eventually(Duration::from_secs(2), || adapter
        .output(150)
        .unwrap()
        .run));
    let quiet_at = Instant::now();
    quiet.go_quiet();
    let Some(Event::TimedOut(info)) = next_event(&adapter, Duration::from_secs(2)) else {
        panic!("no TimedOut event");
    };
    let after = quiet_at.elapsed();
    assert!(
        after < Duration::from_millis(500),
        "timed out after {after:?}"
    );
    assert_eq!(info.output, Some(150));
    assert!(adapter.connections().is_empty());
    assert!(!adapter.output(150).unwrap().run);
    // the scanner reconnects, as Logix does when the cable is back
    let again = open(
        &adapter,
        IoRequest {
            serial: 9,
            ..IoRequest::owner(150, 32, 100, 148, RPI)
        },
    )
    .unwrap();
    assert!(again.wait_for_packets(3, Duration::from_secs(2)));
    assert_eq!(adapter.connections().len(), 1);
}

#[test]
fn input_only_and_listen_only_open_beside_the_owner() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    let listen = |serial| IoRequest {
        serial,
        multicast: true,
        ..IoRequest::heartbeat(237, 100, 148, RPI)
    };
    // listen only needs a connection that already sends the multicast stream
    assert_eq!(refusal(&adapter, listen(5)), [0x0119]);
    let owner = open(
        &adapter,
        IoRequest {
            multicast: true,
            ..IoRequest::owner(150, 32, 100, 148, RPI)
        },
    )
    .unwrap();
    let group = owner.multicast_group.expect("a multicast address item");
    assert_eq!(group.ip().octets()[..2], [239, 192]);
    assert_eq!(group.port(), adapter.io_addr().port());
    let input_only = open(
        &adapter,
        IoRequest {
            serial: 2,
            multicast: true,
            ..IoRequest::heartbeat(238, 100, 148, RPI)
        },
    )
    .unwrap();
    let listener = open(&adapter, listen(3)).unwrap();
    assert_eq!(input_only.t_o_id, owner.t_o_id); // one stream
    assert_eq!(listener.t_o_id, owner.t_o_id);
    assert_eq!(listener.multicast_group, Some(group));
    let kinds: Vec<_> = adapter.connections().iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [
            ConnectionKind::ExclusiveOwner,
            ConnectionKind::InputOnly,
            ConnectionKind::ListenOnly
        ]
    );
    // heartbeats keep input-only and listen-only connections open past their timeout
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(adapter.connections().len(), 3);
    // point-to-point input only gets its own data
    let p2p = open(
        &adapter,
        IoRequest {
            serial: 4,
            ..IoRequest::heartbeat(238, 102, 500, RPI)
        },
    )
    .unwrap();
    assert!(p2p.wait_for_packets(3, Duration::from_secs(2)));
    assert_eq!(p2p.input().unwrap().len(), 500);
    // the owner and the input-only connection close: the listener closes with them
    assert_eq!(owner.close().unwrap().0, 0);
    assert_eq!(input_only.close().unwrap().0, 0);
    assert_eq!(adapter.connections().len(), 1);
    drop(listener);
}

/// A driver over TCP to the adapter's port.
fn driver(adapter: &Adapter) -> CipDriver {
    let port = adapter.addr().port();
    let connector: Connector = Box::new(move |_, _, timeout| {
        Ok(Box::new(TcpTransport::connect("127.0.0.1", port, timeout)?) as Box<dyn Transport>)
    });
    let driver = CipDriver::with_connector("127.0.0.1", CipOptions::default(), connector).unwrap();
    assert!(driver.open().unwrap());
    driver
}

#[test]
fn browsers_read_its_identity_ports_and_ciplink_object() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    adapter.set_detail("station 2");
    let driver = driver(&adapter);
    let identity = driver.identity_at("").unwrap();
    assert_eq!(identity.product_name, "Station");
    assert_eq!(identity.product_code, 42);
    assert_eq!(identity.serial, "01020304");
    assert_eq!(identity.status, [0x30, 0]); // no I/O connection yet
    let ports = driver.ports_at("").unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(
        (ports[0].number, ports[0].type_name().as_str()),
        (2, "EtherNet/IP")
    );
    assert_eq!(
        ports[0].ip,
        Some((Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0)))
    );
    // a ListIdentity over TCP
    let listed = driver.lock().list_identity().unwrap().unwrap();
    assert_eq!(listed.identity.product_name, "Station");
    assert_eq!(listed.ip_address, "127.0.0.1");
}

#[test]
fn browsers_show_what_the_adapter_runs_and_who_owns_it() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    adapter.set_detail("station 2");
    let driver = driver(&adapter);
    let idle = driver.app_at("").unwrap().unwrap();
    assert_eq!(idle.summary(), "Station · station 2 · no connection");
    let _owner = open(&adapter, IoRequest::owner(150, 32, 100, 148, RPI)).unwrap();
    let app = driver.app_at("").unwrap().unwrap();
    assert_eq!(app.connections.len(), 1);
    assert_eq!(
        app.summary(),
        "Station · station 2 · owned by 127.0.0.1, RPI 10 ms"
    );
    // a scan of a network probes each device it finds for the app line
    let nodes = driver
        .browse_port("", 2, Some(&["127.0.0.1".to_owned()]), 1)
        .unwrap();
    assert_eq!(nodes[0].app.as_ref(), Some(&app));
}

#[test]
fn list_identity_over_udp_finds_the_adapter() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    let found = CipDriver::discover_at(None, "127.0.0.1", adapter.addr().port());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].identity.product_name, "Station");
    assert_eq!(found[0].ip_address, "127.0.0.1");
}

#[test]
fn the_eds_uploads_through_the_file_object() {
    let _one_at_a_time = one_at_a_time();
    let adapter = adapter();
    let driver = driver(&adapter);
    let ask = |service: u8, data: Vec<u8>| {
        let reply = driver
            .generic_message(&GenericMessage {
                service,
                class_code: LogicalValue::Int(0x37),
                instance: LogicalValue::Int(0xC8),
                request_data: data,
                connected: false,
                unconnected_send: true,
                route_path: RoutePath::Current,
                ..GenericMessage::default()
            })
            .unwrap();
        assert!(reply.is_ok(), "{:?}", reply.tag.error);
        reply.data().unwrap().to_vec()
    };
    let started = ask(0x4B, vec![0xFF]);
    let size = u32::from_le_bytes([started[0], started[1], started[2], started[3]]) as usize;
    let mut file: Vec<u8> = Vec::new();
    for n in 0..=255u8 {
        let transfer = ask(0x4F, vec![n]);
        file.extend(&transfer[2..]);
        if !matches!(transfer[1], 0 | 1) {
            break;
        }
    }
    file.truncate(file.len() - 2); // the checksum
    assert_eq!(file.len(), size);
    assert_eq!(file, b"[File]\nDescText = \"Station\";\n");
}

#[test]
fn a_second_adapter_on_the_same_port_says_why_it_cannot_start() {
    let _one_at_a_time = one_at_a_time();
    let first = adapter();
    let err = Adapter::start(AdapterConfig {
        assemblies: vec![Assembly::input(100, 4)],
        bind: Ipv4Addr::LOCALHOST,
        port: first.addr().port(),
        io_port: 0,
        ..AdapterConfig::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("FactoryTalk Linx"), "{err}");
}

/// Production timing at 2 ms and 20 ms over 3 s each, printed; run on demand on the machine in question with
/// `cargo test --release -p ciplink-sim --test adapter timing -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check: shared CI runners have no timing guarantees"]
fn timing() {
    let _one_at_a_time = one_at_a_time();
    for rpi in [Duration::from_millis(2), Duration::from_millis(20)] {
        let adapter = adapter();
        let scanner = open(&adapter, IoRequest::owner(150, 32, 100, 148, rpi)).unwrap();
        std::thread::sleep(Duration::from_secs(3));
        let mut intervals = scanner.intervals();
        intervals.sort();
        let at = |p: f64| intervals[((intervals.len() - 1) as f64 * p) as usize];
        println!(
            "RPI {rpi:?}: {} packets, p50 {:?}, p99 {:?}, p99.9 {:?}, max {:?}; adapter {:?}",
            intervals.len() + 1,
            at(0.5),
            at(0.99),
            at(0.999),
            intervals.last().unwrap(),
            adapter.stats()
        );
    }
}
