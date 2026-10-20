//! Fault injection, request hooks, the recorded requests, and the TCP and UDP servers.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::Error;
use ciplink::packets::{
    Encap, Reply, ReplyKind, TAG_TABLE_VERSION_SERVICE, list_identity_request,
    parse_tag_table_version, register_session_request, unregister_session_request,
};
use ciplink::transport::{TcpTransport, Transport};
use ciplink_sim::{Fault, Simulator, TagConfig};
use common::{Client, controller, data, read};
use serde_json::json;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn sim() -> Simulator {
    Simulator::new(controller()).unwrap()
}

#[test]
fn a_dropped_reply_times_out_and_the_next_one_answers() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    sim.inject(Fault::DropReplies(1));
    client
        .transport
        .send(
            &ciplink::packets::send_unit_data_request(
                &client.encap,
                &client.cid,
                9,
                &read("dint", 1),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(client.transport.receive(), Err(Error::Comm(_))));
    assert!(client.unit(&read("dint", 1)).is_valid());
}

#[test]
fn delays_past_the_timeout_leave_a_late_reply() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    sim.inject(Fault::Delay(Duration::from_millis(30)));
    let started = Instant::now();
    assert!(client.unit(&read("dint", 1)).is_valid());
    assert!(started.elapsed() >= Duration::from_millis(30));

    client
        .transport
        .set_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let frame =
        ciplink::packets::send_unit_data_request(&client.encap, &client.cid, 77, &read("int", 1))
            .unwrap();
    client.transport.send(&frame).unwrap();
    assert!(matches!(client.transport.receive(), Err(Error::Comm(_))));
    sim.clear_faults();
    // the late reply answers the next receive, as on a socket
    let late = Reply::parse(
        ReplyKind::SendUnitData,
        &client.transport.receive().unwrap(),
    );
    assert_eq!(
        (late.raw.as_ref().unwrap()[44], data(&late)),
        (77, vec![0xC3, 0, 0xFE, 0xFF])
    );
}

#[test]
fn injected_statuses_answer_a_tag_or_a_service() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    sim.inject(Fault::TagStatus {
        tag: "ary".into(),
        status: 0x05,
        ext: None,
    });
    sim.inject(Fault::TagStatus {
        tag: "Program:Main.local".into(),
        status: 0xFF,
        ext: Some(0x2105),
    });
    assert_eq!(client.unit(&read("ary[3]", 1)).service_status, Some(0x05));
    assert_eq!(client.unit(&read("ARY", 1)).service_status, Some(0x05));
    let reply = client.unit(&read("Program:Main.local", 1));
    assert_eq!(
        (reply.service_status, &reply.raw.as_ref().unwrap()[49..52]),
        (Some(0xFF), &[1, 0x05, 0x21][..])
    );
    assert!(client.unit(&read("dint", 1)).is_valid());

    sim.inject(Fault::ServiceStatus {
        service: 0x03,
        class: Some(0xAC),
        status: 0x10,
        ext: None,
    });
    assert_eq!(
        client.unit(&TAG_TABLE_VERSION_SERVICE).service_status,
        Some(0x10)
    );
    let reply = client.multi(&[read("dint", 1), TAG_TABLE_VERSION_SERVICE.to_vec()]);
    assert_eq!(
        reply
            .replies
            .iter()
            .map(|r| r.service_status.unwrap())
            .collect::<Vec<_>>(),
        [0, 0x10]
    );
    sim.clear_faults();
    assert!(client.unit(&read("ary[3]", 1)).is_valid());
    assert!(client.unit(&TAG_TABLE_VERSION_SERVICE).is_valid());
}

#[test]
fn refused_connections_fail_to_open() {
    let sim = sim();
    let connect = sim.connector();
    assert!(connect("10.0.0.1", 44818, None).is_ok()); // in memory: the address is not used
    sim.inject(Fault::RefuseConnections);
    let err = connect("plc", 44818, None).err().unwrap();
    assert_eq!(err, Error::comm("Failed to open socket to plc:44818"));

    let server = sim.serve("127.0.0.1:0").unwrap();
    let mut tcp =
        TcpTransport::connect("127.0.0.1", server.port(), Some(Duration::from_secs(2))).unwrap();
    let encap = Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    };
    let _ = tcp.send(&register_session_request(&encap, 1, 0));
    assert!(tcp.receive().is_err());
}

#[test]
fn a_hook_can_edit_the_tag_table_between_two_requests() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let first = sim.requests();
    sim.on_request(move |plc, index| {
        if index == first + 1 {
            plc.add_tag(None, &TagConfig::new("between", "DINT"))
                .unwrap();
        }
    });
    let v1 = parse_tag_table_version(&mut client.unit(&TAG_TABLE_VERSION_SERVICE)).unwrap();
    let v2 = parse_tag_table_version(&mut client.unit(&TAG_TABLE_VERSION_SERVICE)).unwrap();
    let v3 = parse_tag_table_version(&mut client.unit(&TAG_TABLE_VERSION_SERVICE)).unwrap();
    assert_eq!((v1.0, v2.0, v3.0), (1, 2, 2));
    sim.clear_hook();
    assert_eq!(sim.value("between").unwrap(), json!(0));
}

#[test]
fn recording_keeps_the_request_frames() {
    let sim = sim();
    sim.record(true);
    let mut client = Client::connected(&sim, 4000);
    client.unit(&read("dint", 1));
    let frames = sim.take_received();
    assert_eq!(frames.len(), 3);
    assert_eq!(
        (&frames[0][..2], &frames[1][..2], &frames[2][..2]),
        (&[0x65, 0][..], &[0x6F, 0][..], &[0x70, 0][..])
    );
    assert!(sim.take_received().is_empty());
    sim.record(false);
    client.unit(&read("dint", 1));
    assert!(sim.take_received().is_empty());
}

#[test]
fn tcp_server_serves_connections_in_parallel() {
    let sim = sim();
    let server = sim.serve("127.0.0.1:0").unwrap();
    let port = server.port();
    let threads: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                let mut tcp =
                    TcpTransport::connect("127.0.0.1", port, Some(Duration::from_secs(5))).unwrap();
                let mut encap = Encap {
                    session: 0,
                    context: [i; 8],
                    option: 0,
                };
                tcp.send(&register_session_request(&encap, 1, 0)).unwrap();
                let reply = Reply::parse(ReplyKind::RegisterSession, &tcp.receive().unwrap());
                encap.session = reply.session.unwrap();
                tcp.send(&list_identity_request(&encap)).unwrap();
                let raw = tcp.receive().unwrap();
                assert_eq!(&raw[12..20], &[i; 8]); // the sender context is echoed
                let identity = Reply::parse(ReplyKind::ListIdentity, &raw)
                    .identity
                    .unwrap();
                tcp.send(&unregister_session_request(&encap)).unwrap();
                assert!(tcp.receive().is_err()); // UnRegisterSession closes the connection
                (encap.session, identity.identity.product_name)
            })
        })
        .collect();
    let mut sessions: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(sessions.iter().all(|(_, name)| name == "1756-SIM/A"));
    sessions.sort();
    sessions.dedup();
    assert_eq!(sessions.len(), 4);
}

#[test]
fn udp_answers_list_identity() {
    let sim = sim();
    let udp = sim.serve_udp("127.0.0.1:0").unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let encap = Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    };
    socket
        .send_to(&list_identity_request(&encap), udp.addr())
        .unwrap();
    let mut buffer = [0u8; 600];
    let size = socket.recv(&mut buffer).unwrap();
    let identity = Reply::parse(ReplyKind::ListIdentity, &buffer[..size])
        .identity
        .unwrap();
    assert_eq!(identity.identity.product_name, "1756-SIM/A");
}
