//! Hooks for an emulator that owns the controller memory: placed and overlapping tags, bit aliases, explicit
//! layouts, lent memory, deferred service, a fixed clock, the identity status and trends switched off.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::Value;
use ciplink::cip::CipOptions;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::packets::{
    Encap, Reply, ReplyKind, generic_message, list_identity_request, register_session_request,
    send_rr_data_request,
};
use ciplink::transport::{TcpTransport, Transport};
use ciplink_sim::{
    LogixConfig, MemberConfig, MemberLayout, Serviced, Simulator, TagConfig, TypeConfig, TypeLayout,
};
use common::{Client, data, read, write};
use serde_json::json;
use std::time::Duration;

/// Memory of 16 bytes: `word` DINT at 0, `alias` a DINT alias of it, `low` its low SINT, `flag` bit 3 of
/// its low byte, `b` a standalone BOOL at 8.
fn placed() -> LogixConfig {
    LogixConfig {
        memory_len: Some(16),
        ..LogixConfig::default()
    }
    .with_tag(
        TagConfig::new("word", "DINT")
            .at(0)
            .value(json!(0x0102_0304)),
    )
    .with_tag(TagConfig {
        alias: true,
        ..TagConfig::new("alias", "DINT").at(0)
    })
    .with_tag(TagConfig::new("low", "SINT").at(0))
    .with_tag(TagConfig::new("flag", "BOOL").at(0).bit(3))
    .with_tag(TagConfig::new("b", "BOOL").at(8))
}

fn general(reply: &Reply) -> u8 {
    reply.service_status.unwrap()
}

#[test]
fn placed_tags_overlap_and_an_alias_shares_its_targets_bytes() {
    let sim = Simulator::new(placed()).unwrap();
    assert_eq!(sim.value("alias").unwrap(), json!(0x0102_0304));
    assert_eq!(sim.value("low").unwrap(), json!(4));
    let mut client = Client::connected(&sim, 4000);
    let reply = client.unit(&write("alias", &[0xC4, 0], 1, &7i32.to_le_bytes()));
    assert_eq!(general(&reply), 0);
    assert_eq!(data(&client.unit(&read("word", 1))), [0xC4, 0, 7, 0, 0, 0]);
    assert_eq!(sim.value("low").unwrap(), json!(7));
    assert_eq!(sim.with_logix(|l| l.memory_len()), Some(16));
}

#[test]
fn a_bit_alias_reads_and_writes_only_its_bit() {
    let sim = Simulator::new(placed()).unwrap();
    let mut client = Client::connected(&sim, 4000);
    // 0x04 has bit 3 clear
    assert_eq!(data(&client.unit(&read("flag", 1))), [0xC1, 0, 0]);
    assert_eq!(
        general(&client.unit(&write("flag", &[0xC1, 0], 1, &[0xFF]))),
        0
    );
    assert_eq!(sim.value("word").unwrap(), json!(0x0102_030C));
    assert_eq!(data(&client.unit(&read("flag", 1))), [0xC1, 0, 1]);
    sim.set_value("flag", &json!(false)).unwrap();
    assert_eq!(sim.value("word").unwrap(), json!(0x0102_0304));
    assert_eq!(sim.value("flag").unwrap(), json!(false));
    // a bit alias has no elements or members
    assert_ne!(general(&client.unit(&read("flag.x", 1))), 0);
    assert!(Simulator::new(placed().with_tag(TagConfig::new("bad", "DINT").at(0).bit(1))).is_err());
    assert!(Simulator::new(placed().with_tag(TagConfig::new("bad", "BOOL").at(0).bit(8))).is_err());
}

#[test]
fn a_write_to_a_placed_bool_stores_zero_or_one() {
    let sim = Simulator::new(placed()).unwrap();
    let mut client = Client::connected(&sim, 4000);
    assert_eq!(
        general(&client.unit(&write("b", &[0xC1, 0], 1, &[0xFF]))),
        0
    );
    assert_eq!(data(&client.unit(&read("b", 1))), [0xC1, 0, 1]);
    let mut memory = vec![0; 16];
    sim.with_logix(|l| l.swap_memory(&mut memory))
        .unwrap()
        .unwrap();
    assert_eq!(memory[8], 1);
}

#[test]
fn placement_errors_name_the_tag() {
    let outside = placed().with_tag(TagConfig::new("far", "DINT").at(14));
    assert!(Simulator::new(outside).unwrap_err().0.contains("far"));
    let too_big = LogixConfig {
        memory_len: Some((1 << 26) + 1),
        ..LogixConfig::default()
    };
    assert!(Simulator::new(too_big).is_err());
    // without memory_len, a tag placed over one that was appended is refused
    let mixed = LogixConfig::default()
        .with_tag(TagConfig::new("appended", "DINT"))
        .with_tag(TagConfig::new("placed", "DINT").at(0));
    assert!(Simulator::new(mixed).unwrap_err().0.contains("placed"));
    // appended tags go after memory_len
    let sim =
        Simulator::new(placed().with_tag(TagConfig::new("extra", "LINT").value(json!(5)))).unwrap();
    assert_eq!(sim.with_logix(|l| l.memory_len()), Some(24));
}

#[test]
fn swapped_memory_must_have_the_same_length() {
    let sim = Simulator::new(placed()).unwrap();
    let mut short = vec![0u8; 15];
    assert!(
        sim.with_logix(|l| l.swap_memory(&mut short))
            .unwrap()
            .is_err()
    );
    let mut memory = vec![0u8; 16];
    memory[0] = 99;
    sim.with_logix(|l| l.swap_memory(&mut memory))
        .unwrap()
        .unwrap();
    assert_eq!(sim.value("word").unwrap(), json!(99));
    assert_eq!(&memory[..4], &[4, 3, 2, 1]);
}

/// MESSAGE-like: an explicit layout of 12 bytes, a predefined template ID, a hidden tail.
fn message_type() -> TypeConfig {
    TypeConfig {
        template_id: Some(0xF10),
        ..TypeConfig::explicit(
            "MSGLIKE",
            12,
            [
                MemberConfig::new("Flags", "DINT").at(0).hidden(),
                MemberConfig::new("EN", "BOOL").at(3).bit(7),
                MemberConfig::new("DN", "BOOL").at(3).bit(5),
                MemberConfig::new("Code", "INT").at(4),
                MemberConfig::array("Tail", "SINT", 6).at(6).hidden(),
            ],
        )
    }
}

#[test]
fn an_explicit_layout_with_a_hidden_tail_round_trips_through_type_layout() {
    let config = LogixConfig::default()
        .with_type(message_type())
        .with_tag(TagConfig::new("m", "MSGLIKE").value(json!({"EN": true, "Code": -3})));
    let sim = Simulator::new(config).unwrap();
    let layout = sim
        .with_logix(|l| l.type_layout("msglike"))
        .unwrap()
        .unwrap();
    let member = |name: &str, offset, bit, data_type: &str, dim, hidden| MemberLayout {
        name: name.into(),
        offset,
        bit,
        data_type: data_type.into(),
        dim,
        hidden,
    };
    assert_eq!(
        layout,
        TypeLayout {
            name: "MSGLIKE".into(),
            template_id: 0xF10,
            size: 12,
            members: vec![
                member("Flags", 0, None, "DINT", 0, true),
                member("EN", 3, Some(7), "BOOL", 0, false),
                member("DN", 3, Some(5), "BOOL", 0, false),
                member("Code", 4, None, "INT", 0, false),
                member("Tail", 6, None, "SINT", 6, true),
            ],
        }
    );
    assert_eq!(
        sim.value("m").unwrap(),
        json!({"EN": true, "DN": false, "Code": -3})
    );
    let mut client = Client::connected(&sim, 4000);
    let raw = data(&client.unit(&read("m", 1)));
    assert_eq!(&raw[4..], &[0, 0, 0, 0x80, 0xFD, 0xFF, 0, 0, 0, 0, 0, 0]);
    assert_ne!(general(&client.unit(&read("m.Flags", 1))), 0);

    // a user type's rule layout is reported the same way
    let sim = Simulator::new(common::controller()).unwrap();
    let point = sim.with_logix(|l| l.type_layout("Point")).unwrap().unwrap();
    assert_eq!((point.size, point.members.len()), (16, 4));
    assert!(point.members[0].hidden);
    assert!(sim.with_logix(|l| l.type_layout("NOPE")).unwrap().is_none());
}

#[test]
fn explicit_layout_errors() {
    let bad = |t: TypeConfig| Simulator::new(LogixConfig::default().with_type(t)).is_err();
    // a member past the size
    assert!(bad(TypeConfig::explicit(
        "A",
        4,
        [MemberConfig::new("x", "DINT").at(2)]
    )));
    // a member without an offset
    assert!(bad(TypeConfig::explicit(
        "A",
        4,
        [MemberConfig::new("x", "DINT")]
    )));
    // a bit on a non-BOOL
    assert!(bad(TypeConfig::explicit(
        "A",
        4,
        [MemberConfig::new("x", "DINT").at(0).bit(1)]
    )));
    // template IDs above 0xEFF need an explicit layout
    assert!(bad(TypeConfig {
        template_id: Some(0xF10),
        ..TypeConfig::udt("A", [MemberConfig::new("x", "DINT")])
    }));
    assert!(bad(TypeConfig {
        template_id: Some(0x1000),
        ..TypeConfig::explicit("A", 4, [MemberConfig::new("x", "DINT").at(0)])
    }));
}

/// A raw request frame on a connected client, sent without waiting for the reply.
fn send_unit(client: &mut Client, message: &[u8]) {
    client.sequence = client.sequence.wrapping_add(1);
    let frame = ciplink::packets::send_unit_data_request(
        &client.encap,
        &client.cid,
        client.sequence,
        message,
    )
    .unwrap();
    client.transport.send(&frame).unwrap();
}

fn receive_unit(client: &mut Client) -> Reply {
    Reply::parse(
        ReplyKind::SendUnitData,
        &client.transport.receive().unwrap(),
    )
}

fn clock_set(us: u64) -> Vec<u8> {
    let mut data = 1u16.to_le_bytes().to_vec();
    data.extend(6u16.to_le_bytes());
    data.extend(us.to_le_bytes());
    generic_message(0x04, 0x8Bu32.into(), 1u32.into(), None, &data).unwrap()
}

#[test]
fn a_deferred_sim_answers_nothing_until_serviced_then_in_order_with_lent_memory() {
    let sim = Simulator::new(placed()).unwrap();
    let mut a = Client::connected(&sim, 4000);
    let mut b = Client::connected(&sim, 4000);
    sim.set_deferred(true);
    a.transport
        .set_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    send_unit(
        &mut a,
        &write("word", &[0xC4, 0], 1, &0x55i32.to_le_bytes()),
    );
    send_unit(&mut b, &read("word", 1));
    assert!(a.transport.receive().is_err(), "answered before service");
    assert!(sim.pending());

    let mut memory = vec![0u8; 16];
    memory[..4].copy_from_slice(&0x11i32.to_le_bytes());
    let served = sim.service(&mut memory, 1).unwrap();
    assert_eq!(
        served,
        Serviced {
            requests: 1,
            writes: vec![(0, 4)],
            clock_set_us: None
        }
    );
    // the write went to the lent memory, the sim's own is untouched
    assert_eq!(&memory[..4], &0x55i32.to_le_bytes());
    assert_eq!(sim.value("word").unwrap(), json!(0x0102_0304));
    assert_eq!(general(&receive_unit(&mut a)), 0);
    assert!(sim.pending());

    send_unit(&mut a, &clock_set(1_700_000_000_000_000));
    let served = sim.service(&mut memory, 10).unwrap();
    assert_eq!(served.requests, 2);
    assert_eq!(served.clock_set_us, Some(1_700_000_000_000_000));
    assert!(served.writes.is_empty());
    assert!(!sim.pending());
    // b's read was served before a's clock set, from the lent memory after a's write
    assert_eq!(data(&receive_unit(&mut b)), [0xC4, 0, 0x55, 0, 0, 0]);
    assert_eq!(general(&receive_unit(&mut a)), 0);

    // a wrong length is refused before anything is served
    send_unit(&mut b, &read("word", 1));
    assert!(sim.service(&mut vec![0; 3], 10).is_err());
    assert!(sim.pending());
    // leaving deferred mode answers what is waiting from the sim's own memory
    sim.set_deferred(false);
    assert!(!sim.pending());
    assert_eq!(data(&receive_unit(&mut b)), [0xC4, 0, 4, 3, 2, 1]);
    assert!(b.unit(&read("word", 1)).is_valid());
}

#[test]
fn a_deferred_driver_on_its_own_thread_is_served_across_service_calls() {
    let sim = Simulator::new(placed()).unwrap();
    sim.set_deferred(true);
    let connector = sim.connector();
    let client = std::thread::spawn(move || {
        let options = LogixOptions {
            cip: CipOptions {
                socket_timeout: Some(Duration::from_secs(5)),
                ..CipOptions::default()
            },
            ..LogixOptions::default()
        };
        let plc = LogixDriver::with_connector("192.0.2.1", options, connector).unwrap();
        plc.open().unwrap();
        let mut seen = Vec::new();
        for i in 0..5 {
            let wrote = plc.write(&[("word", Value::DInt(i))]).unwrap();
            assert!(wrote[0].error.is_none(), "{:?}", wrote[0].error);
            let read = plc.read(&["low"]).unwrap().remove(0);
            seen.push(read.value.unwrap());
        }
        plc.close().unwrap();
        seen
    });
    let mut memory = vec![0u8; 16];
    let mut writes = 0;
    let mut calls = 0;
    while !client.is_finished() {
        let served = sim.service(&mut memory, 1).unwrap();
        writes += served.writes.len();
        calls += 1;
        std::thread::sleep(Duration::from_millis(1));
    }
    let seen = client.join().unwrap();
    assert_eq!(seen, (0..5).map(Value::SInt).collect::<Vec<_>>());
    assert_eq!(writes, 5);
    assert!(calls > 10);
    assert_eq!(&memory[..4], &4i32.to_le_bytes());
}

#[test]
fn a_deferred_tcp_connection_waits_for_service() {
    let sim = Simulator::new(placed()).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    sim.set_deferred(true);
    let port = server.port();
    let client = std::thread::spawn(move || {
        let mut tcp =
            TcpTransport::connect("127.0.0.1", port, Some(Duration::from_secs(5))).unwrap();
        let mut encap = Encap {
            session: 0,
            context: [0; 8],
            option: 0,
        };
        tcp.send(&register_session_request(&encap, 1, 0)).unwrap();
        let registered = Reply::parse(ReplyKind::RegisterSession, &tcp.receive().unwrap());
        encap.session = registered.session.unwrap();
        tcp.send(&send_rr_data_request(&encap, &read("word", 1)).unwrap())
            .unwrap();
        data(&Reply::parse(
            ReplyKind::SendRRData,
            &tcp.receive().unwrap(),
        ))
    });
    let mut memory = vec![0u8; 16];
    memory[0] = 42;
    let mut served = 0;
    while !client.is_finished() {
        served += sim.service(&mut memory, 8).unwrap().requests;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(client.join().unwrap(), [0xC4, 0, 42, 0, 0, 0]);
    assert_eq!(served, 2);
}

#[test]
fn a_fixed_clock_is_reported_and_a_clock_set_moves_it() {
    let sim = Simulator::new(placed()).unwrap();
    sim.with_logix(|l| l.set_clock_us(Some(1_000_000))).unwrap();
    assert_eq!(sim.with_logix(|l| l.clock_us()), Some(1_000_000));
    let mut client = Client::connected(&sim, 4000);
    let get = generic_message(0x03, 0x8Bu32.into(), 1u32.into(), None, &[1, 0, 6, 0]).unwrap();
    assert_eq!(&data(&client.unit(&get))[6..], &1_000_000u64.to_le_bytes());
    assert_eq!(general(&client.unit(&clock_set(5_000_000))), 0);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(sim.with_logix(|l| l.clock_us()), Some(5_000_000));
    sim.with_logix(|l| l.set_clock_us(None)).unwrap();
    assert!(sim.with_logix(|l| l.clock_us()).unwrap() > 1_600_000_000_000_000);
}

#[test]
fn the_identity_status_and_state_can_be_set() {
    let sim = Simulator::new(placed()).unwrap();
    sim.set_identity_status(0x0F34, 4);
    let mut client = Client::new(&sim);
    let status = generic_message(0x0E, 1u32.into(), 1u32.into(), Some(5u32.into()), &[]).unwrap();
    assert_eq!(data(&client.rr(&status)), [0x34, 0x0F]);
    let encap = Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    };
    let reply = client.exchange(&list_identity_request(&encap), ReplyKind::ListIdentity);
    let identity = reply.identity.unwrap();
    assert_eq!(
        (identity.identity.status, identity.state),
        ([0x34, 0x0F], 4)
    );
}

#[test]
fn trends_switched_off_answer_service_not_supported() {
    let sim = Simulator::new(LogixConfig {
        trends: false,
        ..placed()
    })
    .unwrap();
    let mut client = Client::connected(&sim, 4000);
    let create = generic_message(0x08, 0xB2u32.into(), 0u32.into(), None, &[]).unwrap();
    assert_eq!(general(&client.unit(&create)), 0x08);
    let on = Simulator::new(placed()).unwrap();
    let mut client = Client::connected(&on, 4000);
    assert_eq!(general(&client.unit(&create)), 0);
}

#[test]
fn json_configs_take_the_new_fields() {
    let sim = Simulator::from_json(
        r#"{"memory_len": 8, "trends": false,
            "types": [{"name": "T", "size": 4, "template_id": 3900,
                       "members": [{"name": "x", "type": "INT", "offset": 2, "hidden": false}]}],
            "tags": [{"name": "t", "type": "T", "at": 4}, {"name": "f", "type": "BOOL", "at": 0, "bit": 2}]}"#,
    )
    .unwrap();
    assert_eq!(sim.with_logix(|l| l.memory_len()), Some(8));
    assert_eq!(sim.value("t").unwrap(), json!({"x": 0}));
}
