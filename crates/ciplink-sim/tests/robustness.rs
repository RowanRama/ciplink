//! Hostile or extreme input: odd symbol bytes, tiny or huge connections, oversized configurations. The
//! simulator must answer (or refuse) without panicking, and every paged reply must make progress.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::epath::Segment;
use ciplink::packets::{
    ForwardOpen, ReplyKind, forward_open_data, generic_message, send_unit_data_request,
};
use ciplink::transport::Transport;
use ciplink_sim::{LogixConfig, MemberConfig, Simulator, SlcConfig, TagConfig, TypeConfig};
use common::{Client, controller, data, read};
use serde_json::json;

/// The general status of a connected reply.
fn general(reply: &ciplink::packets::Reply) -> u8 {
    assert_eq!(reply.kind, ReplyKind::SendUnitData);
    reply.raw.as_ref().unwrap()[48]
}

/// A client whose connection takes requests of 500 bytes but replies of only `reply_size` bytes.
fn small_replies(sim: &Simulator, reply_size: u16) -> Client {
    let mut client = Client::new(sim);
    let params = ForwardOpen {
        cid: [1, 2, 3, 4],
        csn: [5, 6],
        vid: [7, 8],
        vsn: [9, 10, 11, 12],
        connection_size: 500,
        large: false,
    };
    let mut fo = forward_open_data(&params, &[Segment::port("bp", 0)]).unwrap();
    // T->O network parameters: keep the flags, change the size
    let t_o = u16::from_le_bytes([fo[32], fo[33]]);
    fo[32..34].copy_from_slice(&((t_o & !0x01FF) | reply_size).to_le_bytes());
    let reply = client.rr(&generic_message(0x54, 6u32.into(), 1u32.into(), None, &fo).unwrap());
    assert!(reply.is_valid());
    client
        .cid
        .copy_from_slice(&reply.data.as_ref().unwrap()[..4]);
    client
}

#[test]
fn simulator_handles_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<Simulator>();
    check::<ciplink_sim::Server>();
    check::<ciplink_sim::UdpServer>();
    fn send<T: Send>() {}
    send::<ciplink_sim::SimTransport>();
}

#[test]
fn non_ascii_symbol_names_do_not_panic() {
    let sim = Simulator::new(controller()).unwrap();
    let mut client = Client::connected(&sim, 500);
    // "Program" then 0xE9: as a char it straddles byte 8, where the program prefix is cut
    let name = b"Program\xE9:x";
    let mut m = vec![0x4C, 0, 0x91, name.len() as u8];
    m.extend(name);
    if name.len() % 2 == 1 {
        m.push(0);
    }
    m[1] = ((m.len() - 2) / 2) as u8;
    m.extend([1, 0]);
    assert_eq!(general(&client.unit(&m)), 0x04);
    // the same name as a path of the edit API
    assert!(sim.value("Program\u{e9}:x.y").is_err());
    assert!(sim.value("Program\u{e9}").is_err());
}

#[test]
fn symbol_list_too_small_for_one_symbol_is_an_error_not_an_empty_page() {
    let sim = Simulator::new(controller()).unwrap();
    let mut client = small_replies(&sim, 12);
    let m = [
        0x55, 3, 0x20, 0x6B, 0x25, 0x00, 0, 0, // from instance 0
        2, 0, 1, 0, 2, 0, // name and type
    ];
    let reply = client.unit(&m);
    assert_eq!(general(&reply), 0x11);
    assert!(data(&reply).is_empty());
}

#[test]
fn template_read_with_no_room_is_an_error_not_an_empty_page() {
    let sim = Simulator::new(controller()).unwrap();
    // any template: 0x100 is the first UDT (Point)
    let mut client = small_replies(&sim, 6);
    let reply = client.unit(
        &generic_message(
            0x4C,
            0x6Cu32.into(),
            0x100u32.into(),
            None,
            &[0, 0, 0, 0, 100, 0],
        )
        .unwrap(),
    );
    assert_eq!(general(&reply), 0x11);
}

#[test]
fn replies_of_the_largest_connection_fit_an_encapsulation_frame() {
    let mut config = LogixConfig::default().with_tag(TagConfig::new("big", "SINT").dims(&[65530]));
    config.max_connection_size = u16::MAX;
    let sim = Simulator::new(config).unwrap();
    let mut client = Client::new(&sim);
    assert!(client.forward_open(u32::from(u16::MAX), true).is_valid());
    let frame = send_unit_data_request(&client.encap, &client.cid, 1, &read("big", 65530)).unwrap();
    client.transport.send(&frame).unwrap();
    let frame = client.transport.receive().unwrap();
    let length = usize::from(u16::from_le_bytes([frame[2], frame[3]]));
    assert_eq!(
        length,
        frame.len() - 24,
        "the length field must match the data"
    );
    assert_eq!(frame[48], 0x06); // partial: the rest comes with fragmented reads
}

#[test]
fn oversized_configurations_are_errors() {
    let huge = TagConfig::new("x", "DINT").dims(&[u32::MAX, u32::MAX, u32::MAX]);
    assert!(Simulator::new(LogixConfig::default().with_tag(huge)).is_err());
    let big = TagConfig::new("x", "DINT").dims(&[100_000, 100_000, 100_000]);
    assert!(Simulator::new(LogixConfig::default().with_tag(big)).is_err());
    let udt = TypeConfig::udt(
        "Huge",
        [
            MemberConfig::array("a", "DINT", u32::MAX),
            MemberConfig::array("b", "DINT", u32::MAX),
        ],
    );
    assert!(Simulator::new(LogixConfig::default().with_type(udt)).is_err());
    let string = TypeConfig::string("S", u32::MAX);
    assert!(Simulator::new(LogixConfig::default().with_type(string)).is_err());
    let bools = TagConfig::new("x", "BOOL").dims(&[u32::MAX]);
    assert!(Simulator::new(LogixConfig::default().with_tag(bools)).is_err());
}

#[test]
fn slc_addresses_with_huge_elements_are_errors() {
    let sim = Simulator::new(SlcConfig::default()).unwrap();
    assert!(sim.value(&format!("N7:{}", usize::MAX)).is_err());
    assert!(
        sim.set_value(&format!("N7:{}", usize::MAX), &json!(1))
            .is_err()
    );
    assert_eq!(sim.value("N7:0").unwrap(), json!(0));
}

#[test]
fn symbol_lists_answer_the_highest_instance_id() {
    let sim = Simulator::new(
        LogixConfig::default().with_tag(TagConfig::new("last", "DINT").instance_id(u32::MAX)),
    )
    .unwrap();
    let mut client = Client::connected(&sim, 500);
    // attributes 3 and 5 are computed from the instance ID
    let m = [
        0x55, 3, 0x20, 0x6B, 0x25, 0x00, 0, 0, 3, 0, 1, 0, 3, 0, 5, 0,
    ];
    let reply = client.unit(&m);
    assert_eq!(general(&reply), 0);
    assert!(data(&reply).windows(4).any(|w| w == b"last"));
}

#[test]
fn a_panicking_hook_leaves_the_simulator_usable() {
    let sim = Simulator::new(controller()).unwrap();
    let server = sim.serve("127.0.0.1:0").unwrap();
    sim.on_request(|_, _| panic!("hook failed"));
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let encap = ciplink::packets::Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    };
    std::io::Write::write_all(
        &mut stream,
        &ciplink::packets::register_session_request(&encap, 1, 0),
    )
    .unwrap();
    // the connection closes instead of answering
    let mut buffer = [0u8; 64];
    assert_eq!(
        std::io::Read::read(&mut stream, &mut buffer).unwrap_or(0),
        0
    );
    sim.clear_hook();
    assert_eq!(sim.value("dint").unwrap(), json!(1234));
    let mut client = Client::connected(&sim, 500);
    assert_eq!(general(&client.unit(&read("dint", 1))), 0);
}

#[test]
fn multi_service_replies_never_exceed_the_connection() {
    let sim = Simulator::new(controller()).unwrap();
    let mut client = small_replies(&sim, 100);
    // 30 services of 2 bytes (no path): each is answered with a 4-byte error, 186 bytes in all
    let mut m = vec![0x0A, 2, 0x20, 0x02, 0x24, 0x01, 30, 0];
    for i in 0..30u16 {
        m.extend((2 + 60 + 2 * i).to_le_bytes());
    }
    for _ in 0..30 {
        m.extend([0x4C, 0]);
    }
    let frame = send_unit_data_request(&client.encap, &client.cid, 1, &m).unwrap();
    client.transport.send(&frame).unwrap();
    let frame = client.transport.receive().unwrap();
    // reply message after the 44-byte frame and CPF header and the 2-byte sequence count
    assert!(
        frame.len() - 46 <= 98,
        "a {}-byte reply on a 98-byte connection",
        frame.len() - 46
    );
    assert_eq!(frame[48], 0x11);
}

#[test]
fn injecting_huge_drop_counts_does_not_overflow() {
    let sim = Simulator::new(controller()).unwrap();
    sim.inject(ciplink_sim::Fault::DropReplies(u32::MAX));
    sim.inject(ciplink_sim::Fault::DropReplies(u32::MAX));
    sim.clear_faults();
    let mut client = Client::connected(&sim, 500);
    assert_eq!(general(&client.unit(&read("dint", 1))), 0);
}

#[test]
fn too_many_programs_is_a_config_error() {
    // program references count up from 0x5AD0 in 16 bits: 0xA530 programs would overflow
    let config = LogixConfig {
        programs: (0..0xA530)
            .map(|i| ciplink_sim::ProgramConfig::new(&format!("P{i}")))
            .collect(),
        ..LogixConfig::default()
    };
    assert!(Simulator::new(config).is_err());
}
