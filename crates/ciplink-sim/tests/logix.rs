//! The Logix controller's services, checked with ciplink's request builders and reply parsers.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::epath::wrap_unconnected_send;
use ciplink::packets::{
    ReplyKind, TAG_TABLE_VERSION_SERVICE, generic_message, list_identity_request,
    parse_tag_table_version, register_session_request, send_rr_data_request,
};
use ciplink::transport::Transport;
use ciplink_sim::{
    IdentityConfig, LogixConfig, MemberConfig, ModuleConfig, Simulator, TagConfig, TypeConfig,
};
use common::{Client, controller, data, message, path, read, write};
use serde_json::json;

fn sim() -> Simulator {
    Simulator::new(controller()).unwrap()
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// The general status and extended status words of a reply.
fn status(reply: &ciplink::packets::Reply) -> (u8, Vec<u16>) {
    let raw = reply.raw.as_ref().unwrap();
    let at = if reply.kind == ReplyKind::SendRRData {
        42
    } else {
        48
    };
    let words = usize::from(raw[at + 1]);
    (
        raw[at],
        (0..words).map(|i| u16_at(raw, at + 2 + 2 * i)).collect(),
    )
}

#[test]
fn list_identity_and_session_registration() {
    let sim = sim();
    let mut client = Client::new(&sim);
    let reply = client.exchange(
        &list_identity_request(&client.encap),
        ReplyKind::ListIdentity,
    );
    let identity = reply.identity.unwrap();
    assert_eq!(identity.identity.product_name, "1756-SIM/A");
    assert_eq!(
        (
            identity.identity.revision.major,
            identity.identity.revision.minor
        ),
        (33, 11)
    );
    assert_eq!(identity.identity.serial, "c0ffee01");
    assert_eq!(identity.identity.status, [0x60, 0x30]); // REMOTE RUN
    assert_eq!(
        (identity.ip_address.as_str(), identity.state),
        ("127.0.0.1", 3)
    );

    // SendRRData before RegisterSession, and a protocol version other than 1
    let mut other = sim.transport();
    let encap = ciplink::packets::Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    };
    other
        .send(&send_rr_data_request(&encap, &[0x01, 0x02, 0x20, 0x01, 0x24, 0x01]).unwrap())
        .unwrap();
    assert_eq!(
        ciplink::packets::Reply::parse(ReplyKind::SendRRData, &other.receive().unwrap())
            .command_status,
        Some(0x64)
    );
    other.send(&register_session_request(&encap, 2, 0)).unwrap();
    assert_eq!(
        ciplink::packets::Reply::parse(ReplyKind::RegisterSession, &other.receive().unwrap())
            .command_status,
        Some(0x69)
    );
}

#[test]
fn identity_through_unconnected_send_names_the_slot() {
    let config = LogixConfig {
        modules: vec![ModuleConfig {
            slot: 3,
            identity: IdentityConfig {
                product_name: "1756-EN2T/D".into(),
                ..IdentityConfig::default()
            },
        }],
        ..controller()
    };
    let sim = Simulator::new(config).unwrap();
    let mut client = Client::new(&sim);
    let identity = generic_message(0x01, 1u32.into(), 1u32.into(), None, &[]).unwrap();
    let routed = |slot: u8| wrap_unconnected_send(&identity, &[0x01, 0x00, 0x01, slot]);
    let name = |reply: &ciplink::packets::Reply| {
        let data = data(reply);
        String::from_utf8(data[15..15 + usize::from(data[14])].to_vec()).unwrap()
    };
    assert_eq!(name(&client.rr(&identity)), "1756-SIM/A");
    assert_eq!(name(&client.rr(&routed(0))), "1756-SIM/A");
    assert_eq!(name(&client.rr(&routed(3))), "1756-EN2T/D");
    let reply = client.rr(&routed(5));
    assert_eq!(
        (reply.service, status(&reply)),
        (Some(0x52), (0x01, vec![0x0312]))
    );
}

#[test]
fn forward_open_large_standard_too_big_duplicate_and_close() {
    let sim = sim();
    let mut client = Client::new(&sim);
    assert_eq!(
        status(&client.forward_open(5000, true)),
        (0x01, vec![0x0109, 4002])
    );
    let reply = client.forward_open(4000, true);
    assert!(reply.is_valid());
    let fo = data(&reply);
    assert_eq!(
        (fo.len(), &fo[4..8], &fo[8..10]),
        (26, &[1, 2, 3, 4][..], &[5, 6][..])
    ); // T->O id and serial echoed
    assert_eq!(
        status(&client.forward_open(4000, true)),
        (0x01, vec![0x0100])
    ); // same connection serial
    assert!(client.unit(&read("dint", 1)).is_valid());

    let close = ciplink::packets::forward_close_data(
        &[5, 6],
        &[7, 8],
        &[9, 10, 11, 12],
        &[ciplink::epath::Segment::port("bp", 0)],
    )
    .unwrap();
    assert!(
        client
            .rr(&generic_message(0x4E, 6u32.into(), 1u32.into(), None, &close).unwrap())
            .is_valid()
    );
    assert_eq!(status(&client.unit(&read("dint", 1))), (0x01, vec![0x0107]));

    let no_large = Simulator::new(LogixConfig {
        large_forward_open: false,
        ..controller()
    })
    .unwrap();
    let mut client = Client::new(&no_large);
    assert_eq!(status(&client.forward_open(4000, true)), (0x08, vec![]));
    assert!(client.forward_open(500, false).is_valid());
}

#[test]
fn connected_replies_echo_the_sequence_count() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    client.sequence = 0x1233;
    let reply = client.unit(&read("dint", 1));
    let raw = reply.raw.unwrap();
    assert_eq!(u16_at(&raw, 44), 0x1234);
    assert_eq!(&raw[46..], &[0xCC, 0, 0, 0, 0xC4, 0, 0xD2, 0x04, 0, 0]);
}

/// (instance, name, symbol type, dims, external access)
type Symbol = (u32, String, u16, [u32; 3], u8);

/// The symbols of a scope, paged, and the status of each page.
fn symbols(client: &mut Client, program: Option<&str>) -> (Vec<Symbol>, Vec<u8>) {
    let mut out = Vec::new();
    let mut statuses = Vec::new();
    let mut start = 0u32;
    loop {
        let mut p = Vec::new();
        if let Some(program) = program {
            let name = format!("Program:{program}");
            p.extend([0x91, name.len() as u8]);
            p.extend(name.as_bytes());
            if name.len() % 2 == 1 {
                p.push(0);
            }
        }
        p.extend([0x20, 0x6B, 0x25, 0x00]);
        p.extend((start as u16).to_le_bytes());
        let mut m = vec![0x55, (p.len() / 2) as u8];
        m.extend(p);
        m.extend([7, 0, 1, 0, 2, 0, 3, 0, 5, 0, 6, 0, 8, 0, 10, 0]);
        let reply = client.unit(&m);
        let (general, _) = status(&reply);
        statuses.push(general);
        let d = data(&reply);
        let mut at = 0;
        let mut last = 0;
        while at < d.len() {
            let instance = u32_at(&d, at);
            let size = usize::from(u16_at(&d, at + 4));
            let name = String::from_utf8(d[at + 6..at + 6 + size].to_vec()).unwrap();
            at += 6 + size;
            let symbol_type = u16_at(&d, at);
            let dims = [
                u32_at(&d, at + 14),
                u32_at(&d, at + 18),
                u32_at(&d, at + 22),
            ];
            out.push((instance, name, symbol_type, dims, d[at + 26]));
            at += 27;
            last = instance;
        }
        if general != 0x06 {
            return (out, statuses);
        }
        start = last + 1;
    }
}

#[test]
fn symbol_lists_page_to_the_connection_size() {
    let sim = sim();
    let mut client = Client::connected(&sim, 120);
    let (list, statuses) = symbols(&mut client, None);
    assert!(statuses.len() > 3 && statuses[..statuses.len() - 1].iter().all(|&s| s == 0x06));
    assert_eq!(statuses.last(), Some(&0));
    let names: Vec<_> = list.iter().map(|s| s.1.as_str()).collect();
    assert_eq!(
        names,
        [
            "Program:Main",
            "dint",
            "int",
            "ary",
            "grid",
            "bits",
            "pt",
            "pts",
            "s",
            "tmr",
            "valve",
            "ro",
            "far"
        ]
    );
    let find = |name: &str| list.iter().find(|s| s.1 == name).unwrap().clone();
    assert_eq!(find("Program:Main").2, 0x1068);
    assert_eq!(find("ary").2, 0x20C4);
    assert_eq!((find("grid").2, find("grid").3), (0x40C3, [2, 3, 0]));
    // BOOL[40], held in 2 DWORDs: a controller lists the words (a GuardLogix lists a BOOL[64] as [2])
    assert_eq!((find("bits").2, find("bits").3), (0x20D3, [2, 0, 0]));
    assert_eq!(find("pt").2 & 0x8000, 0x8000);
    assert_eq!((find("ro").4, find("far").0), (2, 70000));

    let (program, _) = symbols(&mut client, Some("Main"));
    assert_eq!(
        program.iter().map(|s| s.1.as_str()).collect::<Vec<_>>(),
        ["Routine:MainRoutine", "local"]
    );
}

#[test]
fn templates_answer_their_makeup_and_page_their_data() {
    let sim = sim();
    let mut client = Client::connected(&sim, 60);
    let (list, _) = symbols(&mut Client::connected(&sim, 4000), None);
    let id = u32::from(list.iter().find(|s| s.1 == "pt").unwrap().2 & 0x0FFF);
    let makeup = client.unit(
        &generic_message(
            0x03,
            0x6Cu32.into(),
            id.into(),
            None,
            &[4, 0, 4, 0, 5, 0, 2, 0, 1, 0],
        )
        .unwrap(),
    );
    let d = data(&makeup);
    assert_eq!(u16_at(&d, 0), 4);
    let ods = u32_at(&d, 6);
    assert_eq!((u16_at(&d, 2), u32_at(&d, 14), u16_at(&d, 22)), (4, 16, 4)); // structure size 16, 4 members
    let mut template = Vec::new();
    loop {
        let wanted = (ods * 4 - 21) as usize - template.len();
        let mut request = (template.len() as u32).to_le_bytes().to_vec();
        request.extend((wanted as u16).to_le_bytes());
        let reply =
            client.unit(&generic_message(0x4C, 0x6Cu32.into(), id.into(), None, &request).unwrap());
        let (general, _) = status(&reply);
        template.extend(data(&reply));
        if general == 0 {
            break;
        }
        assert_eq!(general, 0x06);
    }
    assert!((ods * 4 - 23) as usize - template.len() < 4); // the definition size is in 32-bit words
    let names: Vec<_> = template[32..]
        .split(|&b| b == 0)
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect();
    assert_eq!(&names[..5], ["Point;n", "ZZZZZZZZZZPoint0", "on", "x", "r"]);
    // member info: the BOOL is bit 0 of the hidden SINT at 0, the REAL array of 2 at 8
    assert_eq!(&template[8..16], &[0, 0, 0xC1, 0, 0, 0, 0, 0]);
    assert_eq!(&template[24..32], &[2, 0, 0xCA, 0, 8, 0, 0, 0]);
}

#[test]
fn reads_by_name_and_instance_id() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let ids = |name: &str| sim.with_logix(|plc| plc.instance_id(None, name)).flatten();
    assert_eq!(
        data(&client.unit(&read("dint", 1))),
        [0xC4, 0, 0xD2, 0x04, 0, 0]
    );
    assert_eq!(
        data(&client.unit(&message(0x4C, &path("dint", ids("dint")), &[1, 0]))),
        [0xC4, 0, 0xD2, 0x04, 0, 0]
    );
    assert_eq!(
        data(&client.unit(&message(0x4C, &path("far", Some(70000)), &[1, 0]))),
        [0xC4, 0, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(
        data(&client.unit(&read("ary[5]", 3))),
        [0xC4, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0]
    );
    assert_eq!(
        data(&client.unit(&read("grid[1,1]", 2))),
        [0xC3, 0, 5, 0, 6, 0]
    );
    assert_eq!(
        data(&client.unit(&read("bits[0]", 2))),
        [0xD3, 0, 5, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(data(&client.unit(&read("pt.x", 1))), [0xC4, 0, 7, 0, 0, 0]);
    assert_eq!(data(&client.unit(&read("pt.on", 1))), [0xC1, 0, 1]);
    assert_eq!(data(&client.unit(&read("tmr.DN", 1))), [0xC1, 0, 1]);
    let pt = data(&client.unit(&read("pt", 1)));
    assert_eq!((&pt[..2], pt.len()), (&[0xA0, 0x02][..], 4 + 16));
    assert_eq!(
        &pt[4..],
        &[1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0x3F, 0, 0, 0xC0, 0x3F]
    );
    assert_eq!(
        data(&client.unit(&read("s", 1)))[4..11],
        [3, 0, 0, 0, b'a', b'b', b'c']
    );
    let local = sim
        .with_logix(|plc| plc.instance_id(Some("Main"), "local"))
        .flatten();
    assert_eq!(
        data(&client.unit(&message(0x4C, &path("Program:Main.local", local), &[1, 0]))),
        [0xC4, 0, 42, 0, 0, 0]
    );
    assert_eq!(
        data(&client.unit(&read("Program:Main.local", 1))),
        [0xC4, 0, 42, 0, 0, 0]
    );
    // unconnected reads work too (UCMM)
    assert_eq!(data(&client.rr(&read("int", 1))), [0xC3, 0, 0xFE, 0xFF]);
}

#[test]
fn read_errors_have_logix_statuses() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let mut check =
        |m: Vec<u8>, expected: (u8, Vec<u16>)| assert_eq!(status(&client.unit(&m)), expected);
    check(read("nope", 1), (0x04, vec![]));
    check(read("pt.nope", 1), (0x04, vec![]));
    check(read("pt.ZZZZZZZZZZPoint0", 1), (0x04, vec![])); // hidden members are not addressable
    check(read("dint.x", 1), (0x04, vec![]));
    check(read("ary[100]", 1), (0x05, vec![]));
    check(read("grid[1]", 1), (0x04, vec![])); // an index per dimension
    check(read("ary[98]", 3), (0xFF, vec![0x2105]));
    check(read("dint", 2), (0xFF, vec![0x2105]));
    check(read("Program:Nope.local", 1), (0x04, vec![]));
    check(
        message(0x4C, &path("x", Some(999)), &[1, 0]),
        (0x05, vec![]),
    );
    check(message(0x4C, &path("dint", None), &[]), (0x13, vec![]));
}

#[test]
fn reads_too_big_for_the_connection_are_partial_and_fragmented_reads_page() {
    let sim = sim();
    let mut client = Client::connected(&sim, 200);
    let reply = client.unit(&read("ary", 100));
    assert_eq!(status(&reply).0, 0x06);
    assert!(reply.raw.as_ref().unwrap().len() - 44 <= 200);
    let mut values: Vec<u8> = Vec::new();
    loop {
        let reply = client.unit(&message(
            0x52,
            &path("ary", None),
            &[
                &100u16.to_le_bytes()[..],
                &(values.len() as u32).to_le_bytes(),
            ]
            .concat(),
        ));
        let (general, _) = status(&reply);
        let d = data(&reply);
        assert_eq!(&d[..2], &[0xC4, 0]);
        values.extend(&d[2..]);
        if general == 0 {
            break;
        }
        assert_eq!(general, 0x06);
    }
    let expected: Vec<u8> = (0..100u32).flat_map(|v| v.to_le_bytes()).collect();
    assert_eq!(values, expected);
    let past_end = message(
        0x52,
        &path("ary", None),
        &[&100u16.to_le_bytes()[..], &400u32.to_le_bytes()].concat(),
    );
    assert_eq!(status(&client.unit(&past_end)), (0xFF, vec![0x2105]));
}

#[test]
fn writes_check_type_size_and_access() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let mut status_of = |m: Vec<u8>| status(&client.unit(&m));
    assert_eq!(
        status_of(write("dint", &[0xC4, 0], 1, &(-5i32).to_le_bytes())),
        (0, vec![])
    );
    assert_eq!(
        status_of(write("dint", &[0xC3, 0], 1, &[1, 0])),
        (0xFF, vec![0x2107])
    );
    assert_eq!(
        status_of(write("dint", &[0xC4, 0], 1, &[1, 0])),
        (0x13, vec![])
    );
    assert_eq!(
        status_of(write("dint", &[0xC4, 0], 1, &[1, 0, 0, 0, 0])),
        (0x15, vec![])
    );
    assert_eq!(
        status_of(write("ary[99]", &[0xC4, 0], 2, &[0; 8])),
        (0xFF, vec![0x2105])
    );
    assert_eq!(
        status_of(write("ary[1]", &[0xC4, 0], 2, &[9, 0, 0, 0, 8, 0, 0, 0])),
        (0, vec![])
    );
    assert_eq!(status_of(write("pt.on", &[0xC1, 0], 1, &[0])), (0, vec![]));
    assert_eq!(status_of(write("tmr.EN", &[0xC1, 0], 1, &[1])), (0, vec![]));
    assert_eq!(
        status_of(write("ro", &[0xC4, 0], 1, &[1, 0, 0, 0])),
        (0x0F, vec![0x2100])
    );
    assert_eq!(sim.value("dint").unwrap(), json!(-5));
    assert_eq!(sim.value("ary[0]").unwrap(), json!(0));
    assert_eq!(sim.value("ary[2]").unwrap(), json!(8));
    assert_eq!(sim.value("pt.on").unwrap(), json!(false));
    assert_eq!(
        sim.value("tmr").unwrap(),
        json!({"PRE": 10, "ACC": 0, "EN": true, "TT": false, "DN": true})
    );
    assert_eq!(sim.value("ro").unwrap(), json!(9));

    // a structure: its handle must match
    let pt = data(&client.unit(&read("pt", 1)));
    let handle = &pt[..4];
    let mut value = vec![0u8; 16];
    value[4] = 99;
    assert_eq!(
        status(&client.unit(&write("pts[2]", handle, 1, &value))),
        (0, vec![])
    );
    assert_eq!(
        status(&client.unit(&write(
            "pts[2]",
            &[0xA0, 0x02, handle[2] ^ 1, handle[3]],
            1,
            &value
        ))),
        (0xFF, vec![0x2107])
    );
    assert_eq!(sim.value("pts[2].x").unwrap(), json!(99));

    // a fragmented write in two pieces
    let bytes: Vec<u8> = (0..100i32).flat_map(|v| (-v).to_le_bytes()).collect();
    for (offset, chunk) in [(0usize, &bytes[..240]), (240, &bytes[240..])] {
        let request = [
            &[0xC4, 0][..],
            &100u16.to_le_bytes(),
            &(offset as u32).to_le_bytes(),
            chunk,
        ]
        .concat();
        assert_eq!(
            status(&client.unit(&message(0x53, &path("ary", None), &request))),
            (0, vec![])
        );
    }
    assert_eq!(sim.value("ary[99]").unwrap(), json!(-99));
    let too_far = [
        &[0xC4, 0][..],
        &100u16.to_le_bytes(),
        &396u32.to_le_bytes(),
        &[0u8; 8],
    ]
    .concat();
    assert_eq!(
        status(&client.unit(&message(0x53, &path("ary", None), &too_far))),
        (0x15, vec![])
    );
}

#[test]
fn read_modify_write_applies_or_then_and_masks() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let rmw = |tag: &str, size: u16, or: &[u8], and: &[u8]| {
        message(
            0x4E,
            &path(tag, None),
            &[&size.to_le_bytes()[..], or, and].concat(),
        )
    };
    // dint 1234 = 0x4D2: set bit 0, clear bit 1
    assert_eq!(
        status(&client.unit(&rmw("dint", 4, &[1, 0, 0, 0], &[0xFD, 0xFF, 0xFF, 0xFF]))),
        (0, vec![])
    );
    assert_eq!(sim.value("dint").unwrap(), json!(1233));
    assert_eq!(
        status(&client.unit(&rmw("bits[1]", 4, &[0, 0, 0, 0x80], &[0xFF; 4]))),
        (0, vec![])
    );
    assert_eq!(sim.value("bits").unwrap()[63], json!(true));
    assert_eq!(
        status(&client.unit(&rmw("dint", 2, &[1, 0], &[0xFF, 0xFF]))),
        (0xFF, vec![0x2107])
    );
    assert_eq!(
        status(&client.unit(&rmw("pt.r[0]", 4, &[1, 0, 0, 0], &[0xFF; 4]))),
        (0xFF, vec![0x2107])
    );
    assert_eq!(
        status(&client.unit(&rmw("dint", 4, &[1, 0, 0, 0], &[0xFF; 3]))),
        (0x13, vec![])
    );
}

#[test]
fn multi_service_packets_answer_each_service_within_the_connection_size() {
    let sim = sim();
    let mut client = Client::connected(&sim, 300);
    let reply = client.multi(&[
        read("dint", 1),
        read("nope", 1),
        read("int", 1),
        read("ary", 100),
        read("dint", 1),
    ]);
    assert_eq!(reply.reply.service_status, Some(0x1E));
    let statuses: Vec<_> = reply
        .replies
        .iter()
        .map(|r| r.service_status.unwrap())
        .collect();
    // the partial read leaves room for the reply header of the read after it, which gets no data
    assert_eq!(statuses, [0, 0x04, 0, 0x06, 0x06]);
    assert_eq!(data(&reply.replies[4]), [0xC4, 0]);
    assert!(reply.reply.raw.as_ref().unwrap().len() - 44 <= 300);
    assert_eq!(data(&reply.replies[2]), [0xC3, 0, 0xFE, 0xFF]);

    let ok = client.multi(&[read("dint", 1), TAG_TABLE_VERSION_SERVICE.to_vec()]);
    assert_eq!((ok.reply.service_status, ok.replies.len()), (Some(0), 2));

    let micro =
        Simulator::new(LogixConfig::micro800().with_tag(TagConfig::new("d", "DINT"))).unwrap();
    let mut client = Client::connected(&micro, 500);
    assert_eq!(
        client
            .multi(&[read("d", 1), read("d", 1)])
            .reply
            .service_status,
        Some(0x08)
    );
    assert_eq!(
        status(&client.unit(&message(0x4C, &path("d", Some(1)), &[1, 0]))),
        (0x05, vec![])
    ); // no instance IDs
    assert!(client.unit(&read("d", 1)).is_valid());
}

#[test]
fn aoi_locals_and_whole_aois_with_locals_are_refused() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    assert_eq!(
        status(&client.unit(&read("valve.Count", 1))),
        (0x04, vec![])
    );
    assert_eq!(
        status(&client.unit(&read("valve", 1))),
        (0x0F, vec![0x2100])
    );
    assert_eq!(
        status(&client.unit(&write("valve.Count", &[0xC4, 0], 1, &[0; 4]))),
        (0x04, vec![])
    );
    assert_eq!(
        data(&client.unit(&read("valve.Mode", 1))),
        [0xC4, 0, 2, 0, 0, 0]
    );
    assert_eq!(data(&client.unit(&read("valve.EnableIn", 1))), [0xC1, 0, 0]);

    let open = Simulator::new(LogixConfig {
        aoi_locals_refused: false,
        ..controller()
    })
    .unwrap();
    let mut client = Client::connected(&open, 4000);
    assert_eq!(
        data(&client.unit(&read("valve.Count", 1))),
        [0xC4, 0, 5, 0, 0, 0]
    );
    assert!(client.unit(&read("valve", 1)).is_valid());
}

#[test]
fn tag_table_version_counts_online_edits_and_downloads() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let version = |client: &mut Client| {
        parse_tag_table_version(&mut client.unit(&TAG_TABLE_VERSION_SERVICE)).unwrap()
    };
    let first = version(&mut client);
    assert_eq!(first.0, 1);
    let id = sim
        .with_logix(|plc| plc.add_tag(None, &TagConfig::new("added", "REAL")))
        .unwrap()
        .unwrap();
    assert_eq!(version(&mut client).0, 2);
    let old = sim
        .with_logix(|plc| plc.instance_id(None, "dint"))
        .flatten()
        .unwrap();
    sim.with_logix(|plc| plc.remove_tag(None, "dint"))
        .unwrap()
        .unwrap();
    let reused = sim
        .with_logix(|plc| plc.add_tag(None, &TagConfig::new("other", "INT").value(json!(5))))
        .unwrap()
        .unwrap();
    assert_eq!((reused, version(&mut client).0), (old, 4));
    assert_eq!(
        data(&client.unit(&message(0x4C, &path("x", Some(old)), &[1, 0]))),
        [0xC3, 0, 5, 0]
    );
    assert_ne!(id, old);

    sim.with_logix(|plc| plc.add_type(&TypeConfig::udt("New", [MemberConfig::new("a", "LINT")])))
        .unwrap()
        .unwrap();
    sim.with_logix(|plc| {
        plc.add_tag(
            Some("Main"),
            &TagConfig::new("n", "New").value(json!({"a": 3})),
        )
    })
    .unwrap()
    .unwrap();
    assert_eq!(sim.value("Program:Main.n.a").unwrap(), json!(3));

    sim.with_logix(|plc| plc.download(&controller()))
        .unwrap()
        .unwrap();
    let after = version(&mut client);
    assert_eq!(after.0, 1);
    assert_ne!((after.2, after.4), (first.2, first.4));
    assert!(sim.value("added").is_err());

    let none = Simulator::new(LogixConfig {
        tag_table_version: false,
        ..controller()
    })
    .unwrap();
    let mut client = Client::connected(&none, 4000);
    assert_eq!(
        status(&client.unit(&TAG_TABLE_VERSION_SERVICE)),
        (0x05, vec![])
    );
}

#[test]
fn wall_clock_and_program_name() {
    let sim = Simulator::new(LogixConfig {
        clock_us: Some(1_000_000_000_000),
        program_name: "Line3".into(),
        ..controller()
    })
    .unwrap();
    let mut client = Client::connected(&sim, 4000);
    let get = generic_message(0x03, 0x8Bu32.into(), 1u32.into(), None, &[1, 0, 6, 0]).unwrap();
    let now = |client: &mut Client| {
        let d = data(&client.unit(&get));
        assert_eq!(&d[..6], &[1, 0, 6, 0, 0, 0]);
        u64::from_le_bytes(d[6..14].try_into().unwrap())
    };
    assert!((1_000_000_000_000..1_000_010_000_000).contains(&now(&mut client)));
    let set = [&[1, 0, 6, 0][..], &1_700_000_000_000_000u64.to_le_bytes()].concat();
    let reply =
        client.unit(&generic_message(0x04, 0x8Bu32.into(), 1u32.into(), None, &set).unwrap());
    assert_eq!(data(&reply), [1, 0, 6, 0, 0, 0]);
    assert!((1_700_000_000_000_000..1_700_000_010_000_000).contains(&now(&mut client)));
    let name =
        data(&client.unit(&generic_message(0x01, 0x64u32.into(), 1u32.into(), None, &[]).unwrap()));
    assert_eq!(name, [5, 0, b'L', b'i', b'n', b'e', b'3']);
}

#[test]
fn example_configurations_load() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/sim/");
    let sim = Simulator::from_file(format!("{dir}example_controller.json")).unwrap();
    assert_eq!(sim.value("nested.tmr.ACC").unwrap(), json!(250));
    assert_eq!(
        sim.value("Program:MainProgram.p_str").unwrap(),
        json!("program scope")
    );
    assert_eq!(sim.value("Local:1:I.Ch1Data").unwrap(), json!(-1.25));
    let slc = Simulator::from_file(format!("{dir}example_slc.json")).unwrap();
    assert_eq!(slc.value("ST9:0").unwrap(), json!("Hello SLC"));
    let micro = Simulator::from_file(format!("{dir}example_micro800.json")).unwrap();
    assert_eq!(micro.value("m_ary").unwrap(), json!([1, 2, 3, 4, 5]));
}

#[test]
fn configuration_errors_are_reported() {
    let bad = [
        r#"{"tags": [{"name": "a", "type": "NOPE"}]}"#,
        r#"{"tags": [{"name": "a", "type": "DINT"}, {"name": "A", "type": "INT"}]}"#,
        r#"{"tags": [{"name": "a", "type": "DINT", "instance_id": 5}, {"name": "b", "type": "INT", "instance_id": 5}]}"#,
        r#"{"identity": {"keyswitch": "SIDEWAYS"}}"#,
        r#"{"identity": {"serial": "xyz"}}"#,
        r#"{"types": [{"name": "U", "members": [{"name": "x", "type": "DINT", "local": true}]}]}"#,
        r#"{"tags": [{"name": "b", "type": "BOOL", "dims": [32, 2]}]}"#,
    ];
    for json in bad {
        assert!(Simulator::from_json(json).is_err(), "{json}");
    }
}

#[test]
fn requests_bigger_than_the_connection_are_refused() {
    let sim = sim();
    let mut client = Client::connected(&sim, 100);
    let fits = write("ary", &[0xC4, 0], 20, &[0; 80]); // 2 + 90 bytes with the sequence count
    let too_big = write("ary", &[0xC4, 0], 23, &[0; 92]);
    assert_eq!(status(&client.unit(&fits)), (0, vec![]));
    assert_eq!(status(&client.unit(&too_big)), (0x15, vec![]));
}

#[test]
fn member_external_access_applies_along_the_path() {
    let config = controller()
        .with_type(TypeConfig::udt(
            "Guarded",
            [
                MemberConfig::new("open", "DINT"),
                MemberConfig::new("fixed", "DINT").access("Read Only"),
                MemberConfig::new("secret", "DINT").access("None"),
            ],
        ))
        .with_tag(TagConfig::new("g", "Guarded"));
    let sim = Simulator::new(config).unwrap();
    let mut client = Client::connected(&sim, 4000);
    let denied = (0x0F, vec![0x2100]);
    assert_eq!(
        status(&client.unit(&write("g.open", &[0xC4, 0], 1, &[1, 0, 0, 0]))),
        (0, vec![])
    );
    assert_eq!(status(&client.unit(&read("g.fixed", 1))), (0, vec![]));
    assert_eq!(
        status(&client.unit(&write("g.fixed", &[0xC4, 0], 1, &[1, 0, 0, 0]))),
        denied
    );
    assert_eq!(status(&client.unit(&read("g.secret", 1))), denied);
    // an AOI's EnableIn and EnableOut are Read Only
    assert_eq!(
        status(&client.unit(&write("valve.EnableIn", &[0xC1, 0], 1, &[1]))),
        denied
    );
    assert_eq!(
        status(&client.unit(&write("valve.Cmd", &[0xC1, 0], 1, &[1]))),
        (0, vec![])
    );
}

#[test]
fn raw_values_are_the_controller_memory_image() {
    // Point: host SINT (on), DINT x at 4, REAL r[2] at 8, as Studio 5000 exports a tag's <Data>
    let raw = "01 00 00 00 2A 00 00 00 00 00 80 3F 00 00 00 40";
    let config = controller().with_tag(TagConfig {
        raw: Some(raw.into()),
        ..TagConfig::new("img", "Point")
    });
    let sim = Simulator::new(config).unwrap();
    assert_eq!(
        sim.value("img").unwrap(),
        json!({"on": true, "x": 42, "r": [1.0, 2.0]})
    );
    let short = controller().with_tag(TagConfig {
        raw: Some("01 00".into()),
        ..TagConfig::new("img", "Point")
    });
    assert!(
        Simulator::new(short)
            .unwrap_err()
            .0
            .contains("raw has 2 bytes")
    );
}

#[test]
fn nested_multi_service_packets_are_refused() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let inner = ciplink::packets::multi_service_message(&[read("dint", 1)]).unwrap();
    let reply = client.multi(&[read("dint", 1), inner]);
    let statuses: Vec<_> = reply
        .replies
        .iter()
        .map(|r| r.service_status.unwrap())
        .collect();
    assert_eq!(statuses, [0, 0x08]);
}

#[test]
fn a_repeated_sequence_count_gets_the_last_reply_without_executing_again() {
    let sim = sim();
    let mut client = Client::connected(&sim, 4000);
    let first = client.unit(&write("dint", &[0xC4, 0], 1, &5i32.to_le_bytes()));
    assert!(first.is_valid());
    sim.set_value("dint", &json!(1)).unwrap();
    // the same sequence count again: a duplicate, answered with the last reply and not written
    client.sequence -= 1;
    let again = client.unit(&write("dint", &[0xC4, 0], 1, &6i32.to_le_bytes()));
    assert_eq!(
        again.raw.as_ref().unwrap()[44..],
        first.raw.as_ref().unwrap()[44..]
    );
    assert_eq!(sim.value("dint").unwrap(), json!(1));
    // the next sequence count is executed
    assert!(
        client
            .unit(&write("dint", &[0xC4, 0], 1, &7i32.to_le_bytes()))
            .is_valid()
    );
    assert_eq!(sim.value("dint").unwrap(), json!(7));
    // a new connection starts with no last reply
    let mut other = Client::connected(&sim, 4000);
    other.sequence = client.sequence - 1;
    assert!(
        other
            .unit(&write("dint", &[0xC4, 0], 1, &8i32.to_le_bytes()))
            .is_valid()
    );
    assert_eq!(sim.value("dint").unwrap(), json!(8));
}
