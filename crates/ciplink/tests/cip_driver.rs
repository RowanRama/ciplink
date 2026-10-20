//! CipDriver parity with the Python CIPDriver (fixtures from tools/fixtures/gen_cip_driver.py), and the
//! scenarios of tools/reference/tests/offline/test_cip_driver.py, test_transport.py, test_transport_lifecycle.py and
//! test_socket_.py, run against the scripted fake transport.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use ciplink::cip::{CipConnection, CipDriver, CipOptions, GenericMessage, RoutePath};
use ciplink::epath::LogicalValue;
use ciplink::{Error, ErrorKind, Value};
use common::fake::{self, Fake};
use common::{assert_value, class, hex, to_hex};
use serde_json::{Value as Json, json};

const CID: [u8; 4] = [0xDD, 0xCC, 0xBB, 0xAA];
/// the replies of test_cip_driver.py
const MODULE_INFO_REPLY: &str = "6f0043000213020b000000005f7079636f6d6d5f00000000000000000a00020000000000b20033008100000001000e005900141360309ba00fc020313736392d4c3233452d5142464331204c4f47495835333233452d5142464331";
const FORWARD_CLOSE_REPLY: &str = "6f001e000216020b000000005f7079636f6d6d5f00000000000000000a00020000000000b2000e00ce00000027040910d69c063d0000";

enum Out {
    Bool(bool),
    Unit,
    State(Json),
    Tag(Json),
    Value(Value),
}

fn driver(path: &str, fake: &Fake) -> CipDriver {
    CipDriver::with_connector(path, CipOptions::default(), fake.connector()).unwrap()
}

fn state(d: &CipDriver) -> ciplink::Result<Out> {
    let c = d.lock();
    Ok(Out::State(json!({
        "connected": c.connected(),
        "target_connected": c.target_connected(),
        "session": c.session(),
        "connection_size": c.connection_size(),
        "extended": c.extended_forward_open(),
    })))
}

fn generic(d: &CipDriver, msg: GenericMessage) -> ciplink::Result<Out> {
    let reply = d.generic_message(&msg)?;
    let t = reply.tag;
    Ok(Out::Tag(json!({
        "tag": t.tag,
        "value": match t.value {
            Some(Value::Bytes(b)) => json!({"bytes": to_hex(&b)}),
            None => Json::Null,
            Some(v) => panic!("generic value {v:?}"),
        },
        "error": t.error.as_ref().map(|e| e.message.clone()),
        "kind": t.error.as_ref().map(|e| e.kind.as_str()),
    })))
}

fn msg(service: u8, class: u32, instance: u32) -> GenericMessage {
    GenericMessage {
        service,
        class_code: class.into(),
        instance: instance.into(),
        ..GenericMessage::default()
    }
}

fn unconnected(name: &str, unconnected_send: bool, route_path: RoutePath) -> GenericMessage {
    GenericMessage {
        name: name.into(),
        connected: false,
        unconnected_send,
        route_path,
        ..msg(0x01, 1, 1)
    }
}

type Call = Box<dyn Fn(&CipDriver) -> ciplink::Result<Out>>;

fn open() -> Call {
    Box::new(|d| d.open().map(Out::Bool))
}
fn close() -> Call {
    Box::new(|d| d.close().map(|_| Out::Unit))
}
fn st() -> Call {
    Box::new(state)
}
fn gm(m: GenericMessage) -> Call {
    Box::new(move |d| generic(d, m.clone()))
}
fn module(slot: i64) -> Call {
    Box::new(move |d| d.get_module_info(slot).map(|m| Out::Value(m.to_value())))
}

/// the calls of each fixture scenario, as gen_cip_driver.py makes them
fn calls(name: &str) -> Vec<Call> {
    match name {
        "open_close" => vec![open(), open(), st(), close(), st()],
        "open_no_reply" | "open_zero_session" => vec![open(), st()],
        "connected_generic" => vec![
            open(),
            gm(GenericMessage {
                name: "g1".into(),
                attribute: Some(LogicalValue::Int(7)),
                ..msg(0x0E, 1, 1)
            }),
            st(),
            gm(GenericMessage {
                service: 0x0E,
                class_code: LogicalValue::Raw(vec![0x02]),
                instance: LogicalValue::Raw(vec![0x01, 0x00]),
                attribute: Some(LogicalValue::Raw(vec![])),
                request_data: vec![0x05],
                name: "g2".into(),
                ..GenericMessage::default()
            }),
            close(),
            st(),
        ],
        "fo_fallback" | "fo_both_fail" | "fo_standard_only" => {
            vec![open(), gm(msg(0x01, 1, 1)), st()]
        }
        "fo_without_session" => vec![gm(msg(0x01, 1, 1)), st()],
        "unconnected_routes" => vec![
            open(),
            gm(unconnected("plain", false, RoutePath::Current)),
            gm(unconnected("current", true, RoutePath::Current)),
            gm(unconnected("none", true, RoutePath::None)),
            gm(unconnected("text", true, RoutePath::Text("bp/2".into()))),
            gm(unconnected(
                "bytes",
                true,
                RoutePath::Encoded(vec![0x01, 0x00, 0x01, 0x03]),
            )),
            gm(GenericMessage {
                request_data: vec![1, 2, 3],
                ..unconnected("odd", true, RoutePath::Current)
            }),
            gm(unconnected("error", false, RoutePath::Current)),
            gm(unconnected("no reply", false, RoutePath::Current)),
            gm(unconnected("bad route", true, RoutePath::Text("bp".into()))),
            st(),
        ],
        "module_info" => vec![open(), module(3), module(4), module(300), module(1), st()],
        "close_after_failed_forward_close" | "close_drops_on_forward_close_without_reply" => {
            vec![open(), gm(msg(0x01, 1, 1)), close(), st()]
        }
        "list_identity_session" => vec![
            open(),
            Box::new(|d| Ok(Out::Value(d.lock().list_identity()?.unwrap().to_value()))),
            close(),
            st(),
        ],
        "bad_route_path" => vec![open(), gm(msg(0x01, 1, 1)), st(), close()],
        "generic_edge_replies" => {
            let named = |name: &str, m: GenericMessage| GenericMessage {
                name: name.into(),
                ..m
            };
            let rr = |name: &str, service: u8, class: u32| GenericMessage {
                connected: false,
                ..named(name, msg(service, class, 1))
            };
            vec![
                open(),
                gm(named("partial", msg(0x4C, 0x6B, 1))),
                gm(named("partial_not_multi", msg(0x0E, 1, 1))),
                gm(GenericMessage {
                    class_code: LogicalValue::Raw(vec![1, 2, 3]),
                    ..named("bad class", msg(0x0E, 1, 1))
                }),
                gm(GenericMessage {
                    attribute: Some(LogicalValue::Int(0)),
                    ..named("attr0", msg(0x0E, 1, 1))
                }),
                gm(named("encap error", msg(0x0E, 1, 1))),
                gm(named("truncated", msg(0x0E, 1, 1))),
                gm(rr("rr partial", 0x4C, 0x6B)),
                gm(rr("rr ext", 0x0E, 1)),
                close(),
                st(),
            ]
        }
        "unconnected_empty_path" => vec![
            open(),
            gm(unconnected("current", true, RoutePath::Current)),
            module(2),
            gm(unconnected(
                "empty text",
                true,
                RoutePath::Text(String::new()),
            )),
            gm(unconnected("empty list", true, RoutePath::Segments(vec![]))),
            st(),
        ],
        "reopen_keeps_sequence" | "fallback_survives_reconnect" => {
            let mut calls = vec![open(), gm(msg(0x01, 1, 1))];
            if name == "reopen_keeps_sequence" {
                calls.push(st());
            }
            calls.extend([close(), open(), gm(msg(0x01, 1, 1)), st()]);
            calls
        }
        "standard_size_100" | "large_size_65535" => vec![open(), gm(msg(0x01, 1, 1)), st()],
        "fo_rejected_then_retried" => vec![open(), gm(msg(0x01, 1, 1)), gm(msg(0x01, 1, 1)), st()],
        other => panic!("no calls for scenario {other}"),
    }
}

/// zeroes the random connection triad of Forward Open / Forward Close requests
fn mask_triad(frame: &[u8]) -> Vec<u8> {
    let mut f = frame.to_vec();
    if f.first() == Some(&0x6F) && f.len() >= 56 {
        match f[40] {
            0x54 | 0x5B if f.len() >= 64 => {
                f[52..58].fill(0);
                f[60..64].fill(0);
            }
            0x4E => {
                f[48..50].fill(0);
                f[52..56].fill(0);
            }
            _ => {}
        }
    }
    f
}

fn check_result(result: ciplink::Result<Out>, want: &Json, ctx: &str) {
    match (result, want.get("ok"), want.get("err")) {
        (Ok(out), Some(ok), None) => match out {
            Out::Bool(b) => assert_eq!(ok, &json!({"bool": b}), "{ctx}"),
            Out::Unit => assert!(ok.is_null(), "{ctx}: {ok}"),
            Out::State(s) | Out::Tag(s) => assert_eq!(&s, ok, "{ctx}"),
            Out::Value(v) => assert_value(&v, ok, ctx),
        },
        (Err(err), None, Some(class_name)) => {
            assert_eq!(class(&err), class_name.as_str().unwrap(), "{ctx}: {err:?}");
            // DataError messages carry Python reprs of the segments
            if class_name != "DataError" {
                assert_eq!(err.to_string(), want["msg"].as_str().unwrap(), "{ctx}");
            }
        }
        (Ok(_), _, _) => panic!("{ctx}: got Ok, expected {want}"),
        (Err(err), _, _) => panic!("{ctx}: got {err:?}, expected {want}"),
    }
}

#[test]
fn scenarios_send_the_same_frames_and_return_the_same_results_as_python() {
    let fixture = common::load("cip_driver.json");
    for case in common::cases(&fixture, "scenarios") {
        let name = case["name"].as_str().unwrap();
        let fake = Fake::new();
        for r in case["replies"].as_array().unwrap() {
            fake.reply(hex(r.as_str().unwrap()));
        }
        let mut opts = CipOptions::default();
        if let Some(size) = case["options"]["connection_size"].as_u64() {
            opts.connection_size = size as u16;
        }
        let d = CipDriver::with_connector(case["path"].as_str().unwrap(), opts, fake.connector())
            .unwrap();
        let want_results = case["results"].as_array().unwrap();
        let calls = calls(name);
        assert_eq!(calls.len(), want_results.len(), "{name}: call count");
        for (i, (call, want)) in calls.iter().zip(want_results).enumerate() {
            check_result(call(&d), want, &format!("{name}[{i}]"));
        }
        let sent: Vec<String> = fake.sent().iter().map(|f| to_hex(&mask_triad(f))).collect();
        let want: Vec<String> = case["sent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| to_hex(&mask_triad(&hex(f.as_str().unwrap()))))
            .collect();
        assert_eq!(sent, want, "{name}: sent frames");
    }
}

#[test]
fn list_identity_opens_a_session_and_always_closes_like_python() {
    let fixture = common::load("cip_driver.json");
    for case in common::cases(&fixture, "list_identity") {
        let name = case["name"].as_str().unwrap();
        let fake = Fake::new();
        for r in case["replies"].as_array().unwrap() {
            fake.reply(hex(r.as_str().unwrap()));
        }
        let result = CipDriver::list_identity_with(
            "127.0.0.1",
            CipOptions::default(),
            fake.connector(),
            false,
        )
        .unwrap();
        let value = result.map_or_else(|| Value::Struct(Default::default()), |i| i.to_value());
        assert_value(&value, &case["result"], name);
        let sent: Vec<String> = fake.sent().iter().map(|f| to_hex(f)).collect();
        let want: Vec<String> = case["sent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(sent, want, "{name}");
        assert_eq!(fake.closes(), 1, "{name}: transport closed");
    }
}

#[test]
fn list_identity_closes_after_a_comm_error() {
    // test_list_identity_skips_subclass_open_and_always_closes (CommError case)
    let fake = Fake::new();
    fake.reply(fake::register_reply(5))
        .reply_err(Error::comm("timeout"));
    let result =
        CipDriver::list_identity_with("127.0.0.1/1", CipOptions::default(), fake.connector(), true);
    assert_eq!(result, Err(Error::comm("failed to receive reply")));
    assert_eq!(fake.closes(), 1);
    assert_eq!(fake.sent().len(), 2); // no unregister on the dropped connection
}

#[test]
fn discover_broadcasts_the_python_request_and_collects_replies() {
    let fixture = common::load("cip_driver.json");
    let case = &common::cases(&fixture, "discover")[0];
    let request = hex(case["frame"].as_str().unwrap());
    let reply = hex(case["reply"].as_str().unwrap());

    let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
    responder
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let port = responder.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (n, from) = responder.recv_from(&mut buf).unwrap();
        responder.send_to(&reply, from).unwrap();
        responder.send_to(b"junk", from).unwrap();
        responder.send_to(&reply, from).unwrap();
        buf[..n].to_vec()
    });
    let devices = CipDriver::discover_at(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), "127.0.0.1", port);
    assert_eq!(server.join().unwrap(), request);
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].ip_address, "127.0.0.1");
    assert_eq!(
        devices[0].identity.product_name,
        "1769-L23E-QBFC1 LOGIX5323E-QBFC1"
    );
}

#[test]
fn discover_errors_are_logged_not_returned() {
    // _broadcast_discover logs a failure (here binding to an address that is not local, so nothing is sent)
    let devices = CipDriver::discover_at(
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        "127.0.0.1",
        9,
    );
    assert!(devices.is_empty());
}

// ---- test_cip_driver.py ----

#[test]
fn get_module_info_returns_expected_identity() {
    // test_get_module_info_returns_expected_identity_dict
    let fake = Fake::new();
    fake.reply(fake::register_reply(1))
        .reply(hex(MODULE_INFO_REPLY));
    let d = driver("192.168.1.100", &fake);
    d.open().unwrap();
    let info = d.get_module_info(1).unwrap();
    assert_eq!(info.vendor, "Rockwell Automation/Allen-Bradley");
    assert_eq!(info.product_type, "Programmable Logic Controller");
    assert_eq!(info.product_code, 89);
    assert_eq!((info.revision.major, info.revision.minor), (20, 19));
    assert_eq!(info.status, *b"`0");
    assert_eq!(info.serial, "c00fa09b");
    assert_eq!(info.product_name, "1769-L23E-QBFC1 LOGIX5323E-QBFC1");
}

#[test]
fn get_module_info_raises_response_error_on_failed_reply_and_lets_comm_errors_through() {
    // test_cip_get_module_info_raises_response_error_if_response_falsy, test_get_module_info_lets_comm_errors_through
    let fake = Fake::new();
    fake.reply(fake::register_reply(1))
        .reply(fake::rr_reply(0x01, 0x05, &[0], &[]))
        .reply_err(Error::comm("reset"));
    let d = driver("192.168.1.100", &fake);
    d.open().unwrap();
    assert_eq!(
        d.get_module_info(1),
        Err(Error::response("error getting module info"))
    );
    assert_eq!(
        d.get_module_info(1),
        Err(Error::comm("failed to receive reply"))
    );
    assert!(!d.connected());
}

#[test]
fn close_without_session_or_connection_sends_nothing_and_closes_the_transport() {
    // test_close_calls_socket_close_if_socket
    let fake = Fake::new();
    fake.reply(fake::register_reply(0));
    let d = driver("192.168.1.100", &fake);
    assert!(!d.open().unwrap());
    d.close().unwrap();
    assert_eq!(fake.sent().len(), 1);
    assert_eq!(fake.closes(), 1);
}

#[test]
fn close_with_registered_session_unregisters_without_error() {
    // test_close_raises_no_error_on_close_with_registered_session
    let fake = Fake::new();
    fake.reply(fake::register_reply(1));
    let d = driver("192.168.1.100", &fake);
    assert!(d.open().unwrap());
    d.close().unwrap();
    let sent = fake.sent();
    assert_eq!(sent[1][..2], [0x66, 0x00]);
    assert_eq!(sent[1][4..8], 1u32.to_le_bytes());
    assert_eq!(fake.receives(), 1); // no reply read for UnRegisterSession
    assert!(!d.connected());
}

#[test]
fn close_raises_comm_error_when_unregister_fails() {
    // test_close_raises_commerror_on_any_exception (_un_register_session)
    let fake = Fake::new();
    fake.reply(fake::register_reply(1));
    let d = driver("192.168.1.100", &fake);
    d.open().unwrap();
    fake.fail_send(Error::comm("broken"));
    assert_eq!(d.close(), Err(Error::comm("failed to send message")));
    assert!(!d.connected());
    assert_eq!(fake.closes(), 1);
}

#[test]
fn open_raises_comm_error_on_connect_fail_and_can_retry() {
    // test_open_raises_commerror_on_connect_fail, test_open_connect_error_leaves_driver_closed
    let fake = Fake::new();
    fake.fail_connect(Error::comm("Failed to open socket to 192.168.1.100:44818"))
        .fail_connect(Error::comm("again"));
    let d = driver("192.168.1.100", &fake);
    assert_eq!(d.open(), Err(Error::comm("failed to open a connection")));
    assert!(!d.connected());
    assert_eq!(d.open(), Err(Error::comm("failed to open a connection")));
    assert_eq!(fake.connects().len(), 2);
    fake.reply(fake::register_reply(3));
    assert!(d.open().unwrap());
    assert_eq!(
        fake.connects()[2],
        (
            "192.168.1.100".to_owned(),
            44818,
            Some(Duration::from_secs(5))
        )
    );
}

#[test]
fn open_returns_false_without_a_session_and_reopens_a_new_transport() {
    // test_open_returns_false_if_register_session_falsy, test_open_without_session_leaves_driver_closed,
    // test_failed_registration_releases_socket_and_allows_retry, test_zero_session_handle_is_treated_as_failed_registration
    let fake = Fake::new();
    fake.reply(fake::register_reply(0));
    let d = driver("127.0.0.1:2222", &fake);
    assert!(!d.open().unwrap());
    assert!(!d.connected());
    assert_eq!(fake.closes(), 1);
    assert!(!d.open().unwrap()); // no reply: an unparseable reply is a refused session
    assert_eq!(fake.closes(), 2);
    fake.reply(fake::register_reply(10));
    assert!(d.open().unwrap());
    assert!(d.open().unwrap()); // already open: nothing sent
    assert_eq!(fake.connects().len(), 3);
    assert_eq!(fake.connects()[0].1, 2222);
    assert_eq!(fake.sent().len(), 3);
    assert_eq!(d.lock().session(), 10);
}

#[test]
fn register_session_returns_the_session_handle() {
    // test__register_session_returns_configured_session
    for session in [1u32, 0xFFFF_FFFF] {
        let fake = Fake::new();
        let mut reply = vec![0; 4];
        reply.extend(session.to_le_bytes());
        reply.extend([0; 20]);
        fake.reply(reply);
        let d = driver("192.168.1.100", &fake);
        assert!(d.open().unwrap());
        assert_eq!(d.lock().session(), session);
    }
}

#[test]
fn forward_close_returns_false_without_reply_and_true_with_one() {
    // test__forward_close_returns_false_if_no_response, test__forward_close_returns_true_if_response
    let fake = Fake::new();
    fake.reply(fake::register_reply(1));
    let d = driver("192.168.1.100", &fake);
    d.open().unwrap();
    assert!(!d.lock().forward_close().unwrap());
    fake.reply(hex(FORWARD_CLOSE_REPLY));
    assert!(d.lock().forward_close().unwrap());
}

#[test]
fn forward_open_returns_false_on_failed_reply_and_true_when_connected() {
    // test__forward_open_returns_false_if_falsy_response, test__forward_open_returns_true_if_already_connected
    let fake = Fake::new();
    fake.reply(fake::register_reply(1));
    let d = driver("192.168.1.100", &fake);
    d.open().unwrap();
    assert!(!d.lock().forward_open().unwrap());
    fake.reply(fake::forward_open_reply(true, CID));
    assert!(d.lock().forward_open().unwrap());
    let sent = fake.sent().len();
    assert!(d.lock().forward_open().unwrap());
    assert_eq!(fake.sent().len(), sent);
    assert_eq!(d.lock().target_cid(), Some(&CID[..]));
}

#[test]
fn bad_plc_paths_fail_to_parse_or_encode() {
    // test_bad_plc_paths
    let bad = [
        "192.168.1.100/Z",
        "bp/0",
        "192.168.1.100/-1",
        "192.168.1.100/backplan/1",
        "192.168.1.100/backplane/1/10.11.12.13/bp/0",
        "192.168.1.100//bp/1",
        "192.168.1.100/",
        "192.168.1.100,bp,1,0",
        "192.168.1.100,",
        "192.168.1.100:abc",
        "192.168.1.100:/bp/0",
        "192.168.1.100:-123",
    ];
    for path in bad {
        let failed =
            match CipConnection::new(path, CipOptions::default(), Fake::new().connector(), false) {
                Err(err) => matches!(class(&err), "RequestError" | "DataError"),
                Ok(conn) => {
                    ciplink::epath::encode_epath(conn.cip_path(), true, true, false).is_err()
                }
            };
        assert!(failed, "{path}");
    }
}

// ---- test_transport.py ----

fn connected_driver(fake: &Fake) -> CipDriver {
    fake.respond(fake::session_responder(CID, |seq, _| {
        fake::unit_reply(CID, seq, 0x01, 0, &[], &[0x01])
    }));
    let d = driver("1.2.3.4", fake);
    assert!(d.open().unwrap());
    assert!(d.generic_message(&msg(0x01, 1, 1)).unwrap().is_ok());
    d
}

#[test]
fn send_drops_connection_when_reply_does_not_finish() {
    // test_send_drops_connection_when_reply_does_not_finish,
    // test_transport_failure_invalidates_connection_without_retry (_receive)
    let fake = Fake::new();
    let d = connected_driver(&fake);
    let before = fake.sent().len();
    fake.reply_err(Error::comm("timed out"));
    assert_eq!(
        d.lock().list_identity(),
        Err(Error::comm("failed to receive reply"))
    );
    let c = d.lock();
    assert!(!c.connected() && !c.target_connected());
    assert_eq!(c.session(), 0);
    assert_eq!(c.target_cid(), None);
    assert_eq!(fake.closes(), 1);
    assert_eq!(fake.sent().len(), before + 1);
}

#[test]
fn send_failure_drops_connection_without_receiving() {
    // test_transport_failure_invalidates_connection_without_retry (_send)
    let fake = Fake::new();
    let d = connected_driver(&fake);
    let receives = fake.receives();
    fake.fail_send(Error::comm("timed out"));
    assert_eq!(
        d.lock().list_identity(),
        Err(Error::comm("failed to send message"))
    );
    assert_eq!(fake.receives(), receives);
    assert!(!d.connected());
    assert_eq!(fake.closes(), 1);
}

#[test]
fn send_keeps_connection_when_request_fails_to_build() {
    // test_send_keeps_connection_when_request_fails_to_build
    let fake = Fake::new();
    let d = connected_driver(&fake);
    let before = fake.sent().len();
    let too_big = vec![0u8; 70000];
    assert!(d.send_connected_raw(&too_big).is_err());
    assert!(d.connected());
    assert_eq!(fake.sent().len(), before);
}

#[test]
fn list_identity_returns_none_when_session_rejected() {
    // test_list_identity_returns_empty_when_session_rejected
    let fake = Fake::new();
    fake.reply(fake::register_reply(0));
    let result =
        CipDriver::list_identity_with("1.2.3.4", CipOptions::default(), fake.connector(), false);
    assert_eq!(result, Ok(None));
    assert_eq!(fake.sent().len(), 1); // only the RegisterSession
}

#[test]
fn two_threads_send_one_forward_open() {
    // test_two_threads_send_one_forward_open, test_two_threads_can_reopen_a_shared_driver
    let fake = Fake::new();
    fake.respond(fake::session_responder(CID, |seq, _| {
        std::thread::sleep(Duration::from_millis(5));
        fake::unit_reply(CID, seq, 0x01, 0, &[], &[0x01])
    }));
    let d = Arc::new(driver("1.2.3.4", &fake));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&d);
            std::thread::spawn(move || {
                assert!(d.open().unwrap());
                d.generic_message(&msg(0x01, 1, 1)).unwrap().is_ok()
            })
        })
        .collect();
    for t in threads {
        assert!(t.join().unwrap());
    }
    let sent = fake.sent();
    let count = |cmd: u8, service: Option<u8>| {
        sent.iter()
            .filter(|f| f[0] == cmd && service.is_none_or(|s| f[40] == s))
            .count()
    };
    assert_eq!(count(0x65, None), 1);
    assert_eq!(count(0x6F, Some(0x5B)), 1);
    let mut sequences: Vec<u16> = sent
        .iter()
        .filter(|f| f[0] == 0x70)
        .map(|f| fake::sent_sequence(f))
        .collect();
    sequences.sort();
    assert_eq!(sequences, [1, 2, 3, 4]);
}

#[test]
fn threads_share_the_sequence_counter() {
    // test_threads_share_the_sequence_counter
    let d = Arc::new(driver("1.2.3.4", &Fake::new()));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&d);
            std::thread::spawn(move || {
                for _ in 0..20000 {
                    d.next_sequence();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(u32::from(d.next_sequence()), 80000 - 65535 + 1);
}

fn fo_rejecting(fake: &Fake) -> CipDriver {
    fake.reply(fake::register_reply(1));
    let d = driver("1.2.3.4", fake);
    d.open().unwrap();
    d
}

#[test]
fn forward_open_fallback_uses_new_triad_and_keeps_large_forward_open() {
    // test_forward_open_fallback_uses_new_triad_and_keeps_large_forward_open
    let fake = Fake::new();
    let d = fo_rejecting(&fake);
    fake.reply(fake::rr_reply(0x5B, 0x08, &[], &[]))
        .reply(fake::rr_reply(0x54, 0x01, &[0x0100], &[]));
    assert_eq!(
        d.lock().ensure_forward_open("read"),
        Err(Error::response(
            "Target did not connected. read will not be executed."
        ))
    );
    let sent = fake.sent();
    let (large, standard) = (&sent[1][46..], &sent[2][46..]);
    assert_eq!((sent[1][40], sent[2][40]), (0x5B, 0x54));
    assert_ne!(large[10..18], standard[10..18]); // csn, vendor id, vsn
    assert_ne!(large[6..10], standard[6..10]); // T->O connection id
    let c = d.lock();
    assert!(c.extended_forward_open());
    assert_eq!(c.connection_size(), 4000);
}

#[test]
fn transport_error_in_forward_open_fallback_keeps_large_forward_open() {
    // test_transport_error_in_forward_open_fallback_keeps_large_forward_open
    let fake = Fake::new();
    let d = fo_rejecting(&fake);
    fake.reply(fake::rr_reply(0x5B, 0x08, &[], &[]))
        .reply_err(Error::comm("timeout"));
    assert_eq!(
        d.lock().ensure_forward_open("read"),
        Err(Error::comm("failed to receive reply"))
    );
    let c = d.lock();
    assert!(c.extended_forward_open());
    assert_eq!(c.connection_size(), 4000);
}

#[test]
fn forward_open_and_close_address_connection_manager_instance_1() {
    // test_forward_open_close_address_connection_manager_instance_1
    let fake = Fake::new();
    let d = fo_rejecting(&fake);
    let _ = d.lock().forward_open();
    let _ = d.lock().forward_close();
    let sent = fake.sent();
    assert_eq!(sent[1][40..46], [0x5B, 0x02, 0x20, 0x06, 0x24, 0x01]);
    assert_eq!(sent[2][40..46], [0x4E, 0x02, 0x20, 0x06, 0x24, 0x01]);
}

#[test]
fn forward_close_uses_the_triad_of_the_forward_open() {
    let fake = Fake::new();
    let d = connected_driver(&fake);
    d.close().unwrap();
    let sent = fake.sent();
    let fo = &sent[1][46..];
    let fc = sent.iter().find(|f| f[0] == 0x6F && f[40] == 0x4E).unwrap();
    let fc = &fc[46..];
    assert_eq!(fc[2..4], fo[10..12]); // csn
    assert_eq!(fc[4..6], [0x09, 0x10]); // vendor id
    assert_eq!(fc[6..10], fo[14..18]); // vsn
}

#[test]
fn connected_messages_use_the_target_connection_id_and_session() {
    let fake = Fake::new();
    let _d = connected_driver(&fake);
    let frame = fake.sent().pop().unwrap();
    assert_eq!(frame[..2], [0x70, 0x00]);
    assert_eq!(frame[4..8], 1u32.to_le_bytes());
    assert_eq!(frame[36..40], CID);
    assert_eq!(fake::sent_sequence(&frame), 1);
    assert_eq!(
        fake::sent_message(&frame),
        [0x01, 0x02, 0x20, 0x01, 0x24, 0x01]
    );
}

#[test]
fn raw_passthrough_sends_connected_and_unconnected_messages() {
    let fake = Fake::new();
    let d = connected_driver(&fake);
    let reply = d
        .send_connected_raw(&[0x01, 0x02, 0x20, 0x01, 0x24, 0x01])
        .unwrap();
    assert_eq!(reply[46], 0x81);
    let frame = fake.sent().pop().unwrap();
    assert_eq!(fake::sent_sequence(&frame), 2);
    fake.reply(fake::rr_reply(0x01, 0, &[], &[9]));
    let reply = d
        .send_unconnected_raw(&[0x01, 0x02, 0x20, 0x01, 0x24, 0x01])
        .unwrap();
    assert_eq!(*reply.last().unwrap(), 9);
    let frame = fake.sent().pop().unwrap();
    assert_eq!(frame[..2], [0x6F, 0x00]);
    assert_eq!(frame[40..], [0x01, 0x02, 0x20, 0x01, 0x24, 0x01]);
}

#[test]
fn generic_message_errors_are_kind_other_and_values_are_raw_bytes() {
    let fake = Fake::new();
    let d = connected_driver(&fake);
    fake.reply(fake::unit_reply(CID, 2, 0x01, 0x05, &[0], &[]));
    let reply = d.generic_message(&msg(0x01, 1, 1)).unwrap();
    assert!(!reply.is_ok());
    assert_eq!(reply.tag.error_kind(), Some(ErrorKind::Other));
    assert_eq!(reply.tag.value, Some(Value::Bytes(vec![])));
    assert_eq!(reply.reply.service_status, Some(0x05));
}

#[test]
fn un_register_session_resets_session_to_zero() {
    // test_un_register_session_resets_session_to_zero
    let fake = Fake::new();
    fake.reply(fake::register_reply(1));
    let d = driver("1.2.3.4", &fake);
    d.open().unwrap();
    d.close().unwrap();
    assert_eq!(d.lock().session(), 0);
}

#[test]
fn unconnected_requests_before_open_are_send_failures() {
    // Python's send on a driver without a socket: CommError "failed to send message", nothing sent,
    // and get_module_info lets that CommError through
    let fake = Fake::new();
    let d = driver("1.2.3.4/bp/0", &fake);
    assert_eq!(
        d.generic_message(&unconnected("u", false, RoutePath::Current)),
        Err(Error::comm("failed to send message"))
    );
    assert_eq!(
        d.get_module_info(1),
        Err(Error::comm("failed to send message"))
    );
    assert!(fake.sent().is_empty() && fake.connects().is_empty());
    assert!(!d.connected());
}

// ---- test_transport_lifecycle.py ----

#[test]
fn connection_size_and_timeout_configuration() {
    // test_connection_size_selects_forward_open_format, test_invalid_connection_size_is_rejected,
    // test_live_connection_size_change_is_rejected, test_timeout_configuration_applies_to_an_open_socket,
    // test_invalid_socket_timeout_is_rejected
    let fake = Fake::new();
    let opts = CipOptions {
        socket_timeout: Some(Duration::from_millis(2500)),
        connection_size: 500,
    };
    let d = CipDriver::with_connector("127.0.0.1", opts, fake.connector()).unwrap();
    assert!(!d.lock().extended_forward_open());
    assert!(d.set_connection_size(0).is_err());
    d.set_connection_size(512).unwrap();
    assert!(d.lock().extended_forward_open());
    assert!(d.set_socket_timeout(Some(Duration::ZERO)).is_err());

    let d = connected_driver(&fake);
    assert_eq!(
        d.set_connection_size(500),
        Err(Error::request(
            "Close the connection before changing connection_size"
        ))
    );
    assert_eq!(d.connection_size(), 4000);
    d.set_socket_timeout(Some(Duration::from_millis(1250)))
        .unwrap();
    assert_eq!(fake.timeouts(), [Some(Duration::from_millis(1250))]);
    assert_eq!(d.socket_timeout(), Some(Duration::from_millis(1250)));
}

#[test]
fn unregister_is_attempted_after_a_rejected_forward_close() {
    // test_unregister_is_attempted_even_if_forward_close_fails (a rejected Forward Close)
    let fake = Fake::new();
    let d = connected_driver(&fake);
    fake.reply(fake::rr_reply(0x4E, 0x01, &[0x0107], &[]));
    d.close().unwrap();
    let sent = fake.sent();
    assert_eq!(sent.last().unwrap()[..2], [0x66, 0x00]);
    assert!(!d.connected() && d.lock().target_cid().is_none());
}

#[test]
fn close_skips_unregister_after_forward_close_drops_the_connection() {
    // test_close_skips_unregister_after_forward_close_drops_the_connection
    let fake = Fake::new();
    let d = connected_driver(&fake);
    let before = fake.sent().len();
    fake.fail_send(Error::comm("timed out"));
    assert_eq!(d.close(), Err(Error::comm("failed to send message")));
    assert_eq!(fake.sent().len(), before + 1);
    assert!(!d.connected());
    assert_eq!(fake.closes(), 1);
}

// ---- test_socket_.py / test_transport_lifecycle.py framing: covered by transport.rs over TCP ----

#[test]
fn tcp_transport_reassembles_frames_split_at_every_byte_and_reports_early_eof() {
    use ciplink::transport::{TcpTransport, Transport};
    use std::io::Write;
    use std::net::TcpListener;

    let frame = |payload: &[u8]| {
        let mut f = vec![0x70, 0x00];
        f.extend((payload.len() as u16).to_le_bytes());
        f.resize(24, 0);
        f.extend(payload);
        f
    };
    let data = frame(b"payload");
    let second = frame(&[0; 4000]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (d1, d2) = (data.clone(), second.clone());
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();
        for b in &d1 {
            s.write_all(&[*b]).unwrap();
            s.flush().unwrap();
        }
        s.write_all(&d2).unwrap();
        s.write_all(&d1[..10]).unwrap(); // then EOF mid header
    });
    let mut t = TcpTransport::connect("127.0.0.1", port, Some(Duration::from_secs(5))).unwrap();
    assert_eq!(t.receive().unwrap(), data);
    assert_eq!(t.receive().unwrap(), second);
    server.join().unwrap();
    let err = t.receive().unwrap_err();
    assert!(err.to_string().contains("complete frame"), "{err}");
}

#[test]
fn tcp_connect_failure_is_a_comm_error() {
    // test_socket_connect_raises_commerror_on_failed_host_lookup / on_timeout
    use ciplink::transport::TcpTransport;
    // port 0 can never be connected to; a freed ephemeral port could be reused by a parallel test's listener
    let port = 0;
    let err = TcpTransport::connect("127.0.0.1", port, Some(Duration::from_secs(2)))
        .err()
        .unwrap();
    assert_eq!(
        err,
        Error::comm(format!("Failed to open socket to 127.0.0.1:{port}"))
    );
}

#[test]
fn driver_handles_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CipDriver>();
    assert_send_sync::<ciplink::cip::GenericReply>();
}

#[test]
fn panic_while_locked_drops_the_connection_and_the_driver_stays_usable() {
    // a panic mid-exchange may leave a reply unread: the next request must not take it as its own
    let fake = Fake::new();
    let d = Arc::new(fo_rejecting(&fake));
    assert!(d.connected());
    let d2 = Arc::clone(&d);
    let panicked = std::thread::spawn(move || {
        let _conn = d2.lock();
        panic!("panic while holding the connection");
    })
    .join();
    assert!(panicked.is_err());
    assert!(!d.connected());
    assert_eq!(d.lock().session(), 0);
    assert_eq!(fake.closes(), 1);
    // the poison is cleared: later calls neither panic nor drop a fresh connection
    fake.reply(fake::register_reply(7));
    assert!(d.open().unwrap());
    assert!(d.connected());
    assert_eq!(d.lock().session(), 7);
}
