//! Packet parity with the reference Python driver: tools/fixtures/gen_packets.py writes fixtures/packets.json.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::epath::{LogicalValue, parse_connection_path};
use ciplink::packets::{
    self, Encap, ForwardOpen, ReadModifyWrite, Reply, ReplyKind, TAG_TABLE_VERSION_REPLY_SIZE,
    TAG_TABLE_VERSION_REQUEST_SIZE, TAG_TABLE_VERSION_SERVICE,
};
use ciplink::types::Elementary;
use common::*;
use serde_json::Value as Json;

fn hex_of(json: &Json) -> Vec<u8> {
    hex(json.as_str().unwrap())
}

fn u64_of(json: &Json) -> u64 {
    json.as_u64().unwrap()
}

fn encap(case: &Json) -> Encap {
    Encap {
        session: u64_of(&case["session"]) as u32,
        context: hex_of(&case["context"]).try_into().unwrap(),
        option: u64_of(&case["option"]) as u32,
    }
}

fn opt_hex(json: &Json) -> Option<Vec<u8>> {
    json.as_str().map(hex)
}

#[test]
fn session_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "session") {
        let e = encap(case);
        let got = match case["op"].as_str().unwrap() {
            "register" => {
                let version = hex_of(&case["version"]);
                let flags = hex_of(&case["flags"]);
                packets::register_session_request(
                    &e,
                    u16::from_le_bytes([version[0], version[1]]),
                    u16::from_le_bytes([flags[0], flags[1]]),
                )
            }
            "unregister" => packets::unregister_session_request(&e),
            "list_identity" => packets::list_identity_request(&e),
            other => panic!("{other}"),
        };
        assert_eq!(to_hex(&got), case["bytes"].as_str().unwrap(), "{case}");
    }
}

fn logical(json: &Json) -> LogicalValue {
    LogicalValue::Int(json.as_i64().unwrap())
}

fn generic(
    case: &Json,
) -> (
    u8,
    LogicalValue,
    LogicalValue,
    Option<LogicalValue>,
    Vec<u8>,
) {
    (
        case["service"].as_u64().unwrap() as u8,
        logical(&case["class"]),
        logical(&case["instance"]),
        case["attribute"].as_i64().map(LogicalValue::Int),
        hex_of(&case["data"]),
    )
}

#[test]
fn generic_connected_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "generic_connected") {
        let (service, class, instance, attribute, data) = generic(case);
        let msg = packets::generic_message(service, class, instance, attribute, &data).unwrap();
        assert_eq!(to_hex(&msg), case["tag_only"].as_str().unwrap(), "{case}");
        let seq = case["sequence"].as_u64().unwrap() as u16;
        let mut with_seq = seq.to_le_bytes().to_vec();
        with_seq.extend(&msg);
        assert_eq!(
            to_hex(&with_seq),
            case["message"].as_str().unwrap(),
            "{case}"
        );
        for full in case["full"].as_array().unwrap() {
            let got =
                packets::send_unit_data_request(&encap(full), &hex_of(&full["cid"]), seq, &msg)
                    .unwrap();
            assert_eq!(to_hex(&got), full["bytes"].as_str().unwrap(), "{full}");
        }
    }
}

#[test]
fn generic_unconnected_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "generic_unconnected") {
        let (service, class, instance, attribute, data) = generic(case);
        let msg = packets::generic_unconnected_message(
            service,
            class,
            instance,
            attribute,
            &data,
            &hex_of(&case["route"]),
            case["unconnected_send"].as_bool().unwrap(),
        )
        .unwrap();
        assert_eq!(to_hex(&msg), case["message"].as_str().unwrap(), "{case}");
        for full in case["full"].as_array().unwrap() {
            let got = packets::send_rr_data_request(&encap(full), &msg).unwrap();
            assert_eq!(to_hex(&got), full["bytes"].as_str().unwrap(), "{full}");
        }
    }
}

fn with_seq(seq: &Json, msg: &[u8]) -> String {
    let mut out = (seq.as_u64().unwrap() as u16).to_le_bytes().to_vec();
    out.extend(msg);
    to_hex(&out)
}

#[test]
fn read_tag_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "read_tag") {
        let msg = packets::read_tag_message(
            &hex_of(&case["path"]),
            case["elements"].as_u64().unwrap() as u16,
        );
        assert_eq!(to_hex(&msg), case["tag_only"].as_str().unwrap(), "{case}");
        assert_eq!(
            with_seq(&case["sequence"], &msg),
            case["message"].as_str().unwrap()
        );
    }
    for case in cases(&fixture, "read_tag_fragmented") {
        let path = hex_of(&case["path"]);
        let elements = case["elements"].as_u64().unwrap() as u16;
        let msg = packets::read_tag_fragmented_message(
            &path,
            elements,
            case["offset"].as_u64().unwrap() as u32,
        );
        assert_eq!(
            with_seq(&case["sequence"], &msg),
            case["message"].as_str().unwrap(),
            "{case}"
        );
        // Python embeds a fragmented read in a multi-service packet without its offset
        let tag_only = packets::read_tag_message(&path, elements);
        let mut tag_only = tag_only;
        tag_only[0] = 0x52;
        assert_eq!(
            to_hex(&tag_only),
            case["tag_only"].as_str().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn write_tag_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "write_tag") {
        let handle = case["struct_handle"].as_u64().map(|h| h as u16);
        let code = packets::write_type_code(case["type_name"].as_str().unwrap(), handle);
        if let Some(err) = case.get("err") {
            let err_got = code.unwrap_err();
            assert_eq!(class(&err_got), err.as_str().unwrap(), "{case}");
            assert_eq!(err_got.to_string(), case["msg"].as_str().unwrap(), "{case}");
            continue;
        }
        let code = code.unwrap();
        let msg = packets::write_tag_message(
            &hex_of(&case["path"]),
            &code,
            case["elements"].as_u64().unwrap() as u16,
            &hex_of(&case["value"]),
        );
        assert_eq!(to_hex(&msg), case["tag_only"].as_str().unwrap(), "{case}");
    }
    for case in cases(&fixture, "write_tag_fragmented") {
        let handle = case["struct_handle"].as_u64().map(|h| h as u16);
        let code = packets::write_type_code(case["type_name"].as_str().unwrap(), handle).unwrap();
        let msg = packets::write_tag_fragmented_message(
            &hex_of(&case["path"]),
            &code,
            case["elements"].as_u64().unwrap() as u16,
            case["offset"].as_u64().unwrap() as u32,
            &hex_of(&case["value"]),
        );
        assert_eq!(to_hex(&msg), case["tag_only"].as_str().unwrap(), "{case}");
        assert_eq!(
            with_seq(&case["sequence"], &msg),
            case["message"].as_str().unwrap()
        );
    }
}

#[test]
fn read_modify_write_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "read_modify_write") {
        let typ = Elementary::from_name(case["type_name"].as_str().unwrap()).unwrap();
        let mut rmw = ReadModifyWrite::new(typ);
        for bit in case["bits"].as_array().unwrap() {
            rmw.set_bit(bit[0].as_u64().unwrap() as u32, bit[1].as_bool().unwrap());
        }
        let ctx = case.to_string();
        let result = rmw.message(&hex_of(&case["path"]));
        if let Some(err) = case["tag_only"].get("err") {
            let e = result.unwrap_err();
            assert_eq!(class(&e), err.as_str().unwrap(), "{ctx}");
            assert_eq!(
                e.to_string(),
                case["tag_only"]["msg"].as_str().unwrap(),
                "{ctx}"
            );
        } else {
            check_bytes(result, &case["tag_only"], &ctx);
        }
    }
}

#[test]
fn tag_table_version_request_matches_python() {
    let fixture = load("packets.json");
    let case = &cases(&fixture, "tag_table_version")[0];
    assert_eq!(
        to_hex(&TAG_TABLE_VERSION_SERVICE),
        case["tag_only"].as_str().unwrap()
    );
    assert_eq!(
        with_seq(&case["sequence"], &TAG_TABLE_VERSION_SERVICE),
        case["message"].as_str().unwrap()
    );
    assert_eq!(
        TAG_TABLE_VERSION_REQUEST_SIZE as u64,
        u64_of(&case["request_size"])
    );
    assert_eq!(
        TAG_TABLE_VERSION_REPLY_SIZE as u64,
        u64_of(&case["reply_size"])
    );
}

#[test]
fn multi_service_requests_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "multi_service") {
        let messages: Vec<Vec<u8>> = case["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex_of)
            .collect();
        let msg = packets::multi_service_message(&messages).unwrap();
        assert_eq!(
            with_seq(&case["sequence"], &msg),
            case["message"].as_str().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn forward_open_and_close_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "forward") {
        let (_, _, route) = parse_connection_path(case["path"].as_str().unwrap(), false).unwrap();
        let large = case["large"].as_bool().unwrap();
        let params = ForwardOpen {
            cid: hex_of(&case["cid"]).try_into().unwrap(),
            csn: hex_of(&case["csn"]).try_into().unwrap(),
            vid: hex_of(&case["vid"]).try_into().unwrap(),
            vsn: hex_of(&case["vsn"]).try_into().unwrap(),
            connection_size: case["size"].as_u64().unwrap() as u32,
            large,
        };
        let data = packets::forward_open_data(&params, &route).unwrap();
        let service = if large {
            packets::LARGE_FORWARD_OPEN
        } else {
            packets::FORWARD_OPEN
        };
        let msg = packets::generic_unconnected_message(
            service,
            LogicalValue::Int(packets::CONNECTION_MANAGER.into()),
            LogicalValue::Int(1),
            None,
            &data,
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            to_hex(&msg),
            case["forward_open"].as_str().unwrap(),
            "{case}"
        );

        let data =
            packets::forward_close_data(&params.csn, &params.vid, &params.vsn, &route).unwrap();
        let msg = packets::generic_unconnected_message(
            packets::FORWARD_CLOSE,
            LogicalValue::Int(packets::CONNECTION_MANAGER.into()),
            LogicalValue::Int(1),
            None,
            &data,
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            to_hex(&msg),
            case["forward_close"].as_str().unwrap(),
            "{case}"
        );
    }
}

fn kind_of(name: &str) -> ReplyKind {
    match name {
        "send_unit_data" => ReplyKind::SendUnitData,
        "send_rr_data" => ReplyKind::SendRRData,
        "register_session" => ReplyKind::RegisterSession,
        "unregister_session" => ReplyKind::Encapsulation,
        "list_identity" => ReplyKind::ListIdentity,
        other => panic!("{other}"),
    }
}

fn parse(kind: ReplyKind, raw: &Json) -> Reply {
    match opt_hex(raw) {
        Some(raw) => Reply::parse(kind, &raw),
        None => Reply::no_response(kind),
    }
}

/// asserts the fields gen_packets.py `fields()` captured
fn assert_fields(reply: &Reply, case: &Json, ctx: &str) {
    assert_eq!(
        reply.command.as_deref().map(to_hex),
        case["command"]
            .get("bytes")
            .and_then(Json::as_str)
            .map(str::to_owned),
        "{ctx}: command"
    );
    assert_eq!(
        reply.command_status.map(i64::from),
        case["command_status"].as_i64(),
        "{ctx}: command_status"
    );
    assert_eq!(
        reply.service.map(|s| to_hex(&[s])),
        case["service"]
            .get("bytes")
            .and_then(Json::as_str)
            .map(str::to_owned),
        "{ctx}: service"
    );
    assert_eq!(
        reply.service_status.map(u64::from),
        case["service_status"].as_u64(),
        "{ctx}: service_status"
    );
    assert_eq!(
        reply.data.as_deref().map(to_hex),
        case["data"]
            .get("bytes")
            .and_then(Json::as_str)
            .map(str::to_owned),
        "{ctx}: data"
    );
    assert_eq!(
        reply.is_valid(),
        case["is_valid"].as_bool().unwrap(),
        "{ctx}: is_valid"
    );
    match case["error"].get("ok") {
        Some(want) => assert_eq!(
            reply.error(),
            want.get("str").and_then(Json::as_str).map(str::to_owned),
            "{ctx}: error"
        ),
        // Python's error property raises on a truncated extended status, Rust reports the status alone
        None => assert!(reply.error().is_some(), "{ctx}: error"),
    }
    if let Some(want) = case["response_error"].get("ok") {
        let got = packets::response_error(reply, None);
        assert_eq!(
            got.message,
            want["message"].as_str().unwrap(),
            "{ctx}: response_error"
        );
        assert_eq!(
            got.kind.as_str(),
            want["kind"].as_str().unwrap(),
            "{ctx}: kind"
        );
        assert_eq!(
            got.status.map(u64::from),
            want["status"].as_u64(),
            "{ctx}: status"
        );
        assert_eq!(got.ext.map(u64::from), want["ext"].as_u64(), "{ctx}: ext");
    }
}

#[test]
fn replies_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "replies") {
        let ctx = format!("{} {}", case["kind"], case["raw"]);
        let kind = kind_of(case["kind"].as_str().unwrap());
        let reply = parse(kind, &case["raw"]);
        assert_fields(&reply, case, &ctx);
        if let Some(session) = case.get("session") {
            assert_eq!(
                reply.session.map(u64::from),
                session.as_u64(),
                "{ctx}: session"
            );
        }
        if let Some(identity) = case.get("identity") {
            match identity.is_null() {
                true => assert!(reply.identity.is_none(), "{ctx}"),
                false => assert_value(&reply.identity.as_ref().unwrap().to_value(), identity, &ctx),
            }
        }
    }
}

#[test]
fn multi_service_replies_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "multi_replies") {
        let ctx = format!("{} {}", case["count"], case["raw"]);
        let count = case["count"].as_u64().unwrap() as usize;
        let multi = match opt_hex(&case["raw"]) {
            Some(raw) => packets::parse_multi_service_reply(&raw, count),
            None => packets::MultiServiceReply {
                reply: Reply::no_response(ReplyKind::SendUnitData),
                replies: Vec::new(),
            },
        };
        assert_fields(&multi.reply, case, &ctx);
        let want = case["replies"].as_array().unwrap();
        assert_eq!(multi.replies.len(), want.len(), "{ctx}: replies");
        for (i, (sub, want)) in multi.replies.iter().zip(want).enumerate() {
            assert_fields(sub, want, &format!("{ctx} [{i}]"));
        }
    }
}

#[test]
fn tag_table_version_replies_match_python() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "tag_table_version_replies") {
        let ctx = case["raw"].to_string();
        let mut reply = parse(ReplyKind::SendUnitData, &case["raw"]);
        let value = packets::parse_tag_table_version(&mut reply);
        assert_fields(&reply, case, &ctx);
        match case["value"].is_null() {
            true => assert!(value.is_none(), "{ctx}"),
            false => {
                let (a, b, c, d, e) = value.unwrap();
                let got: Vec<i64> = vec![a.into(), b.into(), c.into(), d.into(), e.into()];
                let want: Vec<i64> = case["value"]["list"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(input_int)
                    .collect();
                assert_eq!(got, want, "{ctx}");
            }
        }
    }
}

// Intent of tools/reference/tests/offline/test_packets.py

#[test]
fn encapsulation_errors_report_encapsulation_status() {
    let header = |cmd: [u8; 2], status: u32| {
        let mut raw = cmd.to_vec();
        raw.extend([0; 6]);
        raw.extend(status.to_le_bytes());
        raw.extend([0; 12]);
        raw
    };
    let r = Reply::parse(ReplyKind::SendRRData, &header([0x6f, 0], 0x64));
    assert!(!r.is_valid());
    assert_eq!(r.error().unwrap(), ciplink::status::encap_status_text(0x64));
    let r = Reply::parse(ReplyKind::ListIdentity, &header([0x63, 0], 0x01));
    assert!(!r.is_valid() && r.identity.is_none());
    assert_eq!(r.error().unwrap(), ciplink::status::encap_status_text(0x01));
}

#[test]
fn generic_reply_without_data_is_success() {
    let mut raw = vec![0x6f, 0];
    raw.extend([0; 38]);
    raw.extend([0x90, 0, 0, 0]);
    let r = Reply::parse(ReplyKind::SendRRData, &raw);
    assert!(r.is_valid());
    assert_eq!(r.data.as_deref(), Some(&[][..]));
}

#[test]
fn connected_request_wire_bytes() {
    let msg = packets::generic_message(
        0x0E,
        LogicalValue::Int(1),
        LogicalValue::Int(1),
        Some(LogicalValue::Int(1)),
        &[],
    )
    .unwrap();
    let e = Encap {
        session: 7,
        context: *b"_pycomm_",
        option: 0,
    };
    let got = packets::send_unit_data_request(&e, &[1, 2, 3, 4], 3, &msg).unwrap();
    assert_eq!(
        to_hex(&got),
        "70001e0007000000000000005f7079636f6d6d5f00000000000000000a000200a100040001020304b1000a0003000e03200124013001"
    );
}

#[test]
fn oversized_message_is_an_error_not_a_panic() {
    let e = Encap {
        session: 0,
        context: [0; 8],
        option: 0,
    };
    assert!(packets::send_rr_data_request(&e, &vec![0; 70_000]).is_err());
    let big = vec![vec![0u8; 40_000]; 3]; // the third offset is past 65535
    assert!(packets::multi_service_message(&big).is_err());
}

#[test]
fn write_type_codes_match_python_for_every_type_name() {
    let fixture = load("packets.json");
    for case in cases(&fixture, "write_type_codes") {
        let name = case["type_name"].as_str().unwrap();
        let got = packets::write_type_code(name, None);
        if let Some(err) = case["result"].get("err") {
            let err_got = got.unwrap_err();
            assert_eq!(class(&err_got), err.as_str().unwrap(), "{case}");
            assert_eq!(
                err_got.to_string(),
                case["result"]["msg"].as_str().unwrap(),
                "{case}"
            );
        } else {
            check_bytes(got, &case["result"], &format!("{case}"));
        }
    }
}
