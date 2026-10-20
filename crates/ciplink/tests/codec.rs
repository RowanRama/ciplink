//! Codec parity with the reference Python driver: tools/fixtures/gen_codec.py writes fixtures/codec.json.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::Value;
use ciplink::epath::{
    self, DataValue, Link, LogicalType, LogicalValue, PortId, Segment, encode_epath,
    encode_segment, parse_cip_route, parse_connection_path, request_path, tag_request_path,
    wrap_unconnected_send,
};
use ciplink::identity::{ListIdentity, ModuleIdentity};
use ciplink::reader::Reader;
use ciplink::status;
use ciplink::types::{
    ArrayLen, Elementary, FixedString, decode_array, dword_to_bools, encode_array, encode_stringn,
};
use common::*;
use serde_json::Value as Json;

fn elementary(name: &str) -> Elementary {
    Elementary::from_name(name).unwrap_or_else(|| panic!("no type {name}"))
}

#[test]
fn elementary_encode_matches_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "elementary_encode") {
        let ctx = case.to_string();
        let typ = elementary(case["type"].as_str().unwrap());
        let big_int = case["value"]
            .get("int")
            .is_some_and(|n| n.as_i64().is_none() && n.as_u64().is_none());
        if big_int {
            continue; // beyond 64 bits, a Value cannot hold it
        }
        let Some(value) = input(&case["value"]) else {
            assert!(case["result"].get("err").is_some(), "{ctx}");
            continue;
        };
        check_bytes(typ.encode(&value), &case["result"], &ctx);
    }
}

#[test]
fn elementary_decode_matches_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "elementary_decode") {
        let ctx = case.to_string();
        let typ = elementary(case["type"].as_str().unwrap());
        let raw = hex(case["raw"].as_str().unwrap());
        check(
            typ.decode(&mut Reader::new(&raw)),
            &case["result"],
            &ctx,
            |v, want| assert_value(v, want, &ctx),
        );
    }
}

#[test]
fn strings_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "strings") {
        let ctx = case.to_string();
        let name = case["type"].as_str().unwrap();
        let op = case["op"].as_str().unwrap();
        match (name, op) {
            ("FIXED", _) => {
                let fixed = FixedString {
                    size: case["size"].as_u64().unwrap() as usize,
                    max_len: case["max_len"].as_u64().unwrap() as usize,
                };
                if op == "encode" {
                    check_bytes(
                        fixed.encode(&input(&case["value"]).unwrap()),
                        &case["result"],
                        &ctx,
                    );
                } else {
                    let raw = hex(case["raw"].as_str().unwrap());
                    let result = fixed.decode(&mut Reader::new(&raw));
                    check(result, &case["result"], &ctx, |v, want| {
                        assert_value(v, want, &ctx)
                    });
                }
            }
            ("STRINGN", "encode") => {
                let text = case["value"]["str"].as_str().unwrap();
                let size = case["char_size"].as_u64().unwrap() as u16;
                check_bytes(encode_stringn(text, size), &case["result"], &ctx);
            }
            (_, "encode") => check_bytes(
                elementary(name).encode(&input(&case["value"]).unwrap()),
                &case["result"],
                &ctx,
            ),
            (_, _) => {
                let raw = hex(case["raw"].as_str().unwrap());
                let result = elementary(name).decode(&mut Reader::new(&raw));
                check(result, &case["result"], &ctx, |v, want| {
                    assert_value(v, want, &ctx)
                });
            }
        }
    }
}

#[test]
fn bit_arrays_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "bits") {
        let ctx = case.to_string();
        let name = case["type"].as_str().unwrap();
        if name == "dword_to_bool_array" {
            let bools = dword_to_bools(input_int(&case["value"]) as u32);
            let value = Value::Array(bools.into_iter().map(Value::Bool).collect());
            assert_value(&value, &case["result"]["ok"], &ctx);
        } else if case["op"] == "encode" {
            check_bytes(
                elementary(name).encode(&input(&case["value"]).unwrap()),
                &case["result"],
                &ctx,
            );
        } else {
            let raw = hex(case["raw"].as_str().unwrap());
            let result = elementary(name).decode(&mut Reader::new(&raw));
            check(result, &case["result"], &ctx, |v, want| {
                assert_value(v, want, &ctx)
            });
        }
    }
}

#[test]
fn arrays_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "arrays") {
        let ctx = case.to_string();
        let elem = elementary(case["elem"].as_str().unwrap());
        let length = match &case["length"] {
            Json::Null => ArrayLen::Unbounded,
            Json::String(name) => ArrayLen::Prefixed(elementary(name)),
            n => ArrayLen::Fixed(n.as_u64().unwrap() as usize),
        };
        let over = case["override"].as_u64().map(|n| n as usize);
        if case["op"] == "encode" {
            let Some(Value::Array(values)) = input(&case["value"]) else {
                panic!("{ctx}")
            };
            check_bytes(
                encode_array(elem, &length, &values, over),
                &case["result"],
                &ctx,
            );
        } else {
            let raw = hex(case["raw"].as_str().unwrap());
            let result =
                decode_array(elem, &length, &mut Reader::new(&raw), over).map(Value::Array);
            check(result, &case["result"], &ctx, |v, want| {
                assert_value(v, want, &ctx)
            });
        }
    }
}

fn port_id(json: &Json) -> PortId {
    match input(json).unwrap() {
        Value::String(name) => PortId::Name(name),
        v => PortId::Number(v.as_i128().unwrap() as i64),
    }
}

fn link(json: &Json) -> Link {
    match input(json).unwrap() {
        Value::String(text) => Link::Text(text),
        Value::Bytes(raw) => Link::Raw(raw),
        v => Link::Number(v.as_i128().unwrap() as i64),
    }
}

fn logical_value(json: &Json) -> LogicalValue {
    match input(json).unwrap() {
        Value::Bytes(raw) => LogicalValue::Raw(raw),
        v => LogicalValue::Int(v.as_i128().unwrap() as i64),
    }
}

#[test]
fn segments_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "segments") {
        let ctx = case.to_string();
        let (segment, padded) = match case["kind"].as_str().unwrap() {
            "port" => (
                Segment::Port {
                    port: port_id(&case["port"]),
                    link: link(&case["link"]),
                },
                false,
            ),
            "logical" => {
                let Some(kind) = LogicalType::from_name(case["type"].as_str().unwrap()) else {
                    assert!(case["result"].get("err").is_some(), "{ctx}");
                    continue;
                };
                let segment = Segment::Logical {
                    kind,
                    value: logical_value(&case["value"]),
                };
                (segment, case["padded"].as_bool().unwrap())
            }
            _ => {
                let data = match input(&case["data"]).unwrap() {
                    Value::String(s) => DataValue::Symbol(s),
                    Value::Bytes(b) => DataValue::Raw(b),
                    v => panic!("{v:?}"),
                };
                (Segment::Data(data), false)
            }
        };
        check_bytes(encode_segment(&segment, padded), &case["result"], &ctx);
    }
}

fn segment_set(name: &str) -> Vec<Segment> {
    let port = |p: &str, l: Link| Segment::Port {
        port: PortId::Name(p.into()),
        link: l,
    };
    match name {
        "router" => epath::message_router_path(),
        "bp0" => vec![port("bp", Link::Number(0))],
        "route" => vec![
            port("bp", Link::Number(2)),
            port("enet", Link::Text("10.1.2.3".into())),
            port("bp", Link::Number(0)),
        ],
        "symbol" => vec![
            Segment::Data(DataValue::Symbol("Program:Main".into())),
            Segment::Logical {
                kind: LogicalType::ClassId,
                value: LogicalValue::Int(0x6B),
            },
            Segment::Logical {
                kind: LogicalType::InstanceId,
                value: LogicalValue::Int(0x1234),
            },
        ],
        "empty" => vec![],
        "raw" => vec![
            Segment::Raw(vec![0x20, 0x06]),
            Segment::Logical {
                kind: LogicalType::InstanceId,
                value: LogicalValue::Int(1),
            },
        ],
        other => panic!("{other}"),
    }
}

#[test]
fn epaths_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "epaths") {
        let ctx = case.to_string();
        let segments = segment_set(case["set"].as_str().unwrap());
        let flag = |k: &str| case[k].as_bool().unwrap();
        check_bytes(
            encode_epath(
                &segments,
                flag("padded"),
                flag("length"),
                flag("pad_length"),
            ),
            &case["result"],
            &ctx,
        );
    }
}

#[test]
fn connection_paths_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "connection_paths") {
        let ctx = case.to_string();
        if let Some(path) = case.get("path") {
            let auto_slot = case["auto_slot"].as_bool().unwrap();
            let result = parse_connection_path(path.as_str().unwrap(), auto_slot).and_then(
                |(ip, port, route)| {
                    let mut forward_open = route.clone();
                    forward_open.extend(epath::message_router_path());
                    let micro800 = &route[..route.len().saturating_sub(1)];
                    Ok((
                        ip,
                        port,
                        encode_epath(&route, true, true, true)?,
                        encode_epath(&forward_open, true, true, false)?,
                        encode_epath(micro800, true, true, true)?,
                    ))
                },
            );
            check(
                result,
                &case["result"],
                &ctx,
                |(ip, port, a, b, c), want| {
                    let want = want["list"].as_array().unwrap();
                    assert_eq!(ip, want[0]["str"].as_str().unwrap(), "{ctx}");
                    assert_eq!(
                        port.map(i64::from),
                        want[1].get("int").and_then(Json::as_i64),
                        "{ctx}"
                    );
                    for (bytes, w) in [a, b, c].into_iter().zip(&want[2..]) {
                        assert_eq!(to_hex(bytes), w["bytes"].as_str().unwrap(), "{ctx}");
                    }
                },
            );
        } else {
            let result = parse_cip_route(case["route"].as_str().unwrap(), false)
                .and_then(|route| encode_epath(&route, true, true, true));
            check_bytes(result, &case["result"], &ctx);
        }
    }
}

fn scalar_id(json: &Json) -> Option<LogicalValue> {
    match input(json).unwrap() {
        Value::Array(_) => None,
        Value::Bytes(raw) => Some(LogicalValue::Raw(raw)),
        v => Some(LogicalValue::Int(v.as_i128().unwrap() as i64)),
    }
}

#[test]
fn request_paths_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "request_paths") {
        let ctx = case.to_string();
        if let Some(class) = case.get("class") {
            // lists of classes or instances are only built by the Python package's own helper
            let (Some(class), Some(instance), Some(attribute)) = (
                scalar_id(class),
                scalar_id(&case["instance"]),
                scalar_id(&case["attribute"]),
            ) else {
                continue;
            };
            check_bytes(
                request_path(class, instance, Some(attribute)),
                &case["result"],
                &ctx,
            );
        } else if let Some(tag) = case.get("tag") {
            let info = &case["info"]["dict"];
            let id = |key: &str| {
                info.as_array()
                    .unwrap()
                    .iter()
                    .find(|kv| kv[0] == key)
                    .map(|kv| kv[1]["int"].as_u64().unwrap() as u32)
            };
            let instance_id = id("base_instance_id").or_else(|| id("instance_id"));
            let result = tag_request_path(
                tag.as_str().unwrap(),
                instance_id,
                case["use_ids"].as_bool().unwrap(),
            );
            check_bytes(result, &case["result"], &ctx);
        } else {
            let message = hex(case["wrap"].as_str().unwrap());
            let route = hex(case["route"].as_str().unwrap());
            check_bytes(
                Ok(wrap_unconnected_send(&message, &route)),
                &case["result"],
                &ctx,
            );
        }
    }
}

#[test]
fn status_text_and_kinds_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "status") {
        let ctx = case.to_string();
        let ok = &case["result"]["ok"];
        match case["fn"].as_str().unwrap() {
            "service_status" => {
                let text = status::service_status_text(case["status"].as_u64().unwrap() as u8);
                assert_eq!(text, ok["str"].as_str().unwrap(), "{ctx}");
            }
            "extended_status" => {
                let msg = hex(case["msg"].as_str().unwrap());
                let text =
                    status::extended_status_text(&msg, case["start"].as_u64().unwrap() as usize);
                assert_eq!(
                    text.as_deref(),
                    ok.get("str").and_then(Json::as_str),
                    "{ctx}"
                );
            }
            "extended_status_code" => {
                let msg = hex(case["msg"].as_str().unwrap());
                let code =
                    status::extended_status_code(&msg, case["start"].as_u64().unwrap() as usize);
                assert_eq!(
                    code.map(u64::from),
                    ok.get("int").and_then(Json::as_u64),
                    "{ctx}"
                );
            }
            _ => {
                let ext = case["ext"].as_u64().map(|e| e as u16);
                let kind = status::status_kind(case["status"].as_u64().unwrap() as u8, ext);
                assert_eq!(kind.as_str(), ok["str"].as_str().unwrap(), "{ctx}");
            }
        }
    }
}

#[test]
fn identities_match_python() {
    let fixture = load("codec.json");
    for case in cases(&fixture, "identity") {
        let ctx = case.to_string();
        let raw = hex(case["raw"].as_str().unwrap());
        let mut reader = Reader::new(&raw);
        let result = match case["type"].as_str().unwrap() {
            "module" => ModuleIdentity::decode(&mut reader).map(|i| i.to_value()),
            "list_identity" => ListIdentity::decode(&mut reader).map(|i| i.to_value()),
            _ => continue,
        };
        check(result, &case["result"], &ctx, |v, want| {
            assert_value(v, want, &ctx)
        });
    }
}

#[test]
fn lookup_tables_match_python() {
    let tables = load("tables.json");
    let rows = |name: &str| tables[name].as_array().unwrap().clone();
    for row in rows("VENDORS") {
        assert_eq!(
            status::vendor(row[0].as_u64().unwrap() as u16),
            row[1].as_str(),
            "{row}"
        );
    }
    for row in rows("PRODUCT_TYPES") {
        assert_eq!(
            status::product_type(row[0].as_u64().unwrap() as u16),
            row[1].as_str(),
            "{row}"
        );
    }
    for row in rows("STATES") {
        assert_eq!(
            status::state(row[0].as_u64().unwrap() as u8),
            row[1].as_str(),
            "{row}"
        );
    }
    for row in rows("KEYSWITCH") {
        let (a, b) = (
            row[0].as_u64().unwrap() as u8,
            row[1].as_u64().unwrap() as u8,
        );
        assert_eq!(status::keyswitch(a, b), row[2].as_str().unwrap(), "{row}");
    }
    assert_eq!(status::keyswitch(1, 2), "UNKNOWN");
    for row in rows("EXTERNAL_ACCESS") {
        assert_eq!(
            status::external_access(Some(row[0].as_u64().unwrap() as u8)),
            row[1].as_str().unwrap()
        );
    }
    assert_eq!(status::external_access(None), "Unknown");
    for row in rows("STATUS") {
        assert_eq!(
            status::encap_status_text(row[0].as_u64().unwrap() as u32),
            row[1].as_str().unwrap()
        );
    }
    assert_eq!(
        status::encap_status_text(0x1234),
        "Unknown encapsulation status (0x1234)"
    );
    for row in rows("DATA_TYPES") {
        let typ = Elementary::from_code(row[0].as_u64().unwrap() as u8).unwrap();
        assert_eq!(typ.name(), row[1].as_str().unwrap(), "{row}");
    }
}
