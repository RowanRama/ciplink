//! PCCC/SLC parity with the reference Python driver: tools/fixtures/gen_pccc.py writes fixtures/pccc.json.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::Value;
use ciplink::reader::Reader;
use ciplink::slc::pccc::{
    self, Address, FILE_DIRECTORY_CHUNK, FileType, Requestor, SLC_REPLY_START, Sys0Info,
};
use common::*;
use serde_json::Value as Json;

fn fixture() -> Json {
    load("pccc.json")
}

fn requestor() -> Requestor {
    Requestor::default()
}

/// the sequence number the Python driver put in a message (bytes 15..17, after the 13-byte header, CMD, STS)
fn seq_of(message: &[u8]) -> u16 {
    u16::from_le_bytes([message[15], message[16]])
}

fn ok_bytes(expected: &Json) -> Option<Vec<u8>> {
    expected
        .get("ok")
        .map(|ok| hex(ok["bytes"].as_str().unwrap()))
}

fn assert_address(actual: &Address, want: &Json, ctx: &str) {
    assert_eq!(
        actual.file_type.name(),
        want["file_type"].as_str().unwrap(),
        "{ctx}"
    );
    assert_eq!(
        u64::from(actual.file_number),
        want["file_number"].as_u64().unwrap(),
        "{ctx}"
    );
    assert_eq!(
        u64::from(actual.element_number),
        want["element_number"].as_u64().unwrap(),
        "{ctx}"
    );
    assert_eq!(
        actual.pos_number.map(u64::from),
        want["pos_number"].as_u64(),
        "{ctx}"
    );
    assert_eq!(
        actual.sub_element.map(u64::from),
        want["sub_element"].as_u64(),
        "{ctx}"
    );
    assert_eq!(
        actual.bit,
        want["address_field"].as_u64().unwrap() == 3,
        "{ctx}"
    );
    assert_eq!(
        actual.element_count as u64,
        want["element_count"].as_u64().unwrap(),
        "{ctx}"
    );
    assert_eq!(actual.tag, want["tag"].as_str().unwrap(), "{ctx}");
}

/// asserts a Rust error has the class and message Python raised
fn assert_err(err: &ciplink::Error, expected: &Json, ctx: &str) {
    let class_name = expected["err"].as_str().unwrap();
    if matches!(
        class_name,
        "DataError" | "BufferEmptyError" | "RequestError" | "ResponseError" | "CommError"
    ) {
        assert_eq!(class(err), class_name, "{ctx}: {err:?}");
        assert_eq!(err.to_string(), expected["msg"].as_str().unwrap(), "{ctx}");
    }
}

fn check_msg<T: std::fmt::Debug>(
    result: Result<T, ciplink::Error>,
    expected: &Json,
    ctx: &str,
    ok: impl FnOnce(&T, &Json),
) {
    match (&result, expected.get("ok")) {
        (Ok(value), Some(want)) => ok(value, want),
        (Err(err), None) => assert_err(err, expected, ctx),
        _ => panic!("{ctx}: got {result:?}, expected {expected}"),
    }
}

#[test]
fn tables_match_python() {
    let fixture = fixture();
    for case in cases(&fixture, "tables") {
        if let Some(name) = case["name"].as_str() {
            let typ = FileType::from_name(name).unwrap();
            assert_eq!(typ.name(), name);
            assert_eq!(
                u64::from(typ.code()),
                case["code"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                typ.element_size() as u64,
                case["size"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(FileType::from_code(typ.code()), Some(typ));
        } else {
            let ct = case["ct"].as_str().unwrap();
            assert_eq!(
                pccc::ct_bit(ct).map(u64::from),
                case["value"].as_u64(),
                "{ct}"
            );
        }
    }
    assert_eq!(FileType::from_code(0x81), None);
    assert_eq!(pccc::ct_bit("XX"), None);
}

#[test]
fn parse_tag_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "parse_tag") {
        let address = case["address"].as_str().unwrap();
        let ctx = format!("{address:?}");
        match (pccc::parse_tag(address), &case["result"]) {
            (None, Json::Null) => {}
            (Some(actual), want) if !want.is_null() => assert_address(&actual, want, &ctx),
            (actual, want) => panic!("{ctx}: got {actual:?}, expected {want}"),
        }
    }
}

#[test]
fn pccc_strings_match_python() {
    let fixture = fixture();
    for case in cases(&fixture, "strings") {
        let ctx = case.to_string();
        let ascii = case["type"].as_str().unwrap() == "PCCC_ASCII";
        if case["op"] == "encode" {
            let Some(value) = input(&case["value"]) else {
                // Python's None encodes like an empty string
                let bytes = if ascii {
                    pccc::encode_pccc_ascii(&Value::String(String::new()))
                } else {
                    pccc::encode_pccc_string(&Value::String(String::new()))
                };
                check_msg(bytes, &case["result"], &ctx, |b, want| {
                    assert_eq!(to_hex(b), want["bytes"].as_str().unwrap(), "{ctx}")
                });
                continue;
            };
            let bytes = if ascii {
                pccc::encode_pccc_ascii(&value)
            } else {
                pccc::encode_pccc_string(&value)
            };
            check_msg(bytes, &case["result"], &ctx, |b, want| {
                assert_eq!(to_hex(b), want["bytes"].as_str().unwrap(), "{ctx}")
            });
        } else {
            let raw = hex(case["raw"].as_str().unwrap());
            let mut reader = Reader::new(&raw);
            let text = if ascii {
                Ok(pccc::decode_pccc_ascii(&mut reader))
            } else {
                pccc::decode_pccc_string(&mut reader)
            };
            check_msg(text, &case["result"], &ctx, |s, want| {
                assert_eq!(s, want["str"].as_str().unwrap(), "{ctx}")
            });
        }
    }
}

#[test]
fn writeable_value_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "writeable_value") {
        let ctx = case.to_string();
        let Some(address) = pccc::parse_tag(case["address"].as_str().unwrap()) else {
            continue; // Python fails on the None address itself
        };
        let Some(value) = input(&case["value"]) else {
            continue; // no Value for Python's None
        };
        check_msg(
            pccc::writeable_value(&address, &value),
            &case["result"],
            &ctx,
            |b, want| assert_eq!(to_hex(b), want["bytes"].as_str().unwrap(), "{ctx}"),
        );
    }
}

#[test]
fn read_request_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "read_request") {
        let address = case["address"].as_str().unwrap();
        let ctx = case.to_string();
        let expected = &case["result"];
        let seq = ok_bytes(expected).map_or(1, |m| seq_of(&m));
        check_msg(
            pccc::read_request(address, &requestor(), seq),
            expected,
            &ctx,
            |(addr, msg), want| {
                assert_eq!(to_hex(msg), want["bytes"].as_str().unwrap(), "{ctx}");
                assert_eq!(Some(addr), pccc::parse_tag(address).as_ref(), "{ctx}");
            },
        );
    }
}

#[test]
fn write_request_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "write_request") {
        let address = case["address"].as_str().unwrap();
        let ctx = case.to_string();
        let Some(value) = input(&case["value"]) else {
            continue;
        };
        let expected = &case["result"];
        let seq = ok_bytes(expected).map_or(1, |m| seq_of(&m));
        check_msg(
            pccc::write_request(address, &value, &requestor(), seq),
            expected,
            &ctx,
            |(_, msg), want| assert_eq!(to_hex(msg), want["bytes"].as_str().unwrap(), "{ctx}"),
        );
    }
}

#[test]
fn read_reply_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "read_reply") {
        let ctx = case.to_string();
        let data = hex(case["data"].as_str().unwrap());
        let Some(address) = pccc::parse_tag(case["address"].as_str().unwrap()) else {
            assert_eq!(case["result"]["err"], "ResponseError", "{ctx}");
            continue;
        };
        check_msg(
            pccc::parse_read_reply(&address, &data),
            &case["result"],
            &ctx,
            |v, want| assert_value(v, want, &ctx),
        );
    }
}

#[test]
fn request_status_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "request_status") {
        let raw = hex(case["raw"].as_str().unwrap());
        assert_eq!(
            pccc::request_status(&raw).as_deref(),
            case["result"].as_str(),
            "{case}"
        );
    }
}

#[test]
fn processor_type_matches_python() {
    let fixture = fixture();
    let request = ok_bytes(&cases(&fixture, "processor_type_request")[0]["request"]).unwrap();
    assert_eq!(
        pccc::processor_type_request(&requestor(), seq_of(&request)),
        request
    );
    for case in cases(&fixture, "processor_type_reply") {
        let raw = hex(case["raw"].as_str().unwrap());
        let actual = match pccc::request_status(&raw) {
            Some(_) => None,
            None => pccc::parse_processor_type(&raw),
        };
        assert_eq!(actual.as_deref(), case["result"]["str"].as_str(), "{case}");
    }
}

#[test]
fn datalog_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "datalog_request") {
        let queue = case["queue"].as_i64().unwrap();
        let Ok(queue) = u8::try_from(queue) else {
            assert_eq!(case["result"]["err"], "DataError", "{case}");
            continue;
        };
        let want = ok_bytes(&case["result"]).unwrap();
        assert_eq!(
            to_hex(&pccc::datalog_request(queue)),
            to_hex(&want),
            "{case}"
        );
    }
    for case in cases(&fixture, "datalog_reply") {
        let ctx = case.to_string();
        let raw = hex(case["raw"].as_str().unwrap());
        if pccc::request_status(&raw).is_some() {
            assert!(case["result"].is_null(), "{ctx}");
            continue;
        }
        assert_value(&pccc::parse_datalog(&raw), &case["result"], &ctx);
    }
}

fn want_sys0(want: &Json) -> Sys0Info {
    let items = want["dict"].as_array().unwrap();
    let get = |key: &str| items.iter().find(|kv| kv[0] == key).map(|kv| kv[1].clone());
    let byte = |key: &str| hex(get(key).unwrap()["bytes"].as_str().unwrap())[0];
    Sys0Info {
        file_position: get("file_position").unwrap()["int"].as_u64().unwrap() as usize,
        row_size: get("row_size").unwrap()["int"].as_u64().unwrap() as usize,
        file_type: byte("file_type"),
        size_element: byte("size_element"),
        size_len: byte("size_len"),
        size_const: get("size_const").map_or(0, |v| v["int"].as_u64().unwrap() as u16),
    }
}

#[test]
fn sys0_info_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "sys0_info") {
        let plc = case["plc_type"].as_str().unwrap();
        assert_eq!(pccc::sys0_info(plc), want_sys0(&case["result"]), "{plc}");
    }
}

#[test]
fn file_directory_size_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "file_directory_size") {
        let info = pccc::sys0_info(case["plc_type"].as_str().unwrap());
        let request = ok_bytes(&case["request"]).unwrap();
        assert_eq!(
            to_hex(&pccc::file_directory_size_request(
                &info,
                &requestor(),
                seq_of(&request)
            )),
            to_hex(&request),
            "{case}"
        );
        for reply in case["replies"].as_array().unwrap() {
            let raw = hex(reply["raw"].as_str().unwrap());
            let actual = match pccc::request_status(&raw) {
                Some(_) => None,
                None => pccc::parse_file_directory_size(&raw, &info),
            };
            assert_eq!(
                actual.map(i64::from),
                reply["result"]["int"].as_i64(),
                "{reply}"
            );
        }
    }
}

#[test]
fn file_directory_read_loop_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "file_directory_read") {
        let ctx = case.to_string();
        let size = case["size"].as_i64().unwrap();
        let file_type = hex(case["file_type"].as_str().unwrap())[0];
        let lengths: Vec<usize> = case["reply_lengths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as usize)
            .collect();
        let want_requests: Vec<Vec<u8>> = case["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| hex(r.as_str().unwrap()))
            .collect();
        if case.get("status_error").is_some() {
            let reply = [vec![0u8; 58], vec![0x10, 0, 0]].concat();
            let msg = format!(
                "Error reading File 0 contents: {}",
                pccc::request_status(&reply).unwrap()
            );
            assert_eq!(msg, case["result"]["msg"].as_str().unwrap(), "{ctx}");
            continue;
        }
        // the driver's loop over the pure builders
        let mut data = Vec::new();
        let mut offset = 0usize;
        let mut sent = Vec::new();
        let mut replies = lengths.iter();
        while (data.len() as i64) < size {
            let remaining = size as usize - data.len();
            let chunk = remaining.min(usize::from(FILE_DIRECTORY_CHUNK)) as u8;
            let seq = seq_of(&want_requests[sent.len()]);
            let msg =
                pccc::file_directory_read_request(file_type, offset, chunk, &requestor(), seq)
                    .unwrap();
            sent.push(msg);
            let n = *replies.next().unwrap();
            data.extend(vec![0u8; n]);
            offset += n / 2;
        }
        assert_eq!(sent, want_requests, "{ctx}");
        assert_eq!(
            to_hex(&data),
            case["result"]["ok"]["bytes"].as_str().unwrap(),
            "{ctx}"
        );
    }
}

#[test]
fn parse_file_directory_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "parse_file0") {
        let ctx = case.to_string();
        let data = hex(case["data"].as_str().unwrap());
        let pos = case["file_position"].as_u64().unwrap() as usize;
        let row = case["row_size"].as_u64().unwrap() as usize;
        check_msg(
            pccc::parse_file_directory(pos, row, &data),
            &case["result"],
            &ctx,
            |files, want| {
                let want = want["dict"].as_array().unwrap();
                assert_eq!(files.len(), want.len(), "{ctx}");
                for ((name, file), kv) in files.iter().zip(want) {
                    assert_eq!(name, kv[0].as_str().unwrap(), "{ctx}");
                    let fields = kv[1]["dict"].as_array().unwrap();
                    assert_eq!(file.elements as u64, fields[0][1]["int"].as_u64().unwrap());
                    assert_eq!(
                        u64::from(file.length),
                        fields[1][1]["int"].as_u64().unwrap()
                    );
                }
            },
        );
    }
}

#[test]
fn get_bit_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "get_bit") {
        let value = case["value"].as_i64().unwrap();
        let idx = case["idx"].as_u64().unwrap() as u32;
        assert_eq!(
            pccc::get_bit(value, idx),
            case["result"].as_bool().unwrap(),
            "{case}"
        );
    }
}

// --- intent of tools/reference/tests/offline/test_slc_driver.py, test_slc.py and test_pccc_string.py ---

#[test]
fn b_file_bit_address_uses_word_and_bit() {
    let t = pccc::parse_tag("B3/17").unwrap();
    assert_eq!((t.element_number, t.sub_element), (1, Some(1)));
    assert_eq!(
        pccc::writeable_value(&t, &Value::Bool(true)).unwrap(),
        b"\x02\x00\x02\x00"
    );
}

#[test]
fn parse_tag_rejects_trailing_characters() {
    assert!(pccc::parse_tag("N7:1000").is_none());
    assert!(pccc::parse_tag("N7:0/3x").is_none());
    assert_eq!(pccc::parse_tag("N7:0{10}").unwrap().element_count, 10);
    assert!(pccc::parse_tag("t4:0.acc").is_some());
}

#[test]
fn bit_address_with_element_count_is_rejected() {
    let err = pccc::write_request(
        "N7:0/3{2}",
        &Value::Array(vec![Value::Int(1), Value::Int(1)]),
        &requestor(),
        1,
    )
    .unwrap_err();
    assert_eq!(class(&err), "RequestError");
    assert_eq!(
        err.to_string(),
        "Error parsing the tag passed to write() - N7:0/3{2}"
    );
    let err = pccc::read_request("B3/3{2}", &requestor(), 1).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Error parsing the tag passed to read() - B3/3{2}"
    );
}

#[test]
fn address_fields_of_255_are_escaped() {
    let (_, read) = pccc::read_request("N255:255", &requestor(), 1).unwrap();
    let (_, write) = pccc::write_request("N255:255", &Value::Int(1), &requestor(), 1).unwrap();
    for msg in [&read[13..], &write[13..]] {
        assert_eq!(&msg[6..9], b"\xff\xff\x00");
        assert_eq!(msg[9], 0x89);
        assert_eq!(&msg[10..13], b"\xff\xff\x00");
        assert_eq!(msg[13], 0);
    }
}

#[test]
fn file_directory_offset_of_255_is_escaped() {
    let msg = pccc::file_directory_read_request(1, 255, 10, &requestor(), 1).unwrap();
    assert_eq!(&msg[msg.len() - 4..], b"\x01\xff\xff\x00");
    let err = pccc::file_directory_read_request(1, 70_000, 10, &requestor(), 1).unwrap_err();
    assert_eq!(class(&err), "DataError");
}

#[test]
fn write_timer_preset_targets_pre_word() {
    let (_, msg) = pccc::write_request("T4:0.PRE", &Value::Int(1000), &requestor(), 1).unwrap();
    let msg = &msg[13..];
    assert_eq!(msg[5], 2);
    assert_eq!(msg[9], 1);
    assert_eq!(&msg[msg.len() - 2..], 1000u16.to_le_bytes());
}

#[test]
fn write_counter_acc_and_bit_sizes() {
    let (_, msg) = pccc::write_request("C5:3.ACC", &Value::Int(7), &requestor(), 1).unwrap();
    assert_eq!((msg[13 + 5], msg[13 + 8], msg[13 + 9]), (2, 3, 2));
    let (_, msg) = pccc::write_request("T4:0.DN", &Value::Bool(true), &requestor(), 1).unwrap();
    assert_eq!((msg[13 + 5], msg[13 + 9]), (2, 0));
    assert_eq!(&msg[msg.len() - 4..], [0x00, 0x20, 0x00, 0x20]);
    let values = Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
    let (_, msg) = pccc::write_request("N7:0{3}", &values, &requestor(), 1).unwrap();
    assert_eq!((msg[13 + 5], msg[13 + 9]), (6, 0));
}

#[test]
fn pccc_string_encodes_full_84_byte_element() {
    let s = |t: &str| Value::String(t.into());
    assert_eq!(pccc::encode_pccc_string(&s("AB")).unwrap().len(), 84);
    assert_eq!(pccc::encode_pccc_string(&s("")).unwrap().len(), 84);
    let long = pccc::encode_pccc_string(&s(&"x".repeat(100))).unwrap();
    assert_eq!((long.len(), &long[..2]), (84, &b"\x52\x00"[..]));
    let abc = pccc::encode_pccc_string(&s("ABC")).unwrap();
    assert_eq!(
        pccc::decode_pccc_string(&mut Reader::new(&abc)).unwrap(),
        "ABC"
    );
    // odd length: unpadded length header, nulls after the data (#314)
    let enc = pccc::encode_pccc_string(&s("123")).unwrap();
    assert_eq!(&enc[..6], b"\x03\x00\x32\x31\x00\x33");
    // decoding honours the length header and drops garbage (#230)
    let raw = [&b"\x03\x00\x42\x41\x00\x43"[..], &[0xFF; 78]].concat();
    assert_eq!(
        pccc::decode_pccc_string(&mut Reader::new(&raw)).unwrap(),
        "ABC"
    );
    assert_eq!(pccc::encode_pccc_ascii(&s("A")).unwrap(), b" A");
    assert_eq!(pccc::encode_pccc_ascii(&s("")).unwrap(), b"  ");
}

#[test]
fn pccc_strings_reject_non_latin1() {
    let s = |t: &str| Value::String(t.into());
    assert_eq!(
        class(&pccc::encode_pccc_string(&s("€")).unwrap_err()),
        "DataError"
    );
    assert_eq!(
        class(&pccc::encode_pccc_ascii(&s("€A")).unwrap_err()),
        "DataError"
    );
    let cafe = pccc::encode_pccc_string(&s("café")).unwrap();
    assert_eq!(
        pccc::decode_pccc_string(&mut Reader::new(&cafe)).unwrap(),
        "café"
    );
}

#[test]
fn write_string_pair_declares_what_is_sent() {
    let values = Value::Array(vec![
        Value::String("abc".into()),
        Value::String("de".into()),
    ]);
    let (_, msg) = pccc::write_request("ST9:0{2}", &values, &requestor(), 1).unwrap();
    let msg = &msg[13..];
    assert_eq!(msg[5], 168);
    assert_eq!(msg[12..].len(), 168);
    assert_eq!(
        pccc::decode_pccc_string(&mut Reader::new(&msg[12 + 84..])).unwrap(),
        "de"
    );
}

#[test]
fn request_status_reports_ext_sts() {
    let reply = |sts: u8, extra: &[u8]| [vec![0u8; 58], vec![sts, 0, 0], extra.to_vec()].concat();
    assert_eq!(pccc::request_status(&reply(0, b"\x01\x00")), None);
    assert!(
        pccc::request_status(&reply(0xF0, b"\x07"))
            .unwrap()
            .contains("EXT STS 0x07")
    );
    assert!(
        pccc::request_status(&reply(0x55, b""))
            .unwrap()
            .contains("0x55")
    );
}

#[test]
fn processor_type_is_read_from_reply() {
    let raw = [
        vec![0u8; SLC_REPLY_START + 5],
        b"1766-LEC   ".to_vec(),
        vec![0; 3],
    ]
    .concat();
    assert_eq!(
        pccc::parse_processor_type(&raw).as_deref(),
        Some("1766-LEC")
    );
}

#[test]
fn parse_file_directory_input_file_is_always_file_1() {
    let rows = |codes: &[u8]| -> Vec<u8> {
        codes
            .iter()
            .flat_map(|&c| [&[c, 20, 0][..], &[0; 7]].concat())
            .collect()
    };
    let files =
        pccc::parse_file_directory(0, 10, &rows(&[0x83, 0x84, 0x85, 0x89, 0x8A, 0x86])).unwrap();
    let names: Vec<&str> = files.keys().map(String::as_str).collect();
    assert_eq!(names, ["I1", "S2", "B3", "N4", "F5", "T6"]);
    let files =
        pccc::parse_file_directory(0, 10, &rows(&[0x82, 0x83, 0x84, 0x81, 0x89, 0x8A])).unwrap();
    let names: Vec<&str> = files.keys().map(String::as_str).collect();
    assert_eq!(names, ["O0", "I1", "S2", "N4", "F5"]);
    assert_eq!((files["F5"].elements, files["F5"].length), (5, 20));
}

#[test]
fn parse_file_directory_rejects_zero_row_size() {
    assert!(pccc::parse_file_directory(0, 0, &[0x89, 2, 0]).is_err());
}

#[test]
fn file_directory_size_subtracts_constant() {
    let info = pccc::sys0_info("1766-LEC");
    let raw = [vec![0u8; SLC_REPLY_START], 20000u16.to_le_bytes().to_vec()].concat();
    assert_eq!(pccc::parse_file_directory_size(&raw, &info), Some(32));
    assert_eq!(
        pccc::parse_file_directory_size(&raw[..SLC_REPLY_START], &info),
        None
    );
}

#[test]
fn datalog_entry_is_text_or_bytes() {
    let raw = |extra: &[u8]| [vec![0u8; SLC_REPLY_START], extra.to_vec()].concat();
    assert_eq!(
        pccc::parse_datalog(&raw(b"abc")),
        Value::String("abc".into())
    );
    assert_eq!(
        pccc::parse_datalog(&raw(b"\xff\xfe")),
        Value::Bytes(vec![0xff, 0xfe])
    );
}

#[test]
fn writeable_value_error_includes_cause() {
    let t = pccc::parse_tag("N7:0").unwrap();
    let err = pccc::writeable_value(&t, &Value::String("abc".into())).unwrap_err();
    assert_eq!(class(&err), "RequestError");
    assert!(err.to_string().contains("Error packing"));
}

#[test]
fn short_replies_never_panic() {
    for address in [
        "N7:0", "T4:0.ACC", "T4:0.PRE", "ST9:0", "A10:0", "F8:0/3", "B3/17",
    ] {
        let t = pccc::parse_tag(address).unwrap();
        for n in 0..90 {
            let _ = pccc::parse_read_reply(&t, &vec![0xAB; n]);
        }
    }
    for n in 0..80 {
        let raw = vec![0xF0; n];
        let _ = pccc::request_status(&raw);
        let _ = pccc::parse_processor_type(&raw);
        let _ = pccc::parse_datalog(&raw);
        let _ = pccc::parse_file_directory_size(&raw, &pccc::sys0_info(""));
        let _ = pccc::parse_file_directory(3, 10, &raw);
    }
}

#[test]
fn parse_tag_never_panics_on_prefixes_and_multibyte_text() {
    let fixture = fixture();
    for case in cases(&fixture, "parse_tag") {
        let address = case["address"].as_str().unwrap();
        for (i, _) in address.char_indices() {
            let _ = pccc::parse_tag(&address[..i]);
            let _ = pccc::parse_tag(&format!("{}é{{", &address[..i]));
        }
    }
    for odd in [
        "T4:1é",
        "T4:€ACC",
        "N7:0{€}",
        "ST9:0{",
        "I:0.",
        "B3/{1}",
        "T4:9999",
    ] {
        assert_eq!(pccc::parse_tag(odd), None, "{odd}");
    }
}
