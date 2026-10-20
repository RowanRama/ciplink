//! SlcDriver parity with the Python SLCDriver (fixtures from tools/fixtures/gen_slc_driver.py), and the
//! driver scenarios of tools/reference/tests/offline/test_slc_driver.py and test_slc.py, run against the scripted fake
//! transport.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::cip::{CipOptions, TagResult};
use ciplink::slc::driver::SlcDriver;
use ciplink::{Error, ErrorKind, Value};
use common::fake::{self, Fake};
use common::{assert_value, class, hex, input, to_hex};
use serde_json::Value as Json;

const CID: [u8; 4] = [0xDD, 0xCC, 0xBB, 0xAA];

fn driver(path: &str, fake: &Fake) -> SlcDriver {
    SlcDriver::with_connector(path, SlcDriver::default_options(), fake.connector()).unwrap()
}

/// A PCCC Execute reply: requestor ID, CMD, STS, TNS, then `payload` (from byte 61).
fn pccc_reply(payload: &[u8], sts: u8, cip_status: u8) -> Vec<u8> {
    let mut data = vec![0x07, 0x09, 0x10, 0, 0, 0, 0, 0x4F, sts, 0x01, 0x00];
    data.extend(payload);
    fake::unit_reply(CID, 1, 0x4B, cip_status, &[], &data)
}

/// A driver with an open session and CIP connection; the opening frames are taken off the sent list.
fn connected(fake: &Fake) -> SlcDriver {
    fake.reply(fake::register_reply(1))
        .reply(fake::forward_open_reply(false, CID));
    let d = driver("1.2.3.4/0", fake);
    assert!(d.open().unwrap());
    // open the CIP connection with a processor type request
    fake.reply(pccc_reply(&[0; 16], 0, 0));
    d.get_processor_type().unwrap();
    fake.take_sent();
    d
}

/// The PCCC command bytes of a sent frame, after the 13-byte message start (Python's `_sent_pccc`).
fn sent_pccc(frame: &[u8]) -> Vec<u8> {
    fake::sent_message(frame)[13..].to_vec()
}

// ---- fixture replay ----

/// The Forward Open triad of a sent frame (masked), and the vsn of a Forward Open.
fn mask_triad(frame: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut f = frame.to_vec();
    let mut vsn = None;
    if f.first() == Some(&0x6F) && f.len() >= 56 {
        match f[40] {
            0x54 | 0x5B if f.len() >= 64 => {
                vsn = Some(f[60..64].to_vec());
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
    (f, vsn)
}

/// Masks the random parts of the sent frames: the triad, and the requestor serial number of the PCCC
/// messages, which must be the vsn of the latest Forward Open (Python's `_cfg["vsn"]`).
fn mask(frames: &[Vec<u8>], ctx: &str) -> Vec<String> {
    let mut vsn = vec![0x09, 0x10, 0x19, 0x71];
    frames
        .iter()
        .map(|frame| {
            let (mut f, fo_vsn) = mask_triad(frame);
            if let Some(v) = fo_vsn {
                vsn = v;
            }
            if f.first() == Some(&0x70)
                && f.len() >= 59
                && f[46..55] == [0x4B, 0x02, 0x20, 0x67, 0x24, 0x01, 0x07, 0x09, 0x10]
            {
                assert_eq!(f[55..59], vsn[..], "{ctx}: requestor vsn");
                f[55..59].fill(0);
            }
            to_hex(&f)
        })
        .collect()
}

fn tag_json(t: &TagResult) -> Json {
    serde_json::json!({
        "tag": t.tag,
        "type": t.data_type,
        "error": t.error.as_ref().map(|e| e.message.clone()),
        "kind": t.error.as_ref().map(|e| e.kind.as_str()),
    })
}

fn check_tags(got: &[TagResult], want: &Json, ctx: &str) {
    let want = want.as_array().unwrap();
    assert_eq!(got.len(), want.len(), "{ctx}: count");
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        let ctx = format!("{ctx}[{i}]");
        let mut w_meta = w.clone();
        w_meta.as_object_mut().unwrap().remove("value");
        assert_eq!(tag_json(g), w_meta, "{ctx}");
        match (&g.value, &w["value"]) {
            (None, Json::Null) => {}
            (Some(v), want) if !want.is_null() => assert_value(v, want, &ctx),
            (got, want) => panic!("{ctx}: value {got:?}, expected {want}"),
        }
    }
}

enum Out {
    Bool(bool),
    Unit,
    Size(u16),
    Tags(Vec<TagResult>),
    Text(Option<String>),
    Log(Vec<Option<Value>>),
    Files(Vec<(String, usize, u16)>),
}

fn run(d: &SlcDriver, call: &Json) -> ciplink::Result<Out> {
    let args = &call["args"];
    Ok(match call["op"].as_str().unwrap() {
        "open" => Out::Bool(d.open()?),
        "close" => d.close().map(|_| Out::Unit)?,
        "connection_size" => Out::Size(d.cip().connection_size()),
        "read" => {
            let addrs: Vec<&str> = args
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            Out::Tags(d.read(&addrs)?)
        }
        "write" => {
            let pairs: Vec<(&str, Value)> = args
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_str().unwrap(), input(&p[1]).unwrap()))
                .collect();
            Out::Tags(d.write(&pairs)?)
        }
        "get_processor_type" => Out::Text(d.get_processor_type()?),
        "get_datalog_queue" => Out::Log(d.get_datalog_queue(
            args[0].as_u64().unwrap() as usize,
            args[1].as_u64().unwrap() as u8,
        )?),
        "get_file_directory" => Out::Files(
            d.get_file_directory()?
                .into_iter()
                .map(|(name, f)| (name, f.elements, f.length))
                .collect(),
        ),
        other => panic!("unknown op {other}"),
    })
}

fn check_result(result: ciplink::Result<Out>, want: &Json, ctx: &str) {
    match (result, want.get("ok"), want.get("err")) {
        (Ok(out), Some(ok), None) => match out {
            Out::Bool(b) => assert_eq!(Json::Bool(b), *ok, "{ctx}"),
            Out::Unit => assert!(ok.is_null(), "{ctx}"),
            Out::Size(size) => assert_eq!(Json::from(size), *ok, "{ctx}"),
            Out::Tags(tags) => check_tags(&tags, ok, ctx),
            Out::Text(t) => assert_eq!(t.map(Json::String).unwrap_or(Json::Null), *ok, "{ctx}"),
            Out::Log(entries) => {
                let want = ok["list"].as_array().unwrap();
                assert_eq!(entries.len(), want.len(), "{ctx}");
                for (e, w) in entries.iter().zip(want) {
                    match e {
                        None => assert!(w.is_null(), "{ctx}"),
                        Some(v) => assert_value(v, w, ctx),
                    }
                }
            }
            Out::Files(files) => {
                let want = ok["dict"].as_array().unwrap();
                let got: Vec<Json> = files
                    .iter()
                    .map(|(name, elements, length)| {
                        serde_json::json!([name, {"dict": [["elements", {"int": elements}], ["length", {"int": length}]]}])
                    })
                    .collect();
                assert_eq!(&got, want, "{ctx}");
            }
        },
        (Err(err), None, Some(class_name)) => {
            assert_eq!(class(&err), class_name.as_str().unwrap(), "{ctx}: {err:?}");
            assert_eq!(err.to_string(), want["msg"].as_str().unwrap(), "{ctx}");
        }
        (Ok(_), _, _) => panic!("{ctx}: ok, expected {want}"),
        (Err(err), _, _) => panic!("{ctx}: {err:?}, expected {want}"),
    }
}

/// Replays the scenarios of a fixture; a null reply is a receive that fails.
fn replay(fixture_name: &str) {
    let fixture = common::load(fixture_name);
    for case in common::cases(&fixture, "scenarios") {
        let name = case["name"].as_str().unwrap();
        let fake = Fake::new();
        for r in case["replies"].as_array().unwrap() {
            match r.as_str() {
                Some(r) => fake.reply(hex(r)),
                None => fake.reply_err(Error::comm("timed out")),
            };
        }
        let mut options = SlcDriver::default_options();
        if let Some(size) = case["options"]["connection_size"].as_u64() {
            options.connection_size = size as u16;
        }
        let d =
            SlcDriver::with_connector(case["path"].as_str().unwrap(), options, fake.connector())
                .unwrap();
        let calls = case["calls"].as_array().unwrap();
        let results = case["results"].as_array().unwrap();
        assert_eq!(calls.len(), results.len());
        for (i, (call, want)) in calls.iter().zip(results).enumerate() {
            check_result(run(&d, call), want, &format!("{name}[{i}] {call}"));
        }
        let want: Vec<Vec<u8>> = case["sent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| hex(f.as_str().unwrap()))
            .collect();
        assert_eq!(
            mask(&fake.sent(), name),
            mask(&want, name),
            "{name}: sent frames"
        );
    }
}

#[test]
fn scenarios_send_the_same_frames_and_return_the_same_results_as_python() {
    replay("slc_driver.json");
}

#[test]
fn edge_scenarios_send_the_same_frames_and_return_the_same_results_as_python() {
    // transport failure mid-read, Large+standard FO rejected then retried, more address forms, write
    // value edge cases, encapsulation errors, empty datalog queue, processor type text, directory edges
    replay("slc_driver_extra.json");
}

#[test]
fn parity_scenarios_send_the_same_frames_and_return_the_same_results_as_python() {
    // the Forward Open error of every call, empty reads and writes, calls after close(), transport failures
    // in the directory size, directory chunk and datalog loops, and write values of the wrong shape
    replay("slc_driver_parity.json");
}

#[test]
fn transaction_code_and_packet_sequence_share_the_wrapping_counter() {
    // Python: cycle(65535, start=1), one next() for the PCCC transaction code, then one for the packet; read
    // k uses 2k-1 and 2k, so read 32768 takes 65535 and wraps to 1 for its packet
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let d = responding(move |sequence, message| {
        let tns = u16::from_le_bytes([message[15], message[16]]);
        log.lock().unwrap().push((tns, sequence));
        pccc_reply(&[1, 0], 0, 0)
    });
    for _ in 0..32769 {
        d.read(&["N7:0"]).unwrap();
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], (1, 2));
    assert_eq!(seen[32766], (65533, 65534));
    assert_eq!(seen[32767], (65535, 1));
    assert_eq!(seen[32768], (2, 3));
}

// ---- test_slc_driver.py ----

#[test]
fn bit_address_with_element_count_is_rejected_without_sending() {
    // test_bit_address_with_element_count_is_rejected
    let fake = Fake::new();
    let d = connected(&fake);
    let err = d.write(&[("N7:0/3{2}", Value::Array(vec![Value::DInt(1); 2]))]);
    assert!(matches!(err, Err(Error::Request { .. })), "{err:?}");
    let err = d.read(&["B3/3{2}"]);
    assert!(matches!(err, Err(Error::Request { .. })), "{err:?}");
    assert!(fake.sent().is_empty());
}

#[test]
fn address_fields_of_255_are_escaped() {
    // test_address_fields_of_255_are_escaped
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(&[1, 0], 0, 0))
        .reply(pccc_reply(&[], 0, 0));
    d.read(&["N255:255"]).unwrap();
    d.write(&[("N255:255", Value::DInt(1))]).unwrap();
    for frame in fake.sent() {
        let msg = sent_pccc(&frame);
        assert_eq!(msg[6..9], [0xFF, 0xFF, 0x00]); // file number
        assert_eq!(msg[9], 0x89); // file type N
        assert_eq!(msg[10..13], [0xFF, 0xFF, 0x00]); // element
        assert_eq!(msg[13], 0x00); // sub-element
    }
}

#[test]
fn file_directory_offset_of_255_is_escaped() {
    // test_file_directory_offset_of_255_is_escaped
    let fake = Fake::new();
    let d = connected(&fake);
    let mut ptype = vec![0; 5];
    ptype.extend(b"1747-L551  \0\0\0");
    fake.reply(pccc_reply(&ptype, 0, 0))
        .reply(pccc_reply(&520u16.to_le_bytes(), 0, 0))
        .reply(pccc_reply(&[0; 510], 0, 0))
        .reply(pccc_reply(&[0; 10], 0, 0));
    assert!(d.get_file_directory().unwrap().is_empty());
    let sent = fake.sent();
    assert_eq!(sent.len(), 4);
    let last = sent_pccc(&sent[3]);
    assert_eq!(last[last.len() - 4..], [0x01, 0xFF, 0xFF, 0x00]);
}

#[test]
fn write_timer_preset_targets_pre_word() {
    // test_write_timer_preset_targets_pre_word
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(&[], 0, 0));
    d.write(&[("T4:0.PRE", Value::DInt(1000))]).unwrap();
    let msg = sent_pccc(&fake.sent()[0]);
    assert_eq!(msg[5], 2); // byte size: one word
    assert_eq!(msg[9], 1); // sub-element: PRE
    assert_eq!(msg[msg.len() - 2..], 1000u16.to_le_bytes());
}

#[test]
fn write_counter_acc_and_bit_sizes() {
    // test_write_counter_acc_and_bit_sizes
    let fake = Fake::new();
    let d = connected(&fake);
    fake.respond(|_| Ok(pccc_reply(&[], 0, 0)));
    d.write(&[("C5:3.ACC", Value::DInt(7))]).unwrap();
    d.write(&[("T4:0.DN", Value::Bool(true))]).unwrap();
    d.write(&[(
        "N7:0{3}",
        Value::Array(vec![Value::DInt(1), Value::DInt(2), Value::DInt(3)]),
    )])
    .unwrap();
    let sent = fake.sent();
    let msg = sent_pccc(&sent[0]);
    assert_eq!((msg[5], msg[8], msg[9]), (2, 3, 2));
    let msg = sent_pccc(&sent[1]);
    assert_eq!((msg[5], msg[9]), (2, 0)); // bit writes go to the control word
    assert_eq!(msg[msg.len() - 4..], [0x00, 0x20, 0x00, 0x20]);
    let msg = sent_pccc(&sent[2]);
    assert_eq!((msg[5], msg[9]), (6, 0));
}

#[test]
fn write_string_pair_declares_what_is_sent() {
    // test_write_string_pair_declares_what_is_sent
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(&[], 0, 0));
    let value = Value::Array(vec![
        Value::String("abc".into()),
        Value::String("de".into()),
    ]);
    let result = d.write(&[("ST9:0{2}", value.clone())]).unwrap();
    assert_eq!(result[0].value, Some(value));
    assert_eq!(result[0].data_type.as_deref(), Some("ST"));
    let msg = sent_pccc(&fake.sent()[0]);
    assert_eq!(msg[5], 168);
    assert_eq!(msg[12..].len(), 168);
    assert_eq!(msg[12 + 84..12 + 86], [2, 0]); // second string, length 2
}

#[test]
fn get_processor_type_returns_none_on_pccc_error_and_reads_type() {
    // test_get_processor_type_returns_none_on_pccc_error, test_get_processor_type_reads_type
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(&[0; 19], 0x10, 0));
    assert_eq!(d.get_processor_type().unwrap(), None);
    let mut ptype = vec![0; 5];
    ptype.extend(b"1766-LEC   \0\0\0");
    fake.reply(pccc_reply(&ptype, 0, 0));
    assert_eq!(d.get_processor_type().unwrap().as_deref(), Some("1766-LEC"));
}

#[test]
fn read_errors_report_ext_sts_and_cip_errors() {
    // test_request_status_reports_ext_sts_and_cip_errors
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(&[1, 0], 0, 0))
        .reply(pccc_reply(&[0x07], 0xF0, 0))
        .reply(pccc_reply(&[], 0x55, 0))
        .reply(pccc_reply(&[], 0, 0x08));
    let results = d.read(&["N7:0", "N7:1", "N7:2", "N7:3"]).unwrap();
    assert_eq!(results[0].value, Some(Value::Int(1)));
    let errors: Vec<String> = results[1..]
        .iter()
        .map(|r| r.error.as_ref().unwrap().message.clone())
        .collect();
    assert!(errors[0].contains("EXT STS 0x07"), "{errors:?}");
    assert!(errors[1].contains("0x55"), "{errors:?}");
    assert!(errors[2].starts_with("Service not supported"), "{errors:?}");
    assert!(
        results[1..]
            .iter()
            .all(|r| r.error_kind() == Some(ErrorKind::Other) && r.value.is_none())
    );
}

#[test]
fn get_datalog_queue_reads_entries_then_clears_queue() {
    // test_get_datalog_queue_reads_entries_then_clears_queue, test_get_datalog_entry
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(b"abc", 0, 0))
        .reply(pccc_reply(&[0xFF, 0xFE], 0, 0))
        .reply(pccc_reply(&[], 0x10, 0));
    let entries = d.get_datalog_queue(2, 0).unwrap();
    assert_eq!(
        entries,
        vec![
            Some(Value::String("abc".into())),
            Some(Value::Bytes(vec![0xFF, 0xFE])),
        ]
    );
    assert_eq!(fake.sent().len(), 3);
    fake.reply(pccc_reply(&[], 0x10, 0))
        .reply(pccc_reply(&[], 0x10, 0));
    assert_eq!(d.get_datalog_queue(1, 0).unwrap(), vec![None]);
}

#[test]
fn slc_driver_uses_standard_forward_open_and_slot_paths() {
    // test_slc_driver_uses_standard_forward_open
    let fake = Fake::new();
    let d = driver("192.168.1.100/1", &fake);
    assert_eq!(d.cip().connection_size(), 500);
    assert!(!d.cip().lock().extended_forward_open());
    assert_eq!(d.cip().lock().cip_path().len(), 1); // bp/1
    fake.reply(fake::register_reply(1))
        .reply(fake::rr_reply(0x54, 0x01, &[0x0100], &[]));
    d.open().unwrap();
    assert_eq!(
        d.read(&["N7:0"]),
        Err(Error::response(
            "Target did not connected. read will not be executed."
        ))
    );
    let sent = fake.sent();
    assert_eq!(sent.len(), 2); // no Extended Forward Open attempt first
    assert_eq!(sent[1][40], 0x54);
    // the route of the Forward Open is bp/1, then the message router
    assert_eq!(
        sent[1][sent[1].len() - 6..],
        [0x01, 0x01, 0x20, 0x02, 0x24, 0x01]
    );
    let opts = CipOptions {
        connection_size: 300,
        ..SlcDriver::default_options()
    };
    let d = SlcDriver::with_connector("10.0.0.1", opts, Fake::new().connector()).unwrap();
    assert_eq!(d.cip().connection_size(), 300);
    assert_eq!(d.cip().lock().cip_path().len(), 1); // bp/0
}

#[test]
fn requestor_serial_is_the_vsn_of_the_latest_forward_open() {
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(&[1, 0], 0, 0));
    d.read(&["N7:0"]).unwrap();
    // reopen: a new Forward Open with a new vsn
    fake.reply(fake::rr_reply(0x4E, 0, &[], &[0; 10]));
    d.close().unwrap();
    fake.reply(fake::register_reply(1))
        .reply(fake::forward_open_reply(false, CID))
        .reply(pccc_reply(&[1, 0], 0, 0));
    d.open().unwrap();
    d.read(&["N7:0"]).unwrap();
    let sent = fake.sent();
    let fo = sent
        .iter()
        .rfind(|f| f[0] == 0x6F && f[40] == 0x54)
        .unwrap();
    let last = sent.last().unwrap();
    assert_eq!(last[55..59], fo[60..64]);
}

#[test]
fn transport_failure_mid_read_is_a_comm_error_and_drops_the_connection() {
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply_err(Error::comm("timed out"));
    assert_eq!(
        d.read(&["N7:0"]),
        Err(Error::comm("failed to receive reply"))
    );
    assert!(!d.connected());
}

#[test]
fn send_failure_mid_write_is_a_comm_error_and_needs_a_new_session() {
    // CIPDriver.send/_send: "failed to send message", _drop_connection; the next call's Forward Open
    // finds no session
    let fake = Fake::new();
    let d = connected(&fake);
    fake.fail_send(Error::comm("reset"));
    assert_eq!(
        d.write(&[("N7:0", Value::DInt(1))]),
        Err(Error::comm("failed to send message"))
    );
    assert!(!d.connected());
    let err = d.get_datalog_queue(1, 0).unwrap_err();
    assert_eq!(class(&err), "CommError");
    assert!(
        err.to_string().starts_with("A session must be registered"),
        "{err}"
    );
    assert_eq!(fake.sent().len(), 1); // nothing sent after the failure
}

#[test]
fn driver_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<SlcDriver>();
}

// ---- test_slc.py ----

#[test]
fn read_tag_raises_request_error_for_an_invalid_address() {
    // test_slc__read_tag_raises_requesterror_for_none
    let fake = Fake::new();
    let d = connected(&fake);
    let err = d.read(&[""]).unwrap_err();
    assert_eq!(class(&err), "RequestError");
}

#[test]
fn read_tag_returns_a_result_for_an_unparseable_reply() {
    // test_slc__read_tag_returns_tag
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(vec![0x00]);
    let result = d.read(&["N7:0"]).unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].value.is_none() && result[0].error.is_some());
}

#[test]
fn get_processor_type_returns_none_for_a_bad_reply() {
    // test_slc_get_processor_type_returns_none_if_falsy_response / _if_parsing_exception
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(vec![0x00]);
    assert_eq!(d.get_processor_type().unwrap(), None);
    fake.reply(pccc_reply(&[], 0, 0));
    assert_eq!(d.get_processor_type().unwrap(), None);
}

// ---- robustness ----

/// A connected driver whose connected requests are answered by `answer(sequence, message)`.
fn responding(answer: impl FnMut(u16, &[u8]) -> Vec<u8> + Send + 'static) -> SlcDriver {
    let fake = Fake::new();
    fake.respond(fake::session_responder(CID, answer));
    let d = driver("1.2.3.4/0", &fake);
    assert!(d.open().unwrap());
    d
}

/// A small deterministic byte generator for hostile replies.
fn noise(seed: &mut u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            *seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (*seed >> 16) as u8
        })
        .collect()
}

#[test]
fn datalog_queue_with_a_huge_count_does_not_preallocate() {
    // a count from the caller must not abort on allocation before the first request is sent
    let fake = Fake::new();
    let d = connected(&fake);
    fake.reply(pccc_reply(b"abc", 0, 0))
        .reply_err(Error::comm("timed out"));
    let err = d.get_datalog_queue(usize::MAX, 0).unwrap_err();
    assert_eq!(class(&err), "CommError");
    assert!(!d.connected());
}

#[test]
fn truncated_and_garbage_replies_never_panic() {
    let mut seed = 7u32;
    let valid = pccc_reply(&[1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0], 0, 0);
    let mut replies: Vec<Vec<u8>> = (0..valid.len()).map(|n| valid[..n].to_vec()).collect();
    for len in [0usize, 1, 2, 5, 11, 40, 300] {
        replies.push(pccc_reply(&noise(&mut seed, len), 0, 0));
        replies.push(pccc_reply(&noise(&mut seed, len), 0xF0, 0));
        let mut frame = valid.clone();
        frame.extend(noise(&mut seed, len));
        replies.push(frame);
    }
    for reply in replies {
        let r = reply.clone();
        let d = responding(move |_, _| r.clone());
        for tag in [
            "N7:0", "N7:0{3}", "F8:0", "F8:0{2}", "ST9:0", "T4:0.ACC", "C5:0/DN", "B3:0/1", "L9:0",
            "A10:0", "I:0", "O:0/1", "S:1",
        ] {
            let _ = d.read(&[tag]);
        }
        let _ = d.write(&[("N7:0", Value::Int(1)), ("F8:0", Value::Real(1.5))]);
        let _ = d.get_processor_type();
        let _ = d.get_datalog_queue(2, 0);
        let _ = d.get_file_directory();
    }
}

#[test]
fn hostile_file_directories_never_panic_and_always_finish() {
    for (seed0, ptype) in [
        (1u32, "1747-L551"),
        (2, "1766-LEC"),
        (3, "1761-L16"),
        (4, "1763-L16"),
    ] {
        for round in 0..20u32 {
            let mut seed = seed0 * 1000 + round;
            let mut requests = 0usize;
            let ptype = ptype.to_owned();
            let d = responding(move |_, _| {
                requests += 1;
                assert!(requests < 5000, "the directory loop does not finish");
                match requests {
                    1 => {
                        let mut p = vec![0; 5];
                        p.extend(ptype.as_bytes());
                        pccc_reply(&p, 0, 0)
                    }
                    2 => pccc_reply(&noise(&mut seed, 2), 0, 0),
                    _ => {
                        let len = usize::from(noise(&mut seed, 1)[0]) % 120;
                        pccc_reply(&noise(&mut seed, len), 0, 0)
                    }
                }
            });
            let _ = d.get_file_directory();
        }
    }
}

#[test]
fn file_directory_reads_make_progress_with_one_byte_replies() {
    let fake = Fake::new();
    let d = connected(&fake);
    let mut ptype = vec![0; 5];
    ptype.extend(b"1747-L551  \0\0\0");
    fake.reply(pccc_reply(&ptype, 0, 0))
        .reply(pccc_reply(&3u16.to_le_bytes(), 0, 0));
    for _ in 0..3 {
        fake.reply(pccc_reply(&[0x81], 0, 0));
    }
    assert!(d.get_file_directory().unwrap().is_empty());
    assert_eq!(fake.sent().len(), 5);
}

#[test]
fn concurrent_reads_from_several_threads_are_serialised() {
    use std::collections::HashSet;
    use std::sync::Arc;
    // every reply carries the low byte of its request's sequence count as the N word
    let d = Arc::new(responding(|seq, _| {
        let mut data = vec![0x07, 0x09, 0x10, 0, 0, 0, 0, 0x4F, 0, 0x01, 0x00];
        data.extend(seq.to_le_bytes());
        fake::unit_reply(CID, seq, 0x4B, 0, &[], &data)
    }));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let d = Arc::clone(&d);
            std::thread::spawn(move || {
                (0..25)
                    .map(|_| {
                        let r = d.read(&["N7:0"]).unwrap();
                        assert!(r[0].error.is_none(), "{:?}", r[0]);
                        r[0].value.clone().unwrap()
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut seen = HashSet::new();
    for t in threads {
        for v in t.join().unwrap() {
            assert!(
                seen.insert(format!("{v:?}")),
                "two reads got the same reply {v:?}"
            );
        }
    }
    assert_eq!(seen.len(), 200);
}

#[test]
fn a_panic_mid_request_drops_the_connection_and_the_driver_stays_usable() {
    // a panic while the connection lock is held (here in the transport) poisons it; the next call must
    // neither panic nor reuse a half-read connection, and open() must reconnect
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let armed = Arc::new(AtomicBool::new(true));
    let trigger = Arc::clone(&armed);
    let d = Arc::new(responding(move |seq, _| {
        if trigger.swap(false, Ordering::SeqCst) {
            panic!("transport blew up");
        }
        let mut data = vec![0x07, 0x09, 0x10, 0, 0, 0, 0, 0x4F, 0, 0x01, 0x00];
        data.extend(7u16.to_le_bytes());
        fake::unit_reply(CID, seq, 0x4B, 0, &[], &data)
    }));
    let d2 = Arc::clone(&d);
    assert!(
        std::thread::spawn(move || d2.read(&["N7:0"]))
            .join()
            .is_err()
    );
    assert!(!armed.load(Ordering::SeqCst));
    assert!(!d.connected());
    let err = d.read(&["N7:0"]).unwrap_err();
    assert_eq!(class(&err), "CommError");
    assert!(d.open().unwrap());
    let r = d.read(&["N7:0"]).unwrap();
    assert!(r[0].error.is_none(), "{:?}", r[0]);
}
